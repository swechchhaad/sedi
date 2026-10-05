#!/usr/bin/env python3
"""SEDI joint satisfiability: BBS credentials + zero-knowledge presentations,
checked against CRY-01, CRY-02, PRV-01, PRV-02 and PRV-03 in ONE design.

Usage:
    python3 scripts/bbs_proverif.py              # generate + run all
    python3 scripts/bbs_proverif.py --only LINK_
    python3 scripts/bbs_proverif.py --list
    python3 scripts/bbs_proverif.py --generate

Writes  proverif/bbs/<config>.pv
        results/bbs/<config>.log, summary.md, results.json

Design under test (see docs/bbs.md):

 * Issuer D signs a BBS credential over (hid, attributes, rh): hid is the
   holder's KERI-style identifier h(pk(sk0), h(pk(sk1))), rh a revocation
   handle. The credential signature is a WALLET secret; it is never shown.
 * Device keys sk0 (old device) / sk1 (pre-rotated, new device) live in the
   secure element and are only used through sign() (HW-NX, as in CRY-02).
 * Honest witnesses keep a key-event log and, per epoch, sign a key-state
   attestation (ks, hid, current device key, epoch). Migration = rotation to
   the pre-committed sk1; the epoch-1 attestation names pk(sk1), so the old
   key has no current attestation. The credential is never reissued.
 * Revocation: an accumulator per epoch. A non-revoked holder computes its
   non-membership witness nmw(rh, e) from the public whole-list update
   (scheduled, presentation-independent); nmw is not computable for revoked rh.
 * Presentation = (t, b, C, pi_auth, pi_rev), C = com(rh, rc) fresh:
     pi_auth: ZK proof of knowledge of a BBS credential on (hid, a, rh), a
              witness attestation (hid, pk(kd), e) and a device signature by
              kd on (nonce, t, C), such that the t-th predicate of a is b.
     pi_rev:  ZK proof that rh (committed in C) is not revoked at epoch e.
   Verifier state: issuer pk, witness pk, current epoch (synced on a schedule).

Symbolic ZK follows Backes-Maffei-Unruh (S&P 2008): a proof is a constructor
zk(secrets, publics, randomness) with a public verification destructor that
checks the relation; there is no destructor returning the secrets. Trace
models additionally use PRIVATE "ghost" destructors (the knowledge extractor)
so that the verifier's events can name the hidden holder/credential; the
attacker cannot apply them, and the equivalence models do not declare them.

Two kinds of model:
  trace (TRACE_CONFIGS): CRY-01, CRY-02, PRV-03 trace lemmas; phase 0 = epoch
        0 (before migration), phase 1 = epoch 1 (after migration).
  equivalence (EQ_CONFIGS): LINK = PRV-01 unlinkability against colluding
        verifiers AND issuer; PRED = PRV-02 predicate-only disclosure;
        NI = PRV-03 Department non-interference.

Exit status is non-zero if any result differs from the expected one.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "proverif" / "bbs"
RESULTS = ROOT / "results" / "bbs"

# ---------------------------------------------------------------------------
# Trace queries. kind "safety": ProVerif `true` = holds.
# kind "reach": holds when ProVerif reports `false` (a trace exists).
# ---------------------------------------------------------------------------
QUERIES = [
    ("sanity_accept_pre", "reach",
     "n, t, b, cm, hid, a, p: bitstring; event(Accept(ph0, n, t, b, cm, hid, a)) && event(DeviceSigned(hid, n, t, cm, p)) && event(OldKey(hid, p)) ==> false",
     "the honest holder's old device is accepted before migration"),
    ("sanity_accept_post", "reach",
     "n, t, b, cm, hid, a, p: bitstring; event(Accept(ph1, n, t, b, cm, hid, a)) && event(DeviceSigned(hid, n, t, cm, p)) && event(NewKey(hid, p)) ==> false",
     "CRY-02.4: the migrated holder is accepted under the new device key, same credential"),
    ("sanity_authentic_but_revoked", "reach",
     "n, t, b, cm, hid, a: bitstring; event(Accept(ph0, n, t, b, cm, hid, a)) && event(RevokedHolder(hid)) && event(StatusFail(n)) ==> false",
     "CRY-01.3: a revoked credential is authentic but fails the separate status check"),
    ("cry01_unforgeable", "safety",
     "ph, n, t, b, cm, hid, a, rh: bitstring; event(Accept(ph, n, t, b, cm, hid, a)) ==> event(Issued(hid, a, rh))",
     "CRY-01.1: an accepted credential (holder id + attributes) was issued"),
    ("cry01_prv03_no_presentation_traffic", "safety",
     "g, k, x: bitstring; event(DObs(cpres, g, k, x))",
     "CRY-01.2 / PRV-03 L1-L4: no Department-visible message is caused by a presentation"),
    ("cry01_status_sound", "safety",
     "n, rh: bitstring; event(StatusGood(n, rh)) && event(Revoked(rh)) ==> false",
     "CRY-01.3: a revoked credential never passes the status check"),
    ("cry02_control_pre", "safety",
     "n, t, b, cm, hid, a, p: bitstring; event(Accept(ph0, n, t, b, cm, hid, a)) && event(Honest(hid)) ==> event(DeviceSigned(hid, n, t, cm, p))",
     "CRY-02.3: accepting an honest holder's credential => its device signed this challenge"),
    ("cry02_control_post", "safety",
     "n, t, b, cm, hid, a, p: bitstring; event(Accept(ph1, n, t, b, cm, hid, a)) && event(Honest(hid)) ==> event(DeviceSigned(hid, n, t, cm, p)) && event(NewKey(hid, p))",
     "CRY-02.3/4: after migration, only the NEW device key is accepted (old key invalid)"),
    ("cry02_control_or_compromise", "safety",
     "ph, n, t, b, cm, hid, a, p: bitstring; event(Accept(ph, n, t, b, cm, hid, a)) && event(Honest(hid)) ==> event(DeviceSigned(hid, n, t, cm, p)) || event(Compromised(hid))",
     "CRY-02.6: holder control fails only after a device-key compromise"),
    ("cry02_sk0_secret", "safety", "attacker(new sk0)",
     "CRY-02.2/5: old device key stays secret (HW-NX)"),
    ("cry02_sk1_secret", "safety", "attacker(new sk1)",
     "CRY-02.2/5: pre-rotated device key stays secret (HW-NX)"),
]
# Extra queries for configurations whose issuer key state comes from a KEL.
ISSUER_QUERIES = [
    ("issuer_key_anchored", "safety",
     "e, p, acc: bitstring; event(VerifierState(e, p, acc)) ==> event(AnchoredKey(p))",
     "CRY-01.1: the BBS key the verifier uses was anchored in the issuer's KEL"),
    ("issuer_acc_anchored", "safety",
     "e, p, acc: bitstring; event(VerifierState(e, p, acc)) ==> event(AnchoredAcc(e, acc))",
     "CRY-01.3: the accumulator value the verifier uses was anchored for that epoch"),
]
QIDS = [q[0] for q in QUERIES]
ALL_QIDS = QIDS + [q[0] for q in ISSUER_QUERIES]
H, F = "holds", "fails"


def queries_for(flags):
    return QUERIES + (ISSUER_QUERIES if "ISSUER_KEL" in flags else [])


def expect(**over):
    base = {q: H for q in ALL_QIDS}
    base.update(over)
    return base


# id -> (description, flags, expected)
TRACE_CONFIGS = [
    ("POS_joint", "BBS + ZK, hardware-bound device key, witnessed key state, "
     "accumulator revocation, scheduled syncs", [], expect()),
    ("E_wallet_data_leak", "wallet storage leaks (credential, rh, witnesses); secure element intact",
     ["WALLET_LEAK"], expect()),
    ("NEG_no_device_signature", "negative control: proof does not include a device signature "
     "(software link secret only) and wallet storage leaks",
     ["NO_DEVICE_SIG", "WALLET_LEAK"],
     expect(cry02_control_pre=F, cry02_control_post=F, cry02_control_or_compromise=F)),
    ("E_device_malware", "malware reads wallet storage and drives the old device's secure element (phase 0)",
     ["ORACLE", "WALLET_LEAK"], expect(cry02_control_pre=F)),
    ("E_old_device_after_migration", "old device (key + storage) compromised after migration",
     ["OLD_DEVICE"], expect(cry02_sk0_secret=F)),
    ("E_old_device_stale_verifier", "old device compromised after migration; verifier still on epoch 0",
     ["OLD_DEVICE", "STALE_VERIFIER"],
     expect(cry02_sk0_secret=F, sanity_accept_post=F, cry02_control_post=F)),
    ("E_recovery_key", "pre-rotated (recovery) key compromised before migration, wallet intact",
     ["RECOVERY"], expect(cry02_sk1_secret=F)),
    ("E_recovery_key_and_wallet_leak", "pre-rotated key compromised and wallet storage leaks",
     ["RECOVERY", "WALLET_LEAK"], expect(cry02_sk1_secret=F, cry02_control_post=F)),
    ("NEG_online_status", "negative control: verifier sends the status proof to the Department",
     ["ONLINE_STATUS"], expect(cry01_prv03_no_presentation_traffic=F)),
    ("POS_issuer_kel", "hybrid: verifier pins only the issuer AID; the issuer's BBS key and each "
     "epoch's accumulator value are anchored in the issuer KEL", ["ISSUER_KEL"], expect()),
    ("NEG_unchecked_key_anchor", "negative control: as POS_issuer_kel, but the verifier does not "
     "check the KEL signature on the BBS-key anchor", ["ISSUER_KEL", "UNCHECKED_ANCHOR"],
     expect(issuer_key_anchored=F, cry01_unforgeable=F)),
]

# id -> (kind, description, flags, expected equivalence)
EQ_CONFIGS = [
    ("LINK_pos", "link", "PRV-01: one holder twice vs. two holders; issuer colludes with verifiers",
     [], "true"),
    ("LINK_pos_across_migration", "link", "PRV-01: as LINK_pos, second presentation after both holders migrated",
     ["MIGRATE"], "true"),
    ("LINK_neg_signature_disclosed", "link", "negative: the BBS signature itself is shown",
     ["SHOW_SIG"], "false"),
    ("LINK_neg_device_key_disclosed", "link", "negative: device public key + signature shown (mdoc-style binding)",
     ["SHOW_DEVKEY"], "false"),
    ("LINK_neg_revocation_handle_disclosed", "link", "negative: revocation handle shown (status-list index)",
     ["SHOW_RH"], "false"),
    ("PRED_pos", "pred", "PRV-02: age 22 vs 27; holder approves >=21 and >=30, declines >=25; unbounded requests",
     [], "true"),
    ("PRED_neg_arbitrary_predicates", "pred", "negative: wallet answers every requested predicate",
     ["ANSWER_ALL"], "false"),
    ("NI_pos", "ni", "PRV-03: presentation vs. no presentation, Department = issuer sees its endpoints",
     [], "true"),
    ("NI_neg_online_status", "ni", "negative: verifier sends the status proof to the Department",
     ["ONLINE_STATUS"], "false"),
    ("LINK_pos_issuer_kel", "link", "PRV-01: as LINK_pos, revocation proofs against the KEL-anchored accumulator",
     ["ISSUER_KEL"], "true"),
    ("NI_pos_issuer_kel", "ni", "PRV-03: as NI_pos, the verifier's scheduled sync fetches the issuer KEL",
     ["ISSUER_KEL"], "true"),
]

ATTR_H = "(tt, ff, ff)"    # holder H: age 22 -> >=21 T, >=25 F, >=30 F
ATTR_R = "(tt, tt, ff)"    # holder R: age 27 (revoked)
THRESHOLDS = (("t21", "b1"), ("t25", "b2"), ("t30", "b3"))

# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------


def primitives(device_sig=True, ghosts=False):
    ds = "sign((prf, n, {t}, com(rh, rc)), kd)" if device_sig else "ds"
    rules = []
    for t, b in THRESHOLDS:
        P = f"(pk(ki), pk(kw), e, n, {t}, {b}, com(rh, rc))"
        S = (f"(bbs((hid, (b1, b2, b3), rh), ki), sign((ks, hid, pk(kd), e), kw), "
             f"{ds.format(t=t)}, rh, rc)")
        extra = "" if device_sig else ", ds"
        rules.append(f"  forall hid, b1, b2, b3, rh, ki, kw, kd, e, n, rc, r{extra}: bitstring;\n"
                     f"    vauth(zkauth({S},\n          {P}, r),\n          {P}) = true")
    text = f"""
const icp, rot, ixn, ks, prf, req, getcred, issued, declined, norev, nods: bitstring.
const bbskey, accseal: bitstring.
const tt, ff, t21, t25, t30, e0, e1, ph0, ph1: bitstring.
const cpres, csched, status, fetchall, statusquery, vid, hep: bitstring.

fun h(bitstring): bitstring.
fun pk(bitstring): bitstring.
(* device / witness signatures (e.g. ECDSA in the secure element) *)
fun sign(bitstring, bitstring): bitstring.
reduc forall m: bitstring, k: bitstring; verify(sign(m, k), m, pk(k)) = true.
reduc forall m: bitstring, k: bitstring; getmsg(sign(m, k)) = m.

(* hiding, binding commitment *)
fun com(bitstring, bitstring): bitstring.

(* BBS signature over a message vector; only the holder ever sees it *)
fun bbs(bitstring, bitstring): bitstring.
reduc forall m: bitstring, k: bitstring; bbsver(bbs(m, k), m, pk(k)) = true.

(* accumulator non-membership witness: computable only for non-revoked
   handles, from the public whole-list update (private = attacker cannot
   compute it for a revoked handle) *)
fun nmw(bitstring, bitstring): bitstring [private].

(* zero-knowledge proofs: zk(secrets, publics, randomness). No destructor
   returns the secrets; verification checks the relation for given publics. *)
fun zkauth(bitstring, bitstring, bitstring): bitstring.
fun zkrev(bitstring, bitstring, bitstring): bitstring.

(* pi_auth: I know a BBS credential on (hid, a, rh) under ki, a witness
   attestation that kd is hid's device key at epoch e, {"and a signature by kd on (nonce, t, C)" if device_sig else "(NO device signature: any ds)"},
   such that predicate t of a has value b, and C commits to rh. One rule
   per predicate in the bounded domain. *)
reduc
{";\n".join(rules)}.

(* pi_rev: the rh committed in C is not revoked in accumulator value acc
   (the epoch constant, or a KEL-anchored value with ISSUER_KEL) *)
reduc forall rh, acc, n, rc, r: bitstring;
  vrev(zkrev((rh, nmw(rh, acc), rc), (acc, n, com(rh, rc)), r), (acc, n, com(rh, rc))) = true.

"""
    if ghosts:
        text += """
(* GHOST knowledge extractors: verification bookkeeping only (private, so
   the attacker cannot use them). They let Accept / StatusGood name the
   hidden holder, attributes and revocation handle. *)
reduc forall hid, a, rh, ki, s2, s3, rh2, rc, p, r: bitstring;
  ghost(zkauth((bbs((hid, a, rh), ki), s2, s3, rh2, rc), p, r)) = (hid, a) [private].
reduc forall rh, w, rc, p, r: bitstring;
  ghostrh(zkrev((rh, w, rc), p, r)) = rh [private].
"""
    return text


def proof(cred, att, ds, rh, rc, pkI, pkW, e, n, t, b, C, ra, rb, acc=None):
    acc = acc or e
    return (f"zkauth(({cred}, {att}, {ds}, {rh}, {rc}), ({pkI}, {pkW}, {e}, {n}, {t}, {b}, {C}), {ra}),\n"
            f"          zkrev(({rh}, nmw({rh}, {acc}), {rc}), ({acc}, {n}, {C}), {rb})")


# ---------------------------------------------------------------------------
# Trace model
# ---------------------------------------------------------------------------

def trace_model(cid, desc, flags):
    f = set(flags)
    devsig = "NO_DEVICE_SIG" not in f
    kel = "ISSUER_KEL" in f
    out = [f"""(* GENERATED by scripts/bbs_proverif.py -- do not edit by hand.
   SEDI joint (BBS + ZK) {cid}: {desc}
   Flags: {" ".join(flags) or "-"}
   phase 0 = epoch e0 (before migration), phase 1 = epoch e1 (after).
   Accumulator values a0 / a1: {"KEL-anchored names" if kel else "the epoch constants (synced out of band)"}. *)

free c: channel.
free enrollH, deliverH, enrollR, deliverR: channel [private].
"""]
    out.append(primitives(device_sig=devsig, ghosts=True))
    out.append("""
table kel(bitstring, bitstring, bitstring).   (* hid, inception key, next-key digest *)

event Honest(bitstring).
event RevokedHolder(bitstring).
event OldKey(bitstring, bitstring).
event NewKey(bitstring, bitstring).
event Issued(bitstring, bitstring, bitstring).
event Revoked(bitstring).
event DeviceSigned(bitstring, bitstring, bitstring, bitstring, bitstring).
event Accept(bitstring, bitstring, bitstring, bitstring, bitstring, bitstring, bitstring).
event StatusGood(bitstring, bitstring).
event StatusFail(bitstring).
event Compromised(bitstring).
event MigrationDone(bitstring).
event DObs(bitstring, bitstring, bitstring, bitstring).
event AnchoredKey(bitstring).
event AnchoredAcc(bitstring, bitstring).
event VerifierState(bitstring, bitstring, bitstring).

""")
    out += [f"query {q[2]}.  (* {q[0]}: {q[3]} *)\n" for q in queries_for(f)]

    out.append(f"""
(* Issuer D: the two honest holders over private enrolment, plus any number
   of attacker-controlled holders, who must prove control of their inception
   key. Every issuance raises Issued. *)
let Issuer(skI: bitstring, a0: bitstring, a1: bitstring) =
  ( in(enrollH, hid: bitstring); new rh: bitstring;
    event Issued(hid, {ATTR_H}, rh);
    out(deliverH, (rh, bbs((hid, {ATTR_H}, rh), skI))) )
| ( in(enrollR, hid: bitstring); new rh: bitstring;
    event Issued(hid, {ATTR_R}, rh); event Revoked(rh);
    out(deliverR, (rh, bbs((hid, {ATTR_R}, rh), skI))) )
| !( in(c, ((=getcred, hid: bitstring, a: bitstring), p: bitstring, nd: bitstring, sg: bitstring));
     if hid = h((p, nd)) then
     if verify(sg, (getcred, hid, a), p) = true then
     new rh: bitstring;
     event Issued(hid, a, rh);
     out(c, (rh, bbs((hid, a, rh), skI), nmw(rh, a0), nmw(rh, a1))) ).

(* Honest witnesses: attest self-certifying inceptions for epoch e0; in
   epoch e1 attest the key a pre-rotation-checked rotation moved to. *)
let Witness(skW: bitstring) =
  ( !( in(c, (=icp, a: bitstring, p: bitstring, nd: bitstring));
       if a = h((p, nd)) then
       insert kel(a, p, nd);
       out(c, sign((ks, a, p, e0), skW)) ) )
| ( phase 1;
    !( in(c, ((=rot, a: bitstring, p1: bitstring, n2: bitstring), sg: bitstring));
       get kel(=a, p0: bitstring, =h(p1)) in
       if verify(sg, (rot, a, p1, n2), p1) = true then
       event MigrationDone(a);
       out(c, sign((ks, a, p1, e1), skW)) ) ).
""")

    def present(sk, att, e, acc, attrs_b, hidv="hid"):
        ds = f"sign((prf, n, t, C), {sk})" if devsig else "nods"
        return f"""!( in(c, (=req, n: bitstring, t: bitstring));
       if t = t21 then
       new rc: bitstring; new ra: bitstring; new rb: bitstring;
       let C = com(rh, rc) in
       event DeviceSigned({hidv}, n, t, C, pk({sk}));
       out(c, (t, {attrs_b}, C,
          {proof("cred", att, ds, "rh", "rc", "pkI", "pkW", e, "n", "t", attrs_b, "C", "ra", "rb", acc)})) )"""

    branches = ""
    if "WALLET_LEAK" in f:
        branches += "\n  | out(c, (cred, rh, nmw(rh, a0), nmw(rh, a1)))"
    if "ORACLE" in f:
        branches += "\n  | !( in(c, m: bitstring); event Compromised(hid); out(c, sign(m, sk0)) )"
    if "OLD_DEVICE" in f:
        branches += "\n  | ( phase 1; event Compromised(hid); out(c, (sk0, cred, rh, nmw(rh, a0))) )"
    if "RECOVERY" in f:
        branches += "\n  | ( event Compromised(hid); out(c, sk1) )"

    out.append(f"""
(* Honest holder H. sk0 is generated in the old device's secure element,
   sk1 in the new device's; both are only used through sign() (HW-NX).
   At migration the new device rotates hid to sk1 and receives the wallet
   data (credential, rh) -- no private key moves, no reissuance. *)
let HolderH(pkI: bitstring, pkW: bitstring, a0: bitstring, a1: bitstring) =
  new sk0: bitstring; new sk1: bitstring;
  let hid = h((pk(sk0), h(pk(sk1)))) in
  event Honest(hid); event OldKey(hid, pk(sk0)); event NewKey(hid, pk(sk1));
  out(c, (icp, hid, pk(sk0), h(pk(sk1))));
  out(enrollH, hid);
  in(deliverH, (rh: bitstring, cred: bitstring));
  if bbsver(cred, (hid, {ATTR_H}, rh), pkI) = true then
  in(c, att0: bitstring);
  if verify(att0, (ks, hid, pk(sk0), e0), pkW) = true then
  (* scheduled whole-list revocation update: presentation-independent *)
  event DObs(csched, status, fetchall, e0); out(c, (fetchall, hep, e0));
  ( {present("sk0", "att0", "e0", "a0", "tt")}
  | ( phase 1;
      new sk2: bitstring;
      let rotev = (rot, hid, pk(sk1), h(pk(sk2))) in
      out(c, (rotev, sign(rotev, sk1)));
      in(c, att1: bitstring);
      if verify(att1, (ks, hid, pk(sk1), e1), pkW) = true then
      event DObs(csched, status, fetchall, e1); out(c, (fetchall, hep, e1));
      {present("sk1", "att1", "e1", "a1", "tt")} ){branches} ).

(* Honest holder R whose credential is revoked: it has no non-membership
   witness, so it presents without a status proof. Epoch 0 only. *)
let HolderR(pkI: bitstring, pkW: bitstring) =
  new rk0: bitstring; new rk1: bitstring;
  let hid = h((pk(rk0), h(pk(rk1)))) in
  event Honest(hid); event RevokedHolder(hid);
  out(c, (icp, hid, pk(rk0), h(pk(rk1))));
  out(enrollR, hid);
  in(deliverR, (rh: bitstring, cred: bitstring));
  in(c, att0: bitstring);
  if verify(att0, (ks, hid, pk(rk0), e0), pkW) = true then
  !( in(c, (=req, n: bitstring, t: bitstring));
     if t = t21 then
     new rc: bitstring; new ra: bitstring;
     let C = com(rh, rc) in
     event DeviceSigned(hid, n, t, C, pk(rk0));
     out(c, (t, tt, C,
        zkauth((cred, att0, {"sign((prf, n, t, C), rk0)" if devsig else "nods"}, rh, rc), (pkI, pkW, e0, n, t, tt, C), ra),
        norev)) ).
""")

    online = ""
    if "ONLINE_STATUS" in f:
        online = ("\n     event DObs(cpres, status, statusquery, C);"
                  "\n     out(c, (statusquery, vid, C, pr));")
    key_check = ("" if "UNCHECKED_ANCHOR" in f else
                 "\n  if verify(sgk, (ixn, aidI, bbskey, pkI), kp) = true then")
    if kel:
        verifier_head = f"""
(* Verifier: pins only the issuer AID (and the witness key). Its scheduled
   sync fetches the issuer KEL: the inception (self-certifying against the
   pinned AID), the anchor of the issuer's BBS key, and the anchor of this
   epoch's accumulator value -- all signed by the issuer's current KEL key.
   Then it verifies OFFLINE. *)
let Verifier(aidI: bitstring, pkW: bitstring, ph: bitstring, e: bitstring) =
  event DObs(csched, status, fetchall, e); out(c, (fetchall, vid, e));
  in(c, (=icp, =aidI, kp: bitstring, nd: bitstring));
  if aidI = h((kp, nd)) then
  in(c, ((=ixn, =aidI, =bbskey, pkI: bitstring), sgk: bitstring));{key_check}
  in(c, ((=ixn, =aidI, =accseal, =e, acc: bitstring), sga: bitstring));
  if verify(sga, (ixn, aidI, accseal, e, acc), kp) = true then
  event VerifierState(e, pkI, acc);"""
    else:
        verifier_head = """
(* Verifier: syncs the epoch's accumulator / key-state root on a schedule,
   then verifies OFFLINE with the issuer key, the witness key and that
   epoch. Authenticity first; status is a separate, later check. *)
let Verifier(pkI: bitstring, pkW: bitstring, ph: bitstring, e: bitstring) =
  event DObs(csched, status, fetchall, e); out(c, (fetchall, vid, e));
  let acc = e in"""
    out.append(verifier_head + f"""
  !( in(c, t: bitstring);
     new n: bitstring;
     out(c, (req, n, t));
     in(c, (=t, b: bitstring, C: bitstring, pa: bitstring, pr: bitstring));
     if vauth(pa, (pkI, pkW, e, n, t, b, C)) = true then
     let (hid: bitstring, a: bitstring) = ghost(pa) in
     event Accept(ph, n, t, b, C, hid, a);{online}
     let ok = vrev(pr, (acc, n, C)) in event StatusGood(n, ghostrh(pr))
     else event StatusFail(n) ).
""")
    ev = "e0" if "STALE_VERIFIER" in f else "e1"
    if kel:
        out.append(f"""
(* Issuer KEL: inception, then anchors (interaction events signed with the
   current KEL key kI0) for the BBS key and for each epoch's accumulator. *)
let IssuerKEL(kI0: bitstring, kI1: bitstring, skI: bitstring, a0: bitstring, a1: bitstring) =
  let aidI = h((pk(kI0), h(pk(kI1)))) in
  event AnchoredKey(pk(skI)); event AnchoredAcc(e0, a0);
  out(c, (icp, aidI, pk(kI0), h(pk(kI1))));
  out(c, ((ixn, aidI, bbskey, pk(skI)), sign((ixn, aidI, bbskey, pk(skI)), kI0)));
  out(c, ((ixn, aidI, accseal, e0, a0), sign((ixn, aidI, accseal, e0, a0), kI0)));
  phase 1;
  event AnchoredAcc(e1, a1);
  out(c, ((ixn, aidI, accseal, e1, a1), sign((ixn, aidI, accseal, e1, a1), kI0))).

process
  new skI: bitstring; new skW: bitstring; new kI0: bitstring; new kI1: bitstring;
  new acc0: bitstring; new acc1: bitstring;
  out(c, pk(skW));
  ( IssuerKEL(kI0, kI1, skI, acc0, acc1)
  | Issuer(skI, acc0, acc1) | Witness(skW)
  | HolderH(pk(skI), pk(skW), acc0, acc1) | HolderR(pk(skI), pk(skW))
  | !Verifier(h((pk(kI0), h(pk(kI1)))), pk(skW), ph0, e0)
  | ( phase 1; !Verifier(h((pk(kI0), h(pk(kI1)))), pk(skW), ph1, {ev}) ) )
""")
    else:
        out.append(f"""
process
  new skI: bitstring; new skW: bitstring;
  out(c, pk(skI)); out(c, pk(skW));
  ( Issuer(skI, e0, e1) | Witness(skW)
  | HolderH(pk(skI), pk(skW), e0, e1) | HolderR(pk(skI), pk(skW))
  | !Verifier(pk(skI), pk(skW), ph0, e0)
  | ( phase 1; !Verifier(pk(skI), pk(skW), ph1, {ev}) ) )
""")
    return "".join(out)


# ---------------------------------------------------------------------------
# Equivalence models
# ---------------------------------------------------------------------------

def eq_header(cid, desc, flags, note):
    return f"""(* GENERATED by scripts/bbs_proverif.py -- do not edit by hand.
   SEDI joint (BBS + ZK) {cid}: {desc}
   Flags: {" ".join(flags) or "-"}
   {note} *)

free c: channel.
free hv, sink, vlocal: channel [private].
const accepted, none: bitstring.
"""


# Issuer KEL for the equivalence models: the colluding Department knows its
# KEL keys; the anchors (BBS key, accumulator values) are public, the same
# for every holder, and published in both worlds.
ISSUER_KEL_SETUP = """  new kI0: bitstring; new kI1: bitstring; new acc0: bitstring; new acc1: bitstring;
  let aidI = h((pk(kI0), h(pk(kI1)))) in
  out(c, (kI0, kI1));
  out(c, (icp, aidI, pk(kI0), h(pk(kI1))));
  out(c, ((ixn, aidI, bbskey, pk(skI)), sign((ixn, aidI, bbskey, pk(skI)), kI0)));
  out(c, ((ixn, aidI, accseal, e0, acc0), sign((ixn, aidI, accseal, e0, acc0), kI0)));
  out(c, ((ixn, aidI, accseal, e1, acc1), sign((ixn, aidI, accseal, e1, acc1), kI0)));
"""


def holder_setup(i, attrs, migrate):
    s = f"""  new k{i}0: bitstring; new k{i}1: bitstring; new k{i}2: bitstring; new rh{i}: bitstring;
  let hid{i} = h((pk(k{i}0), h(pk(k{i}1)))) in
  let cred{i} = bbs((hid{i}, {attrs}, rh{i}), skI) in
  let att{i}0 = sign((ks, hid{i}, pk(k{i}0), e0), skW) in
  let att{i}1 = sign((ks, hid{i}, pk(k{i}1), e1), skW) in
  let rot{i} = (rot, hid{i}, pk(k{i}1), h(pk(k{i}2))) in
  out(c, ((icp, hid{i}, pk(k{i}0), h(pk(k{i}1))), att{i}0));    (* public key-event log *)
  out(c, (issued, hid{i}, {attrs}, rh{i}));                    (* issuance record, to colluders *)
"""
    if migrate:
        s += f"  out(c, ((rot{i}, sign(rot{i}, k{i}1)), att{i}1));\n"
    return s


def link_model(cid, desc, flags):
    f = set(flags)
    mig = "MIGRATE" in f
    out = [eq_header(cid, desc, flags,
                     "world 0: holder 1 presents to V1 and V2; world 1: holder 1 to V1, holder 2 to V2.\n"
                     "   Verifiers AND the issuer are the attacker (issuer key + issuance records)."),
           primitives()]
    kel = "ISSUER_KEL" in f
    out.append("""
process
  new skI: bitstring; new skW: bitstring;
  out(c, (pk(skI), pk(skW), skI));
""")
    if kel:
        out.append(ISSUER_KEL_SETUP)
    # undisclosed attributes differ between the holders; the disclosed one agrees
    out.append(holder_setup(1, "(tt, ff, ff)", mig))
    out.append(holder_setup(2, "(tt, tt, ff)", mig))
    j = "1" if mig else "0"
    e2 = "e1" if mig else "e0"
    out.append(f"""  let hidP = choice[hid1, hid2] in
  let credP = choice[cred1, cred2] in
  let rhP = choice[rh1, rh2] in
  let skP = choice[k1{j}, k2{j}] in
  let attP = choice[att1{j}, att2{j}] in
""")

    def pres(i, cred, rh, sk, att, e):
        acc = ("acc0" if e == "e0" else "acc1") if kel else e
        extra = ""
        if "SHOW_SIG" in f:
            extra += f", {cred}"
        if "SHOW_DEVKEY" in f:
            extra += f", pk({sk}), sign((prf, n{i}, t21, C{i}), {sk})"
        if "SHOW_RH" in f:
            extra += f", {rh}"
        return f"""( in(c, n{i}: bitstring);
      new rc{i}: bitstring; new ra{i}: bitstring; new rb{i}: bitstring;
      let C{i} = com({rh}, rc{i}) in
      out(c, (t21, tt, C{i},
          {proof(cred, att, f"sign((prf, n{i}, t21, C{i}), {sk})", rh, f"rc{i}", "pk(skI)", "pk(skW)",
                 e, f"n{i}", "t21", "tt", f"C{i}", f"ra{i}", f"rb{i}", acc)}{extra})) )"""

    out.append(f"  ( {pres(1, 'cred1', 'rh1', 'k10', 'att10', 'e0')}\n"
               f"  | {pres(2, 'credP', 'rhP', 'skP', 'attP', e2)} )\n")
    return "".join(out)


def pred_model(cid, desc, flags):
    f = set(flags)
    out = [eq_header(cid, desc, flags,
                     "world 0: attributes of age 22 (T,F,F); world 1: age 27 (T,T,F).\n"
                     "   The holder approves >=21 and >=30 (equal in both worlds) and declines >=25."),
           primitives()]

    def answer(t, b):
        return (f"out(c, ({t}, {b}, C,\n          "
                f"{proof('cred', 'att', f'sign((prf, n, {t}, C), k0)', 'rh', 'rc', 'pk(skI)', 'pk(skW)', 'e0', 'n', t, b, 'C', 'ra', 'rb')}))")

    extra = ""
    if "ANSWER_ALL" in f:
        extra = f"\n     else if t = t25 then {answer('t25', 'b2')}"
    out.append(f"""
process
  new skI: bitstring; new skW: bitstring;
  out(c, (pk(skI), pk(skW)));
  new k0: bitstring; new k1: bitstring; new rh: bitstring;
  let hid = h((pk(k0), h(pk(k1)))) in
  let att = sign((ks, hid, pk(k0), e0), skW) in
  out(c, ((icp, hid, pk(k0), h(pk(k1))), att));
  let b1 = tt in let b2 = choice[ff, tt] in let b3 = ff in
  let cred = bbs((hid, (b1, b2, b3), rh), skI) in
  !( in(c, (=req, n: bitstring, t: bitstring));
     new rc: bitstring; new ra: bitstring; new rb: bitstring;
     let C = com(rh, rc) in
     if t = t21 then {answer('t21', 'b1')}
     else if t = t30 then {answer('t30', 'b3')}{extra}
     else out(c, (declined, n)) )
""")
    return "".join(out)


def ni_model(cid, desc, flags):
    f = set(flags)
    out = [eq_header(cid, desc, flags,
                     "world 0: the holder presents; world 1: it does not. As in prv03: the private\n"
                     "   holder<->verifier exchange runs in both worlds (the Department cannot see\n"
                     "   it); presentation-caused Department traffic goes to choice[c, sink] and\n"
                     "   the verifier's local record to choice[record, none] on private vlocal.\n"
                     "   The attacker is the Department: issuer key, issuance records, channel c."),
           primitives()]
    online = ""
    if "ONLINE_STATUS" in f:
        online = "\n      out(choice[c, sink], (statusquery, vid, C, pr));"
    kel = "ISSUER_KEL" in f
    acc = "acc0" if kel else "e0"
    out.append(f"""
process
  new skI: bitstring; new skW: bitstring;
  out(c, (pk(skI), pk(skW), skI));
{ISSUER_KEL_SETUP if kel else ""}  new k0: bitstring; new k1: bitstring; new rh: bitstring;
  let hid = h((pk(k0), h(pk(k1)))) in
  let cred = bbs((hid, {ATTR_H}, rh), skI) in
  let att = sign((ks, hid, pk(k0), e0), skW) in
  out(c, ((icp, hid, pk(k0), h(pk(k1))), att));
  out(c, (issued, hid, {ATTR_H}, rh));
  (* scheduled background syncs: identical in both worlds *)
  out(c, (fetchall, vid, e0)); out(c, (fetchall, hep, e0));
  ( ( new n: bitstring; out(hv, n);
      in(hv, (=t21, b: bitstring, C: bitstring, pa: bitstring, pr: bitstring));
      if vauth(pa, (pk(skI), pk(skW), e0, n, t21, b, C)) = true then{online}
      let ok = vrev(pr, ({acc}, n, C)) in
      out(vlocal, choice[(accepted, n), none]) )
  | ( in(hv, n: bitstring);
      new rc: bitstring; new ra: bitstring; new rb: bitstring;
      let C = com(rh, rc) in
      out(hv, (t21, tt, C,
          {proof('cred', 'att', 'sign((prf, n, t21, C), k0)', 'rh', 'rc', 'pk(skI)', 'pk(skW)', 'e0', 'n', 't21', 'tt', 'C', 'ra', 'rb', acc)})) ) )
""")
    return "".join(out)


EQ_BUILDERS = {"link": link_model, "pred": pred_model, "ni": ni_model}

# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


def find_proverif(explicit):
    for cand in (explicit, shutil.which("proverif"),
                 os.path.expanduser("~/opt/proverif2.05/proverif")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    sys.exit("proverif not found: pass --proverif PATH or put it on PATH")


def raw_results(out):
    if "Verification summary:" not in out:
        return []
    summary = out.split("Verification summary:")[1]
    return [ln.strip() for ln in summary.splitlines() if ln.strip().startswith("Query ")]


def verdict(line):
    if line.endswith("is true."):
        return "true"
    if line.endswith("is false."):
        return "false"
    return "cannot be proved"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--proverif", default=None)
    args = ap.parse_args()

    trace = [c for c in TRACE_CONFIGS if c[0].startswith(args.only)]
    eq = [c for c in EQ_CONFIGS if c[0].startswith(args.only)]
    if args.list:
        for c in trace:
            print(f"{c[0]:38} trace  {' '.join(c[2])}")
        for c in eq:
            print(f"{c[0]:38} {c[1]:6} expected={c[4]}")
        return 0

    MODELS.mkdir(parents=True, exist_ok=True)
    for cid, desc, flags, _ in trace:
        (MODELS / f"{cid}.pv").write_text(trace_model(cid, desc, flags))
    for cid, kind, desc, flags, _ in eq:
        (MODELS / f"{cid}.pv").write_text(EQ_BUILDERS[kind](cid, desc, flags))
    if args.generate:
        print(f"wrote {len(trace) + len(eq)} models to {MODELS.relative_to(ROOT)}")
        return 0

    pv = find_proverif(args.proverif)
    RESULTS.mkdir(parents=True, exist_ok=True)

    def run(cid):
        t0 = time.time()
        try:
            p = subprocess.run([pv, str(MODELS / f"{cid}.pv")], capture_output=True,
                               text=True, timeout=args.timeout)
            out = p.stdout + p.stderr
        except subprocess.TimeoutExpired:
            out = "TIMEOUT"
        (RESULTS / f"{cid}.log").write_text(out)
        return out, round(time.time() - t0, 2)

    records, mismatches = [], 0
    for cid, desc, flags, exp in trace:
        out, secs = run(cid)
        res = raw_results(out)
        qs = queries_for(flags)
        qids = [q[0] for q in qs]
        exp = {q: exp[q] for q in qids}
        got = {}
        if len(res) != len(qs):
            got = {q: "error" for q in qids}
        else:
            for (qid, kind, _, _), line in zip(qs, res):
                v = verdict(line)
                if v == "cannot be proved":
                    got[qid] = "unknown"
                elif kind == "safety":
                    got[qid] = H if v == "true" else F
                else:
                    got[qid] = H if v == "false" else F
        bad = [q for q in qids if got[q] != exp[q]]
        mismatches += len(bad)
        records.append(dict(id=cid, kind="trace", description=desc, flags=flags,
                            expected=exp, actual=got, mismatches=bad, seconds=secs))
        print(f"{cid:38} {len(qids) - len(bad)}/{len(qids)} as expected"
              f"{'' if not bad else '  MISMATCH: ' + ', '.join(bad)}  ({secs}s)", flush=True)

    for cid, kind, desc, flags, exp in eq:
        out, secs = run(cid)
        if "RESULT Observational equivalence is true" in out:
            actual = "true"
        elif "RESULT Observational equivalence cannot be proved" in out:
            actual = "false"
        else:
            actual = "error"
        trace_found = "A trace has been found" in out
        ok = actual == exp and (exp == "true" or trace_found)
        mismatches += not ok
        lines = out.splitlines()
        test = next(([ln.strip() for ln in lines[i:i + 5]]
                     for i in range(len(lines) - 1, -1, -1)
                     if lines[i].startswith("The attacker tests whether")), [])
        records.append(dict(id=cid, kind=kind, description=desc, flags=flags, expected=exp,
                            actual=actual, trace_found=trace_found, match=ok, test=test,
                            seconds=secs))
        print(f"{cid:38} expected={exp:5} actual={actual:5}"
              f"{' (trace)' if trace_found else ''} {'ok' if ok else 'MISMATCH'}  ({secs}s)",
              flush=True)

    ver = subprocess.run([pv, "-help"], capture_output=True, text=True).stdout.splitlines()[0]
    (RESULTS / "results.json").write_text(json.dumps(
        dict(proverif=ver, generated=time.strftime("%Y-%m-%dT%H:%M:%S"),
             mismatches=mismatches, results=records), indent=1))

    lines = [f"# Joint BBS + ZK ProVerif results ({ver})", "",
             "Trace models: `holds` / **FAILS** per query (✗ = differs from expected).", "",
             "| config | " + " | ".join(ALL_QIDS) + " |", "|---|" + "---|" * len(ALL_QIDS)]
    for r in records:
        if r["kind"] != "trace":
            continue
        cells = []
        for q in ALL_QIDS:
            if q not in r["actual"]:
                cells.append("—")
                continue
            a = r["actual"][q]
            cell = "holds" if a == H else ("**FAILS**" if a == F else a)
            cells.append(cell + ("" if a == r["expected"][q] else " ✗"))
        lines.append(f"| {r['id']} | " + " | ".join(cells) + " |")
    lines += ["", "Equivalence models: `true` = equivalent (private).", "",
              "| config | description | expected | actual | match |", "|---|---|---|---|---|"]
    for r in records:
        if r["kind"] != "trace":
            lines.append(f"| {r['id']} | {r['description']} | {r['expected']} | "
                         f"{r['actual']} | {'yes' if r['match'] else '**NO**'} |")
    (RESULTS / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\n{mismatches} mismatch(es)")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
