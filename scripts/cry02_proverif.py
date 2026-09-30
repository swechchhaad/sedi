#!/usr/bin/env python3
"""SEDI-CRY-02 (holder key control, migration, compromise) in ProVerif.

Usage:
    python3 scripts/cry02_proverif.py              # generate + run all
    python3 scripts/cry02_proverif.py --only E_    # configs whose id starts with E_
    python3 scripts/cry02_proverif.py --list
    python3 scripts/cry02_proverif.py --generate   # only write the .pv files

Writes  proverif/cry02/<config>.pv
        results/cry02/<config>.log, summary.md, results.json

Two kinds of model:

 * Trace models (variants A-E): correspondence, secrecy and reachability
   queries. phase 0 = before migration, phase 1 = after migration.
 * Equivalence models (PRV_*): does binding the credential to a stable holder
   AID / device key make two presentations linkable (SEDI-PRV-01)? Same
   two-world set-up as scripts/prv01_proverif.py.

HARDWARE ASSUMPTION (HW-NX). A device key is created with `new` inside the
device process and is only ever used through sign(); it is never output
except by an explicit compromise branch (Reveal). This is an ASSUMPTION about
the secure element, not something the symbolic model proves: a fresh name
that is never output is trivially secret. The meaningful results are the
compromise configurations, which show what breaks when HW-NX fails.

Exit status is non-zero if any query result differs from the expected one.
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
MODELS = ROOT / "proverif" / "cry02"
RESULTS = ROOT / "results" / "cry02"

# ---------------------------------------------------------------------------
# Queries of the trace models. kind "safety": ProVerif `true` = property holds.
# kind "reach": property holds when ProVerif reports `false` (a trace exists).
# ---------------------------------------------------------------------------
QUERIES = [
    ("sanity_accept_pre", "reach",
     "a, n, s, p: bitstring; event(AcceptControl(a, n, s, p))",
     "a verifier can accept proof of control before migration"),
    ("Q1a_control_pre", "safety",
     "a, n, s, p: bitstring; inj-event(AcceptControl(a, n, s, p)) ==> inj-event(DeviceSigned(a, n, s, p))",
     "1. holder control (before migration): acceptance => the holder device signed this challenge"),
    ("Q1b_control_post", "safety",
     "a, n, s, p: bitstring; event(AcceptCurrent(a, n, s, p)) && event(MigrationDone(a)) ==> event(DeviceSigned(a, n, s, p))",
     "1. holder control (after a completed migration)"),
    ("Q1c_control_pre_or_compromise", "safety",
     "a, n, s, p: bitstring; event(AcceptControl(a, n, s, p)) ==> event(DeviceSigned(a, n, s, p)) || event(Compromised(p))",
     "1. holder control before migration, except after compromise of that key"),
    ("Q1d_control_post_or_compromise", "safety",
     "a, n, s, p: bitstring; event(AcceptCurrent(a, n, s, p)) && event(MigrationDone(a)) ==> event(DeviceSigned(a, n, s, p)) || event(Compromised(p))",
     "1. holder control after migration, except after compromise of that key"),
    ("Q2a_secret_sk_old", "safety", "attacker(new sk0)",
     "2. key secrecy: old/current device key"),
    ("Q2b_secret_sk_new", "safety", "attacker(new sk1)",
     "2. key secrecy: new device / pre-rotated key"),
    ("Q2c_secret_unless_reveal", "safety",
     "k: bitstring; event(KeyGen(k, pk(k))) && attacker(k) ==> event(Reveal(pk(k)))",
     "2. any holder key known to the attacker was explicitly revealed"),
    ("Q3_no_server_copy", "safety",
     "p: bitstring; event(ServerGotKey(p))",
     "3. no issuer/server ever receives a holder private key"),
    ("Q4a_migrated_accept", "reach",
     "a, n, s, p: bitstring; event(AcceptCurrent(a, n, s, p)) && event(NewKey(a, p)) ==> false",
     "4. after migration, the credential is accepted under the NEW key"),
    ("Q4b_no_reissue", "safety",
     "a, n, s, p: bitstring; event(AcceptCurrent(a, n, s, p)) ==> event(Issued(s, a))",
     "4. ...for the credential issued once, before migration (no new Issued event)"),
    ("Q5_old_key_invalid", "safety",
     "a, n, s, p: bitstring; event(AcceptCurrent(a, n, s, p)) && event(OldKey(a, p)) && event(MigrationDone(a)) ==> false",
     "5. after a completed migration, the old key cannot produce an accepted presentation"),
]
QIDS = [q[0] for q in QUERIES]

# Expected outcome per query: "holds" / "fails" / "n/a" (vacuous in variant)
H, F = "holds", "fails"


def expect(**over):
    base = {q: H for q in QIDS}
    base.update(over)
    return base


# id -> (variant, description, flags, expected {query: holds/fails})
TRACE_CONFIGS = [
    ("A_B_C_D_keri", "A-D",
     "KERI: holder-generated device key, credential bound to holder AID, "
     "challenge-response proof of control, migration by pre-rotation",
     ["BIND_AID"], expect()),
    ("B_bind_device_key", "B",
     "credential bound directly to the device public key (no KEL)",
     ["BIND_KEY"], expect(Q4a_migrated_accept=F)),
    ("E_signing_oracle", "E",
     "attacker gets signing-oracle access to the current device (key not extracted)",
     ["BIND_AID", "ORACLE"], expect(Q1a_control_pre=F)),
    ("E_extract_current", "E",
     "full extraction of the current device key before migration",
     ["BIND_AID", "EXTRACT"], expect(Q1a_control_pre=F, Q2a_secret_sk_old=F)),
    ("E_old_device_after_migration", "E",
     "old device (old key) compromised after migration",
     ["BIND_AID", "OLD_DEVICE"], expect(Q2a_secret_sk_old=F)),
    ("E_old_device_stale_verifier", "E",
     "old device compromised after migration, verifier uses stale key state",
     ["BIND_AID", "OLD_DEVICE", "STALE_VERIFIER"],
     expect(Q2a_secret_sk_old=F, Q1b_control_post=F, Q1d_control_post_or_compromise=H,
            Q4a_migrated_accept=F, Q5_old_key_invalid=F)),
    ("E_old_device_bind_key", "E",
     "old device compromised after migration, credential bound to device key",
     ["BIND_KEY", "OLD_DEVICE"],
     expect(Q2a_secret_sk_old=F, Q1b_control_post=F, Q4a_migrated_accept=F,
            Q5_old_key_invalid=F)),
    ("E_recovery_key", "E",
     "pre-rotated (next / recovery) key compromised before migration",
     ["BIND_AID", "RECOVERY"],
     expect(Q1b_control_post=F, Q2b_secret_sk_new=F)),
    ("E_server_escrow", "E",
     "issuer/server escrows the holder's keys (server honest)",
     ["BIND_AID", "ESCROW"], expect(Q3_no_server_copy=F)),
    ("E_server_escrow_breach", "E",
     "issuer/server escrows the holder's keys and the escrow is breached",
     ["BIND_AID", "ESCROW", "ESCROW_BREACH"],
     expect(Q3_no_server_copy=F, Q1a_control_pre=F, Q1b_control_post=F,
            Q2a_secret_sk_old=F, Q2b_secret_sk_new=F)),
]

# PRV-01 cross-check: id -> (description, holder-bound values, migrated, bind, expected)
#   k  = current key, nx = pre-rotated next key, nn = next key after migration
#   pres1 always before migration; pres2 after migration if migrated == "second",
#   both after migration if "both".
PRV_CONFIGS = [
    ("PRV_stable_aid", "one holder AID, credential bound to it", {"k", "nx"}, "none", "aid", "false"),
    ("PRV_stable_aid_across_rotation", "one holder AID; presentation 2 after key rotation", {"k", "nx"}, "second", "aid", "false"),
    ("PRV_bind_device_key", "credential copies bound to one device public key", {"k"}, "none", "key", "false"),
    ("PRV_percopy_aid_shared_device_key", "per-copy AIDs, but one device key signs for all", {"k"}, "none", "aid", "false"),
    ("PRV_percopy_aid_shared_next_key", "per-copy AIDs, but one pre-rotated (new-device/recovery) key for all", {"nx"}, "none", "aid", "false"),
    ("PRV_percopy_aid_percopy_keys", "per-copy AIDs with per-copy current and next keys", set(), "none", "aid", "true"),
    ("PRV_percopy_aid_after_migration", "per-copy AIDs, each rotated to its own new key", set(), "both", "aid", "true"),
]

# ---------------------------------------------------------------------------
# Trace model
# ---------------------------------------------------------------------------

PRELUDE = """(* GENERATED by scripts/cry02_proverif.py -- do not edit by hand.
   SEDI-CRY-02 {cid}: {desc}
   Flags: {flags}
   phase 0 = before migration, phase 1 = after migration.
   HW-NX: device keys are `new` names used only through sign(); they leave the
   device only through an explicit compromise branch. *)

free c: channel.
free pair, enroll, deliver, handover, srv: channel [private].

fun h(bitstring): bitstring.
fun pk(bitstring): bitstring.
fun sign(bitstring, bitstring): bitstring.
reduc forall m: bitstring, k: bitstring; verify(sign(m, k), m, pk(k)) = true.
reduc forall m: bitstring, k: bitstring; getmsg(sign(m, k)) = m.

const s0, s1, icp, rot, pres, cred, schema: bitstring.

(* key event log held by an honest witness pool: aid, sn, current key, next digest *)
table kel(bitstring, bitstring, bitstring, bitstring).

event KeyGen(bitstring, bitstring).
event OldKey(bitstring, bitstring).
event NewKey(bitstring, bitstring).
event Issued(bitstring, bitstring).
event DeviceSigned(bitstring, bitstring, bitstring, bitstring).
event AcceptControl(bitstring, bitstring, bitstring, bitstring).
event AcceptCurrent(bitstring, bitstring, bitstring, bitstring).
event Rotated(bitstring, bitstring).
event Compromised(bitstring).
event Reveal(bitstring).
event OracleUsed(bitstring).
event ServerGotKey(bitstring).
event MigrationDone(bitstring).

"""


def trace_model(cid, desc, flags):
    f = set(flags)
    aid = "BIND_AID" in f
    out = [PRELUDE.format(cid=cid, desc=desc, flags=" ".join(flags))]
    out += [f"query {q[2]}.  (* {q[0]}: {q[3]} *)\n" for q in QUERIES]
    w = out.append

    # --- issuer: issues exactly one credential, in phase 0 -----------------
    w("""
let Issuer(skI: bitstring) =
  in(enroll, subj: bitstring);
  new u: bitstring;
  let said = h((pk(skI), schema, subj, u)) in
  event Issued(said, subj);
  out(deliver, said);
  out(c, (cred, said, subj, sign((said, subj), skI))).
""")

    # --- verifier: current key state = latest KEL entry --------------------
    if aid:
        w("""
let CheckPresentation(pkI: bitstring, sn: bitstring) =
  in(c, (=cred, said: bitstring, subj: bitstring, isig: bitstring));
  if verify(isig, (said, subj), pkI) = true then
  new n: bitstring; out(c, n);
  in(c, sg: bitstring);
  (* the verifier's view of the current key: the inception key (sn = s0)
     before migration, the rotated key (sn = s1) after migration; a stale
     verifier still uses s0 after migration. No negative table lookup, so
     ProVerif's over-approximation of `get ... else` does not arise. *)
  get kel(=subj, =sn, p: bitstring, nd: bitstring) in
  if verify(sg, (pres, n, said), p) = true then VERDICT(subj, n, said, p).
""")
    else:
        w("""
let CheckPresentation(pkI: bitstring, sn: bitstring) =
  in(c, (=cred, said: bitstring, subj: bitstring, isig: bitstring));
  if verify(isig, (said, subj), pkI) = true then
  new n: bitstring; out(c, n);
  in(c, sg: bitstring);
  (* device-bound credential: the subject IS the device public key *)
  if verify(sg, (pres, n, said), subj) = true then VERDICT(subj, n, said, subj).
""")

    # --- witnesses (KERI only) ----------------------------------------------
    if aid:
        w("""
(* Witness: accepts self-certifying inceptions and pre-rotation-checked
   rotations; first-seen rotation wins (duplicity is refused). *)
let Witness =
  ( in(c, (=icp, a: bitstring, p: bitstring, nd: bitstring));
    if a = h((p, nd)) then insert kel(a, s0, p, nd) )
  | ( in(c, ((=rot, a: bitstring, p1: bitstring, n2: bitstring), sg: bitstring));
      get kel(=a, =s0, p0: bitstring, n1: bitstring) in
      if h(p1) = n1 then
      if verify(sg, (rot, a, p1, n2), p1) = true then
      get kel(=a, =s1, x: bitstring, y: bitstring) in 0
      else (insert kel(a, s1, p1, n2); event MigrationDone(a)) ).
""")

    # --- devices --------------------------------------------------------------
    oracle = """
  | !( in(c, m: bitstring); event Compromised(pk(sk0)); event OracleUsed(pk(sk0));
       out(c, sign(m, sk0)) )""" if "ORACLE" in f else ""
    extract = """
  | ( event Compromised(pk(sk0)); event Reveal(pk(sk0)); out(c, sk0) )""" if "EXTRACT" in f else ""
    olddev = """
  | ( phase 1; event Compromised(pk(sk0)); event Reveal(pk(sk0)); out(c, sk0) )""" if "OLD_DEVICE" in f else ""
    escrow0 = """
  | out(srv, sk0)""" if "ESCROW" in f else ""
    escrow1 = """
  | out(srv, sk1)""" if "ESCROW" in f else ""
    recovery = """
  | ( event Compromised(pk(sk1)); event Reveal(pk(sk1)); out(c, sk1) )""" if "RECOVERY" in f else ""

    if aid:
        w(f"""
(* Old device: generates sk0 on-device, incepts the holder AID committing to
   the new device's pre-rotated key, enrols the AID, presents, and hands the
   AID + credential (NOT any private key) to the new device at migration. *)
let OldDevice =
  new sk0: bitstring;
  event KeyGen(sk0, pk(sk0));
  in(pair, n1: bitstring);
  let aid = h((pk(sk0), n1)) in
  event OldKey(aid, pk(sk0));
  insert kel(aid, s0, pk(sk0), n1);
  out(c, (icp, aid, pk(sk0), n1));
  out(enroll, aid);
  in(deliver, said: bitstring);
  ( !( in(c, n: bitstring); event DeviceSigned(aid, n, said, pk(sk0));
       out(c, sign((pres, n, said), sk0)) )
  | out(handover, (aid, said)){oracle}{extract}{olddev}{escrow0} ).

(* New device / recovery hardware: holds the pre-rotated key sk1 from the
   start; at migration it rotates the AID to sk1 and commits to a fresh next
   key sk2. No new credential is requested. *)
let NewDevice =
  new sk1: bitstring;
  event KeyGen(sk1, pk(sk1));
  out(pair, h(pk(sk1)));
  ( ( in(handover, (aid: bitstring, said: bitstring));
    new sk2: bitstring;
    let rotev = (rot, aid, pk(sk1), h(pk(sk2))) in
    event NewKey(aid, pk(sk1));
    event Rotated(aid, pk(sk1));
    out(c, (rotev, sign(rotev, sk1)));
    phase 1;
    !( in(c, n: bitstring); event DeviceSigned(aid, n, said, pk(sk1));
       out(c, sign((pres, n, said), sk1)) ) ){recovery}{escrow1} ).
""")
    else:
        w(f"""
(* Old device: credential is bound to its public key pk(sk0). *)
let OldDevice =
  new sk0: bitstring;
  event KeyGen(sk0, pk(sk0));
  event OldKey(pk(sk0), pk(sk0));
  out(enroll, pk(sk0));
  in(deliver, said: bitstring);
  ( !( in(c, n: bitstring); event DeviceSigned(pk(sk0), n, said, pk(sk0));
       out(c, sign((pres, n, said), sk0)) )
  | out(handover, (pk(sk0), said)){oracle}{extract}{olddev}{escrow0} ).

(* New device: a fresh key; without reissuance it can only present the old
   credential, which is bound to the old key. *)
let NewDevice =
  new sk1: bitstring;
  event KeyGen(sk1, pk(sk1));
  ( ( in(handover, (subj: bitstring, said: bitstring));
    event NewKey(subj, pk(sk1));
    event MigrationDone(subj);
    phase 1;
    !( in(c, n: bitstring); event DeviceSigned(subj, n, said, pk(sk1));
       out(c, sign((pres, n, said), sk1)) ) ){recovery}{escrow1} ).
""")

    if "ESCROW" in f:
        breach = "; event Compromised(pk(k)); event Reveal(pk(k)); out(c, k)" if "ESCROW_BREACH" in f else ""
        w(f"""
(* Issuer/server key-escrow service *)
let Server = !( in(srv, k: bitstring); event ServerGotKey(pk(k)){breach} ).
""")

    stale = "s0" if "STALE_VERIFIER" in f else "s1"
    w(f"""
process
  new skI: bitstring;
  out(c, pk(skI));
  ( Issuer(skI) | OldDevice | NewDevice
  | !CheckPresentation(pk(skI), s0)
  | (phase 1; !CheckPresentation1(pk(skI), {stale}))
""")
    if aid:
        w("  | !Witness\n")
    if "ESCROW" in f:
        w("  | Server\n")
    w("  )\n")

    text = "".join(out)
    # Phase-0 verifiers emit AcceptControl, phase-1 verifiers AcceptCurrent.
    body = text.split("let CheckPresentation(")[1].split("\n\n")[0]
    check = "let CheckPresentation(" + body
    v0 = check.replace("VERDICT(", "event AcceptControl(")
    v1 = (check.replace("let CheckPresentation(", "let CheckPresentation1(")
               .replace("VERDICT(", "event AcceptCurrent("))
    text = text.replace(check, v0.rstrip(".") + ".\n" + v1)
    return text


# ---------------------------------------------------------------------------
# PRV-01 equivalence model
# ---------------------------------------------------------------------------

def prv_model(cid, desc, bound, migrated, bind):
    def val(name):
        if name in bound:
            return (f"  new {name}1: bitstring; new {name}2r: bitstring;\n"
                    f"  let {name}2 = choice[{name}1, {name}2r] in\n")
        return f"  new {name}1: bitstring; new {name}2: bitstring;\n"

    out = [f"""(* GENERATED by scripts/cry02_proverif.py -- do not edit by hand.
   SEDI-CRY-02 x PRV-01 {cid}: {desc}
   world 0 (left): one holder, two presentations; world 1 (right): two holders.
   Copies have per-copy SAIDs (bulk issuance), so only the AID/key binding
   can link. *)

free c: channel.
fun h(bitstring): bitstring.
fun pk(bitstring): bitstring.
fun sign(bitstring, bitstring): bitstring.
reduc forall m: bitstring, k: bitstring; verify(sign(m, k), m, pk(k)) = true.
reduc forall m: bitstring, k: bitstring; getmsg(sign(m, k)) = m.
const icp, rot, pres, cred, schema: bitstring.

process
  new skI: bitstring;
  out(c, pk(skI));
"""]
    # holder's real identity, only inside a salted attribute block (always holder-bound)
    out.append("  new nm1: bitstring; new nm2r: bitstring;\n"
               "  let nm2 = choice[nm1, nm2r] in\n")
    for name in ("k", "nx", "nn"):
        out.append(val(name))
    for i in ("1", "2"):
        after = migrated == "both" or (migrated == "second" and i == "2")
        subj = f"aid{i}" if bind == "aid" else f"pk(k{i})"
        signer = f"nx{i}" if after else f"k{i}"
        kel = f"(icp{i}, rot{i})" if after else f"icp{i}"
        if bind == "key":
            kel = "cred"
        out.append(f"""  new u{i}: bitstring;
  let aid{i} = h((pk(k{i}), h(pk(nx{i})))) in
  let icp{i} = (icp, aid{i}, pk(k{i}), h(pk(nx{i}))) in
  let rotev{i} = (rot, aid{i}, pk(nx{i}), h(pk(nn{i}))) in
  let rot{i} = (rotev{i}, sign(rotev{i}, nx{i})) in
  new a{i}: bitstring;
  let ab{i} = h((nm{i}, a{i})) in
  let said{i} = h((pk(skI), schema, {subj}, ab{i}, u{i})) in
  let cr{i} = (cred, said{i}, {subj}, ab{i}, sign((said{i}, {subj}, ab{i}), skI)) in
""")
    out.append("  (\n")
    for i in ("1", "2"):
        after = migrated == "both" or (migrated == "second" and i == "2")
        signer = f"nx{i}" if after else f"k{i}"
        kel = "cred" if bind == "key" else (f"(icp{i}, rot{i})" if after else f"icp{i}")
        bar = "  | " if i == "2" else "    "
        out.append(f"""{bar}( in(c, n{i}: bitstring);
        out(c, (cr{i}, {kel}, pk({signer}), sign((pres, n{i}, said{i}), {signer}))) )
""")
    out.append("  )\n")
    return "".join(out)


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
    """One line per query, in declaration order, from the final summary."""
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
    prv = [c for c in PRV_CONFIGS if c[0].startswith(args.only)]
    if args.list:
        for c in trace:
            print(f"{c[0]:34} trace  {' '.join(c[3])}")
        for c in prv:
            print(f"{c[0]:34} equiv  expected={c[5]}")
        return 0

    MODELS.mkdir(parents=True, exist_ok=True)
    for cid, _, desc, flags, _ in trace:
        (MODELS / f"{cid}.pv").write_text(trace_model(cid, desc, flags))
    for cid, desc, bound, migrated, bind, _ in prv:
        (MODELS / f"{cid}.pv").write_text(prv_model(cid, desc, bound, migrated, bind))
    if args.generate:
        print(f"wrote {len(trace) + len(prv)} models to {MODELS.relative_to(ROOT)}")
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
    for cid, variant, desc, flags, exp in trace:
        out, secs = run(cid)
        res = raw_results(out)
        got = {}
        if len(res) != len(QUERIES):
            got = {q: "error" for q in QIDS}
        else:
            for (qid, kind, _, _), line in zip(QUERIES, res):
                v = verdict(line)
                if v == "cannot be proved":
                    got[qid] = "unknown"
                elif kind == "safety":
                    got[qid] = H if v == "true" else F
                else:
                    got[qid] = H if v == "false" else F
        bad = [q for q in QIDS if got[q] != exp[q]]
        mismatches += len(bad)
        records.append(dict(id=cid, kind="trace", variant=variant, description=desc,
                            flags=flags, expected=exp, actual=got,
                            mismatches=bad, seconds=secs))
        print(f"{cid:34} {len(QIDS) - len(bad)}/{len(QIDS)} as expected"
              f"{'' if not bad else '  MISMATCH: ' + ', '.join(bad)}  ({secs}s)", flush=True)

    for cid, desc, bound, migrated, bind, exp in prv:
        out, secs = run(cid)
        if "RESULT Observational equivalence is true" in out:
            actual = "true"
        elif "RESULT Observational equivalence cannot be proved" in out:
            actual = "false"
        else:
            actual = "error"
        ok = actual == exp
        mismatches += not ok
        lines = out.splitlines()
        test = next(([ln.strip() for ln in lines[i:i + 5]]
                     for i in range(len(lines) - 1, -1, -1)
                     if lines[i].startswith("The attacker tests whether")), [])
        records.append(dict(id=cid, kind="equivalence", description=desc,
                            expected=exp, actual=actual, match=ok, test=test, seconds=secs))
        print(f"{cid:34} expected={exp:5} actual={actual:5} "
              f"{'ok' if ok else 'MISMATCH'}  ({secs}s)", flush=True)

    ver = subprocess.run([pv, "-help"], capture_output=True, text=True).stdout.splitlines()[0]
    (RESULTS / "results.json").write_text(json.dumps(
        dict(proverif=ver, generated=time.strftime("%Y-%m-%dT%H:%M:%S"),
             mismatches=mismatches, results=records), indent=1))

    short = {"sanity_accept_pre": "sanity", "Q1a_control_pre": "Q1 pre",
             "Q1b_control_post": "Q1 post", "Q1c_control_pre_or_compromise": "Q1 pre|comp",
             "Q1d_control_post_or_compromise": "Q1 post|comp", "Q2a_secret_sk_old": "Q2 sk_old",
             "Q2b_secret_sk_new": "Q2 sk_new", "Q2c_secret_unless_reveal": "Q2 unless-reveal",
             "Q3_no_server_copy": "Q3 no copy", "Q4a_migrated_accept": "Q4 new-key accept",
             "Q4b_no_reissue": "Q4 no reissue", "Q5_old_key_invalid": "Q5 old key invalid"}
    lines = [f"# CRY-02 ProVerif results ({ver})", "",
             "Trace models: `holds` / **FAILS** per query (mismatches vs. expected marked with ✗).", "",
             "| config | " + " | ".join(short[q] for q in QIDS) + " |",
             "|---|" + "---|" * len(QIDS)]
    for r in records:
        if r["kind"] != "trace":
            continue
        cells = []
        for q in QIDS:
            a = r["actual"][q]
            cell = "holds" if a == H else ("**FAILS**" if a == F else a)
            cells.append(cell + ("" if a == r["expected"][q] else " ✗"))
        lines.append(f"| {r['id']} | " + " | ".join(cells) + " |")
    lines += ["", "Equivalence (PRV-01 cross-check): `true` = unlinkable.", "",
              "| config | description | expected | actual | match |", "|---|---|---|---|---|"]
    for r in records:
        if r["kind"] == "equivalence":
            lines.append(f"| {r['id']} | {r['description']} | {r['expected']} | "
                         f"{r['actual']} | {'yes' if r['match'] else '**NO**'} |")
    (RESULTS / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\n{mismatches} mismatch(es)")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
