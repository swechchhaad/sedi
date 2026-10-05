#!/usr/bin/env python3
"""SEDI-CRY-01 (offline authenticity verification) in ProVerif.

ProVerif port of tamarin/cry01_offline_verification.spthy, to be re-verified
with Tamarin later.

Usage:
    python3 scripts/cry01_proverif.py            # generate + run all
    python3 scripts/cry01_proverif.py --only B_
    python3 scripts/cry01_proverif.py --list
    python3 scripts/cry01_proverif.py --generate

Writes  proverif/cry01/<config>.pv
        results/cry01/<config>.log, summary.md, results.json

Attacker: Dolev-Yao network. The Department/issuer, its witnesses and its
status registry are honest unless a compromise flag reveals a key.

Every verification session has a fresh id `sid`, so "no query DURING the
authenticity check" is stated per session: AuthAccept(sid,..) and
OnlineQuery(sid,..) never both occur.

KERI timeline (phases):
  phase 0  inception; credentials issued (anchored) under the inception key k0
  phase 1  rotation to the pre-committed key k1; credentials issued under k1;
           key compromise happens here (retired k0 or current k1)
  phase 2  verification (carried / online) -- or the verifier's cache sync
  phase 3  verification from the cache (cached variant)
Witnesses accept an anchoring (ixn) event only if it is signed by the key that
is current in that phase (AS-WIT), and receipt it with their key.

Where the verifier gets current KEL state, per variant:
  A              not applicable (static published key)
  B_carried      carried by the holder as a proof (icp [+ rot] [+ receipt])
  B_cached       cached locally, obtained online BEFORE the check (phase 2)
  C_*            retrieved online DURING the check
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
MODELS = ROOT / "proverif" / "cry01"
RESULTS = ROOT / "results" / "cry01"

KERI_MATERIAL = "h((pk(new sk0), h(pk(new sk1)), pk(new skW)))"

# (id, kind, query, description). kind "safety": `true` = holds;
# "reach": holds when ProVerif reports `false` (a trace exists).
QUERIES = [
    ("sanity_honest_accept", "reach",
     "sid, s, a: bitstring; event(AuthAccept(sid, s, a)) && event(Issued(s)) ==> false",
     "an honestly issued credential is accepted"),
    ("L1_strict_unforgeability", "safety",
     "sid, s, a: bitstring; event(AuthAccept(sid, s, a)) ==> event(Issued(s))",
     "1. accepted => issued (no exception)"),
    ("L1_unforgeability", "safety",
     "sid, s, a: bitstring; event(AuthAccept(sid, s, a)) ==> event(Issued(s)) || event(Compromised(a))",
     "1. accepted => issued, unless an issuer signing key was revealed"),
    ("L1b_post_rotation", "safety",
     "sid, s, a: bitstring; event(AuthAccept(sid, s, a)) ==> event(Issued(s)) || event(CompromisedCurrent(a))",
     "1b. accepted => issued, unless the CURRENT key was revealed (a retired key does not suffice)"),
    ("L2_offline", "safety",
     "sid, s, a, k: bitstring; event(AuthAccept(sid, s, a)) && event(OnlineQuery(sid, k)) ==> false",
     "2. no Department / third-party query during an accepted authenticity check"),
    ("L3a_status_not_required", "reach",
     "sid, s, a: bitstring; event(AuthAccept(sid, s, a)) ==> event(StatusQuery(sid))",
     "3. authenticity can be accepted before / without any status query"),
    ("L3b_status_failure_distinct", "safety",
     "sid, s: bitstring; event(AuthReject(sid, s, nostatus))",
     "3. an authenticity check never fails because status is unavailable"),
]
QIDS = [q[0] for q in QUERIES]
L4 = ("L4_no_shared_secret", "the verifier's pinned verification material is publicly derivable")

H, F = "holds", "fails"


def expect(**over):
    base = {q: H for q in QIDS + [L4[0]]}
    base.update(over)
    return base


CONFIGS = [
    dict(id="A_static_key", variant="A",
         desc="plain offline credential, Department's published key", flags=["A"],
         exp=expect()),
    dict(id="A_static_key_revealed", variant="A",
         desc="as A, the Department signing key is revealed", flags=["A", "REVEAL"],
         exp=expect(L1_strict_unforgeability=F)),
    dict(id="A_shared_secret_NEG", variant="A",
         desc="NEGATIVE CONTROL: MAC under a key shared by Department and verifier",
         flags=["A", "SHARED_SECRET"], exp=expect(L4_no_shared_secret=F)),
    dict(id="B_carried", variant="B",
         desc="KERI/ACDC, holder carries icp [+ rot]; no witness receipts", flags=["KERI", "CARRIED"],
         exp=expect()),
    dict(id="B_carried_retired_key_revealed", variant="B",
         desc="as B_carried, the retired (pre-rotation) key is revealed after rotation",
         flags=["KERI", "CARRIED", "REVEAL_RETIRED"],
         exp=expect(L1_strict_unforgeability=F, L1b_post_rotation=F)),
    dict(id="B_carried_receipts_retired_key_revealed", variant="B",
         desc="holder carries icp + witness receipt for the anchor; retired key revealed",
         flags=["KERI", "CARRIED_RECEIPTS", "REVEAL_RETIRED"], exp=expect()),
    dict(id="B_cached_retired_key_revealed", variant="B",
         desc="verifier synced the witnessed KEL before the check; retired key revealed",
         flags=["KERI", "CACHED", "REVEAL_RETIRED"], exp=expect()),
    dict(id="B_cached_current_key_revealed", variant="B",
         desc="as B_cached, the CURRENT key is revealed",
         flags=["KERI", "CACHED", "REVEAL_CURRENT"],
         exp=expect(L1_strict_unforgeability=F)),
    dict(id="C_online_kel", variant="C",
         desc="verifier queries witnesses for the KEL during the check; status checked separately",
         flags=["KERI", "ONLINE"], exp=expect(L2_offline=F)),
    dict(id="C_keripy_online_kel_tel", variant="C",
         desc="as keripy: KEL from witnesses AND TEL state from the registry are required before acceptance",
         flags=["KERI", "ONLINE", "TEL_GATED"],
         exp=expect(L2_offline=F, L3a_status_not_required=F, L3b_status_failure_distinct=F)),
]

PRELUDE = """(* GENERATED by scripts/cry01_proverif.py -- do not edit by hand.
   SEDI-CRY-01 {cid}: {desc}
   Flags: {flags} *)

free c: channel.

fun h(bitstring): bitstring.
fun pk(bitstring): bitstring.
fun sign(bitstring, bitstring): bitstring.
fun mac(bitstring, bitstring): bitstring.
fun verify(bitstring, bitstring, bitstring): bool
  reduc forall m: bitstring, k: bitstring; verify(sign(m, k), m, pk(k)) = true
  otherwise forall x: bitstring, y: bitstring, z: bitstring; verify(x, y, z) = false.
reduc forall m: bitstring, k: bitstring; getmsg(sign(m, k)) = m.

const icp, ixn, rot, rct, stat, good, telq, kelq, none: bitstring.
const badsig, nostatus, notanchored, witness, registry: bitstring.

table wkel(bitstring, bitstring).      (* witnessed anchors: aid, SAID *)
table vcache(bitstring, bitstring).    (* verifier's local copy *)

event Issued(bitstring).
event AuthAccept(bitstring, bitstring, bitstring).
event AuthReject(bitstring, bitstring, bitstring).
event OnlineQuery(bitstring, bitstring).
event StatusQuery(bitstring).
event StatusGood(bitstring, bitstring).
event StatusFail(bitstring, bitstring).
event Compromised(bitstring).
event CompromisedCurrent(bitstring).
event CacheSync(bitstring).

"""

STATUS = """
(* Status: an external check, run only AFTER authenticity was accepted. *)
let Status(sid: bitstring, s: bitstring, pkR: bitstring) =
  event StatusQuery(sid);
  out(c, (telq, s));
  in(c, r: bitstring);
  if verify(r, (stat, s, good), pkR) = true then event StatusGood(sid, s)
  else event StatusFail(sid, s).

let Registry(skR: bitstring) =
  in(c, (=telq, s: bitstring));
  out(c, sign((stat, s, good), skR)).
"""


def model_A(cfg):
    f = set(cfg["flags"])
    ss = "SHARED_SECRET" in f
    material = "new kDV" if ss else "pk(new skD)"
    out = [PRELUDE.format(cid=cfg["id"], desc=cfg["desc"], flags=" ".join(cfg["flags"]))]
    out += [f"query {q}.  (* {i}: {d} *)\n" for i, _, q, d in QUERIES]
    out.append(f"query attacker({material}).  (* {L4[0]}: {L4[1]} *)\n")
    out.append(STATUS)
    tag = "mac(s, kDV)" if ss else "sign(s, skD)"
    check = "tag = mac(s, kDV)" if ss else "verify(tag, s, pkD) = true"
    out.append(f"""
let Issuer(skD: bitstring, kDV: bitstring) =
  new attrs: bitstring;
  let s = h((pk(skD), attrs)) in
  event Issued(s);
  out(c, (s, {tag})).

(* pkD (and kDV in the negative control) are loaded once, out of band (AS-PUB) *)
let Verifier(pkD: bitstring, kDV: bitstring, pkR: bitstring) =
  new sid: bitstring;
  in(c, (s: bitstring, tag: bitstring));
  if {check} then
    (event AuthAccept(sid, s, pkD); Status(sid, s, pkR))
  else event AuthReject(sid, s, badsig).

process
  new skD: bitstring; new skR: bitstring; new kDV: bitstring;
  out(c, pk(skD)); out(c, pk(skR));
  ( !Issuer(skD, kDV) | !Registry(skR) | !Verifier(pk(skD), kDV, pk(skR))
""")
    if "REVEAL" in f:
        out.append("  | (event Compromised(pk(skD)); event CompromisedCurrent(pk(skD)); out(c, skD))\n")
    out.append("  )\n")
    return "".join(out)


def model_KERI(cfg):
    f = set(cfg["flags"])
    out = [PRELUDE.format(cid=cfg["id"], desc=cfg["desc"], flags=" ".join(cfg["flags"]))]
    out += [f"query {q}.  (* {i}: {d} *)\n" for i, _, q, d in QUERIES]
    out.append(f"query attacker({KERI_MATERIAL}).  (* {L4[0]}: {L4[1]} (the pinned AID) *)\n")
    out.append(STATUS)
    out.append("""
(* Issuer: the ACDC carries no signature of its own; it is anchored by an
   interaction event (ixn) carrying its SAID, signed with the current key. *)
let IssueUnder(aid: bitstring, sk: bitstring) =
  new attrs: bitstring;
  let s = h((aid, attrs)) in
  let ev = (ixn, aid, s) in
  event Issued(s);
  out(c, (ev, sign(ev, sk))).

(* Witness (AS-WIT): receipts an anchor only if it is signed by the key that is
   current in this phase. *)
let Witness(aid: bitstring, pkCur: bitstring, skW: bitstring) =
  in(c, (ev: bitstring, sg: bitstring));
  let (=ixn, =aid, s: bitstring) = ev in
  if verify(sg, ev, pkCur) = true then
  insert wkel(aid, s);
  out(c, (rct, ev, sign((rct, ev), skW))).
""")

    accept_then_status = "(event AuthAccept(sid, s, aid); Status(sid, s, pkR))"
    if "CARRIED" in f:
        out.append(f"""
(* Carried KEL, no receipts: the verifier checks the carried inception against
   the pinned AID, optionally a carried rotation, and the anchor signature
   under the resulting key. It cannot tell whether the carried KEL is the
   latest one. *)
let VerifierIcpOnly(aid: bitstring, pkR: bitstring) =
  new sid: bitstring;
  in(c, (s: bitstring, isg: bitstring, icpev: bitstring));
  let (=icp, =aid, k0: bitstring, n1: bitstring, w: bitstring) = icpev in
  if aid = h((k0, n1, w)) then
  if verify(isg, (ixn, aid, s), k0) = true then {accept_then_status}
  else event AuthReject(sid, s, badsig).

let VerifierIcpRot(aid: bitstring, pkR: bitstring) =
  new sid: bitstring;
  in(c, (s: bitstring, isg: bitstring, icpev: bitstring, rotev: bitstring, rsg: bitstring));
  let (=icp, =aid, k0: bitstring, n1: bitstring, w: bitstring) = icpev in
  if aid = h((k0, n1, w)) then
  let (=rot, =aid, k1: bitstring, n2: bitstring) = rotev in
  if h(k1) = n1 then
  if verify(rsg, rotev, k1) = true then
  if verify(isg, (ixn, aid, s), k1) = true then {accept_then_status}
  else event AuthReject(sid, s, badsig).
""")
        verifiers = "(phase 2; (!VerifierIcpOnly(aid, pk(skR)) | !VerifierIcpRot(aid, pk(skR))))"
    elif "CARRIED_RECEIPTS" in f:
        out.append(f"""
(* Carried KEL with a witness receipt for the anchoring event: the witness key
   comes from the carried inception, which is bound to the pinned AID. *)
let VerifierReceipt(aid: bitstring, pkR: bitstring) =
  new sid: bitstring;
  in(c, (s: bitstring, rsg: bitstring, icpev: bitstring));
  let (=icp, =aid, k0: bitstring, n1: bitstring, w: bitstring) = icpev in
  if aid = h((k0, n1, w)) then
  if verify(rsg, (rct, (ixn, aid, s)), w) = true then {accept_then_status}
  else event AuthReject(sid, s, notanchored).
""")
        verifiers = "(phase 2; !VerifierReceipt(aid, pk(skR)))"
    elif "CACHED" in f:
        out.append(f"""
(* Cached KEL: the verifier copies the witnessed KEL in phase 2 (online,
   BEFORE any check) and checks anchors locally in phase 3. *)
let SyncCache(aid: bitstring) =
  get wkel(=aid, s: bitstring) in
  event CacheSync(s);
  insert vcache(aid, s).

let VerifierCached(aid: bitstring, pkR: bitstring) =
  new sid: bitstring;
  in(c, s: bitstring);
  get vcache(=aid, =s) in {accept_then_status}
  else event AuthReject(sid, s, notanchored).
""")
        verifiers = ("(phase 2; !SyncCache(aid)) | (phase 3; !VerifierCached(aid, pk(skR)))")
    elif "ONLINE" in f:
        if "TEL_GATED" in f:
            gate = """
  event OnlineQuery(sid, registry);
  event StatusQuery(sid);
  out(c, (telq, s));
  in(c, r: bitstring);
  if verify(r, (stat, s, good), pkR) = true then
    (event AuthAccept(sid, s, aid); event StatusGood(sid, s))
  else event AuthReject(sid, s, nostatus)"""
        else:
            gate = f"\n  {accept_then_status}"
        out.append(f"""
(* Online: during the check the verifier queries the witnesses for the KEL
   (keripy: an OOBI/KEL resolution{' and a telquery for TEL state, escrowing the credential until it arrives -- src/keri/vdr/verifying.py:126-143' if 'TEL_GATED' in f else ''}). *)
let VerifierOnline(aid: bitstring, pkR: bitstring) =
  new sid: bitstring;
  in(c, s: bitstring);
  event OnlineQuery(sid, witness);
  out(c, (kelq, aid, s));
  get wkel(=aid, =s) in{gate}
  else event AuthReject(sid, s, notanchored).
""")
        verifiers = "(phase 2; !VerifierOnline(aid, pk(skR)))"

    comp = ""
    if "REVEAL_RETIRED" in f:
        comp = "\n    | (event Compromised(aid); out(c, sk0))"
    if "REVEAL_CURRENT" in f:
        comp = "\n    | (event Compromised(aid); event CompromisedCurrent(aid); out(c, sk1))"
    out.append(f"""
process
  new sk0: bitstring; new sk1: bitstring; new sk2: bitstring;
  new skW: bitstring; new skR: bitstring;
  let aid = h((pk(sk0), h(pk(sk1)), pk(skW))) in
  let icpev = (icp, aid, pk(sk0), h(pk(sk1)), pk(skW)) in
  let rotev = (rot, aid, pk(sk1), h(pk(sk2))) in
  out(c, pk(skR));
  out(c, (icpev, sign(icpev, sk0)));
  ( !IssueUnder(aid, sk0) | !Witness(aid, pk(sk0), skW)
  | (phase 1;
      ( out(c, (rotev, sign(rotev, sk1)))
      | !IssueUnder(aid, sk1) | !Witness(aid, pk(sk1), skW){comp} ))
  | !Registry(skR)
  | {verifiers}
  )
""")
    return "".join(out)


def generate(cfg):
    return model_A(cfg) if "A" in cfg["flags"] else model_KERI(cfg)


# ---------------------------------------------------------------------------

def find_proverif(explicit):
    for cand in (explicit, shutil.which("proverif"),
                 os.path.expanduser("~/opt/proverif2.05/proverif")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    sys.exit("proverif not found: pass --proverif PATH or put it on PATH")


def summary_lines(out):
    if "Verification summary:" not in out:
        return []
    return [ln.strip() for ln in out.split("Verification summary:")[1].splitlines()
            if ln.strip().startswith("Query ")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--proverif", default=None)
    args = ap.parse_args()

    cfgs = [c for c in CONFIGS if c["id"].startswith(args.only)]
    if args.list:
        for c in cfgs:
            print(f"{c['id']:42} {' '.join(c['flags'])}")
        return 0
    MODELS.mkdir(parents=True, exist_ok=True)
    for c in cfgs:
        (MODELS / f"{c['id']}.pv").write_text(generate(c))
    if args.generate:
        print(f"wrote {len(cfgs)} models to {MODELS.relative_to(ROOT)}")
        return 0

    pv = find_proverif(args.proverif)
    RESULTS.mkdir(parents=True, exist_ok=True)
    kinds = [q[1] for q in QUERIES] + ["reach"]
    ids = QIDS + [L4[0]]
    records, mismatches = [], 0
    for c in cfgs:
        t0 = time.time()
        try:
            p = subprocess.run([pv, str(MODELS / f"{c['id']}.pv")], capture_output=True,
                               text=True, timeout=args.timeout)
            out = p.stdout + p.stderr
        except subprocess.TimeoutExpired:
            out = "TIMEOUT"
        (RESULTS / f"{c['id']}.log").write_text(out)
        res = summary_lines(out)
        got = {}
        if len(res) != len(ids):
            got = {i: "error" for i in ids}
        else:
            for i, kind, line in zip(ids, kinds, res):
                if "cannot be proved" in line:
                    got[i] = "unknown"
                elif kind == "safety":
                    got[i] = H if line.endswith("is true.") else F
                else:
                    got[i] = H if line.endswith("is false.") else F
        bad = [i for i in ids if got[i] != c["exp"][i]]
        mismatches += len(bad)
        records.append(dict(id=c["id"], variant=c["variant"], description=c["desc"],
                            flags=c["flags"], expected=c["exp"], actual=got,
                            mismatches=bad, seconds=round(time.time() - t0, 2)))
        print(f"{c['id']:42} {len(ids) - len(bad)}/{len(ids)} as expected"
              + ("" if not bad else "  MISMATCH: " + ", ".join(bad)), flush=True)

    ver = subprocess.run([pv, "-help"], capture_output=True, text=True).stdout.splitlines()[0]
    (RESULTS / "results.json").write_text(json.dumps(
        dict(proverif=ver, generated=time.strftime("%Y-%m-%dT%H:%M:%S"),
             mismatches=mismatches, results=records), indent=1))
    short = ["sanity", "L1 strict", "L1", "L1b post-rot", "L2 offline", "L3a status-free",
             "L3b distinct", "L4 no secret"]
    lines = [f"# CRY-01 ProVerif results ({ver})", "",
             "`holds` / **FAILS** (✗ = differs from expected)", "",
             "| config | " + " | ".join(short) + " |", "|---|" + "---|" * len(short)]
    for r in records:
        cells = []
        for i in ids:
            a = r["actual"][i]
            cells.append(("holds" if a == H else "**FAILS**" if a == F else a)
                         + ("" if a == r["expected"][i] else " ✗"))
        lines.append(f"| {r['id']} | " + " | ".join(cells) + " |")
    (RESULTS / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\n{mismatches} mismatch(es)")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
