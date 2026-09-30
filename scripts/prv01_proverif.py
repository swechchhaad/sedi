#!/usr/bin/env python3
"""SEDI-PRV-01 unlinkability in ProVerif: generate one biprocess per
configuration, prove observational (diff-)equivalence, compare to expected.

Usage:
    python3 scripts/prv01_proverif.py                # generate + run all
    python3 scripts/prv01_proverif.py --only A_      # configs whose id starts with A_
    python3 scripts/prv01_proverif.py --list         # list configs
    python3 scripts/prv01_proverif.py --generate     # only write the .pv files

Writes  proverif/prv01/<config>.pv          (the generated models)
        results/prv01/<config>.log          (full ProVerif output incl. traces)
        results/prv01/summary.md, results.json

Two-world experiment (choice[L, R]):
    world 0 (L): ONE holder presents copy C1 to V1 and copy C2 to V2
    world 1 (R): holder H1 presents C1 to V1, holder H2 presents C2 to V2
V1 and V2 are malicious and pool their views, so they are the attacker: every
presentation goes out on the public channel and the attacker picks each
verifier's challenge nonce. Issuer, schema, disclosed attribute, presentation
count and (in experiment A) size/timing are identical in both worlds.

Each privacy mechanism turns one holder-bound value into a per-copy value:
    holder-bound:  new x1; new x2; let x2' = choice[x1, x2]   (same in world 0)
    per-copy:      new x1; new x2                              (independent)
Configurations are cumulative: P_k enables M1..Mk. See MECHANISMS below and
docs/prv01.md for the rationale of each abstraction.

Exit status is non-zero if any result differs from the expected one.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "proverif" / "prv01"
RESULTS = ROOT / "results" / "prv01"

MECHANISMS = {
    "M1": "bulk-issued copies with unique SAIDs (per-copy uuid + attribute salt), Merkle-batched",
    "M2": "fresh, individually anchored copy per presentation (no batch aggregate/leaf list)",
    "M3": "unique Issuee AID per copy",
    "M4": "independent TEL registry per copy",
    "M5": "no stable holder (sender) AID",
    "M6": "fresh presentation proof key per presentation",
    "M7": "normalised message size / timing class",
    "M8": "private / anonymous status retrieval",
}
ALL = [f"M{i}" for i in range(1, 9)]


def P(k):
    return ALL[:k]


def minus(flags, *drop):
    return [f for f in flags if f not in drop]


# id -> (experiment, description, flags, expected)
#   expected: "true" (equivalence proved) or "false" (cannot be proved / attack)
#   culprit:  what should distinguish the worlds when expected is "false"
CONFIGS = [
    # --- A. artifact-only, cumulative mechanisms ----------------------------
    ("A_P0", "A", "baseline ACDC", P(0), "false", "SAID, uuid, attr digest, Issuee AID, TEL, holder AID, proof key"),
    ("A_P1", "A", "+ bulk issuance (full leaf list, as keripy)", P(1), "false", "leaf list / B, Issuee AID, TEL, holder AID, proof key"),
    ("A_P2", "A", "+ fresh individually anchored copy", P(2), "false", "Issuee AID, TEL, holder AID, proof key"),
    ("A_P3", "A", "+ unique Issuee AID per copy", P(3), "false", "TEL, holder AID, proof key"),
    ("A_P4", "A", "+ independent TEL per copy", P(4), "false", "holder AID, proof key"),
    ("A_P5", "A", "+ no stable holder AID", P(5), "false", "proof key"),
    ("A_P6", "A", "+ fresh proof key", P(6), "true", ""),
    ("A_P7", "A", "+ normalised size/timing", P(7), "true", ""),
    ("A_P8", "A", "+ private status retrieval", P(8), "true", ""),
    # --- A. single-leak ablations from P8: minimal counterexamples ----------
    ("A_leak_SAID", "A", "P8 but one credential reused (uuid + attribute salt shared)", minus(P(8), "M1") + ["M2"], "false", "SAID / uuid / blinded attribute digest"),
    ("A_leak_batch_fulllist", "A", "P8 but copies batched, full leaf list", minus(P(8), "M2"), "false", "batch leaf list / aggregate B"),
    ("A_leak_batch_inclusion", "A", "P8 but copies batched, Merkle inclusion proof", minus(P(8), "M2") + ["INCLUSION"], "false", "aggregate B / sibling leaf"),
    ("A_leak_issuee", "A", "P8 but stable Issuee AID", minus(P(8), "M3"), "false", "Issuee AID"),
    ("A_leak_TEL", "A", "P8 but per-holder TEL registry", minus(P(8), "M4"), "false", "TEL registry id"),
    ("A_leak_holderAID", "A", "P8 but stable holder AID", minus(P(8), "M5"), "false", "holder (sender) AID"),
    ("A_leak_proofkey", "A", "P8 but stable proof key", minus(P(8), "M6"), "false", "presentation proof key"),
    # --- keripy reference deployment (tests/acdc/test_bulk_issuance.py) -----
    ("A_keripy_ref", "A", "keripy example: bulk + per-copy holder AID, shared registry, full list", ["M1", "M3", "M5", "M6"], "false", "batch list / B, TEL registry"),
    # --- B. disclosed-field correlation --------------------------------------
    ("B_unique_attr", "B", "P8 + a holder-unique attribute is disclosed", P(8) + ["DISCLOSE_UNIQUE"], "false", "disclosed data"),
    ("B_shared_attr_salt", "B", "P8 but undisclosed attribute block salted per credential", P(8) + ["SHARED_ATTR_SALT"], "false", "blinded attribute digest"),
    ("B_common_attr", "B", "P8, only a population-wide predicate disclosed", P(8), "true", ""),
    # --- C. status / TEL correlation ----------------------------------------
    ("C_shared_TEL", "C", "P8 but per-holder registry, holder fetches status", minus(P(8), "M4") + ["STATUS"], "false", "TEL registry id"),
    ("C_status_session", "C", "P7 + holder fetches status over an identifiable session", P(7) + ["STATUS"], "false", "status query"),
    ("C_private_status", "C", "P8 + holder fetches status privately", P(8) + ["STATUS"], "true", ""),
    # --- D. network metadata correlation ------------------------------------
    ("D_addr", "D", "P8, presentations carry the holder's transport address", P(8) + ["NETWORK"], "false", "network metadata (address)"),
    ("D_shape", "D", "P8 minus M7, anonymous transport", minus(P(8), "M7") + ["NETWORK", "ANON_TRANSPORT"], "false", "network metadata (size/timing)"),
    ("D_anon", "D", "P8 + anonymous transport", P(8) + ["NETWORK", "ANON_TRANSPORT"], "true", ""),
    # --- E. malicious issuer ------------------------------------------------
    ("E_issuer_colludes", "E", "full deployment, issuer shares issuance records", P(8) + ["STATUS", "NETWORK", "ANON_TRANSPORT", "MALICIOUS_ISSUER"], "false", "issuer observation"),
    # --- Everything on, all deployment assumptions ---------------------------
    ("FULL", "all", "P8 + status + network, anonymous transport, honest issuer", P(8) + ["STATUS", "NETWORK", "ANON_TRANSPORT"], "true", ""),
]


# ---------------------------------------------------------------------------
# Model generation
# ---------------------------------------------------------------------------

HEADER = """(* GENERATED by scripts/prv01_proverif.py -- do not edit by hand.
   SEDI-PRV-01 two-world unlinkability experiment: {cid}
   {desc}
   Flags: {flags}
   world 0 (left):  one holder presents C1 to V1 and C2 to V2
   world 1 (right): H1 presents C1 to V1, H2 presents C2 to V2 *)

free c: channel.

fun h(bitstring): bitstring.
fun pk(bitstring): bitstring.
fun sign(bitstring, bitstring): bitstring.
reduc forall m: bitstring, k: bitstring; verify(sign(m, k), m, pk(k)) = true.
reduc forall m: bitstring, k: bitstring; getmsg(sign(m, k)) = m.

const schema, over21, attrs, ixn, leaf, node, aid, pres, tel, iss,
      telquery, issuedto, std, anon: bitstring.

process
  new skI: bitstring;
  out(c, pk(skI));
"""


def holder_bound(name):
    """Same value for both presentations in world 0, independent in world 1."""
    return (f"  new {name}1: bitstring; new {name}2r: bitstring;\n"
            f"  let {name}2 = choice[{name}1, {name}2r] in\n")


def per_copy(name):
    return f"  new {name}1: bitstring; new {name}2: bitstring;\n"


def constant(name, value):
    return f"  let {name}1 = {value} in let {name}2 = {value} in\n"


def generate(cid, desc, flags):
    f = set(flags)
    out = [HEADER.format(cid=cid, desc=desc, flags=" ".join(flags) or "(none)")]
    w = out.append

    w("  (* holder's real identity: only ever inside the salted attribute block,\n"
      "     or handed over by a colluding issuer (E) *)\n")
    w(holder_bound("n"))
    w("  (* credential uuid: makes the SAID unique per copy under M1 *)\n")
    w(per_copy("u") if "M1" in f else holder_bound("u"))
    w("  (* salt of the undisclosed attribute block *)\n")
    w(per_copy("a") if ("M1" in f and "SHARED_ATTR_SALT" not in f) else holder_bound("a"))
    w("  (* Issuee AID key *)\n")
    w(per_copy("e") if "M3" in f else holder_bound("e"))
    w("  (* TEL registry id (ri) *)\n")
    w(per_copy("r") if "M4" in f else holder_bound("r"))
    w("  (* holder/sender AID: stable across key rotation unless M5, so it is\n"
      "     independent of the signing key k *)\n")
    w(per_copy("s") if "M5" in f else holder_bound("s"))
    w("  (* presentation proof signing key *)\n")
    w(per_copy("k") if "M6" in f else holder_bound("k"))
    w("  (* disclosed attribute *)\n")
    w(holder_bound("d") if "DISCLOSE_UNIQUE" in f else constant("d", "over21"))
    w("  (* size/timing class *)\n")
    w(holder_bound("z") if ("NETWORK" in f and "M7" not in f) else constant("z", "std"))
    w("  (* transport address *)\n")
    w(holder_bound("t") if ("NETWORK" in f and "ANON_TRANSPORT" not in f) else constant("t", "anon"))
    w("  (* status-retrieval session *)\n")
    w(holder_bound("q") if ("STATUS" in f and "M8" not in f) else constant("q", "anon"))

    w("""
  (* ACDC: SAID is a digest over the credential content *)
  let pkI = pk(skI) in
  let ab1 = h((attrs, n1, a1)) in
  let ab2 = h((attrs, n2, a2)) in
  let said1 = h((pkI, schema, pk(e1), r1, d1, ab1, u1)) in
  let said2 = h((pkI, schema, pk(e2), r2, d2, ab2, u2)) in
  let cred1 = (said1, pkI, schema, pk(e1), r1, d1, ab1, u1) in
  let cred2 = (said2, pkI, schema, pk(e2), r2, d2, ab2, u2) in
""")
    if "M1" in f and "M2" not in f:
        w("""  (* M1 without M2: the copies are leaves of one Merkle batch per holder.
     world 0: C1 and C2 are siblings in ONE batch; world 1: each holder's batch
     has its own other (unpresented) leaf *)
  new bl1: bitstring; new bl2: bitstring; new o1: bitstring; new o2: bitstring;
  let b1 = h((leaf, said1, bl1)) in
  let b2 = h((leaf, said2, bl2)) in
""")
        if "INCLUSION" in f:
            w("""  (* inclusion proof: disclose only the sibling leaf and the root *)
  let sib1 = choice[b2, h((leaf, o1))] in
  let sib2 = choice[b1, h((leaf, o2))] in
  let B1 = h((node, b1, sib1)) in
  let B2 = h((node, sib2, b2)) in
  let anc1 = (bl1, sib1, B1, sign((ixn, B1), skI)) in
  let anc2 = (bl2, sib2, B2, sign((ixn, B2), skI)) in
""")
        else:
            w("""  (* full list, as in keripy tests/acdc/test_bulk_issuance.py *)
  let list1 = choice[(b1, b2), (b1, h((leaf, o1)))] in
  let list2 = choice[(b1, b2), (h((leaf, o2)), b2)] in
  let B1 = h((node, list1)) in
  let B2 = h((node, list2)) in
  let anc1 = (bl1, list1, B1, sign((ixn, B1), skI)) in
  let anc2 = (bl2, list2, B2, sign((ixn, B2), skI)) in
""")
    else:
        w("""  (* single credential, or individually anchored copies *)
  let anc1 = sign((ixn, said1), skI) in
  let anc2 = sign((ixn, said2), skI) in
""")

    w("""
  (* presentation i: verifier Vi (attacker) picks the challenge *)
  (
    ( in(c, nonce1: bitstring);
      let sid1 = h((aid, s1)) in
      let msg1 = (pres, cred1, anc1, sid1, pk(k1)) in
      out(c, (t1, z1, msg1, sign((nonce1, msg1), k1))) )
  | ( in(c, nonce2: bitstring);
      let sid2 = h((aid, s2)) in
      let msg2 = (pres, cred2, anc2, sid2, pk(k2)) in
      out(c, (t2, z2, msg2, sign((nonce2, msg2), k2))) )
""")
    if "STATUS" in f:
        w("""  (* C: holder fetches a fresh TEL status proof and carries it along *)
  | ( out(c, (telquery, q1, r1, said1));
      out(c, (tel, r1, said1, iss, sign((tel, r1, said1, iss), skI))) )
  | ( out(c, (telquery, q2, r2, said2));
      out(c, (tel, r2, said2, iss, sign((tel, r2, said2, iss), skI))) )
""")
    if "MALICIOUS_ISSUER" in f:
        w("""  (* E: issuer hands its issuance records to V1 and V2 *)
  | out(c, (issuedto, n1, said1))
  | out(c, (issuedto, n2, said2))
""")
    w("  )\n")
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


def parse(out):
    if "RESULT Observational equivalence is true" in out:
        return "true"
    if "RESULT Observational equivalence cannot be proved" in out:
        return "false"
    return "error"


def distinguisher(out):
    """The attacker's final distinguishing test from ProVerif's reconstructed
    trace ("The attacker tests whether X is equal to Y ..."), if any."""
    lines = out.splitlines()
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].startswith("The attacker tests whether"):
            return [ln.strip() for ln in lines[i:i + 5]]
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--proverif", default=None)
    args = ap.parse_args()

    configs = [c for c in CONFIGS if c[0].startswith(args.only)]
    if args.list:
        for cid, exp, desc, flags, expected, _ in configs:
            print(f"{cid:26} {exp:4} {expected:5} {' '.join(flags)}")
        return 0

    MODELS.mkdir(parents=True, exist_ok=True)
    for cid, _, desc, flags, _, _ in configs:
        (MODELS / f"{cid}.pv").write_text(generate(cid, desc, flags))
    if args.generate:
        print(f"wrote {len(configs)} models to {MODELS.relative_to(ROOT)}")
        return 0

    pv = find_proverif(args.proverif)
    RESULTS.mkdir(parents=True, exist_ok=True)
    records, mismatches = [], 0
    for cid, exp, desc, flags, expected, culprit in configs:
        t0 = time.time()
        try:
            proc = subprocess.run([pv, str(MODELS / f"{cid}.pv")], capture_output=True,
                                  text=True, timeout=args.timeout)
            out = proc.stdout + proc.stderr
            actual = parse(out)
        except subprocess.TimeoutExpired:
            out, actual = "TIMEOUT", "timeout"
        elapsed = round(time.time() - t0, 2)
        (RESULTS / f"{cid}.log").write_text(out)
        ok = actual == expected
        mismatches += not ok
        rec = dict(id=cid, experiment=exp, description=desc, flags=flags,
                   expected=expected, actual=actual, match=ok,
                   expected_culprit=culprit, trace_tail=distinguisher(out),
                   seconds=elapsed)
        records.append(rec)
        print(f"{cid:26} expected={expected:5} actual={actual:7} "
              f"{'ok' if ok else 'MISMATCH'}  ({elapsed}s)", flush=True)

    ver = subprocess.run([pv, "-help"], capture_output=True, text=True).stdout.splitlines()[0]
    (RESULTS / "results.json").write_text(json.dumps(
        dict(proverif=ver, generated=time.strftime("%Y-%m-%dT%H:%M:%S"),
             mismatches=mismatches, results=records), indent=1))
    lines = [f"# PRV-01 ProVerif results ({ver})", "",
             "`true` = observational equivalence proved (unlinkable); "
             "`false` = cannot be proved (see log for the trace).", "",
             "| config | exp | description | expected | actual | match | linking values (expected) |",
             "|---|---|---|---|---|---|---|"]
    for r in records:
        lines.append(f"| {r['id']} | {r['experiment']} | {r['description']} | "
                     f"{r['expected']} | {r['actual']} | "
                     f"{'yes' if r['match'] else '**NO**'} | {r['expected_culprit']} |")
    (RESULTS / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\n{len(records) - mismatches}/{len(records)} as expected")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
