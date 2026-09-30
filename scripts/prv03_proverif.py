#!/usr/bin/env python3
"""SEDI-PRV-03 (architectural anti-surveillance) in ProVerif.

Usage:
    python3 scripts/prv03_proverif.py              # generate + run all
    python3 scripts/prv03_proverif.py --only C_
    python3 scripts/prv03_proverif.py --list
    python3 scripts/prv03_proverif.py --generate

Writes  proverif/prv03/<config>__{ni,trace,corr}.pv
        results/prv03/<config>__{ni,trace,corr}.log, summary.md, results.json

The Department D is the ProVerif attacker, but it is NOT omniscient: it sees
only the public channel `c`, which carries exactly the traffic that reaches a
Department-operated endpoint (callback API, TEL/status service, witnesses,
audit/log upload). Holder<->verifier traffic (`hv*`) and verifier-local state
are private channels D cannot read.

Every message on `c` is a Department-view record
    (kind, endpoint id, content, timing class)
so the view contains D-visible messages, status queries, KEL/TEL lookups,
endpoint identifiers, timing classes, logs and credential identifiers.

Three models per configuration:

  __ni     NON-INTERFERENCE (central property). world 0: the holder presents;
           world 1: it does not. The private presentation exchange runs in
           both worlds (D cannot see it); every D-visible effect CAUSED by the
           presentation is sent on choice[c, sink] -- to D in world 0, to a
           private dead end in world 1. Background traffic (scheduled
           refreshes, cover traffic) goes to D in both worlds. Equivalence =
           D cannot tell whether a presentation happened.
  __trace  trace lemmas 1-4, 6 on world 0, with every D-visible message tagged
           by its cause (pres | sched) and category (auth | status | log).
  __corr   lemma 5, correlation. Fixed population of two holders (same
           issuance records, same background in both worlds). world 0: H1
           presents to V1 and V2; world 1: H1 presents to V1, H2 to V2.

"The Department promises not to log" is never an assumption here: anything
that reaches `c` is in D's view, and D can keep it.
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
MODELS = ROOT / "proverif" / "prv03"
RESULTS = ROOT / "results" / "prv03"

# ---------------------------------------------------------------------------
# Deployment configurations.
#   pres:   D-visible messages caused by a presentation, as
#           (who, category, kind, content, credential-specific?)
#           who = "V" (verifier) or "H" (holder); content may use
#           {said} {ri} {ep} (endpoint of who) ; category auth|status|log
#   sched:  background D-visible messages, sent whether or not anyone presents
#   seen:   scheduled refresh whose CONTENT depends on presented credentials
#   waits:  the verifier needs D's answer before accepting
# ---------------------------------------------------------------------------
CONFIGS = [
    dict(id="A_callback", variant="A",
         desc="online Department callback: verifier asks D whether the credential is valid",
         pres=[("V", "auth", "callback", "{said}", True)], waits=True),
    dict(id="B_online_tel", variant="B",
         desc="online TEL/status retrieval from the issuer-controlled registry (issuer KEL cached)",
         pres=[("V", "status", "telquery", "({ri}, {said})", True)], waits=True),
    dict(id="C_cached_snapshot", variant="C",
         desc="offline verifier; whole-registry status snapshot refreshed on a schedule; issuer KEL cached",
         sched=[("V", "status", "fetchall", "registry")]),
    dict(id="C_cached_snapshot_kel_online", variant="C",
         desc="as C, but the verifier fetches the issuer KEL from D-hosted witnesses at presentation",
         pres=[("V", "auth", "kellookup", "aidD", False)],
         sched=[("V", "status", "fetchall", "registry")], waits=True),
    dict(id="C_refresh_on_miss", variant="C",
         desc="offline cache, but an uncached credential triggers a status fetch",
         pres=[("V", "status", "telquery", "({ri}, {said})", True)], waits=True),
    dict(id="C_refresh_seen_credentials", variant="C",
         desc="offline cache; the scheduled refresh asks for the credentials the verifier has seen",
         sched=[("V", "status", "fetchall", "registry")], seen=True),
    dict(id="C_cached_snapshot_audit_upload", variant="C",
         desc="as C, but the verifier uploads a presentation log to D",
         pres=[("V", "log", "auditlog", "{said}", True)],
         sched=[("V", "status", "fetchall", "registry")]),
    dict(id="D_holder_status_scheduled", variant="D",
         desc="holder-carried status; the holder refreshes its status proof on a schedule",
         sched=[("H", "status", "telquery", "({ri}, {said})")], holder_carried=True),
    dict(id="D_holder_status_on_demand", variant="D",
         desc="holder-carried status; the holder fetches a fresh status proof just before presenting",
         pres=[("H", "status", "telquery", "({ri}, {said})", True)], holder_carried=True),
    dict(id="E_anon_credential_query", variant="E",
         desc="anonymous status query (no verifier id) that still names the credential",
         pres=[("V", "status", "telquery", "({ri}, {said})", True)], anon=True, waits=True),
    dict(id="E_anon_wholelist_on_demand", variant="E",
         desc="anonymous whole-list / PIR retrieval, performed when a presentation arrives",
         pres=[("V", "status", "fetchall", "registry", False)], anon=True, waits=True),
    dict(id="E_anon_wholelist_cover_traffic", variant="E",
         desc="anonymous whole-list retrieval in every time slot, whether or not a presentation arrives",
         sched=[("V", "status", "fetchall", "registry")], anon=True, slot=True),
]

LEMMAS = [
    ("L1_no_auth_callback", "safety",
     "k, x: bitstring; event(DObs(pres, auth, k, x))",
     "1. no Department callback / KEL lookup caused by authenticity verification"),
    ("L2_no_status_query", "safety",
     "k, x: bitstring; event(DObs(pres, status, k, x))",
     "2. no Department-visible status query caused by a presentation"),
    ("L3_no_presentation_log", "safety",
     "g, k, x: bitstring; event(DObs(pres, g, k, x))",
     "3. no presentation-caused message reaches D, so D can keep no presentation log"),
    ("L4_no_credential_id", "safety",
     "x: bitstring; event(DCredId(pres, x))",
     "4. no credential-specific identifier reaches D because of a presentation"),
    ("L6_offline_accept", "reach",
     "s: bitstring; event(Accept(s)) ==> event(DQueried(s))",
     "6. the verifier can accept without any presentation-caused Department query"),
]
# expected outcome per config: holds / fails for L1-L4, L6, NI, CORR
H, F = "holds", "fails"
EXPECTED = {
    "A_callback":                     dict(L1=F, L2=H, L3=F, L4=F, L6=F, NI=F, CORR=F),
    "B_online_tel":                   dict(L1=H, L2=F, L3=F, L4=F, L6=F, NI=F, CORR=F),
    "C_cached_snapshot":              dict(L1=H, L2=H, L3=H, L4=H, L6=H, NI=H, CORR=H),
    "C_cached_snapshot_kel_online":   dict(L1=F, L2=H, L3=F, L4=H, L6=F, NI=F, CORR=H),
    "C_refresh_on_miss":              dict(L1=H, L2=F, L3=F, L4=F, L6=F, NI=F, CORR=F),
    "C_refresh_seen_credentials":     dict(L1=H, L2=F, L3=F, L4=F, L6=H, NI=F, CORR=F),
    "C_cached_snapshot_audit_upload": dict(L1=H, L2=H, L3=F, L4=F, L6=H, NI=F, CORR=F),
    "D_holder_status_scheduled":      dict(L1=H, L2=H, L3=H, L4=H, L6=H, NI=H, CORR=H),
    "D_holder_status_on_demand":      dict(L1=H, L2=F, L3=F, L4=F, L6=H, NI=F, CORR=F),
    "E_anon_credential_query":        dict(L1=H, L2=F, L3=F, L4=F, L6=F, NI=F, CORR=F),
    "E_anon_wholelist_on_demand":     dict(L1=H, L2=F, L3=F, L4=H, L6=F, NI=F, CORR=H),
    "E_anon_wholelist_cover_traffic": dict(L1=H, L2=H, L3=H, L4=H, L6=H, NI=H, CORR=H),
}
LKEYS = ["L1", "L2", "L3", "L4", "L6"]

PRELUDE = """(* GENERATED by scripts/prv03_proverif.py -- do not edit by hand.
   SEDI-PRV-03 {cid} [{mode}]: {desc}
   D (the attacker) sees only channel c = traffic reaching Department endpoints.
   Holder<->verifier traffic and verifier-local state are private. *)

free c: channel.
free hv, hv1, hv2, sink, vlocal: channel [private].

fun h(bitstring): bitstring.
fun pk(bitstring): bitstring.
fun sign(bitstring, bitstring): bitstring.
reduc forall m: bitstring, k: bitstring; verify(sign(m, k), m, pk(k)) = true.
reduc forall m: bitstring, k: bitstring; getmsg(sign(m, k)) = m.

(* Department-view vocabulary *)
const schema, reg, issued, registry, aidD, none: bitstring.
const callback, telquery, kellookup, fetchall, refresh, auditlog: bitstring.
const vid, vid1, vid2, anon: bitstring.            (* endpoint identifiers *)
const t_pres, t_sched, t_slot: bitstring.          (* timing classes *)
const pres, sched, auth, status, log: bitstring.   (* causes / categories *)

event DObs(bitstring, bitstring, bitstring, bitstring).
event DCredId(bitstring, bitstring).
event DQueried(bitstring).
event Accept(bitstring).
"""


def endpoint(cfg, who, vtag, hep):
    if who == "H":
        return hep
    return "anon" if cfg.get("anon") else vtag


def msg(cfg, who, kind, content, said, ri, vtag, hep, timing):
    body = content.format(said=said, ri=ri)
    return f"({kind}, {endpoint(cfg, who, vtag, hep)}, {body}, {timing})"


def credential(prefix, holder, skD="skD"):
    return (f"  new u{prefix}: bitstring;\n"
            f"  let said{prefix} = h((pk({skD}), schema, {holder}, u{prefix})) in\n"
            f"  let ri{prefix} = h((said{prefix}, reg)) in\n"
            f"  let cred{prefix} = (said{prefix}, ri{prefix}, sign((said{prefix}, ri{prefix}), {skD})) in\n")


def dept_setup():
    return ("process\n"
            "  new skD: bitstring;\n"
            "  out(c, skD); out(c, pk(skD));     (* D knows its own issuing key *)\n")


def events(who, cause, cat, m, credid, said):
    """Trace-mode bookkeeping for one D-visible message."""
    kind = m[1:].split(",")[0]
    ev = f"event DObs({cause}, {cat}, {kind}, {m}); "
    if credid:
        ev += f"event DCredId({cause}, {said}); "
    if cause == "pres" and who == "V" and cat in ("auth", "status"):
        ev += f"event DQueried({said}); "
    return ev


def verifier_block(cfg, mode, hvchan, vtag, pres_chan):
    """Verifier: receives a presentation privately, checks the issuer
    signature with its cached issuer key, performs the configured
    presentation-caused D traffic, and accepts (after D answers, if the
    design waits for D)."""
    msgs = [(cat, msg(cfg, who, kind, content, "s", "r", vtag, None, "t_pres"), credid)
            for who, cat, kind, content, credid in cfg.get("pres", []) if who == "V"]
    head = (f"  ( in({hvchan}, (s: bitstring, r: bitstring, isg: bitstring));\n"
            f"    if verify(isg, (s, r), pk(skD)) = true then\n")
    if mode == "trace":
        seq = "".join(events("V", "pres", cat, m, credid, "s") + f"out(c, {m}); "
                      for cat, m, credid in msgs)
        if cfg.get("waits"):
            seq += "in(c, answer: bitstring); "
        return head + f"      {seq}event Accept(s) )\n"
    if not msgs:
        return head + "      0 )\n"
    return head + "      ( " + " | ".join(f"out({pres_chan}, {m})" for _, m, _ in msgs) + " ) )\n"


def holder_block(cfg, mode, cred, said, ri, hep, hvchan, pres_chan):
    parts = []
    for who, cat, kind, content, credid in cfg.get("pres", []):
        if who != "H":
            continue
        m = msg(cfg, who, kind, content, said, ri, None, hep, "t_pres")
        if mode == "trace":
            parts.append(f"({events('H', 'pres', cat, m, credid, said)}out(c, {m}))")
        else:
            parts.append(f"out({pres_chan}, {m})")
    parts.append(f"out({hvchan}, {cred})")
    return "  ( " + " | ".join(parts) + " )\n"


def sched_block(cfg, mode, vtags, holders):
    """Background D-visible traffic: identical in both worlds.
    holders: list of (said, ri, hep)."""
    parts = []
    timing = "t_slot" if cfg.get("slot") else "t_sched"
    for who, cat, kind, content in cfg.get("sched", []):
        targets = [(None, None, v, None) for v in vtags] if who == "V" else \
                  [(s, r, None, hp) for s, r, hp in holders]
        for s, r, v, hp in targets:
            m = msg(cfg, who, kind, content, s, r, v, hp, timing)
            ev = events(who, "sched", cat, m, False, "none") if mode == "trace" else ""
            parts.append(f"({ev}out(c, {m}))")
    return parts


def ni_model(cfg, mode):
    """mode 'ni' (biprocess) or 'trace' (world 0 only, with events)."""
    cid = cfg["id"]
    lines = [PRELUDE.format(cid=cid, mode=mode, desc=cfg["desc"])]
    if mode == "trace":
        lines += [f"query {q}.  (* {lid}: {doc} *)\n" for lid, _, q, doc in LEMMAS]
    lines.append(dept_setup())
    lines.append("  new hid: bitstring; new hep: bitstring;\n")
    lines.append(credential("", "hid"))
    lines.append("  out(c, (issued, hid, hep, said));   (* D issued this credential *)\n")
    pres_chan = "choice[c, sink]" if mode == "ni" else "c"
    parts = [holder_block(cfg, mode, "cred", "said", "ri", "hep", "hv", pres_chan),
             verifier_block(cfg, mode, "hv", "vid", pres_chan)]
    # the verifier's own presentation record, kept locally (not D-accessible)
    parts.append("  out(vlocal, " + ("choice[(said, t_pres), none]" if mode == "ni"
                                    else "(said, t_pres)") + ")\n")
    parts += [f"  {p}\n" for p in sched_block(cfg, mode, ["vid"], [("said", "ri", "hep")])]
    if cfg.get("seen"):
        # the scheduled refresh asks for every credential this verifier has seen
        if mode == "ni":
            parts.append("  out(c, (refresh, vid, choice[said, none], t_sched))\n")
        else:
            m = "(refresh, vid, said, t_sched)"
            parts.append(f"  ({events('V', 'pres', 'status', m, True, 'said')}out(c, {m}))\n")
    lines.append("  (\n" + "  |\n".join(parts) + "  )\n")
    return "".join(lines)


def corr_model(cfg):
    """Lemma 5: fixed population {H1, H2} with identical issuance records and
    background traffic in both worlds. world 0: H1 presents to V1 and V2 (two
    bulk copies); world 1: H1 presents to V1, H2 presents to V2."""
    lines = [PRELUDE.format(cid=cfg["id"], mode="corr", desc=cfg["desc"])]
    lines.append(dept_setup())
    lines.append("  new hid1: bitstring; new hep1: bitstring;\n"
                 "  new hid2: bitstring; new hep2: bitstring;\n")
    lines.append(credential("1a", "hid1") + credential("1b", "hid1") + credential("2", "hid2"))
    lines.append("  out(c, (issued, hid1, hep1, said1a)); out(c, (issued, hid1, hep1, said1b));\n"
                 "  out(c, (issued, hid2, hep2, said2));\n"
                 "  let credP2 = choice[cred1b, cred2] in\n"
                 "  let saidP2 = choice[said1b, said2] in\n"
                 "  let riP2 = choice[ri1b, ri2] in\n"
                 "  let hepP2 = choice[hep1, hep2] in\n")
    parts = [holder_block(cfg, "corr", "cred1a", "said1a", "ri1a", "hep1", "hv1", "c"),
             verifier_block(cfg, "corr", "hv1", "vid1", "c"),
             holder_block(cfg, "corr", "credP2", "saidP2", "riP2", "hepP2", "hv2", "c"),
             verifier_block(cfg, "corr", "hv2", "vid2", "c")]
    holders = [("said1a", "ri1a", "hep1"), ("said1b", "ri1b", "hep1"), ("said2", "ri2", "hep2")]
    parts += [f"  {p}\n" for p in sched_block(cfg, "corr", ["vid1", "vid2"], holders)]
    if cfg.get("seen"):
        parts.append("  out(c, (refresh, vid1, said1a, t_sched))\n")
        parts.append("  out(c, (refresh, vid2, saidP2, t_sched))\n")
    return "".join(lines) + "  (\n" + "  |\n".join(parts) + "  )\n"


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
            if ln.strip().startswith(("Query ", "Observational"))]


def last_test(out):
    lines = out.splitlines()
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].startswith("The attacker tests whether"):
            return " ".join(ln.strip() for ln in lines[i:i + 4])
        if lines[i].startswith("An input on channel c and an output on channel choice[c,sink]"):
            return ("D receives a presentation-caused message in world 0 that does "
                    "not exist in world 1 (" + lines[i + 2].strip().strip("()") + ")")
    return ""


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
            print(f"{c['id']:34} {c['variant']}  {c['desc']}")
        return 0
    MODELS.mkdir(parents=True, exist_ok=True)
    for c in cfgs:
        (MODELS / f"{c['id']}__ni.pv").write_text(ni_model(c, "ni"))
        (MODELS / f"{c['id']}__trace.pv").write_text(ni_model(c, "trace"))
        (MODELS / f"{c['id']}__corr.pv").write_text(corr_model(c))
    if args.generate:
        print(f"wrote {3 * len(cfgs)} models to {MODELS.relative_to(ROOT)}")
        return 0

    pv = find_proverif(args.proverif)
    RESULTS.mkdir(parents=True, exist_ok=True)

    def run(name):
        t0 = time.time()
        try:
            p = subprocess.run([pv, str(MODELS / f"{name}.pv")], capture_output=True,
                               text=True, timeout=args.timeout)
            out = p.stdout + p.stderr
        except subprocess.TimeoutExpired:
            out = "TIMEOUT"
        (RESULTS / f"{name}.log").write_text(out)
        return out, round(time.time() - t0, 2)

    def equiv(out):
        if "RESULT Observational equivalence is true" in out:
            return H
        if "RESULT Observational equivalence cannot be proved" in out:
            return F if "A trace has been found" in out else "unknown"
        return "error"

    records, mismatches = [], 0
    for c in cfgs:
        cid, exp = c["id"], EXPECTED[c["id"]]
        got, tests = {}, {}
        out, _ = run(f"{cid}__trace")
        res = summary_lines(out)
        if len(res) == len(LEMMAS):
            for (lid, kind, _, _), line, key in zip(LEMMAS, res, LKEYS):
                if "cannot be proved" in line:
                    got[key] = "unknown"
                else:
                    true = line.endswith("is true.")
                    # safety queries are stated as "not event(...)": true = holds.
                    # L6 correspondence Accept ==> DQueried: false = offline accept exists.
                    got[key] = (H if true else F) if kind == "safety" else (F if true else H)
        else:
            got.update({k: "error" for k in LKEYS})
        for mode, key in (("ni", "NI"), ("corr", "CORR")):
            out, _ = run(f"{cid}__{mode}")
            got[key] = equiv(out)
            tests[key] = last_test(out) if got[key] == F else ""
        bad = [k for k in exp if got.get(k) != exp[k]]
        mismatches += len(bad)
        records.append(dict(id=cid, variant=c["variant"], description=c["desc"],
                            expected=exp, actual=got, mismatches=bad, tests=tests))
        print(f"{cid:34} " + " ".join(f"{k}={got[k][:5]:5}" for k in exp)
              + ("" if not bad else "   MISMATCH: " + ",".join(bad)), flush=True)

    ver = subprocess.run([pv, "-help"], capture_output=True, text=True).stdout.splitlines()[0]
    (RESULTS / "results.json").write_text(json.dumps(
        dict(proverif=ver, generated=time.strftime("%Y-%m-%dT%H:%M:%S"),
             mismatches=mismatches, results=records), indent=1))
    cols = ["L1", "L2", "L3", "L4", "L5 (CORR)", "L6", "Non-interference"]
    keys = ["L1", "L2", "L3", "L4", "CORR", "L6", "NI"]
    lines = [f"# PRV-03 ProVerif results ({ver})", "",
             "`holds` / **FAILS**; ✗ marks a mismatch with the expected result.", "",
             "| config | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for r in records:
        cells = []
        for k in keys:
            a = r["actual"][k]
            cells.append(("holds" if a == H else "**FAILS**" if a == F else a)
                         + ("" if a == r["expected"][k] else " ✗"))
        lines.append(f"| {r['id']} | " + " | ".join(cells) + " |")
    (RESULTS / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\n{mismatches} mismatch(es)")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
