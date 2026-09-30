#!/usr/bin/env python3
"""Run every SEDI Tamarin theory/variant and compare against expected results.

Usage:
    python3 scripts/run_all.py                 # run everything
    python3 scripts/run_all.py --only cry01    # runs whose id starts with cry01
    python3 scripts/run_all.py --list          # list run ids

Reads   scripts/manifest.json   (runs + expected lemma status)
Writes  results/results.json    (machine-readable, one record per lemma)
        results/summary.md      (human-readable table)
        results/logs/<run>__<lemma>.log  (full Tamarin output incl. traces)

Each lemma is proved in its own tamarin-prover process (--prove=<lemma>),
so a non-terminating lemma is reported as "timeout" without hiding others.

Exit status is non-zero if any lemma's status differs from the expected one
or any run fails to parse / times out. Expected values are NEVER rewritten
by this script.
"""
import argparse
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "scripts" / "manifest.json"
RESULTS = ROOT / "results"

LINE = re.compile(
    r"^\s+(?P<lemma>\S+)\s+\((?P<kind>all-traces|exists-trace)\):\s+"
    r"(?P<status>verified|falsified - found trace|falsified - no trace found|"
    r"analysis incomplete)"
)
DIFF_LINE = re.compile(
    r"^\s+(?P<lemma>DiffLemma:\s+\S+|\S+)\s+:\s+"
    r"(?P<status>verified|falsified - found trace|falsified - no trace found|"
    r"analysis incomplete)"
)


def normalise(status):
    return {
        "verified": "verified",
        "falsified - found trace": "falsified",
        "falsified - no trace found": "falsified",
        "analysis incomplete": "incomplete",
    }[status]


def tamarin_version():
    out = subprocess.run(["tamarin-prover", "--version"], capture_output=True,
                         text=True).stdout
    m = re.search(r"Tamarin version (\S+)", out)
    mm = re.search(r"Maude version (\S+)", out)
    return (m.group(1) if m else "unknown", mm.group(1) if mm else "unknown")


def run_one(run, timeout, lemma):
    cmd = ["tamarin-prover", run["theory"]]
    if run.get("diff"):
        cmd.append("--diff")
    for flag in run.get("flags", []):
        cmd.append(f"-D{flag}")
    cmd.append(f"--prove={lemma}")
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=run.get("timeout", timeout), cwd=ROOT)
        out = proc.stdout + proc.stderr
        timed_out = False
    except subprocess.TimeoutExpired as ex:
        out = (ex.stdout or b"").decode() if isinstance(ex.stdout, bytes) else (ex.stdout or "")
        timed_out = True
    elapsed = round(time.time() - t0, 2)

    logdir = RESULTS / "logs"
    logdir.mkdir(parents=True, exist_ok=True)
    (logdir / f"{run['id']}__{lemma}.log").write_text(" ".join(cmd) + "\n\n" + out)

    found = {}
    if "summary of summaries" in out:
        summary = out.split("summary of summaries")[-1]
        for line in summary.splitlines():
            m = LINE.match(line)
            if m:
                found[m.group("lemma")] = (m.group("kind"), normalise(m.group("status")))
                continue
            m = DIFF_LINE.match(line)
            if m and run.get("diff"):
                name = m.group("lemma").replace("DiffLemma:", "").strip()
                found[name] = ("diff", normalise(m.group("status")))
    return " ".join(cmd), out, found, elapsed, timed_out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    runs = [r for r in manifest["runs"] if r["id"].startswith(args.only)]
    if args.list:
        for r in runs:
            print(r["id"], r["theory"], r.get("flags", []), "diff" if r.get("diff") else "")
        return 0

    tv, mv = tamarin_version()
    RESULTS.mkdir(exist_ok=True)
    records, mismatches = [], 0
    jobs = [(run, lemma) for run in runs for lemma in run["expected"]]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        outs = list(pool.map(lambda j: run_one(j[0], args.timeout, j[1]), jobs))
    for (run, lemma), (cmd, out, found, elapsed, timed_out) in zip(jobs, outs):
        exp = run["expected"][lemma]
        if timed_out:
            kind, actual = "?", "timeout"
        else:
            kind, actual = found.get(lemma, ("?", "error"))
        ok = exp == actual
        if not ok:
            mismatches += 1
        records.append({
            "run": run["id"],
            "requirement": run["requirement"],
            "variant": run.get("variant", ""),
            "theory": run["theory"],
            "flags": run.get("flags", []),
            "diff": bool(run.get("diff")),
            "lemma": lemma,
            "kind": kind,
            "expected": exp,
            "actual": actual,
            "match": ok,
            "seconds": elapsed,
            "command": cmd,
            "log": f"results/logs/{run['id']}__{lemma}.log",
        })
        print(f"[{run['id']}] {'ok ' if ok else 'MISMATCH'} {lemma}: "
              f"{actual} (expected {exp}) {elapsed}s")

    (RESULTS / "results.json").write_text(json.dumps({
        "tamarin_version": tv,
        "maude_version": mv,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "mismatches": mismatches,
        "results": records,
    }, indent=2) + "\n")

    lines = [f"# Tamarin results (Tamarin {tv}, Maude {mv})", "",
             "| run | requirement | variant | lemma | actual | expected | match |",
             "|---|---|---|---|---|---|---|"]
    for r in records:
        lines.append(f"| {r['run']} | {r['requirement']} | {r['variant']} | "
                     f"`{r['lemma']}` | {r['actual']} | {r['expected']} | "
                     f"{'yes' if r['match'] else '**NO**'} |")
    (RESULTS / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\n{len(records)} lemma results, {mismatches} mismatches")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
