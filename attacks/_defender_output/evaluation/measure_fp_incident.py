#!/usr/bin/env python3
"""
Measure the figures behind the primitive-01 false-positive incident.

Run from:  attacks/_defender_output/evaluation/
    python3 measure_fp_incident.py

Reports, for the committed corpus:
  - how many events carry an AssumedRole session name
  - how many of those match the ORIGINAL (buggy) regex  i-[0-9a-f]+
  - how many match the CORRECTED regex  ^i-[0-9a-f]{17}$
  - the CI/CD subset that caused the incident
Every number is derived from the corpus, not from memory.
"""
import json, re, sys, collections
from pathlib import Path

CORPUS = Path("corpora/combined_corpus.jsonl")
if not CORPUS.exists():
    sys.exit(f"not found: {CORPUS}  (run from the evaluation/ directory)")

BUGGY   = re.compile(r"i-[0-9a-f]+")        # unanchored, matches substrings
CORRECT = re.compile(r"^i-[0-9a-f]{17}$")   # complete modern EC2 instance IDs

def session_name(ev):
    """Pull the assumed-role session name out of a CloudTrail-shaped record."""
    ui = ev.get("userIdentity") or {}
    if ui.get("type") != "AssumedRole":
        return None
    arn = ui.get("arn") or ""
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    sc = ui.get("sessionContext") or {}
    return (sc.get("sessionIssuer") or {}).get("userName")

total = assumed = 0
buggy_hits = correct_hits = 0
cicd_buggy = 0
attack_events = 0
buggy_sessions, correct_sessions = set(), set()
sample_buggy = collections.Counter()

with CORPUS.open() as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        ev = json.loads(line)
        total += 1
        if ev.get("attack_id"):
            attack_events += 1
        sn = session_name(ev)
        if sn is None:
            continue
        assumed += 1
        if BUGGY.search(sn):
            buggy_hits += 1
            buggy_sessions.add(sn)
            if "circleci" in sn:
                cicd_buggy += 1
            else:
                sample_buggy[sn[:34]] += 1
        if CORRECT.match(sn):
            correct_hits += 1
            correct_sessions.add(sn)

W = 42
def row(label, value):
    print(f"  {label:<{W}}{value:>10,}")

print(f"\ncorpus: {CORPUS}")
print("=" * 56)
row("total events", total)
row("labelled attack events", attack_events)
row("events with an AssumedRole session", assumed)
print()
print("  session name matched by ...")
row("  BUGGY  i-[0-9a-f]+   (substring)", buggy_hits)
row("    of which CI/CD (circleci-deployer)", cicd_buggy)
row("    distinct sessions", len(buggy_sessions))
row("  CORRECT ^i-[0-9a-f]{17}$", correct_hits)
row("    distinct sessions", len(correct_sessions))
print()
row("SPURIOUS: buggy minus correct", buggy_hits - correct_hits)

if sample_buggy:
    print("\n  non-CI/CD session names caught by the buggy regex:")
    for name, n in sample_buggy.most_common(5):
        print(f"    {name:<38}{n:>8,}")
print()
