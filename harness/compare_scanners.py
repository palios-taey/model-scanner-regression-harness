#!/usr/bin/env python3
"""Read scan_matrix.py JSONL output and surface candidate findings.

A candidate is a file where:
  (a) at least one scanner says CLEAN or skips,
  (b) static disassembly shows HIGH-risk opcodes, and
  (c) the contradiction is not trivially explainable.

Output: JSON list of candidate records sorted by interestingness.
"""
from __future__ import annotations
import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def score_candidate(rec: dict) -> int:
    """Heuristic interestingness score; higher = more worth investigating."""
    score = 0
    contradictions = rec.get("contradictions", [])
    if "modelscan_clean_but_disasm_high" in contradictions:
        score += 5
    if "fickling_likely_safe_but_disasm_high" in contradictions:
        score += 4
    if "modelscan_vs_fickling_disagree" in contradictions:
        score += 3
    if "disasm_parse_error_fickling_ok" in contradictions:
        score += 2
    if "fickling_error_disasm_ok" in contradictions:
        score += 2

    # Bonus: REDUCE+GLOBAL pattern (the classic RCE primitive) makes a clean
    # scanner verdict more concerning.
    disasm = rec.get("disasm", {})
    rc = disasm.get("risk_counts", {})
    if rc.get("REDUCE") and rc.get("GLOBAL"):
        score += 2
    if rc.get("STACK_GLOBAL") and rc.get("REDUCE"):
        score += 2

    # Penalize if modelscan reports an error (file unreadable etc)
    if rec.get("modelscan", {}).get("error"):
        score -= 5

    return score


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True, help="JSONL from scan_matrix.py")
    p.add_argument("--out", type=Path, required=True, help="JSON list of candidates")
    p.add_argument("--min-score", type=int, default=2)
    args = p.parse_args()

    records = []
    with args.input.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    candidates = []
    contradiction_hist: Counter = Counter()
    for rec in records:
        if not rec.get("contradictions"):
            continue
        s = score_candidate(rec)
        for c in rec["contradictions"]:
            contradiction_hist[c] += 1
        if s >= args.min_score:
            candidates.append({
                "score": s,
                "path": rec.get("path"),
                "sha256": rec.get("sha256"),
                "size": rec.get("size"),
                "contradictions": rec.get("contradictions"),
                "disasm_risk_level": rec.get("disasm", {}).get("risk_level"),
                "disasm_risk_counts": rec.get("disasm", {}).get("risk_counts"),
                "modelscan_summary": rec.get("modelscan", {}).get("summary"),
                "fickling_likely_safe": rec.get("fickling", {}).get("likely_safe"),
            })

    candidates.sort(key=lambda r: -r["score"])

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as f:
        json.dump({
            "input": str(args.input),
            "total_records": len(records),
            "candidates_above_threshold": len(candidates),
            "min_score": args.min_score,
            "contradiction_histogram": dict(contradiction_hist),
            "candidates": candidates,
        }, f, indent=2)

    print(f"scanned {len(records)} records, {len(candidates)} candidates >= score {args.min_score}", file=sys.stderr)
    print(f"contradiction hist: {dict(contradiction_hist)}", file=sys.stderr)


if __name__ == "__main__":
    main()
