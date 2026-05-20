#!/usr/bin/env python3
"""Run multiple scanners against a corpus of model files and emit JSONL.

NO EXECUTION OF MODEL CONTENT. Calls scanners that operate statically
(modelscan, fickling.is_likely_safe via Python API, our disassemble_pickle).

Output per file: one JSON object with keys
  path, sha256, size, modelscan, fickling, disasm, contradictions
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

# Package-relative imports below
from harness.disassemble_pickle import disassemble


def run_modelscan(path: Path) -> dict:
    """Invoke modelscan CLI as a subprocess; never imports the target."""
    try:
        r = subprocess.run(
            ["modelscan", "-p", str(path), "-r", "json"],
            capture_output=True, text=True, timeout=30,
        )
        # modelscan exits non-zero on detected issues; that's fine for us.
        try:
            data = json.loads(r.stdout)
            return {
                "exit_code": r.returncode,
                "issues": data.get("issues", []),
                "summary": data.get("summary", {}),
                "errors": data.get("errors", []),
            }
        except json.JSONDecodeError:
            return {"exit_code": r.returncode, "raw": r.stdout[:500], "stderr": r.stderr[:500]}
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except FileNotFoundError:
        return {"error": "modelscan_not_installed"}


def run_fickling(path: Path) -> dict:
    """Fickling static analysis. likely_safe + opcode info from Pickled.load."""
    try:
        # fickling.pickle moved to fickling.fickle in 0.0.8 — use the new path.
        try:
            from fickling.fickle import Pickled
        except ImportError:
            from fickling.pickle import Pickled  # fallback for older fickling
        with path.open("rb") as f:
            pkl = Pickled.load(f)
        ops = list(pkl)
        analysis = {"op_count": len(ops)}
        try:
            from fickling.analysis import check_safety
            result = check_safety(pkl)
            # Result is a Severity enum or wrapping object depending on version.
            analysis["likely_safe"] = bool(getattr(result, "likely_safe", None)) if hasattr(result, "likely_safe") else None
            analysis["severity"] = getattr(result, "severity", None).name if hasattr(getattr(result, "severity", None), "name") else str(getattr(result, "severity", result))
            analysis["detail"] = str(result)[:500]
        except Exception as e:
            analysis["check_safety_error"] = f"{type(e).__name__}: {e}"
        return analysis
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def scan_one(path: Path) -> dict:
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    ms = run_modelscan(path)
    fk = run_fickling(path)
    ds = disassemble(path)

    contradictions = []
    # Contradiction 1: modelscan clean but disasm flags HIGH risk.
    # Modelscan emits issues=[] and summary=None when nothing is flagged
    # (verified empirically 2026-05-17); count len(issues) instead of trusting
    # summary, and treat absent/empty issues as clean.
    ms_issue_count = len(ms.get("issues") or [])
    ms_clean = ms_issue_count == 0 and not ms.get("error")
    if ms_clean and ds.get("risk_level") == "HIGH":
        contradictions.append("modelscan_clean_but_disasm_high")
    # Contradiction 2: fickling likely_safe=True but disasm HIGH risk
    if fk.get("likely_safe") is True and ds.get("risk_level") == "HIGH":
        contradictions.append("fickling_likely_safe_but_disasm_high")
    # Contradiction 3: scanners disagree on safety
    if ms_clean != (fk.get("likely_safe") is True):
        if fk.get("likely_safe") is not None and "error" not in fk:
            contradictions.append("modelscan_vs_fickling_disagree")
    # Contradiction 4: parse error from one scanner but not the other
    if ds.get("parse_error") and not fk.get("error"):
        contradictions.append("disasm_parse_error_fickling_ok")
    if fk.get("error") and not ds.get("parse_error"):
        contradictions.append("fickling_error_disasm_ok")

    return {
        "path": str(path),
        "sha256": sha,
        "size": len(raw),
        "modelscan": ms,
        "fickling": fk,
        "disasm": {k: v for k, v in ds.items() if k not in ("opcodes_head", "opcodes_tail")},
        "contradictions": contradictions,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--paths", required=True, type=Path, help="Directory or single file")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--ext", nargs="+", default=[".pkl", ".joblib", ".dill", ".cloudpickle"])
    args = p.parse_args()

    files: list[Path] = []
    if args.paths.is_dir():
        for ext in args.ext:
            files.extend(args.paths.rglob(f"*{ext}"))
    elif args.paths.is_file():
        files = [args.paths]
    files = sorted(files)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as out:
        for i, path in enumerate(files, 1):
            try:
                rec = scan_one(path)
            except Exception as e:
                rec = {"path": str(path), "error": f"{type(e).__name__}: {e}"}
            out.write(json.dumps(rec) + "\n")
            if i % 50 == 0:
                print(f"  scanned {i}/{len(files)}", file=sys.stderr)
    print(f"scanned {len(files)} files -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
