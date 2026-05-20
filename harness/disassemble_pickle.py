#!/usr/bin/env python3
"""Disassemble a pickle/joblib/dill/cloudpickle file via pickletools.

NO EXECUTION. Walks the opcode stream with pickletools.genops, surfaces
high-risk opcode indicators that a scanner SHOULD catch:

  - GLOBAL / STACK_GLOBAL     -> imports an attribute by name; gadget root
  - REDUCE                    -> calls __reduce__ result; the classic RCE primitive
  - BUILD                     -> __setstate__ trigger
  - INST / OBJ                -> instantiate-class opcodes (proto 0/1, rare modern)
  - PERSID / BINPERSID        -> persistent_load callback; sometimes attacker-controlled
  - EXT1 / EXT2 / EXT4        -> extension opcodes; reference copyreg.dispatch_table
  - FRAME                     -> framing (proto 4+); not risky alone but worth tracking

Output: JSON with raw opcode list + risk summary + classification ("joblib", "raw_pickle", "compressed").

Joblib files start with the joblib magic header ("\\x80\\x05\\x95" pickle frame OR
"\\x00\\x00\\x00") wrapped sometimes in zlib/lz4/bz2. We strip the wrapper if we
recognize it so pickletools sees the actual stream.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import pickletools
import sys
import zlib
from pathlib import Path

HIGH_RISK_OPS = {"GLOBAL", "STACK_GLOBAL", "REDUCE", "BUILD", "INST", "OBJ",
                 "PERSID", "BINPERSID", "EXT1", "EXT2", "EXT4"}
NEUTRAL_TRACKED = {"FRAME", "PROTO", "MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT", "GET", "BINGET", "LONG_BINGET"}


def _try_unwrap(data: bytes) -> tuple[bytes, str]:
    """Return (raw_pickle_bytes, classification). Static unwrapping only."""
    # joblib uses pickle directly for small objects; for arrays, NumpyArrayWrapper
    # Modern joblib writes plain pickle stream (no compression by default).
    if len(data) >= 2 and data[:2] == b"\x78\x9c":  # zlib default
        try:
            return zlib.decompress(data), "zlib_wrapped"
        except Exception:
            pass
    # lz4, bz2 detection could go here; modelscan handles unwrapping anyway.
    return data, "raw_pickle"


def disassemble(path: Path) -> dict:
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    pickle_bytes, classification = _try_unwrap(raw)

    opcodes: list[dict] = []
    risk_counts: dict[str, int] = {}
    error = None
    try:
        for op, arg, pos in pickletools.genops(io.BytesIO(pickle_bytes)):
            name = op.name
            opcodes.append({"name": name, "arg": repr(arg)[:200] if arg is not None else None, "pos": pos})
            if name in HIGH_RISK_OPS:
                risk_counts[name] = risk_counts.get(name, 0) + 1
    except Exception as e:
        error = f"{type(e).__name__}: {e}"

    risk_level = "HIGH" if any(k in {"REDUCE", "GLOBAL", "STACK_GLOBAL", "BUILD"} for k in risk_counts) else (
        "MEDIUM" if risk_counts else "LOW"
    )

    return {
        "path": str(path),
        "sha256": sha256,
        "size": len(raw),
        "classification": classification,
        "opcode_count": len(opcodes),
        "risk_counts": risk_counts,
        "risk_level": risk_level,
        "parse_error": error,
        # Truncate opcode list in output to keep JSON usable; full list available via re-run.
        "opcodes_head": opcodes[:50],
        "opcodes_tail": opcodes[-20:] if len(opcodes) > 70 else [],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("paths", nargs="+", type=Path)
    p.add_argument("--out", type=Path, help="Write JSONL output to this file (one record per path)")
    args = p.parse_args()

    out_fh = args.out.open("w") if args.out else sys.stdout
    try:
        for path in args.paths:
            if not path.exists():
                rec = {"path": str(path), "error": "file_not_found"}
            else:
                rec = disassemble(path)
            out_fh.write(json.dumps(rec) + "\n")
    finally:
        if args.out:
            out_fh.close()


if __name__ == "__main__":
    main()
