# Methodology notes

A short writeup of how to use this harness honestly. The harness's output
is a verdict matrix; turning that matrix into a defensible claim about a
scanner requires discipline.

## Three-register truth on every claim

When publishing results from this harness, label each claim as:

- **OBSERVED** — directly produced by re-running the harness against a
  named corpus at named versions. Cite the JSONL.
- **INFERRED** — pattern derived from OBSERVED data, not directly verified.
  Example: "scanner X misses an entire class of bypass" is INFERRED from a
  finite corpus that exemplifies that class.
- **UNKNOWN** — cannot be determined from harness output. Maintainer plans,
  in-flight patches, internal priorities all belong here.

If you are tempted to write "scanner X is broken" or "scanner X misses
100% of class Y," stop and decompose the claim into OBSERVED/INFERRED/UNKNOWN
parts. Most such headlines collapse into OBSERVED-on-a-specific-corpus plus
INFERRED-without-warrant.

## What the contradictions mean (and don't)

`scan_matrix.py` emits a small set of named contradictions:

- `modelscan_clean_but_disasm_high` — `modelscan` reports no issues, but
  the disassembler saw `REDUCE` + `GLOBAL` / `STACK_GLOBAL` opcodes. This
  is the classic "denylist gap" pattern: the disassembler flags the
  *opcode shape* of a `__reduce__`-driven RCE primitive, while
  `modelscan`'s denylist of callable names doesn't recognize the
  specific module being invoked.
- `fickling_likely_safe_but_disasm_high` — same shape, against fickling's
  safety verdict.
- `modelscan_vs_fickling_disagree` — the two scanners produce different
  safety verdicts. By itself this is **not** evidence either one is wrong;
  it reflects architectural difference (denylist vs opcode/AST analysis).
- `disasm_parse_error_fickling_ok` / `fickling_error_disasm_ok` — one
  parser tripped, the other did not. Useful as a fuzzing signal; not a
  security claim on its own.

A contradiction is a **prompt to investigate**, not a finding. Treat it
the way you would treat a failed assertion in a fuzzer: surfaces a case,
doesn't tell you what it means.

## Scanner architectures (short reference)

The scanners this harness invokes have meaningfully different designs.
A "contradiction" between them is usually traceable to one of:

- **modelscan** (`modelscan.tools.picklescanner.PickleUnsafeOpScan`) uses
  a callable denylist keyed by `(module, attribute)`. It walks the opcode
  stream with `pickletools.genops` and checks `GLOBAL` / `STACK_GLOBAL`
  references against `settings["unsafe_globals"][severity]`. Misses are
  typically *denylist coverage gaps* (the called function is dangerous
  but not enumerated).
- **fickling** (`fickling.fickle.Pickled` + `check_safety`) uses opcode-pattern
  + AST symbolic analysis. It is intentionally paranoid about `REDUCE` with
  non-stdlib imports. False positives on edge cases are by design.
- **disassemble_pickle.py** (in this repo) flags opcode *shapes* without
  callable-name analysis: any `REDUCE` / `GLOBAL` / `STACK_GLOBAL` / `BUILD`
  raises the risk level. Coarser than the other two; useful as a
  "did this even reach the scanner" check.

These are not directly comparable on a "did it catch the bad file" basis
without explaining the architecture. If you publish a comparison, say so.

## When to use which corpus

- **Public disclosure artifacts** (e.g., `Lyutoon/PickleCloak`) are
  testing oracles. Pin a commit SHA. Treat them as already-public; do not
  re-publish their contents into your own repo without explicit license.
- **Internal red-team corpora**: keep private. Run this harness against
  them locally; do not push the JSONL.
- **Your own benign seed corpus**: useful for noise-floor measurement —
  if a scanner flags benign files, that is a false-positive signal worth
  measuring alongside.

## Reproducibility checklist for publishing results

If you publish a claim that "scanner X catches N/M files in corpus C":

1. Name the scanner version exactly (`modelscan==0.8.8`, not
   "the latest").
2. Name the corpus by repo URL + commit SHA. Not just the repo.
3. Name the harness version (this repo's commit SHA).
4. Include the raw JSONL output as an artifact or paste, not just the
   summary.
5. State the date of measurement. Scanner coverage changes.
6. Label every claim OBSERVED / INFERRED / UNKNOWN.

## What this harness deliberately does not do

- It does not produce novel malicious pickles or extend a public bypass
  catalog. The harness measures coverage on inputs you supply.
- It does not call any deserializer that would execute the model.
- It does not publish results automatically. Publication is the operator's
  decision, with the OBSERVED/INFERRED/UNKNOWN discipline above.
- It does not gate or score scanners. Two scanners disagreeing is a
  prompt for investigation, not a leaderboard signal.

## Limitations

- Pickle is a Turing-complete state machine; gadget chains have an
  effectively infinite surface. No denylist-style scanner can be complete;
  the right defensive posture is a positive allowlist or sandboxed
  loading, not "more entries on the deny list." A harness like this can
  identify gaps but cannot certify safety.
- The harness's own classification (`HIGH` risk if `REDUCE`/`GLOBAL` is
  present) is intentionally coarse. It is a noise-floor check, not a
  malware detector.
- Network-fetched corpora can move. Pin commit SHAs in your run, and
  re-fetch if the source rebases.
