# model-scanner-regression-harness

Reproducible coverage measurement of static ML model-format scanners against
publicly-disclosed bypass classes.

## What this is

A small Python harness that runs several open-source pickle/joblib scanners
(currently `modelscan`, `fickling`, and a `pickletools`-based disassembler)
against a directory of model files, normalizes the verdicts, and emits one
JSON object per file with cross-scanner agreement / contradictions.

The harness performs **static analysis only**. It does not call `pickle.load`,
`joblib.load`, `torch.load`, or any other deserializer that would execute
the model. It walks the pickle opcode stream with `pickletools.genops` and
invokes scanners via their published Python or CLI surfaces.

It is intentionally narrow:

- Scope: pickle-stream and pickle-wrapped formats (`.pkl`, `.joblib`,
  `.dill`, `.cloudpickle`). Other model formats (TF SavedModel, H5, ONNX,
  GGUF) are out of scope.
- Tooling: no exploit-generation. The harness does not write malicious
  pickles. It runs scanners against an input directory you supply.
- Output: JSONL with per-scanner verdicts plus a small set of named
  contradictions (e.g. `modelscan_clean_but_disasm_high`).

## Why it exists

Several scanner-bypass classes have been disclosed publicly — most
recently the catalog accompanying *Hide and Seek* (Liu et al., USENIX
Security '26, arXiv:2508.19774; GHSA-9gvj-pp9x-gcfr). Disclosures are
typically credited and tracked, but the gap between *"a vendor acknowledged
the class"* and *"the open-source CLI that ML platforms use as a CI gate
has been patched against the disclosed catalog"* is not always visible from
release notes. This harness is small infrastructure for measuring that gap
reproducibly on whatever public corpus you point it at.

It is not a benchmark or a leaderboard. It is a measurement tool.

## What it tests, today

| Scanner | Version pinned in `requirements.txt` | Surface used |
|---|---|---|
| `modelscan` | 0.8.8 | CLI subprocess, JSON output |
| `fickling` | 0.1.11 | Python API (`fickling.fickle.Pickled.load` + `check_safety`) |
| pickletools disassembler | stdlib | Custom opcode-pattern flagger (see `harness/disassemble_pickle.py`) |

The pinned versions reflect the latest public releases as of the harness's
last update. Bump them when you re-run.

## How to run

```bash
git clone https://github.com/palios-taey/model-scanner-regression-harness.git
cd model-scanner-regression-harness
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Fetch a public PoC corpus to scan against — for example, the
# Hide-and-Seek artifact (commit-SHA pinned for reproducibility).
bash scripts/fetch_picklecloak.sh

# Run the matrix
python -m harness.scan_matrix \
    --paths corpora/PickleCloak/gadget/aeg/container/pickles \
    --out reports/picklecloak_scan.jsonl

# Summarize
python -m harness.compare_scanners --input reports/picklecloak_scan.jsonl --out reports/picklecloak_candidates.json
```

## What the output means

Each line of the JSONL is a single file's record:

```json
{
  "path": "corpora/.../exp_0.pkl",
  "sha256": "...",
  "size": 233,
  "modelscan": {"exit_code": 0, "issues": [], "summary": {...}, "errors": []},
  "fickling":  {"op_count": 14, "severity": "OVERTLY_MALICIOUS", ...},
  "disasm":    {"classification": "raw_pickle", "risk_level": "HIGH", "risk_counts": {"GLOBAL": 5, "REDUCE": 5}},
  "contradictions": ["modelscan_clean_but_disasm_high",
                     "modelscan_vs_fickling_disagree"]
}
```

The `contradictions` field is the value-add: it surfaces files where two
scanners disagreed about safety, so you can investigate the architectural
difference rather than just count misses.

## Three-register reading

If you publish results from this harness, please be careful about what is
**observed** (the JSONL output is reproducible per pinned version), what is
**inferred** (e.g., "scanner X misses this class") and what is **unknown**
(e.g., maintainer roadmaps, in-flight fixes). The harness produces verdicts;
it does not predict intent.

See `METHODOLOGY.md` for a longer treatment.

## What this is NOT

- Not a vulnerability disclosure tool. If you find a scanner bypass that is
  not already publicly disclosed, follow the relevant vendor's `SECURITY.md`
  before publishing.
- Not an exploit generator. The harness operates on corpora you supply; it
  does not produce malicious pickles.
- Not a one-shot benchmark. Scanner coverage shifts over time. Pin versions
  in your re-runs.

## License

Apache 2.0 — see `LICENSE`.

The harness scripts are original work. The `requirements.txt`-listed
scanners retain their own licenses. Public PoC corpora (e.g., PickleCloak)
are fetched at runtime under their authors' chosen visibility; this
repository does not vendor them.

## Acknowledgements

The bypass classes this harness was built to measure were disclosed by
Liu et al. (arXiv:2508.19774) and credited via GHSA-9gvj-pp9x-gcfr. We
treat their published artifact as a public testing oracle; we do not
extend or generalize their findings.
