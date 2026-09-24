# DICOM-DeID

**DICOM medical image de-identification tool** — CLI + TUI + REST API, a two-step pipeline: **audit → de-identify**.

> Remove patient health information (PHI) from DICOM medical images before any external
> sharing — with dual de-identification policies, length-preserving UID pseudonymization
> and Siemens CSA private-tag handling.

**v1.0.1 · Python ≥ 3.11 · Windows / macOS / Linux**

---

## Why

Medical images leaving the hospital (research collaboration, dataset release, model training)
must have patient identifiers removed. Manual tag editing easily misses things: vendor UIDs
hiding in private blocks, device serial numbers inside file names, leftovers in sidecar XML.
This tool scans first, de-identifies second — so nothing walks out unnoticed.

## Two core features

| Feature | Description |
|---|---|
| **Audit** | Read-only scan: PHI tags, vendor UIDs in private blocks, file-name leaks, cross-file consistency |
| **De-identify** | Produce a de-identified copy (source stays read-only), dual policies, length-preserving UID remapping |

### Two de-identification policies

| Policy | Clears | Keeps |
|---|---|---|
| **A · Conservative** `-p a` | Name / ID / birth date / accession number / institution / device serial / physician names / workflow identifiers (45 tags) | Sex / age / size / weight / date-time / device model / series description |
| **B · Aggressive** `-p b` | All identifying tags + demographics and date-times | Only imaging-intrinsic parameters (device model, series description) |

> ⚠️ Policy A keeps sex + age + exam date, which may re-identify a person in a small cohort.
> **Use `-p b` for publicly released datasets.** De-identified ≠ free to distribute.

## Features

- 🔍 **Extension-agnostic detection**: `.dcm` / `.dicom` / no extension all recognized
  (magic-number sniffing + trial parsing fallback)
- 🗜 **Lossless compressed DICOM supported out of the box**: RLE / JPEG2000 / JPEG-LS —
  pixel bytes pass through untouched, no codec plugins required
- 🔢 **Length-preserving UID remapping**: fixed root `1.2.826.0.1.3680043.10.9999.` + SHA256-derived digits;
  SOPClassUID / TransferSyntaxUID are never modified; `uid_map.json` is written for traceability
- 🚢 **Siemens CSA private blocks**: substring scan & replacement in `(0029,1010)/(0029,1020)`,
  length unchanged so binary structure stays intact
- 🛡 **Safety guardrails**: source directory is read-only; output dir = source dir is rejected;
  non-interactive runs abort unless `--yes` is given
- 📄 **Sidecar XML handled automatically**: same-directory `.xml` files get PHI tags cleared by tag number

## Installation

```bash
git clone https://github.com/wanyiliudehua/dicom-deid.git
cd dicom-deid
python -m venv .venv

# Online install
.venv/Scripts/python -m pip install ".[api]"     # drop [api] for CLI/TUI only

# Offline install (air-gapped machine, needs the wheelhouse directory)
.venv/Scripts/python -m pip install --no-index --find-links wheelhouse "dicom-deid[api]"
```

> On Windows, adjust the `.venv/Scripts/` prefix to your actual path.
> The `serve` subcommand requires the optional `[api]` extra.

## Quick start

### CLI

```bash
# No arguments = interactive wizard (choose feature → policy → paths)
python -m dicom_deid

# ① Audit (read-only)
python -m dicom_deid audit <DICOM-dir> [--json report.json] [-q]

# ② De-identify (policy required; try a dry run first)
python -m dicom_deid deid <src-dir> <out-dir> -p a --dry-run
python -m dicom_deid deid <src-dir> <out-dir> -p b --yes
```

**Exit codes** (for scripting): `0` success/clean · `1` finished with findings · `2` error or guardrail abort.

### TUI

```bash
python -m dicom_deid tui        # or: python run_tui.py
# 1/2 switch audit/de-identify, a/b pick policy, Enter to run
```

### REST API

```bash
python -m dicom_deid serve --port 8080
```

```bash
curl http://127.0.0.1:8080/health
curl -X POST http://127.0.0.1:8080/audit -H "Content-Type: application/json" -d '{"dir":"D:/DICOM/src"}'
curl -X POST http://127.0.0.1:8080/deid  -H "Content-Type: application/json" \
     -d '{"src_dir":"D:/DICOM/src","profile":"a","rename_files":true}'
```

`POST /deid/upload` accepts direct file uploads. Interactive docs: `/docs` once the server is up.

### Python API

```python
from pathlib import Path
from dicom_deid.policy import Policy, Profile
from dicom_deid.deid import run as deid_run

policy = Policy(profile=Profile.Conservative, rename_files=True)
summary = deid_run(Path("src"), Path("out"), policy)
print(summary.out_files, summary.tags_cleared)
```

## Output layout

```
deid_output/
├── <new-SOPInstanceUID>.dcm   # de-identified, renamed file
├── uid_map.json               # old UID → new UID mapping (for audit trail)
└── <new-StudyInstanceUID>.xml # de-identified sidecar file (if any)
```

## Scope

**DICOM originals only.** Bare images (`.jp2` / `.png` / `.jpg`) carry no metadata to strip;
text burned into pixels (e.g. screenshots of reports) cannot be removed by metadata
de-identification — mask those at the pixel level instead.
Non-DICOM files are flagged and skipped, never modified.

## Project structure

```
dicom_deid/
├── policy.py    # A/B policy definitions    ├── audit.py    # PHI audit
├── uid_map.py   # length-preserving remap   ├── deid.py     # de-identification core
├── csa.py       # Siemens CSA handling      ├── cli.py      # CLI entry
├── api.py       # FastAPI REST              └── __main__.py # python -m dicom_deid
```

## Notes

1. The source directory is read-only; output goes to a copy. De-identification is
   **irreversible** — back up originals first.
2. An output directory that already contains `.dcm` files is rejected by default
   (use `--force`), to avoid mixing old and new files.
3. Re-auditing de-identified output should report **no PHI found** / exit code 0 —
   that self-check is the recommended final step.
