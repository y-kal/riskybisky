> Developer diary for the project.  
> Each entry captures what was planned, what was implemented, folder structure, how to run the current pipeline, design decisions, notes, and TODOs.

---

## Day 1 — SBOM Extraction + Normalisation Pipeline (Working End-to-End)

### Goal (Checklist)
- [x] Decide SBOM formats to generate (CycloneDX + SPDX)
- [x] Implement SBOM extraction from a container image reference (tag or digest)
- [x] Store scan outputs in a digest-keyed artifacts folder (cache-friendly)
- [x] Generate scan metadata (`sbom.meta.json`) for provenance
- [x] Implement SBOM normalisation into an internal package list (`packages.json`)
- [x] Add a digest registry to keep full digest traceability even with shortened artifact keys

---

### What was implemented
- **SBOM Extractor** (`sbom_tool/sbom_extract.py`)
  - Accepts an image ref (e.g., `nginx:1.27-alpine` or `nginx@sha256:...`)
  - Resolves tag → digest (reproducibility)
  - Pulls the image deterministically (optionally pinned by platform)
  - Generates SBOM outputs using **Syft** (via Docker):
    - CycloneDX JSON (`sbom.cdx.json`)
    - SPDX JSON (`sbom.spdx.json`)
  - Writes a metadata record (`sbom.meta.json`)
  - Uses caching: if outputs exist, reuse instead of regenerating
  - Updates digest registry (`digests/`) so shortened keys still map back to full digests

- **SBOM Normaliser** (`sbom_tool/normalize_sbom.py`)
  - Reads `sbom.cdx.json`
  - Produces `packages.json` in a consistent internal schema:
    - stable package id (prefer `purl`, fallback to `type:name@version`)
    - name, version, type, purl, cpe
    - licenses, supplier, hashes
    - dependencies + estimated dependency depth

---

## Folder structure (current)
```text
riskybisky/riskybisky
├── README.md
├── DEV_DIARY.md
├── artifacts
│   └── sha256_<...>
│       ├── packages.json
│       ├── sbom.cdx.json
│       ├── sbom.meta.json
│       └── sbom.spdx.json
├── digests
│   ├── index.json
│   └── sha256_<short>.json
└── sbom_tool
    ├── __init__.py
    ├── sbom_extract.py
    └── normalize_sbom.py


### Notes (repo hygiene + behaviour)

* `__pycache__/` and `*.pyc` files are generated automatically by Python and are not part of the implementation.
* `artifacts/` contains generated scan outputs; it should typically be gitignored later.
* Tags like `nginx:1.27-alpine` are convenient for testing, but tags can change over time. The pipeline resolves tags to a digest (`sha256:...`) for reproducible scans.
* CycloneDX and SPDX often differ in structure; the normaliser currently uses CycloneDX because it provides a clean `components` + `dependencies` model.

---

## One-line explanation for every file/folder

* `README.md` — main project documentation (will be finalised at the end).
* `DEV_DIARY.md` — day-wise implementation log + run instructions + decisions + TODOs.
* `artifacts/` — generated outputs for each scanned image (cached by artifact key).
* `artifacts/sha256_<...>/` — one scan “bundle” (SBOMs + metadata + normalised package list) for a specific image digest.
* `artifacts/.../sbom.cdx.json` — CycloneDX SBOM JSON generated from the image.
* `artifacts/.../sbom.spdx.json` — SPDX SBOM JSON generated from the image.
* `artifacts/.../sbom.meta.json` — provenance (input ref, resolved digest, platform, tool versions, artifact key, timestamps).
* `artifacts/.../packages.json` — internal normalised package list used by later stages (CVE scan join, scoring, dashboard).
* `digests/` — digest registry to map shortened artifact keys back to full digests.
* `digests/index.json` — global mapping of all known `artifact_key → full_digest` records.
* `digests/sha256_<short>.json` — per-scan digest record (same mapping as index entry, but isolated per key).
* `sbom_tool/` — Python tooling/scripts for SBOM extraction and normalisation.
* `sbom_tool/__init__.py` — marks `sbom_tool` as a Python package (enables `python -m sbom_tool...` reliably).
* `sbom_tool/sbom_extract.py` — CLI script: image ref → SBOM outputs + metadata + digest registry update.
* `sbom_tool/normalize_sbom.py` — CLI script: SBOM → normalised `packages.json`.

---

## How to run (current pipeline)

> Run commands from the project root: `riskybisky/riskybisky`

### Prerequisites

* Docker installed and running
* `skopeo` installed (for tag → digest resolution)
* Python venv created with `typer` + `rich`

### 0) Activate environment

```bash
cd ~/riskybisky/riskybisky
source .venv/bin/activate
```

### 1) SBOM extraction (CycloneDX + SPDX)

Example using a public test image:

```bash
python -m sbom_tool.sbom_extract -i nginx:1.27-alpine --platform linux/amd64
```

After this, a folder will exist inside `artifacts/` containing:

* `sbom.cdx.json`
* `sbom.spdx.json`
* `sbom.meta.json`

### 2) Normalise SBOM → internal package list (`packages.json`)

Pick the scan directory inside `artifacts/` and run:

```bash
python -m sbom_tool.normalize_sbom --scan-dir artifacts/<artifact_key>
```

Example:

```bash
python -m sbom_tool.normalize_sbom --scan-dir artifacts/sha256_65645c7bb6a06618
```

---

## Commands used during development (reference)

```bash
# Check Docker
docker --version
docker run --rm hello-world

# Pull/verify syft (runs inside Docker in this project)
docker pull anchore/syft:latest
docker run --rm anchore/syft:latest version

# Inspect digest (registry)
skopeo inspect docker://nginx:1.27-alpine
```

---

## Design decisions

* **Digest-based reproducibility**: resolve tags to `sha256:...` so scans are repeatable and cacheable.
* **Artifact bundling**: store SBOMs + metadata + packages list together per scan in `artifacts/<artifact_key>/`.
* **CycloneDX-first normalisation**: CycloneDX’s dependency representation is straightforward for depth estimation.
* **Digest registry (`digests/`)**:

  * `index.json` makes it easy to list/search all scans.
  * per-key JSON files make it easy to load one mapping without parsing a large index.
* **Single-command CLIs**: avoids the “unexpected extra argument” error caused by Typer subcommand vs single-command mode mismatch.

---

## Known issues / TODO

* [ ] **Local-only images (not pushed to a registry)**: if `skopeo inspect` fails, extractor should fall back to `docker image inspect` to derive a stable local image ID.
* [ ] **Richer file locations**: CycloneDX/SPDX may not include reliable file paths; optionally add Syft native JSON output later and merge locations into `packages.json`.
* [ ] **Improve ecosystem/type mapping**: CycloneDX component `type` can be generic; better derive ecosystem from `purl` when available.
* [ ] **Standardise ignoring generated files**: add `.gitignore` entries for `artifacts/`, `__pycache__/`, `.venv/` (when repo is ready for git hygiene).