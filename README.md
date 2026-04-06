# riskybisky

**riskybisky** is an SBOM-based container security triage platform for container images, combining a **CLI pipeline** and **web dashboard** to move from raw scan data to explainable, prioritised remediation.

It takes a container image reference such as `nginx:1.27-alpine` or a pinned digest, pulls or loads the image, generates SBOMs, scans for vulnerabilities, enriches CVEs using public intelligence sources, maps them to likely **MITRE ATT&CK** techniques, computes a **fix-first risk score**, and presents the results through structured outputs and a dashboard.

The project is built around **open-source tools**, **public/open datasets and APIs**, **reproducible scans**, and **graceful fallback behaviour** so the core pipeline still works even when optional enrichments are temporarily unavailable.

---

## Features

### Core pipeline
- Accepts a container image reference or digest
- Pulls or loads the target image
- Resolves the image to a reproducible digest where possible
- Generates SBOMs in:
  - **CycloneDX JSON**
  - **SPDX JSON**
- Normalises SBOM contents into an internal package inventory
- Scans the image/SBOM for known vulnerabilities
- Produces a structured dataset of CVEs linked to affected packages and versions

### Enrichment
- Enriches CVEs using a public **CVE/CVSS** source
- Adds:
  - severity
  - description
  - CWE
  - references
  - published / modified dates
  - other CVSS-related metadata
- Integrates **EPSS** exploit-likelihood scores from a public feed/API
- Integrates **KEV** exploited-in-the-wild status from a public catalogue

### ATT&CK mapping
- Uses official **MITRE ATT&CK STIX** technique definitions
- Maps CVEs to likely ATT&CK techniques using a configurable mapping engine
- Supports explainable mapping logic, with the default approach based on similarity-driven retrieval
- Supports optional rule-based or model-based mapping extensions where applicable

### Risk prioritisation
- Computes a **fix-first** risk score per CVE
- Computes a risk view per ATT&CK technique
- Combines:
  - CVSS severity
  - EPSS exploit likelihood
  - KEV presence
  - SBOM/package context
  - dependency importance or related image context where available

### Outputs and UX
- Generates prioritised remediation guidance
- Highlights what to patch first and which packages contribute the most risk
- Produces ATT&CK-focused summaries showing top attacker behaviours enabled by current vulnerabilities
- Exposes results through a **web dashboard** with sorting, filtering, and drill-down views
- Supports export features such as:
  - JSON output
  - human-readable HTML/PDF report
  - optional ATT&CK Navigator layer file

---

## Why this project exists

Most container scanners stop at a flat list of vulnerabilities. That is useful, but it does not answer the questions that matter most in practice:

- Which issues should be fixed first?
- Which packages are introducing the most risk?
- Which vulnerabilities are more likely to be exploited?
- Which attacker behaviours are realistically enabled by the image’s current weaknesses?
- How can scanner output be converted into something explainable, dashboard-friendly, and actionable?

**riskybisky** is built to bridge that gap by connecting:

**container image → SBOM → CVEs → public enrichment → ATT&CK mapping → risk prioritisation → remediation guidance**

---

## Architecture overview

```text
Container Image
   ↓
Pull / Load / Resolve Digest
   ↓
SBOM Extraction (CycloneDX / SPDX)
   ↓
SBOM Normalisation
   ↓
Vulnerability Scan
   ↓
Structured CVE Dataset
   ↓
Public Enrichment (CVSS / EPSS / KEV)
   ↓
MITRE ATT&CK Mapping
   ↓
Fix-First Risk Scoring
   ↓
Remediation Prioritisation
   ↓
Dashboard / Reports / Navigator Export
```

---

## Repository structure

```text
riskybisky/
├── README.md
├── DEVDIARY.md
├── artifacts/
│   └── sha256_<short>/
│       ├── sbom.cdx.json
│       ├── sbom.spdx.json
│       ├── sbom.meta.json
│       ├── packages.json
│       ├── vulns.grype.json
│       ├── vulns.json
│       ├── attack_mapping.json
│       ├── enrichment.json
│       ├── report.html
│       ├── report.pdf
│       └── navigator.layer.json
├── digests/
│   ├── index.json
│   └── sha256_<short>.json
├── sbom_tool/
│   ├── __init__.py
│   ├── sbom_extract.py
│   ├── normalize_sbom.py
│   ├── vuln_scan.py
│   ├── enrich.py
│   ├── map_attack.py
│   ├── export_navigator.py
│   └── attack_common.py
└── web/
    └── ...
```

---

## How it works

### 1. Input image
The user provides a container image reference such as:

```bash
nginx:1.27-alpine
```

or a digest-pinned reference for reproducibility.

### 2. SBOM generation
The pipeline generates SBOMs in **CycloneDX JSON** and **SPDX JSON** using open-source tooling.

### 3. SBOM normalisation
SBOM contents are normalised into a consistent internal package inventory so downstream stages can work with a predictable schema.

### 4. Vulnerability scanning
The image or SBOM is scanned using an open-source vulnerability scanner, producing CVE-level findings linked to affected packages and versions.

### 5. Public enrichment
Each CVE is enriched using public/open sources:
- CVSS and CVE metadata from a public CVE database/API
- EPSS from a public EPSS feed/API
- KEV status from a public exploited-vulnerability catalogue

### 6. ATT&CK mapping
The pipeline maps vulnerabilities to likely **MITRE ATT&CK** techniques using official ATT&CK STIX data and explainable mapping logic.

### 7. Risk scoring
A **fix-first** score is computed to prioritise remediation using severity, exploit likelihood, real-world exploitation evidence, and package/image context.

### 8. Reporting and dashboard
Results are exposed through:
- structured JSON outputs
- a human-readable HTML/PDF report
- a dashboard with filters, sorting, and drill-down views
- an optional ATT&CK Navigator layer export

---

## Tooling and data sources

### Open-source tools
- **Docker** for image access/execution
- **Syft** for SBOM generation
- **Grype** for vulnerability scanning
- **Skopeo** for digest/image reference handling
- **Python** for orchestration, enrichment, mapping, scoring, and exports

### Public/open data sources
- Public **CVE/CVSS** database/API
- Public **EPSS** feed/API
- Public **KEV** catalogue
- Official **MITRE ATT&CK STIX** dataset

---

## Key outputs

### `sbom.cdx.json`
CycloneDX SBOM for the image.

### `sbom.spdx.json`
SPDX JSON SBOM for the image.

### `sbom.meta.json`
Metadata about the scan and image reference.

### `packages.json`
Normalised package inventory derived from the SBOM.

### `vulns.grype.json`
Raw scanner output.

### `vulns.json`
Normalised vulnerability dataset.

### `enrichment.json`
Public enrichment data joined onto CVEs.

### `attack_mapping.json`
Likely ATT&CK mappings and related evidence.

### `report.html` / `report.pdf`
Human-readable summary report.

### `navigator.layer.json`
Optional ATT&CK Navigator layer export.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/y-kal/riskybisky.git
cd riskybisky
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

If you maintain a `requirements.txt` or `pyproject.toml`, use that. Otherwise, install the required Python packages for the CLI pipeline.

Example:

```bash
pip install -r requirements.txt
```

If you are still managing packages manually, install the project dependencies you use for the CLI and reporting pipeline.

### 4. Verify external tooling

```bash
docker --version
skopeo --version
docker run --rm anchore/syft:latest version
docker run --rm anchore/grype:latest version
```

---

## Example workflow

Run commands from the project root.

### Step 1: Generate SBOMs

```bash
python -m sbom_tool.sbom_extract -i nginx:1.27-alpine --platform linux/amd64
```

### Step 2: Normalise the SBOM

```bash
python -m sbom_tool.normalize_sbom --scan-dir artifacts/<artifact_key>
```

### Step 3: Run vulnerability scanning

```bash
python -m sbom_tool.vuln_scan --scan-dir artifacts/<artifact_key>
```

### Step 4: Enrich vulnerabilities

```bash
python -m sbom_tool.enrich --scan-dir artifacts/<artifact_key>
```

### Step 5: Map to ATT&CK

```bash
python -m sbom_tool.map_attack --scan-dir artifacts/<artifact_key>
```

### Step 6: Export Navigator layer

```bash
python -m sbom_tool.export_navigator --scan-dir artifacts/<artifact_key>
```

> Depending on your current implementation, command names, flags, or module names may vary slightly. Adjust them to match the exact CLI entry points in the repo.

---

## Dashboard capabilities

The web dashboard is intended to help users inspect and prioritise findings instead of just reading raw JSON.

It supports views such as:

- artifact/image selection
- package inventory browsing
- vulnerability listing
- ATT&CK technique listing
- prioritised remediation ranking

Typical UI capabilities include:

- sorting by:
  - severity
  - EPSS
  - KEV
  - package
  - technique
  - confidence
- filtering by:
  - severity
  - package
  - exploited status
  - technique
- drill-down:
  - **CVE → mapped techniques + evidence**
  - **Technique → contributing CVEs/components**

---

## Design goals

- **Open-source only**
- **Public/open datasets only**
- **Artifact-first pipeline**
- **Explainable scoring and mapping**
- **Reproducible scans**
- **Graceful fallback when optional enrichments are unavailable**
- **Structured outputs for dashboard and reporting**
- **Security triage over raw scanner dumping**

---

## Resilience and caching

The project is designed so the core pipeline can still complete even if optional enrichments are temporarily unavailable.

This includes support for:
- cached external lookups
- retaining raw and normalised data
- reproducible scans via pinned tags or digests
- keeping enrichment and mapping stages modular rather than tightly coupled

---

## Use cases

**riskybisky** can be used for:

- container security triage
- SBOM-based vulnerability analysis
- ATT&CK-oriented threat framing
- prioritised patch planning
- explainable security reporting
- security dashboards and demos
- academic or research projects involving container security analytics

---

## Roadmap direction

While the major pipeline stages are implemented, future work can still improve:

- mapping accuracy and explainability
- better remediation suggestions / fixed-version guidance
- stronger confidence scoring
- historical scan comparison
- multi-image comparison
- richer dashboard analytics
- performance tuning and caching improvements
- offline-friendly operation where practical

---

## Example project summary

**riskybisky** is a cybersecurity tool that combines a CLI pipeline and web dashboard to analyse container images using SBOMs, vulnerability scanning, public CVE intelligence, EPSS, KEV, and MITRE ATT&CK mappings. It transforms raw scan output into an explainable, prioritised remediation workflow by computing fix-first risk scores, surfacing top affected packages and techniques, and exporting structured and human-readable results.

---

## Authors

**Yash Kalbhor**  

GitHub: [y-kal](https://github.com/y-kal)

**Jash Kanani**

GitHub: [jash2805](https://github.com/jash2805)

---

