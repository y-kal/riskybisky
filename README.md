# riskybisky

## Current status

The project now has two layers:

- a Python API that exposes the existing file-based artifact pipeline
- a Next.js portal that consumes the API for scan submission and artifact browsing

The implementation is still in progress, but the first vertical slice is in place.

## Python API

Run the API from the project root:

```bash
uvicorn api.main:app --reload --port 8000
```

The API currently provides:

- `GET /health`
- `GET /api/artifacts`
- `GET /api/artifacts/{artifact_key}`
- `GET /api/artifacts/{artifact_key}/files/{filename}`
- `GET /api/jobs`
- `GET /api/jobs/{job_id}`
- `POST /api/scans`

## Next.js portal

The frontend lives in `web/` and is configured to call the Python API at `http://localhost:8000` by default.

Start it from the `web/` directory:

```bash
cd web
npm install
npm run dev
```

If the API runs on a different host, set `NEXT_PUBLIC_API_BASE_URL` before starting Next.js.

## Existing pipeline commands

The original CLI pipeline still works and remains the source of truth for artifact generation:

```bash
python -m sbom_tool.sbom_extract -i nginx:1.27-alpine --platform linux/amd64
python -m sbom_tool.normalize_sbom --scan-dir artifacts/<artifact_key>
python -m sbom_tool.vuln_scan --scan-dir artifacts/<artifact_key>
python -m sbom_tool.enrich_vulns --scan-dir artifacts/<artifact_key>
python -m sbom_tool.map_attack --scan-dir artifacts/<artifact_key>
python -m sbom_tool.export_navigator --scan-dir artifacts/<artifact_key>
```

## Generated outputs

The API and portal read from the file-based artifact folders under `artifacts/<artifact_key>/` and the digest registry under `digests/`.
