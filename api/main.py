from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .jobs import list_jobs, load_job, start_scan_job
from .schemas import ArtifactDetailResponse, ArtifactListResponse, ArtifactSummary, JobResponse, ScanRequest
from .storage import artifact_files, artifact_summary, ensure_data_dirs, list_artifact_keys, load_artifact_bundle, resolve_artifact_file


app = FastAPI(title="riskybisky API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    ensure_data_dirs()


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok"}


@app.get("/api/artifacts", response_model=ArtifactListResponse)
def get_artifacts() -> ArtifactListResponse:
    items = [ArtifactSummary(**artifact_summary(key)) for key in list_artifact_keys()]
    return ArtifactListResponse(items=items)


@app.get("/api/artifacts/{artifact_key}", response_model=ArtifactDetailResponse)
def get_artifact(artifact_key: str) -> ArtifactDetailResponse:
    if artifact_key not in list_artifact_keys():
        raise HTTPException(status_code=404, detail="Artifact not found")
    bundle = load_artifact_bundle(artifact_key)
    return ArtifactDetailResponse(
        summary=ArtifactSummary(**bundle["summary"]),
        meta=bundle["meta"],
        packages=bundle["packages"],
        vulns=bundle["vulns"],
        enriched_vulns=bundle["enriched_vulns"],
        attack_mapping=bundle["attack_mapping"],
        attack_summary=bundle["attack_summary"],
        navigator_layer=bundle["navigator_layer"],
    )


@app.get("/api/artifacts/{artifact_key}/files/{filename}")
def download_artifact_file(artifact_key: str, filename: str) -> FileResponse:
    try:
        file_path = resolve_artifact_file(artifact_key, filename)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(file_path, filename=file_path.name, media_type="application/json")


@app.get("/api/jobs", response_model=List[JobResponse])
def get_all_jobs() -> List[JobResponse]:
    return [JobResponse(**job) for job in list_jobs()]


@app.get("/api/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: str) -> JobResponse:
    try:
        return JobResponse(**load_job(job_id))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/scans", response_model=JobResponse)
def create_scan(request: ScanRequest) -> JobResponse:
    return JobResponse(**start_scan_job(request.model_dump()))


@app.get("/api/artifacts/{artifact_key}/package-count")
def package_count(artifact_key: str) -> Dict[str, Any]:
    if artifact_key not in list_artifact_keys():
        raise HTTPException(status_code=404, detail="Artifact not found")
    bundle = load_artifact_bundle(artifact_key)
    packages = bundle.get("packages", {}).get("packages", []) if isinstance(bundle.get("packages"), dict) else []
    return {"artifact_key": artifact_key, "count": len(packages)}


def create_app() -> FastAPI:
    return app

