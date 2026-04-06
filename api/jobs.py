from __future__ import annotations

import json
import threading
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from sbom_tool import enrich_vulns, export_navigator, map_attack, normalize_sbom, sbom_extract, vuln_scan

from .settings import JOBS_DIR
from .storage import ensure_data_dirs, read_json, write_json


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _job_path(job_id: str) -> Path:
    return JOBS_DIR / f"{job_id}.json"


def create_job(request: Dict[str, Any]) -> Dict[str, Any]:
    ensure_data_dirs()
    job_id = str(uuid.uuid4())
    now = _iso_now()
    job = {
        "job_id": job_id,
        "status": "queued",
        "stage": "queued",
        "message": "Waiting to start",
        "artifact_key": None,
        "artifact_dir": None,
        "created_at": now,
        "updated_at": now,
        "request": deepcopy(request),
        "outputs": {},
        "error": None,
    }
    write_json(_job_path(job_id), job)
    return job


def load_job(job_id: str) -> Dict[str, Any]:
    path = _job_path(job_id)
    if not path.exists():
        raise FileNotFoundError(f"Missing job {job_id}")
    data = read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid job file for {job_id}")
    return data


def update_job(job_id: str, **changes: Any) -> Dict[str, Any]:
    job = load_job(job_id)
    job.update(changes)
    job["updated_at"] = _iso_now()
    write_json(_job_path(job_id), job)
    return job


def list_jobs() -> list[Dict[str, Any]]:
    ensure_data_dirs()
    jobs: list[Dict[str, Any]] = []
    if not JOBS_DIR.exists():
        return jobs
    for path in sorted(JOBS_DIR.glob("*.json"), reverse=True):
        try:
            data = read_json(path)
        except Exception:
            continue
        if isinstance(data, dict):
            jobs.append(data)
    return jobs


def _copy_json(src: Path, dst: Path) -> None:
    data = read_json(src)
    write_json(dst, data)


def run_scan_job(job_id: str) -> None:
    request = load_job(job_id).get("request", {})
    image = str(request.get("image") or "").strip()
    image_tar_path = str(request.get("image_tar_path") or "").strip()
    tar_image_name = str(request.get("tar_image_name") or "").strip()
    platform = str(request.get("platform") or "linux/amd64").strip()
    short_len = int(request.get("short_len") or 16)
    skip_pull = bool(request.get("skip_pull") or False)

    try:
        if image_tar_path:
            update_job(job_id, status="running", stage="load_tar", message="Loading image tar")
            skip_pull = True

        update_job(job_id, status="running", stage="sbom_extract", message="Generating SBOMs")
        extract_result = sbom_extract.main(
            image=image,
            tar_path=image_tar_path or None,
            tar_image=tar_image_name or None,
            platform=platform,
            short_len=short_len,
            skip_pull=skip_pull,
        ) or {}

        artifact_key = str(extract_result.get("artifact_key") or "").strip()
        if not artifact_key:
            raise RuntimeError("SBOM extraction did not return an artifact key")

        artifact_dir = Path(__file__).resolve().parent.parent / "artifacts" / artifact_key

        update_job(job_id, artifact_key=artifact_key, artifact_dir=f"artifacts/{artifact_key}")

        update_job(job_id, stage="normalize", message="Normalizing packages")
        normalize_sbom.main(scan_dir=artifact_dir)

        update_job(job_id, stage="scan_vulns", message="Scanning vulnerabilities")
        vuln_scan.main(
            scan_dir=artifact_dir,
            mode="sbom",
            grype_image="anchore/grype:latest",
            by_cve=True,
            use_cache=True,
            force=True,
        )

        update_job(job_id, stage="enrich_vulns", message="Enriching vulnerabilities")
        enrich_vulns.main(scan_dir=artifact_dir)
        _copy_json(artifact_dir / "vulns.enriched.json", artifact_dir / "risk_scores.json")

        update_job(job_id, stage="map_attack", message="Mapping ATT&CK techniques")
        map_attack.main(scan_dir=artifact_dir)

        update_job(job_id, stage="export_navigator", message="Building Navigator layer")
        export_navigator.main(scan_dir=artifact_dir)

        outputs = {
            name: name
            for name in [
                "sbom.cdx.json",
                "sbom.spdx.json",
                "sbom.meta.json",
                "packages.json",
                "vulns.grype.json",
                "vulns.json",
                "vulns.enriched.json",
                "risk_scores.json",
                "attack_mapping.json",
                "attack_summary.json",
                "attack_navigator_layer.json",
            ]
            if (artifact_dir / name).exists()
        }
        update_job(job_id, status="completed", stage="done", message="Scan completed", outputs=outputs)
    except Exception as exc:
        update_job(job_id, status="failed", stage="error", message=str(exc), error=str(exc))
    finally:
        if image_tar_path:
            tar_file = Path(image_tar_path)
            try:
                if tar_file.exists():
                    tar_file.unlink()
            except Exception:
                pass


def start_scan_job(request: Dict[str, Any]) -> Dict[str, Any]:
    job = create_job(request)
    thread = threading.Thread(target=run_scan_job, args=(job["job_id"],), daemon=True)
    thread.start()
    return load_job(job["job_id"])
