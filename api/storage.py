from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .settings import ARTIFACTS_DIR, DIGESTS_DIR, JOBS_DIR, UPLOADS_DIR


EXPECTED_ARTIFACT_FILES = [
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


def ensure_data_dirs() -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    DIGESTS_DIR.mkdir(parents=True, exist_ok=True)
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def safe_load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    data = read_json(path)
    return data if isinstance(data, dict) else {}


def artifact_dir(artifact_key: str) -> Path:
    return ARTIFACTS_DIR / artifact_key


def artifact_files(artifact_key: str) -> List[str]:
    path = artifact_dir(artifact_key)
    if not path.exists():
        return []
    return sorted(item.name for item in path.iterdir() if item.is_file())


def list_artifact_keys() -> List[str]:
    ensure_data_dirs()
    if not ARTIFACTS_DIR.exists():
        return []
    return sorted(item.name for item in ARTIFACTS_DIR.iterdir() if item.is_dir())


def _artifact_counts(scan_dir: Path) -> Dict[str, Any]:
    counts: Dict[str, Any] = {}
    packages = safe_load_json(scan_dir / "packages.json")
    vulns = safe_load_json(scan_dir / "vulns.json")
    enriched = safe_load_json(scan_dir / "vulns.enriched.json")
    attack = safe_load_json(scan_dir / "attack_summary.json")

    if isinstance(packages.get("packages"), list):
        counts["packages"] = len(packages["packages"])
    if isinstance(vulns.get("vulnerabilities"), list):
        counts["vulnerabilities"] = len(vulns["vulnerabilities"])
    if isinstance(enriched.get("vulnerabilities"), list):
        counts["enriched_vulnerabilities"] = len(enriched["vulnerabilities"])
    if isinstance(attack.get("techniques"), list):
        counts["techniques"] = len(attack["techniques"])
    if isinstance(vulns.get("counts"), dict):
        counts["severity"] = vulns["counts"].get("by_severity", {})
    if isinstance(attack.get("counts"), dict):
        counts["attack"] = attack["counts"]
    return counts


def artifact_summary(artifact_key: str) -> Dict[str, Any]:
    scan_dir = artifact_dir(artifact_key)
    meta = safe_load_json(scan_dir / "sbom.meta.json")
    return {
        "artifact_key": artifact_key,
        "artifact_dir": f"artifacts/{artifact_key}",
        "image_input": meta.get("image_input"),
        "image_resolved": meta.get("image_resolved"),
        "digest": meta.get("digest"),
        "platform": meta.get("platform"),
        "generated_at": meta.get("generated_at"),
        "files": artifact_files(artifact_key),
        "counts": _artifact_counts(scan_dir),
    }


def load_artifact_bundle(artifact_key: str) -> Dict[str, Any]:
    scan_dir = artifact_dir(artifact_key)
    return {
        "summary": artifact_summary(artifact_key),
        "meta": safe_load_json(scan_dir / "sbom.meta.json"),
        "packages": safe_load_json(scan_dir / "packages.json"),
        "vulns": safe_load_json(scan_dir / "vulns.json"),
        "enriched_vulns": safe_load_json(scan_dir / "vulns.enriched.json"),
        "attack_mapping": safe_load_json(scan_dir / "attack_mapping.json"),
        "attack_summary": safe_load_json(scan_dir / "attack_summary.json"),
        "navigator_layer": safe_load_json(scan_dir / "attack_navigator_layer.json"),
    }


def resolve_artifact_file(artifact_key: str, filename: str) -> Path:
    scan_dir = artifact_dir(artifact_key).resolve()
    file_path = (scan_dir / filename).resolve()
    if scan_dir not in file_path.parents and file_path != scan_dir:
        raise FileNotFoundError("Invalid artifact path")
    if not file_path.exists():
        raise FileNotFoundError(f"Missing {filename} for {artifact_key}")
    return file_path


def load_digest_index() -> Dict[str, Any]:
    path = DIGESTS_DIR / "index.json"
    if not path.exists():
        return {}
    data = read_json(path)
    return data if isinstance(data, dict) else {}
