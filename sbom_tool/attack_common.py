from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

ATTACK_KILL_CHAIN_NAME = "mitre-attack"

STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "before", "by", "can", "causing",
    "for", "from", "in", "into", "is", "it", "its", "may", "no", "of", "on", "or",
    "prior", "result", "that", "the", "their", "them", "this", "to", "using", "via",
    "when", "with", "without",
}


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def to_float(value: Any) -> Optional[float]:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except Exception:
        return None


def cap(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def normalise_priority(score: float) -> str:
    if score >= 9.0:
        return "P1"
    if score >= 7.0:
        return "P2"
    if score >= 4.5:
        return "P3"
    return "P4"


def load_scored_vulnerabilities(path: Path) -> Dict[str, Any]:
    raw = read_json(path)
    if not isinstance(raw, dict):
        raise ValueError("risk_scores.json must be an object")

    vulns = raw.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("risk_scores.json must contain a 'vulnerabilities' list")

    return raw


def collapse_ws(text: Any) -> str:
    return re.sub(r"\s+", " ", safe_str(text)).strip()


def tokenize(text: Any) -> List[str]:
    raw = collapse_ws(text).lower()
    tokens = re.findall(r"[a-z0-9]{2,}", raw)
    return [token for token in tokens if token not in STOPWORDS]


def fetch_attack_bundle(
    cache_dir: Path,
    refresh: bool = False,
    attack_url: str = ATTACK_STIX_URL,
) -> Dict[str, Any]:
    cache_path = cache_dir / "attack" / "enterprise-attack.json"

    if cache_path.exists() and not refresh:
        try:
            cached = read_json(cache_path)
            if isinstance(cached, dict):
                return cached
        except Exception:
            pass

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_suffix(".json.tmp")

    req = urllib.request.Request(
        attack_url,
        headers={
            "User-Agent": "riskybisky/0.1 (+https://github.com/y-kal/riskybisky)",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
    except Exception as exc:
        if cache_path.exists():
            try:
                cached = read_json(cache_path)
                if isinstance(cached, dict):
                    return cached
            except Exception:
                pass
        raise RuntimeError(
            "Unable to fetch MITRE ATT&CK STIX data. "
            f"Tried {attack_url} and no cached copy was available in {cache_path}."
        ) from exc

    data = json.loads(raw)
    write_json(tmp_path, data)
    tmp_path.replace(cache_path)
    return data


def parse_enterprise_techniques(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
    techniques: Dict[str, Dict[str, Any]] = {}

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue

        external_refs = obj.get("external_references") or []
        technique_id = None
        for ref in external_refs:
            if not isinstance(ref, dict):
                continue
            if ref.get("source_name") == "mitre-attack":
                technique_id = safe_str(ref.get("external_id"))
                if technique_id:
                    break

        if not technique_id:
            continue

        tactics: List[str] = []
        for phase in obj.get("kill_chain_phases") or []:
            if not isinstance(phase, dict):
                continue
            if phase.get("kill_chain_name") != ATTACK_KILL_CHAIN_NAME:
                continue
            phase_name = safe_str(phase.get("phase_name")).replace("-", " ")
            if phase_name:
                tactics.append(phase_name.title())

        name = collapse_ws(obj.get("name"))
        description = collapse_ws(obj.get("description"))
        aliases = obj.get("x_mitre_aliases") if isinstance(obj.get("x_mitre_aliases"), list) else []
        platforms = obj.get("x_mitre_platforms") if isinstance(obj.get("x_mitre_platforms"), list) else []

        search_blob = " ".join(
            part for part in [name, description, " ".join(safe_str(x) for x in aliases)] if part
        )

        techniques[technique_id] = {
            "technique_id": technique_id,
            "technique_name": name,
            "description": description,
            "tactics": sorted(set(tactics)),
            "platforms": [safe_str(x) for x in platforms if safe_str(x)],
            "search_blob": search_blob,
            "search_tokens": tokenize(search_blob),
            "stix_id": obj.get("id"),
        }

    return techniques
