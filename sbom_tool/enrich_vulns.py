from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from dotenv import load_dotenv
from rich import print

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _to_float(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except Exception:
        return None


def _chunked(items: List[str], size: int) -> List[List[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def _http_get_json(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> Any:
    req_headers = {
        "User-Agent": "riskybisky/0.1 (+https://github.com/y-kal/riskybisky)",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw)


def _extract_cve_id(vuln: Dict[str, Any]) -> Optional[str]:
    candidates = [
        vuln.get("vuln_id"),
        vuln.get("id"),
        vuln.get("vulnerability_id"),
        vuln.get("cve"),
        vuln.get("cve_id"),
        vuln.get("vulnerability"),
    ]

    nested = vuln.get("vulnerability")
    if isinstance(nested, dict):
        candidates.extend([
            nested.get("id"),
            nested.get("name"),
            nested.get("cve"),
            nested.get("cve_id"),
        ])

    for value in candidates:
        text = _safe_str(value).upper()
        match = CVE_RE.search(text)
        if match:
            return match.group(0)

    blob = json.dumps(vuln, ensure_ascii=False)
    match = CVE_RE.search(blob.upper())
    if match:
        return match.group(0)

    return None


def _extract_vuln_list(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if not isinstance(data, dict):
        raise ValueError("vulns.json must be a list or an object")

    for key in ("vulnerabilities", "matches", "items", "results"):
        value = data.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]

    raise ValueError("Could not find vulnerability list inside vulns.json")


def _build_nvd_cache_path(cache_dir: Path, cve_id: str) -> Path:
    return cache_dir / "nvd" / f"{cve_id.upper()}.json"


def _build_epss_cache_path(cache_dir: Path, cve_id: str) -> Path:
    return cache_dir / "epss" / f"{cve_id.upper()}.json"


def _build_kev_cache_path(cache_dir: Path) -> Path:
    return cache_dir / "kev" / "known_exploited_vulnerabilities.json"


def _load_cached_json(path: Path) -> Optional[Any]:
    if path.exists():
        try:
            return _read_json(path)
        except Exception:
            return None
    return None


def _pick_cvss(metrics: Dict[str, Any]) -> Dict[str, Any]:
    order = [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]

    for key, version in order:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue

        entry = entries[0]
        if not isinstance(entry, dict):
            continue

        cvss_data = entry.get("cvssData") or {}
        return {
            "version": version,
            "base_score": cvss_data.get("baseScore"),
            "base_severity": entry.get("baseSeverity") or cvss_data.get("baseSeverity"),
            "vector": cvss_data.get("vectorString"),
            "exploitability_score": entry.get("exploitabilityScore"),
            "impact_score": entry.get("impactScore"),
            "source": entry.get("source"),
        }

    return {
        "version": None,
        "base_score": None,
        "base_severity": None,
        "vector": None,
        "exploitability_score": None,
        "impact_score": None,
        "source": None,
    }


def _parse_nvd_cve_record(data: Any, cve_id: str) -> Dict[str, Any]:
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    if not vulnerabilities:
        return {
            "cve_id": cve_id,
            "description": None,
            "published": None,
            "updated": None,
            "cwes": [],
            "references": [],
            "cvss": _pick_cvss({}),
        }

    item = vulnerabilities[0].get("cve", {})
    descriptions = item.get("descriptions") or []
    description = None
    for d in descriptions:
        if isinstance(d, dict) and d.get("lang") == "en":
            description = d.get("value")
            break

    cwes: List[str] = []
    for weakness in item.get("weaknesses", []) or []:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description", []) or []:
            if not isinstance(desc, dict):
                continue
            value = _safe_str(desc.get("value"))
            if value.startswith("CWE-"):
                cwes.append(value)

    references: List[str] = []
    for ref in item.get("references", []) or []:
        if isinstance(ref, dict):
            url = _safe_str(ref.get("url"))
            if url:
                references.append(url)

    metrics = item.get("metrics") or {}

    return {
        "cve_id": cve_id,
        "description": description,
        "published": item.get("published"),
        "updated": item.get("lastModified"),
        "cwes": sorted(set(cwes)),
        "references": sorted(set(references)),
        "cvss": _pick_cvss(metrics),
    }


def fetch_nvd_for_cve(
    cve_id: str,
    cache_dir: Path,
    nvd_api_key: Optional[str],
    refresh: bool,
    sleep_seconds: float,
) -> Dict[str, Any]:
    cache_path = _build_nvd_cache_path(cache_dir, cve_id)

    if not refresh:
        cached = _load_cached_json(cache_path)
        if isinstance(cached, dict):
            return cached

    params = urllib.parse.urlencode({"cveId": cve_id})
    url = f"{NVD_URL}?{params}"

    headers = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    data = _http_get_json(url, headers=headers, timeout=30)
    parsed = _parse_nvd_cve_record(data, cve_id)
    _write_json(cache_path, parsed)

    if sleep_seconds > 0:
        time.sleep(sleep_seconds)

    return parsed


def fetch_epss_for_cves(
    cve_ids: List[str],
    cache_dir: Path,
    refresh: bool,
    batch_size: int = 100,
) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}

    missing: List[str] = []
    for cve_id in cve_ids:
        cache_path = _build_epss_cache_path(cache_dir, cve_id)
        if not refresh:
            cached = _load_cached_json(cache_path)
            if isinstance(cached, dict):
                results[cve_id] = cached
                continue
        missing.append(cve_id)

    for batch in _chunked(missing, batch_size):
        params = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"{EPSS_URL}?{params}"
        data = _http_get_json(url, timeout=30)

        rows = data.get("data", []) if isinstance(data, dict) else []
        batch_map: Dict[str, Dict[str, Any]] = {}

        for row in rows:
            if not isinstance(row, dict):
                continue
            cve = _safe_str(row.get("cve")).upper()
            if not cve:
                continue

            item = {
                "cve_id": cve,
                "epss": _to_float(row.get("epss")),
                "percentile": _to_float(row.get("percentile")),
                "date": row.get("date"),
            }
            batch_map[cve] = item
            _write_json(_build_epss_cache_path(cache_dir, cve), item)

        for cve_id in batch:
            results[cve_id] = batch_map.get(
                cve_id,
                {
                    "cve_id": cve_id,
                    "epss": None,
                    "percentile": None,
                    "date": None,
                },
            )
            if cve_id not in batch_map:
                _write_json(_build_epss_cache_path(cache_dir, cve_id), results[cve_id])

    return results


def fetch_kev_catalog(cache_dir: Path, refresh: bool) -> Dict[str, Dict[str, Any]]:
    cache_path = _build_kev_cache_path(cache_dir)

    if not refresh:
        cached = _load_cached_json(cache_path)
        if isinstance(cached, dict):
            return _index_kev(cached)

    data = _http_get_json(KEV_URL, timeout=45)
    _write_json(cache_path, data)
    return _index_kev(data)


def _index_kev(data: Any) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}

    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    for item in vulns:
        if not isinstance(item, dict):
            continue

        cve_id = _safe_str(item.get("cveID") or item.get("cveId")).upper()
        if not cve_id:
            continue

        out[cve_id] = {
            "cve_id": cve_id,
            "vendor_project": item.get("vendorProject"),
            "product": item.get("product"),
            "vulnerability_name": item.get("vulnerabilityName"),
            "date_added": item.get("dateAdded"),
            "short_description": item.get("shortDescription"),
            "required_action": item.get("requiredAction"),
            "due_date": item.get("dueDate"),
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
            "notes": item.get("notes"),
        }

    return out


def _severity_rank(sev: Any) -> int:
    text = _safe_str(sev).upper()
    order = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "MODERATE": 3,
        "LOW": 2,
        "NEGLIGIBLE": 1,
        "UNKNOWN": 0,
    }
    return order.get(text, 0)


def _normalise_counts(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    for v in vulns:
        sev = (
            _safe_str(v.get("severity"))
            or _safe_str((v.get("cvss") or {}).get("base_severity"))
            or _safe_str((v.get("original") or {}).get("severity"))
        ).upper()

        if sev == "CRITICAL":
            counts["critical"] += 1
        elif sev == "HIGH":
            counts["high"] += 1
        elif sev in ("MEDIUM", "MODERATE"):
            counts["medium"] += 1
        elif sev == "LOW":
            counts["low"] += 1
        else:
            counts["unknown"] += 1

    return counts


def enrich_record(
    vuln: Dict[str, Any],
    nvd_map: Dict[str, Dict[str, Any]],
    epss_map: Dict[str, Dict[str, Any]],
    kev_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    cve_id = _extract_cve_id(vuln)

    nvd = nvd_map.get(cve_id, {}) if cve_id else {}
    epss = epss_map.get(cve_id, {}) if cve_id else {}
    kev = kev_map.get(cve_id, {}) if cve_id else {}

    original_severity = _safe_str(vuln.get("severity")).upper() or None
    cvss = nvd.get("cvss") or {}

    out = dict(vuln)
    out["cve_id"] = cve_id
    out["description"] = nvd.get("description")
    out["published"] = nvd.get("published")
    out["updated"] = nvd.get("updated")
    out["cwes"] = nvd.get("cwes", [])
    out["references"] = nvd.get("references", [])
    out["cvss"] = {
        "version": cvss.get("version"),
        "base_score": cvss.get("base_score"),
        "base_severity": cvss.get("base_severity"),
        "vector": cvss.get("vector"),
        "exploitability_score": cvss.get("exploitability_score"),
        "impact_score": cvss.get("impact_score"),
        "source": cvss.get("source"),
    }
    out["epss"] = {
        "score": epss.get("epss"),
        "percentile": epss.get("percentile"),
        "date": epss.get("date"),
    }
    out["kev"] = {
        "present": bool(kev),
        "vendor_project": kev.get("vendor_project"),
        "product": kev.get("product"),
        "vulnerability_name": kev.get("vulnerability_name"),
        "date_added": kev.get("date_added"),
        "short_description": kev.get("short_description"),
        "required_action": kev.get("required_action"),
        "due_date": kev.get("due_date"),
        "known_ransomware_campaign_use": kev.get("known_ransomware_campaign_use"),
        "notes": kev.get("notes"),
    }
    out["enrichment"] = {
        "has_cve_id": cve_id is not None,
        "nvd_found": bool(nvd),
        "epss_found": epss.get("epss") is not None,
        "kev_found": bool(kev),
    }

    derived_severity = cvss.get("base_severity")
    if original_severity and _severity_rank(original_severity) >= _severity_rank(derived_severity):
        out["severity"] = original_severity
    else:
        out["severity"] = derived_severity or original_severity or "UNKNOWN"

    return out


def main(
    scan_dir: Path,
    out_name: str = "vulns.enriched.json",
    cache_dir: Path = Path("cache"),
    refresh_nvd: bool = False,
    refresh_epss: bool = False,
    refresh_kev: bool = False,
    nvd_api_key: Optional[str] = None,
    nvd_sleep_seconds: float = 0.6,
) -> None:
    project_root = Path(__file__).resolve().parent.parent
    cache_dir = (project_root / cache_dir).resolve() if not cache_dir.is_absolute() else cache_dir
    vulns_path = scan_dir / "vulns.json"
    out_path = scan_dir / out_name
    meta_path = scan_dir / "sbom.meta.json"

    if not vulns_path.exists():
        raise FileNotFoundError(f"Missing {vulns_path}")

    raw = _read_json(vulns_path)
    meta = _read_json(meta_path) if meta_path.exists() else {}
    vuln_list = _extract_vuln_list(raw)

    cve_ids = sorted({c for c in (_extract_cve_id(v) for v in vuln_list) if c})
    print(f"[cyan]Input vulnerabilities:[/cyan] {len(vuln_list)}")
    print(f"[cyan]Unique CVEs detected:[/cyan] {len(cve_ids)}")

    nvd_api_key = nvd_api_key or os.getenv("NVD_API_KEY")
    print(f"[cyan]NVD API key loaded:[/cyan] {bool(nvd_api_key)}")

    nvd_map: Dict[str, Dict[str, Any]] = {}
    epss_map: Dict[str, Dict[str, Any]] = {}
    kev_map: Dict[str, Dict[str, Any]] = {}

    nvd_errors: List[str] = []
    epss_error: Optional[str] = None
    kev_error: Optional[str] = None

    print("[cyan]Fetching NVD metadata...[/cyan]")
    for cve_id in cve_ids:
        try:
            nvd_map[cve_id] = fetch_nvd_for_cve(
                cve_id=cve_id,
                cache_dir=cache_dir,
                nvd_api_key=nvd_api_key,
                refresh=refresh_nvd,
                sleep_seconds=nvd_sleep_seconds,
            )
        except Exception as exc:
            nvd_errors.append(f"{cve_id}: {exc}")
            nvd_map[cve_id] = {}

    print("[cyan]Fetching EPSS batch scores...[/cyan]")
    try:
        epss_map = fetch_epss_for_cves(
            cve_ids=cve_ids,
            cache_dir=cache_dir,
            refresh=refresh_epss,
            batch_size=100,
        )
    except Exception as exc:
        epss_error = str(exc)
        epss_map = {cve_id: {} for cve_id in cve_ids}

    print("[cyan]Fetching KEV catalogue...[/cyan]")
    try:
        kev_map = fetch_kev_catalog(cache_dir=cache_dir, refresh=refresh_kev)
    except Exception as exc:
        kev_error = str(exc)
        kev_map = {}

    enriched = [
        enrich_record(v, nvd_map=nvd_map, epss_map=epss_map, kev_map=kev_map)
        for v in vuln_list
    ]

    output = {
        "generated_at": _iso_now(),
        "source": {
            "scan_dir": str(scan_dir),
            "input_file": str(vulns_path.name),
            "output_file": str(out_path.name),
            "image_input": meta.get("image_input"),
            "image_resolved": meta.get("image_resolved"),
            "digest": meta.get("digest"),
            "artifact_key": meta.get("artifact_key"),
        },
        "counts": {
            "input_vulnerabilities": len(vuln_list),
            "unique_cves": len(cve_ids),
            "kev_hits": sum(1 for v in enriched if (v.get("kev") or {}).get("present")),
            **_normalise_counts(enriched),
        },
        "feeds": {
            "nvd": {
                "url": NVD_URL,
                "api_key_used": bool(nvd_api_key),
                "errors": nvd_errors,
            },
            "epss": {
                "url": EPSS_URL,
                "error": epss_error,
            },
            "kev": {
                "url": KEV_URL,
                "error": kev_error,
            },
        },
        "vulnerabilities": enriched,
    }

    _write_json(out_path, output)
    print(f"[bold green]Wrote[/bold green]: {out_path}")


def cli(
    scan_dir: Path = typer.Option(..., "--scan-dir", help="Path to artifacts/<artifact_key>"),
    out_name: str = typer.Option("vulns.enriched.json", "--out-name", help="Output file name"),
    cache_dir: Path = typer.Option(Path("cache"), "--cache-dir", help="Cache directory"),
    refresh_nvd: bool = typer.Option(False, "--refresh-nvd", help="Re-fetch NVD even if cached"),
    refresh_epss: bool = typer.Option(False, "--refresh-epss", help="Re-fetch EPSS even if cached"),
    refresh_kev: bool = typer.Option(False, "--refresh-kev", help="Re-fetch KEV even if cached"),
    nvd_api_key: Optional[str] = typer.Option(
        None,
        "--nvd-api-key",
        help="Optional NVD API key (or set NVD_API_KEY env var)",
    ),
    nvd_sleep_seconds: float = typer.Option(
        0.6,
        "--nvd-sleep-seconds",
        help="Delay between NVD calls to reduce rate-limit problems",
    ),
) -> None:
    return main(
        scan_dir=scan_dir,
        out_name=out_name,
        cache_dir=cache_dir,
        refresh_nvd=refresh_nvd,
        refresh_epss=refresh_epss,
        refresh_kev=refresh_kev,
        nvd_api_key=nvd_api_key,
        nvd_sleep_seconds=nvd_sleep_seconds,
    )


if __name__ == "__main__":
    typer.run(cli)