from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import typer
from rich import print

app = typer.Typer(add_completion=False, no_args_is_help=True)


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


def _severity_to_score(severity: Any) -> float:
    sev = _safe_str(severity).upper()
    mapping = {
        "CRITICAL": 10.0,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "MODERATE": 5.5,
        "LOW": 2.5,
        "NEGLIGIBLE": 1.0,
        "UNKNOWN": 0.0,
    }
    return mapping.get(sev, 0.0)


def _cap(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _load_packages_map(packages_path: Path) -> Dict[Tuple[str, str], Dict[str, Any]]:
    if not packages_path.exists():
        return {}

    raw = _read_json(packages_path)

    pkg_list: List[Dict[str, Any]] = []
    if isinstance(raw, list):
        pkg_list = [x for x in raw if isinstance(x, dict)]
    elif isinstance(raw, dict):
        for key in ("packages", "items", "results"):
            value = raw.get(key)
            if isinstance(value, list):
                pkg_list = [x for x in value if isinstance(x, dict)]
                break

    result: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for pkg in pkg_list:
        name = _safe_str(
            pkg.get("name")
            or pkg.get("package_name")
            or pkg.get("artifact")
        )
        version = _safe_str(
            pkg.get("version")
            or pkg.get("package_version")
        )
        if name:
            result[(name, version)] = pkg
    return result


def _extract_vuln_list(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if not isinstance(data, dict):
        raise ValueError("vulns.enriched.json must be a list or object")

    for key in ("vulnerabilities", "matches", "items", "results"):
        value = data.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]

    raise ValueError("Could not find vulnerability list in vulns.enriched.json")


def _find_package_context(v: Dict[str, Any], packages_map: Dict[Tuple[str, str], Dict[str, Any]]) -> Dict[str, Any]:
    name = _safe_str(
        v.get("package_name")
        or v.get("artifact_name")
        or v.get("name")
    )
    version = _safe_str(
        v.get("package_version")
        or v.get("installed_version")
        or v.get("version")
    )

    pkg = packages_map.get((name, version), {})
    purl = _safe_str(v.get("package_purl") or v.get("purl") or pkg.get("purl"))
    locations = pkg.get("locations") if isinstance(pkg, dict) else None
    licenses = pkg.get("licenses") if isinstance(pkg, dict) else None
    language = _safe_str(pkg.get("language") or pkg.get("type"))

    return {
        "name": name or _safe_str(pkg.get("name")),
        "version": version or _safe_str(pkg.get("version")),
        "purl": purl,
        "language": language,
        "locations": locations if isinstance(locations, list) else [],
        "licenses": licenses if isinstance(licenses, list) else [],
        "raw_package": pkg if isinstance(pkg, dict) else {},
    }


def _component_type_weight(pkg_ctx: Dict[str, Any]) -> float:
    purl = _safe_str(pkg_ctx.get("purl")).lower()
    language = _safe_str(pkg_ctx.get("language")).lower()

    if "pkg:apk/" in purl or "pkg:deb/" in purl or "pkg:rpm/" in purl:
        return 1.15

    if any(x in purl for x in ("pkg:pypi/", "pkg:npm/", "pkg:maven/", "pkg:gem/", "pkg:golang/")):
        return 1.05

    if language in ("python", "javascript", "java", "go", "ruby"):
        return 1.05

    return 1.0


def _package_criticality_weight(pkg_ctx: Dict[str, Any]) -> float:
    name = _safe_str(pkg_ctx.get("name")).lower()
    purl = _safe_str(pkg_ctx.get("purl")).lower()

    high_value_keywords = [
        "openssl", "libssl", "openssl-libs", "glibc", "musl", "busybox",
        "curl", "libcurl", "openssl3", "zlib", "systemd", "bash",
        "python", "node", "openjdk", "jdk", "jre", "nginx", "apache",
    ]

    if any(k in name for k in high_value_keywords):
        return 1.15
    if any(k in purl for k in high_value_keywords):
        return 1.15

    return 1.0


def _fix_available_weight(v: Dict[str, Any]) -> float:
    candidates = [
        v.get("fix"),
        v.get("fixes"),
        v.get("fixed_in"),
        v.get("fix_versions"),
        v.get("available_fixes"),
        v.get("suggested_fixes"),
    ]

    for item in candidates:
        if isinstance(item, list) and len(item) > 0:
            return 1.10
        if isinstance(item, dict) and len(item) > 0:
            return 1.10
        if isinstance(item, str) and item.strip():
            return 1.10

    return 1.0


def _kev_weight(v: Dict[str, Any]) -> float:
    kev = v.get("kev") or {}
    if isinstance(kev, dict) and kev.get("present") is True:
        return 1.35
    return 1.0


def _epss_weight(v: Dict[str, Any]) -> float:
    epss = v.get("epss") or {}
    score = _to_float(epss.get("score")) if isinstance(epss, dict) else None
    percentile = _to_float(epss.get("percentile")) if isinstance(epss, dict) else None

    if score is None and percentile is None:
        return 1.0

    if score is not None and score >= 0.8:
        return 1.35
    if score is not None and score >= 0.5:
        return 1.25
    if score is not None and score >= 0.2:
        return 1.15

    if percentile is not None and percentile >= 0.99:
        return 1.30
    if percentile is not None and percentile >= 0.95:
        return 1.20
    if percentile is not None and percentile >= 0.80:
        return 1.10

    return 1.0


def _base_risk(v: Dict[str, Any]) -> float:
    cvss = v.get("cvss") or {}
    base_score = _to_float(cvss.get("base_score")) if isinstance(cvss, dict) else None
    if base_score is not None:
        return _cap(base_score, 0.0, 10.0)

    severity = v.get("severity") or (cvss.get("base_severity") if isinstance(cvss, dict) else None)
    return _severity_to_score(severity)


def _confidence(v: Dict[str, Any], pkg_ctx: Dict[str, Any]) -> float:
    score = 0.50

    if _safe_str(v.get("cve_id")):
        score += 0.15

    cvss = v.get("cvss") or {}
    if isinstance(cvss, dict) and cvss.get("base_score") is not None:
        score += 0.10

    if isinstance(v.get("epss"), dict) and v["epss"].get("score") is not None:
        score += 0.10

    if isinstance(v.get("kev"), dict) and "present" in v["kev"]:
        score += 0.05

    if _safe_str(pkg_ctx.get("name")):
        score += 0.05

    if _safe_str(pkg_ctx.get("version")):
        score += 0.05

    return round(_cap(score, 0.0, 1.0), 3)


def _normalise_priority(score: float) -> str:
    if score >= 9.0:
        return "P1"
    if score >= 7.0:
        return "P2"
    if score >= 4.5:
        return "P3"
    return "P4"


def _pick_fix_versions(v: Dict[str, Any]) -> List[str]:
    out: List[str] = []

    candidates = [
        v.get("fix_versions"),
        v.get("available_fixes"),
        v.get("suggested_fixes"),
        v.get("fixed_in"),
        v.get("fixes"),
        v.get("fix"),
    ]

    for item in candidates:
        if isinstance(item, list):
            for x in item:
                s = _safe_str(x)
                if s:
                    out.append(s)
        elif isinstance(item, dict):
            for _, val in item.items():
                if isinstance(val, list):
                    for x in val:
                        s = _safe_str(x)
                        if s:
                            out.append(s)
                else:
                    s = _safe_str(val)
                    if s:
                        out.append(s)
        else:
            s = _safe_str(item)
            if s:
                out.append(s)

    seen = set()
    deduped: List[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            deduped.append(x)

    return deduped


def score_vulnerability(v: Dict[str, Any], packages_map: Dict[Tuple[str, str], Dict[str, Any]]) -> Dict[str, Any]:
    pkg_ctx = _find_package_context(v, packages_map)

    base = _base_risk(v)
    component_weight = _component_type_weight(pkg_ctx)
    criticality_weight = _package_criticality_weight(pkg_ctx)
    fix_weight = _fix_available_weight(v)
    kev_weight = _kev_weight(v)
    epss_weight = _epss_weight(v)

    raw_score = base * component_weight * criticality_weight * fix_weight * kev_weight * epss_weight
    final_score = round(_cap(raw_score, 0.0, 10.0), 3)

    reasons: List[str] = []
    if base >= 9.0:
        reasons.append("High base severity")
    elif base >= 7.0:
        reasons.append("Serious base severity")

    if kev_weight > 1.0:
        reasons.append("Listed in CISA KEV")

    if epss_weight >= 1.25:
        reasons.append("High exploit likelihood (EPSS)")
    elif epss_weight > 1.0:
        reasons.append("Elevated exploit likelihood (EPSS)")

    if component_weight > 1.0:
        reasons.append("OS/runtime package impact")

    if criticality_weight > 1.0:
        reasons.append("Critical package family")

    if fix_weight > 1.0:
        reasons.append("Fix appears available")

    fix_versions = _pick_fix_versions(v)

    return {
        "cve_id": v.get("cve_id"),
        "severity": v.get("severity"),
        "package_name": pkg_ctx.get("name"),
        "package_version": pkg_ctx.get("version"),
        "package_purl": pkg_ctx.get("purl"),
        "description": v.get("description"),
        "cvss": v.get("cvss"),
        "epss": v.get("epss"),
        "kev": v.get("kev"),
        "cwes": v.get("cwes", []),
        "references": v.get("references", []),
        "published": v.get("published"),
        "updated": v.get("updated"),
        "fix_versions": fix_versions,
        "risk_score": final_score,
        "priority": _normalise_priority(final_score),
        "confidence": _confidence(v, pkg_ctx),
        "score_breakdown": {
            "base": round(base, 3),
            "component_weight": round(component_weight, 3),
            "criticality_weight": round(criticality_weight, 3),
            "fix_weight": round(fix_weight, 3),
            "kev_weight": round(kev_weight, 3),
            "epss_weight": round(epss_weight, 3),
            "raw_score_before_cap": round(raw_score, 3),
        },
        "reasons": reasons,
        "package_context": {
            "language": pkg_ctx.get("language"),
            "locations": pkg_ctx.get("locations", []),
            "licenses": pkg_ctx.get("licenses", []),
        },
        "original": v,
    }


def _build_remediation_items(scored: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for item in scored:
        pkg = _safe_str(item.get("package_name"))
        ver = _safe_str(item.get("package_version"))
        key = (pkg, ver)

        if key not in grouped:
            grouped[key] = {
                "package_name": pkg,
                "package_version": ver,
                "package_purl": item.get("package_purl"),
                "max_risk_score": item.get("risk_score", 0.0),
                "priority": item.get("priority"),
                "cves": [],
                "fix_versions": [],
                "top_reasons": set(),
            }

        grouped[key]["max_risk_score"] = max(grouped[key]["max_risk_score"], item.get("risk_score", 0.0))

        existing_priority = grouped[key]["priority"]
        current_priority = item.get("priority")
        priority_order = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
        if priority_order.get(_safe_str(current_priority), 0) > priority_order.get(_safe_str(existing_priority), 0):
            grouped[key]["priority"] = current_priority

        cve_id = _safe_str(item.get("cve_id"))
        if cve_id:
            grouped[key]["cves"].append(cve_id)

        for fv in item.get("fix_versions", []) or []:
            if fv not in grouped[key]["fix_versions"]:
                grouped[key]["fix_versions"].append(fv)

        for reason in item.get("reasons", []) or []:
            grouped[key]["top_reasons"].add(reason)

    out: List[Dict[str, Any]] = []
    for _, entry in grouped.items():
        top_reasons = sorted(entry["top_reasons"])
        out.append({
            "package_name": entry["package_name"],
            "package_version": entry["package_version"],
            "package_purl": entry["package_purl"],
            "max_risk_score": round(entry["max_risk_score"], 3),
            "priority": entry["priority"],
            "cve_count": len(entry["cves"]),
            "cves": sorted(set(entry["cves"])),
            "suggested_fix_versions": entry["fix_versions"],
            "why_fix_first": top_reasons[:5],
        })

    out.sort(key=lambda x: (-x["max_risk_score"], -x["cve_count"], x["package_name"]))
    return out


@app.command()
def main(
    scan_dir: Path = typer.Option(..., "--scan-dir", help="Path to artifacts/<artifact_key>"),
    enriched_name: str = typer.Option("vulns.enriched.json", "--enriched-name", help="Enriched vulnerability file"),
    packages_name: str = typer.Option("packages.json", "--packages-name", help="Packages file"),
    scores_name: str = typer.Option("risk_scores.json", "--scores-name", help="Scored vulnerabilities output"),
    remediation_name: str = typer.Option("remediation.json", "--remediation-name", help="Remediation output"),
) -> None:
    enriched_path = scan_dir / enriched_name
    packages_path = scan_dir / packages_name
    scores_path = scan_dir / scores_name
    remediation_path = scan_dir / remediation_name
    meta_path = scan_dir / "sbom.meta.json"

    if not enriched_path.exists():
        raise FileNotFoundError(f"Missing {enriched_path}")

    enriched_raw = _read_json(enriched_path)
    meta = _read_json(meta_path) if meta_path.exists() else {}
    vulns = _extract_vuln_list(enriched_raw)
    packages_map = _load_packages_map(packages_path)

    print(f"[cyan]Loaded enriched vulnerabilities:[/cyan] {len(vulns)}")
    print(f"[cyan]Loaded package records:[/cyan] {len(packages_map)}")

    scored = [score_vulnerability(v, packages_map) for v in vulns]
    scored.sort(key=lambda x: (-x["risk_score"], _safe_str(x.get("cve_id")), _safe_str(x.get("package_name"))))

    remediation_items = _build_remediation_items(scored)

    risk_scores_output = {
        "generated_at": _iso_now(),
        "source": {
            "scan_dir": str(scan_dir),
            "input_file": enriched_path.name,
            "packages_file": packages_path.name if packages_path.exists() else None,
            "image_input": meta.get("image_input"),
            "image_resolved": meta.get("image_resolved"),
            "digest": meta.get("digest"),
            "artifact_key": meta.get("artifact_key"),
        },
        "counts": {
            "input_vulnerabilities": len(vulns),
            "scored_vulnerabilities": len(scored),
            "p1": sum(1 for x in scored if x.get("priority") == "P1"),
            "p2": sum(1 for x in scored if x.get("priority") == "P2"),
            "p3": sum(1 for x in scored if x.get("priority") == "P3"),
            "p4": sum(1 for x in scored if x.get("priority") == "P4"),
        },
        "vulnerabilities": scored,
    }

    remediation_output = {
        "generated_at": _iso_now(),
        "source": {
            "scan_dir": str(scan_dir),
            "input_file": scores_path.name,
            "image_input": meta.get("image_input"),
            "image_resolved": meta.get("image_resolved"),
            "digest": meta.get("digest"),
            "artifact_key": meta.get("artifact_key"),
        },
        "counts": {
            "packages_to_review": len(remediation_items),
            "p1_packages": sum(1 for x in remediation_items if x.get("priority") == "P1"),
            "p2_packages": sum(1 for x in remediation_items if x.get("priority") == "P2"),
            "p3_packages": sum(1 for x in remediation_items if x.get("priority") == "P3"),
            "p4_packages": sum(1 for x in remediation_items if x.get("priority") == "P4"),
        },
        "remediation": remediation_items,
    }

    _write_json(scores_path, risk_scores_output)
    _write_json(remediation_path, remediation_output)

    print(f"[bold green]Wrote[/bold green]: {scores_path}")
    print(f"[bold green]Wrote[/bold green]: {remediation_path}")


if __name__ == "__main__":
    app()