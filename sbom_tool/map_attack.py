from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import typer
from rich import print

from sbom_tool.attack_common import (
    ATTACK_STIX_URL,
    cap,
    collapse_ws,
    fetch_attack_bundle,
    iso_now,
    load_scored_vulnerabilities,
    normalise_priority,
    parse_enterprise_techniques,
    read_json,
    safe_str,
    tokenize,
    to_float,
    write_json,
)

app = typer.Typer(add_completion=False, no_args_is_help=True)

CWE_RULES: List[Dict[str, Any]] = [
    {
        "cwes": {"CWE-77", "CWE-78", "CWE-88", "CWE-89", "CWE-90", "CWE-94", "CWE-917"},
        "technique_id": "T1190",
        "base_confidence": 0.72,
        "reason": "Injection-style weaknesses commonly enable exploit paths through exposed applications or APIs.",
    },
    {
        "cwes": {"CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73", "CWE-98", "CWE-434", "CWE-552", "CWE-918"},
        "technique_id": "T1190",
        "base_confidence": 0.64,
        "reason": "Traversal, upload, file inclusion, and SSRF weaknesses can expose public-facing application exploit paths.",
    },
    {
        "cwes": {"CWE-287", "CWE-288", "CWE-290", "CWE-306", "CWE-307", "CWE-346", "CWE-862", "CWE-863"},
        "technique_id": "T1190",
        "base_confidence": 0.58,
        "reason": "Authentication and authorization bypass flaws can be abused against exposed services.",
    },
    {
        "cwes": {"CWE-269", "CWE-266", "CWE-250", "CWE-732", "CWE-284"},
        "technique_id": "T1068",
        "base_confidence": 0.74,
        "reason": "Privilege and permission weaknesses align with exploitation for privilege escalation.",
    },
    {
        "cwes": {"CWE-798", "CWE-259", "CWE-521", "CWE-1392"},
        "technique_id": "T1078",
        "base_confidence": 0.67,
        "reason": "Default, weak, or hardcoded credentials can enable use of valid accounts.",
    },
    {
        "cwes": {"CWE-502"},
        "technique_id": "T1190",
        "base_confidence": 0.77,
        "reason": "Unsafe deserialization is a common exploit path for public-facing applications.",
    },
]

TECHNIQUE_HINTS: Dict[str, List[str]] = {
    "T1190": [
        "remote code execution",
        "rce",
        "crafted request",
        "crafted input",
        "crafted payload",
        "public facing",
        "web application",
        "server side request forgery",
        "ssrf",
        "sql injection",
        "command injection",
        "path traversal",
        "deserialization",
        "authentication bypass",
        "unauthenticated",
        "api endpoint",
    ],
    "T1210": [
        "remote service",
        "network service",
        "smb",
        "rpc",
        "crafted packet",
        "remote attacker",
    ],
    "T1068": [
        "privilege escalation",
        "elevation of privilege",
        "elevate privileges",
        "gain root",
        "root privileges",
        "local attacker",
    ],
    "T1078": [
        "hardcoded credential",
        "hardcoded password",
        "default credential",
        "default password",
        "valid account",
        "credential reuse",
        "authentication secret",
    ],
    "T1203": [
        "malicious file",
        "malicious document",
        "client side",
        "browser",
        "viewer",
        "opening a file",
        "rendering content",
    ],
}

TARGET_TECHNIQUES = {"T1190", "T1210", "T1068", "T1078", "T1203"}

LOW_SIGNAL_OVERLAP_TOKENS = {
    "access",
    "accounts",
    "application",
    "applications",
    "credential",
    "credentials",
    "daemon",
    "exploit",
    "exploitation",
    "file",
    "files",
    "malicious",
    "network",
    "privilege",
    "privileges",
    "remote",
    "server",
    "service",
    "services",
    "software",
    "valid",
}


def _rule_map_by_cwe(techniques: Dict[str, Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for rule in CWE_RULES:
        technique = techniques.get(rule["technique_id"])
        if not technique:
            continue
        for cwe in rule["cwes"]:
            out.setdefault(cwe, []).append(rule)
    return out


def _collect_cwes(vuln: Dict[str, Any]) -> List[str]:
    raw = vuln.get("cwes")
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    for item in raw:
        cwe = safe_str(item).upper()
        if cwe.startswith("CWE-"):
            out.append(cwe)
    return sorted(set(out))


def _pick_description(vuln: Dict[str, Any]) -> str:
    return collapse_ws(vuln.get("description"))


def _combine_confidence(cwe_score: Optional[float], text_score: Optional[float]) -> float:
    if cwe_score is None and text_score is None:
        return 0.0
    if cwe_score is None:
        return round(text_score or 0.0, 3)
    if text_score is None:
        return round(cwe_score, 3)

    strong = max(cwe_score, text_score)
    weak = min(cwe_score, text_score)
    return round(cap(strong + (0.15 * weak) + 0.03, 0.0, 1.0), 3)


def _score_cwe_rules(
    vuln: Dict[str, Any],
    techniques: Dict[str, Dict[str, Any]],
    cwe_rule_map: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    cwes = _collect_cwes(vuln)

    for cwe in cwes:
        for rule in cwe_rule_map.get(cwe, []):
            technique_id = rule["technique_id"]
            technique = techniques.get(technique_id)
            if not technique:
                continue

            entry = results.setdefault(
                technique_id,
                {
                    "technique": technique,
                    "score": 0.0,
                    "evidence": [],
                    "methods": set(),
                    "source_fields": set(),
                },
            )

            entry["score"] = max(entry["score"], float(rule["base_confidence"]))
            entry["methods"].add("cwe_rule")
            entry["source_fields"].add("cwes")
            entry["evidence"].append(
                f"{cwe} matched {technique['technique_id']} ({technique['technique_name']}): {rule['reason']}"
            )

    return results


def _score_description_matches(
    vuln: Dict[str, Any],
    techniques: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    description = _pick_description(vuln)
    if not description:
        return {}

    desc_tokens = set(tokenize(description))
    if not desc_tokens:
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    lowered_description = description.lower()

    for technique_id in TARGET_TECHNIQUES:
        technique = techniques.get(technique_id)
        if not technique:
            continue

        tech_tokens = set(technique.get("search_tokens", []))
        overlap = sorted((desc_tokens & tech_tokens) - LOW_SIGNAL_OVERLAP_TOKENS)
        overlap_score = min(0.42, 0.09 * len(overlap))

        hint_hits = [hint for hint in TECHNIQUE_HINTS.get(technique_id, []) if hint in lowered_description]
        hint_score = min(0.55, 0.15 * len(hint_hits))

        score = cap(overlap_score + hint_score, 0.0, 0.88)
        if score < 0.18:
            continue

        evidence: List[str] = []
        if overlap:
            overlap_terms = ", ".join(overlap[:6])
            evidence.append(
                f"Description token overlap matched {technique['technique_name']} via: {overlap_terms}"
            )
        if hint_hits:
            hints = ", ".join(hint_hits[:5])
            evidence.append(
                f"Description keyword overlap matched {technique['technique_name']} via: {hints}"
            )

        results[technique_id] = {
            "technique": technique,
            "score": round(score, 3),
            "evidence": evidence,
            "methods": {"text_match"},
            "source_fields": {"description"},
        }

    return results


def map_vulnerability(
    vuln: Dict[str, Any],
    techniques: Dict[str, Dict[str, Any]],
    cwe_rule_map: Dict[str, List[Dict[str, Any]]],
    min_confidence: float,
) -> Dict[str, Any]:
    cwe_hits = _score_cwe_rules(vuln, techniques, cwe_rule_map)
    text_hits = _score_description_matches(vuln, techniques)

    technique_ids = sorted(set(cwe_hits) | set(text_hits))
    mappings: List[Dict[str, Any]] = []

    for technique_id in technique_ids:
        technique = techniques[technique_id]
        cwe_hit = cwe_hits.get(technique_id)
        text_hit = text_hits.get(technique_id)

        cwe_score = cwe_hit.get("score") if cwe_hit else None
        text_score = text_hit.get("score") if text_hit else None
        confidence = _combine_confidence(cwe_score, text_score)
        if confidence < min_confidence:
            continue

        evidence: List[str] = []
        methods: Set[str] = set()
        source_fields: Set[str] = set()

        for hit in (cwe_hit, text_hit):
            if not hit:
                continue
            evidence.extend(hit.get("evidence", []))
            methods.update(hit.get("methods", set()))
            source_fields.update(hit.get("source_fields", set()))

        mappings.append(
            {
                "technique_id": technique_id,
                "technique_name": technique["technique_name"],
                "tactics": technique["tactics"],
                "confidence": confidence,
                "mapping_method": sorted(methods),
                "evidence": evidence[:6],
                "source_fields": sorted(source_fields),
            }
        )

    mappings.sort(key=lambda item: (-item["confidence"], item["technique_id"]))

    return {
        "cve_id": vuln.get("cve_id"),
        "package_name": vuln.get("package_name"),
        "package_version": vuln.get("package_version"),
        "package_purl": vuln.get("package_purl") or vuln.get("purl"),
        "severity": vuln.get("severity"),
        "cvss": vuln.get("cvss"),
        "epss": vuln.get("epss"),
        "kev": vuln.get("kev"),
        "risk_score": to_float(vuln.get("risk_score")),
        "priority": vuln.get("priority"),
        "cwes": _collect_cwes(vuln),
        "description": _pick_description(vuln),
        "reasons": vuln.get("reasons") if isinstance(vuln.get("reasons"), list) else [],
        "mappings": mappings,
    }


def _summarise_evidence(values: List[str], limit: int = 5) -> List[str]:
    counter = Counter(value for value in values if value)
    return [item for item, _ in counter.most_common(limit)]


def _aggregate_risk(max_risk: float, average_risk: float, average_confidence: float, vuln_count: int) -> float:
    count_factor = min(1.25, 1.0 + (0.05 * max(0, vuln_count - 1)))
    weighted = (max_risk * 0.45) + (average_risk * 0.35) + (average_confidence * 2.0)
    return round(cap(weighted * count_factor, 0.0, 10.0), 3)


def build_attack_summary(mapped_vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}

    for vuln in mapped_vulns:
        risk_score = to_float(vuln.get("risk_score")) or 0.0
        package_name = safe_str(vuln.get("package_name"))
        package_version = safe_str(vuln.get("package_version"))
        package = f"{package_name}@{package_version}" if package_name and package_version else package_name

        for mapping in vuln.get("mappings", []) or []:
            if not isinstance(mapping, dict):
                continue

            technique_id = safe_str(mapping.get("technique_id"))
            if not technique_id:
                continue

            entry = grouped.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "technique_name": mapping.get("technique_name"),
                    "tactics": set(mapping.get("tactics") or []),
                    "cves": set(),
                    "packages": set(),
                    "risk_scores": [],
                    "confidences": [],
                    "evidence": [],
                },
            )

            entry["tactics"].update(mapping.get("tactics") or [])
            cve_id = safe_str(vuln.get("cve_id"))
            if cve_id:
                entry["cves"].add(cve_id)
            if package:
                entry["packages"].add(package)
            entry["risk_scores"].append(risk_score)
            entry["confidences"].append(to_float(mapping.get("confidence")) or 0.0)
            entry["evidence"].extend(mapping.get("evidence") or [])

    techniques: List[Dict[str, Any]] = []
    for entry in grouped.values():
        risk_scores = entry["risk_scores"] or [0.0]
        confidences = entry["confidences"] or [0.0]
        max_risk = max(risk_scores)
        avg_risk = sum(risk_scores) / len(risk_scores)
        avg_conf = sum(confidences) / len(confidences)
        aggregate_risk = _aggregate_risk(max_risk, avg_risk, avg_conf, len(risk_scores))

        techniques.append(
            {
                "technique_id": entry["technique_id"],
                "technique_name": entry["technique_name"],
                "tactics": sorted(entry["tactics"]),
                "aggregate_risk": aggregate_risk,
                "max_risk_score": round(max_risk, 3),
                "average_risk_score": round(avg_risk, 3),
                "average_confidence": round(avg_conf, 3),
                "priority": normalise_priority(aggregate_risk),
                "vulnerability_count": len(risk_scores),
                "cves": sorted(entry["cves"]),
                "packages": sorted(entry["packages"]),
                "top_evidence": _summarise_evidence(entry["evidence"]),
            }
        )

    techniques.sort(
        key=lambda item: (
            -item["aggregate_risk"],
            -item["max_risk_score"],
            -item["vulnerability_count"],
            item["technique_id"],
        )
    )
    return techniques


@app.command()
def main(
    scan_dir: Path = typer.Option(..., "--scan-dir", help="Path to artifacts/<artifact_key>"),
    scores_name: str = typer.Option("risk_scores.json", "--scores-name", help="Scored vulnerability input"),
    mapping_name: str = typer.Option("attack_mapping.json", "--mapping-name", help="Mapping output file"),
    summary_name: str = typer.Option("attack_summary.json", "--summary-name", help="Technique summary output file"),
    cache_dir: Path = typer.Option(Path("cache"), "--cache-dir", help="Cache directory"),
    refresh_attack: bool = typer.Option(False, "--refresh-attack", help="Re-fetch ATT&CK STIX data"),
    min_confidence: float = typer.Option(0.2, "--min-confidence", min=0.0, max=1.0, help="Minimum mapping confidence"),
    attack_url: str = typer.Option(ATTACK_STIX_URL, "--attack-url", help="ATT&CK STIX bundle URL"),
) -> None:
    scores_path = scan_dir / scores_name
    mapping_path = scan_dir / mapping_name
    summary_path = scan_dir / summary_name
    meta_path = scan_dir / "sbom.meta.json"
    project_root = Path(__file__).resolve().parent.parent
    cache_dir = (project_root / cache_dir).resolve() if not cache_dir.is_absolute() else cache_dir

    if not scores_path.exists():
        raise FileNotFoundError(f"Missing {scores_path}")

    scored_raw = load_scored_vulnerabilities(scores_path)
    meta = read_json(meta_path) if meta_path.exists() else {}
    vulnerabilities = [item for item in scored_raw.get("vulnerabilities", []) if isinstance(item, dict)]

    print(f"[cyan]Loaded scored vulnerabilities:[/cyan] {len(vulnerabilities)}")
    print(f"[cyan]ATT&CK cache:[/cyan] {cache_dir / 'attack'}")

    bundle = fetch_attack_bundle(cache_dir=cache_dir, refresh=refresh_attack, attack_url=attack_url)
    techniques = parse_enterprise_techniques(bundle)
    cwe_rule_map = _rule_map_by_cwe(techniques)

    print(f"[cyan]Loaded ATT&CK techniques:[/cyan] {len(techniques)}")
    print(f"[cyan]Configured CWE rules:[/cyan] {len(CWE_RULES)}")

    mapped_vulns = [
        map_vulnerability(vuln, techniques, cwe_rule_map, min_confidence=min_confidence)
        for vuln in vulnerabilities
    ]
    summary = build_attack_summary(mapped_vulns)

    attack_mapping_output = {
        "generated_at": iso_now(),
        "source": {
            "scan_dir": str(scan_dir),
            "input_file": scores_path.name,
            "attack_stix_url": attack_url,
            "attack_cache_file": str((cache_dir / "attack" / "enterprise-attack.json").resolve()),
            "image_input": meta.get("image_input"),
            "image_resolved": meta.get("image_resolved"),
            "digest": meta.get("digest"),
            "artifact_key": meta.get("artifact_key"),
        },
        "counts": {
            "input_vulnerabilities": len(vulnerabilities),
            "mapped_vulnerabilities": sum(1 for item in mapped_vulns if item.get("mappings")),
            "unmapped_vulnerabilities": sum(1 for item in mapped_vulns if not item.get("mappings")),
            "mapped_techniques": len({m["technique_id"] for item in mapped_vulns for m in item.get("mappings", [])}),
            "total_mappings": sum(len(item.get("mappings", [])) for item in mapped_vulns),
        },
        "mapping_config": {
            "min_confidence": min_confidence,
            "cwe_rule_count": len(CWE_RULES),
            "text_match_target_techniques": sorted(TARGET_TECHNIQUES),
        },
        "vulnerabilities": mapped_vulns,
    }

    attack_summary_output = {
        "generated_at": iso_now(),
        "source": {
            "scan_dir": str(scan_dir),
            "input_file": mapping_path.name,
            "scores_file": scores_path.name,
            "artifact_key": meta.get("artifact_key"),
            "image_input": meta.get("image_input"),
            "image_resolved": meta.get("image_resolved"),
            "digest": meta.get("digest"),
        },
        "counts": {
            "techniques": len(summary),
            "p1": sum(1 for item in summary if item.get("priority") == "P1"),
            "p2": sum(1 for item in summary if item.get("priority") == "P2"),
            "p3": sum(1 for item in summary if item.get("priority") == "P3"),
            "p4": sum(1 for item in summary if item.get("priority") == "P4"),
        },
        "techniques": summary,
    }

    write_json(mapping_path, attack_mapping_output)
    write_json(summary_path, attack_summary_output)

    print(f"[bold green]Wrote[/bold green]: {mapping_path}")
    print(f"[bold green]Wrote[/bold green]: {summary_path}")


if __name__ == "__main__":
    app()
