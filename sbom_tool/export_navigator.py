from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import typer
from rich import print

from sbom_tool.attack_common import iso_now, normalise_priority, read_json, safe_str, to_float, write_json

app = typer.Typer(add_completion=False, no_args_is_help=True)


def _priority_color(priority: str) -> str:
    mapping = {
        "P1": "#B42318",
        "P2": "#F79009",
        "P3": "#FEC84B",
        "P4": "#98A2B3",
    }
    return mapping.get(priority, "#98A2B3")


def build_navigator_layer(summary: Dict[str, Any], layer_name: str) -> Dict[str, Any]:
    techniques = summary.get("techniques", []) if isinstance(summary, dict) else []
    source = summary.get("source", {}) if isinstance(summary.get("source"), dict) else {}

    layer_techniques: List[Dict[str, Any]] = []
    for item in techniques:
        if not isinstance(item, dict):
            continue

        technique_id = safe_str(item.get("technique_id"))
        if not technique_id:
            continue

        aggregate_risk = round(to_float(item.get("aggregate_risk")) or 0.0, 3)
        priority = safe_str(item.get("priority")) or normalise_priority(aggregate_risk)
        tactics = item.get("tactics") if isinstance(item.get("tactics"), list) else []
        comment_parts = [
            f"Priority {priority}",
            f"Aggregate risk {aggregate_risk}",
            f"Vulns {item.get('vulnerability_count', 0)}",
        ]
        if tactics:
            comment_parts.append("Tactics: " + ", ".join(safe_str(x) for x in tactics if safe_str(x)))
        if isinstance(item.get("cves"), list) and item["cves"]:
            comment_parts.append("CVEs: " + ", ".join(item["cves"][:5]))

        layer_techniques.append(
            {
                "techniqueID": technique_id,
                "score": aggregate_risk,
                "color": _priority_color(priority),
                "comment": " | ".join(comment_parts),
                "metadata": [
                    {"name": "Technique", "value": safe_str(item.get("technique_name"))},
                    {"name": "Priority", "value": priority},
                    {"name": "Aggregate Risk", "value": str(aggregate_risk)},
                    {"name": "Max Risk", "value": str(item.get("max_risk_score", 0.0))},
                    {"name": "Average Confidence", "value": str(item.get("average_confidence", 0.0))},
                ],
            }
        )

    return {
        "name": layer_name,
        "description": (
            "Technique-centric view of container vulnerability exposure derived from riskybisky "
            "risk scores and ATT&CK mapping."
        ),
        "domain": "enterprise-attack",
        "versions": {
            "layer": "4.5",
            "navigator": "4.9.1",
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showID": False,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": layer_techniques,
        "gradient": {
            "colors": ["#D0D5DD", "#F79009", "#B42318"],
            "minValue": 0,
            "maxValue": 10,
        },
        "legendItems": [
            {"label": "P1", "color": _priority_color("P1")},
            {"label": "P2", "color": _priority_color("P2")},
            {"label": "P3", "color": _priority_color("P3")},
            {"label": "P4", "color": _priority_color("P4")},
        ],
        "metadata": [
            {"name": "Generated At", "value": iso_now()},
            {"name": "Artifact Key", "value": safe_str(source.get("artifact_key"))},
            {"name": "Scores File", "value": safe_str(source.get("scores_file"))},
            {"name": "Summary File", "value": safe_str(source.get("input_file"))},
        ],
    }


@app.command()
def main(
    scan_dir: Path = typer.Option(..., "--scan-dir", help="Path to artifacts/<artifact_key>"),
    summary_name: str = typer.Option("attack_summary.json", "--summary-name", help="Technique summary input"),
    out_name: str = typer.Option("attack_navigator_layer.json", "--out-name", help="Navigator layer output"),
    layer_name: str = typer.Option("riskybisky ATT&CK Exposure", "--layer-name", help="Navigator layer name"),
) -> None:
    summary_path = scan_dir / summary_name
    out_path = scan_dir / out_name

    if not summary_path.exists():
        raise FileNotFoundError(f"Missing {summary_path}")

    summary = read_json(summary_path)
    layer = build_navigator_layer(summary, layer_name=layer_name)
    write_json(out_path, layer)

    print(f"[bold green]Wrote[/bold green]: {out_path}")


if __name__ == "__main__":
    app()
