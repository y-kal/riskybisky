# sbom_tool/vuln_scan.py
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import typer
from rich import print

app = typer.Typer(add_completion=False, no_args_is_help=True)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_packages_map(packages_path: Path) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Returns:
      purl_to_id: map purl -> internal package id
      fallback_to_id: map "<type>:<name>@<version>" -> internal package id
    """
    data = _read_json(packages_path)
    pkgs = data.get("packages") if isinstance(data, dict) else data
    if not isinstance(pkgs, list):
        raise ValueError("packages.json must be a list or an object with key 'packages'")

    purl_to_id: Dict[str, str] = {}
    fallback_to_id: Dict[str, str] = {}

    for p in pkgs:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("id") or "").strip()
        if not pid:
            continue

        purl = p.get("purl")
        if isinstance(purl, str) and purl.strip():
            purl_to_id[purl.strip()] = pid

        ptype = str(p.get("type") or "unknown").strip()
        name = str(p.get("name") or "").strip()
        version = str(p.get("version") or "UNKNOWN").strip()
        if name:
            fallback_to_id[f"{ptype}:{name}@{version}"] = pid

    return purl_to_id, fallback_to_id


def _resolve_pkg_id(artifact: Dict[str, Any], purl_to_id: Dict[str, str], fallback_to_id: Dict[str, str]) -> str:
    purl = artifact.get("purl")
    if isinstance(purl, str) and purl in purl_to_id:
        return purl_to_id[purl]

    name = str(artifact.get("name") or "").strip()
    version = str(artifact.get("version") or "UNKNOWN").strip()
    ptype = str(artifact.get("type") or "unknown").strip()
    key = f"{ptype}:{name}@{version}"
    if key in fallback_to_id:
        return fallback_to_id[key]

    # fallback: keep something stable even if we can't join to packages.json
    if isinstance(purl, str) and purl.strip():
        return purl.strip()
    return key


def _extract_fix_info(match: Dict[str, Any]) -> Tuple[List[str], Optional[str]]:
    """
    Best-effort extraction across Grype versions:
      - fix_versions: list[str]
      - fix_state: e.g. fixed / not-fixed / wont-fix / unknown (if present)
    """
    vuln = match.get("vulnerability") or {}
    fix = vuln.get("fix")

    fix_versions: List[str] = []
    fix_state: Optional[str] = None

    if isinstance(fix, dict):
        vs = fix.get("versions")
        if isinstance(vs, list):
            fix_versions = [str(x) for x in vs if str(x).strip()]
        st = fix.get("state") or fix.get("status")
        if isinstance(st, str) and st.strip():
            fix_state = st.strip()

    return fix_versions, fix_state


def _extract_match_types(match: Dict[str, Any]) -> List[str]:
    """
    Grype JSON includes match detail objects; we store any type/matcher fields we find
    so we can later filter by confidence (exact-direct, exact-indirect, cpe-match, etc.).
    """
    out: List[str] = []
    details = match.get("matchDetails") or match.get("match_details") or []
    if isinstance(details, list):
        for d in details:
            if not isinstance(d, dict):
                continue
            for k in ("type", "matchType", "matcher", "confidence"):
                v = d.get(k)
                if isinstance(v, str) and v.strip():
                    out.append(f"{k}:{v.strip()}")
    return sorted(set(out))


def _grype_scan_sbom(scan_dir: Path, out_raw: Path, grype_image: str, by_cve: bool, use_cache: bool) -> None:
    sbom_path = scan_dir / "sbom.cdx.json"
    if not sbom_path.exists():
        raise FileNotFoundError(f"Missing {sbom_path}")

    # Optional: persist Grype DB cache across runs (faster + less network)
    # Linux default cache is typically ~/.cache/grype/... :contentReference[oaicite:1]{index=1}
    cache_mount: List[str] = []
    if use_cache:
        host_cache = (Path.home() / ".cache" / "grype").resolve()
        host_cache.mkdir(parents=True, exist_ok=True)
        cache_mount = ["-v", f"{host_cache}:/root/.cache/grype"]

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{scan_dir.resolve()}:/scan:ro",
        *cache_mount,
        grype_image,
        f"sbom:/scan/{sbom_path.name}",
        "-o", "json",
    ]
    if by_cve:
        # Normalise vuln IDs to CVE where possible (easier correlation later). :contentReference[oaicite:2]{index=2}
        cmd.append("--by-cve")

    p = _run(cmd)
    if p.returncode != 0:
        raise RuntimeError(f"Grype failed:\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")

    out_raw.write_text(p.stdout, encoding="utf-8")


def _grype_scan_image(image_ref: str, out_raw: Path, grype_image: str, by_cve: bool, use_cache: bool) -> None:
    cache_mount: List[str] = []
    if use_cache:
        host_cache = (Path.home() / ".cache" / "grype").resolve()
        host_cache.mkdir(parents=True, exist_ok=True)
        cache_mount = ["-v", f"{host_cache}:/root/.cache/grype"]

    # Scanning Docker images from the Grype container typically mounts docker.sock. :contentReference[oaicite:3]{index=3}
    cmd = [
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        *cache_mount,
        grype_image,
        image_ref,
        "-o", "json",
    ]
    if by_cve:
        cmd.append("--by-cve")

    p = _run(cmd)
    if p.returncode != 0:
        raise RuntimeError(f"Grype failed:\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")

    out_raw.write_text(p.stdout, encoding="utf-8")


@app.command()
def main(
    scan_dir: Path = typer.Option(..., "--scan-dir", help="Path like artifacts/<artifact_key>"),
    mode: str = typer.Option("sbom", "--mode", help="sbom (recommended) or image"),
    grype_image: str = typer.Option("anchore/grype:latest", "--grype-image", help="Docker image for Grype"),
    by_cve: bool = typer.Option(True, "--by-cve/--no-by-cve", help="Prefer CVE IDs when possible"),
    use_cache: bool = typer.Option(True, "--cache/--no-cache", help="Persist Grype DB cache across runs"),
    force: bool = typer.Option(False, "--force", help="Rescan even if outputs already exist"),
):
    scan_dir = scan_dir.resolve()
    if not scan_dir.exists():
        raise typer.BadParameter(f"scan_dir does not exist: {scan_dir}")

    meta_path = scan_dir / "sbom.meta.json"
    packages_path = scan_dir / "packages.json"
    if not meta_path.exists():
        raise typer.BadParameter(f"Missing sbom.meta.json in {scan_dir}")
    if not packages_path.exists():
        raise typer.BadParameter(f"Missing packages.json in {scan_dir}")

    meta = _read_json(meta_path)
    image_resolved = meta.get("image_resolved") or meta.get("image")  # best-effort

    out_raw = scan_dir / "vulns.grype.json"
    out_norm = scan_dir / "vulns.json"

    if (out_raw.exists() and out_norm.exists()) and not force:
        print(f"[yellow]Skipping[/yellow] (already exists): {out_raw.name}, {out_norm.name}  (use --force to rescan)")
        raise typer.Exit(code=0)

    # 1) Run Grype (raw)
    print(f"[cyan]Running Grype[/cyan] mode={mode} -> {out_raw}")
    if mode.lower() == "sbom":
        _grype_scan_sbom(scan_dir, out_raw, grype_image, by_cve, use_cache)
    elif mode.lower() == "image":
        if not isinstance(image_resolved, str) or not image_resolved.strip():
            raise typer.BadParameter("sbom.meta.json missing usable image_resolved/image for --mode image")
        _grype_scan_image(image_resolved.strip(), out_raw, grype_image, by_cve, use_cache)
    else:
        raise typer.BadParameter("mode must be 'sbom' or 'image'")

    raw = _read_json(out_raw)

    # 2) Normalise (join to packages.json)
    purl_to_id, fallback_to_id = _load_packages_map(packages_path)

    vulns: List[Dict[str, Any]] = []
    matches = raw.get("matches") if isinstance(raw, dict) else None
    if not isinstance(matches, list):
        matches = []

    for m in matches:
        if not isinstance(m, dict):
            continue

        vuln = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}

        vuln_id = str(vuln.get("id") or "").strip()
        if not vuln_id:
            continue

        pkg_id = _resolve_pkg_id(artifact, purl_to_id, fallback_to_id)
        fix_versions, fix_state = _extract_fix_info(m)

        entry = {
            "vuln_id": vuln_id,                       # CVE/GHSA/etc (prefer CVE when --by-cve). :contentReference[oaicite:4]{index=4}
            "severity": vuln.get("severity") or "Unknown",
            "package_id": pkg_id,
            "package_name": artifact.get("name"),
            "package_version": artifact.get("version"),
            "package_type": artifact.get("type"),
            "purl": artifact.get("purl"),
            "cpe": artifact.get("cpe"),
            "fix_versions": fix_versions,
            "fix_state": fix_state,
            "match_types": _extract_match_types(m),   # keep for confidence filtering (exact/direct/cpe-match, etc.). :contentReference[oaicite:5]{index=5}
            "source": {"scanner": "grype", "mode": mode, "grype_image": grype_image},
        }
        vulns.append(entry)

    # simple summary
    sev_counts: Dict[str, int] = {}
    for v in vulns:
        s = str(v.get("severity") or "Unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    normalized = {
        "generated_at": _iso_now(),
        "scan_dir": str(scan_dir),
        "image": meta.get("image"),
        "image_resolved": meta.get("image_resolved"),
        "artifact_key": meta.get("artifact_key"),
        "counts": {
            "total": len(vulns),
            "by_severity": dict(sorted(sev_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        },
        "vulnerabilities": vulns,
    }

    _write_json(out_norm, normalized)

    # 3) Update meta (non-destructive)
    meta.setdefault("outputs", {})
    meta["outputs"]["grype_raw"] = out_raw.name
    meta["outputs"]["vulns_normalized"] = out_norm.name
    meta["outputs"]["vuln_scan_completed_at"] = _iso_now()
    _write_json(meta_path, meta)

    print(f"[green]Done[/green] wrote: {out_raw.name}, {out_norm.name}")


if __name__ == "__main__":
    app()