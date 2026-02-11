import json
from pathlib import Path
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

import typer
from rich import print

def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def is_cyclonedx(data: Dict[str, Any]) -> bool:
    return data.get("bomFormat") == "CycloneDX" or "components" in data

def pick_license_strings(lic_obj: Any) -> List[str]:
    out = []
    if not lic_obj:
        return out
    if isinstance(lic_obj, list):
        for item in lic_obj:
            if isinstance(item, dict):
                lic = item.get("license") or item.get("expression") or item
                if isinstance(lic, dict):
                    out.append(lic.get("id") or lic.get("name") or "")
                elif isinstance(lic, str):
                    out.append(lic)
    elif isinstance(lic_obj, str):
        out.append(lic_obj)
    return [x for x in (s.strip() for s in out) if x]

def props_to_map(props: Any) -> Dict[str, str]:
    m = {}
    if isinstance(props, list):
        for p in props:
            if isinstance(p, dict) and "name" in p and "value" in p:
                m[str(p["name"])] = str(p["value"])
    return m

def make_pkg_id(purl: Optional[str], ptype: str, name: str, version: Optional[str]) -> str:
    if purl:
        return purl
    v = version or "UNKNOWN"
    t = ptype or "unknown"
    return f"{t}:{name}@{v}"

def parse_cyclonedx(data: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[str]], List[str]]:
    components = data.get("components", []) or []
    pkg_by_ref: Dict[str, Dict[str, Any]] = {}

    roots: List[str] = []
    meta_comp = (data.get("metadata") or {}).get("component")
    if isinstance(meta_comp, dict):
        rref = meta_comp.get("bom-ref") or meta_comp.get("bomRef")
        if rref:
            roots.append(rref)

    for comp in components:
        if not isinstance(comp, dict):
            continue

        bom_ref = comp.get("bom-ref") or comp.get("bomRef") or comp.get("ref")
        if not bom_ref:
            bom_ref = comp.get("purl") or f"ref::{comp.get('type','unknown')}::{comp.get('name','unknown')}::{comp.get('version','')}"

        purl = comp.get("purl")
        cpe = comp.get("cpe")
        name = comp.get("name") or "UNKNOWN"
        version = comp.get("version")
        ptype = comp.get("type") or "unknown"

        supplier = None
        if isinstance(comp.get("supplier"), dict):
            supplier = comp["supplier"].get("name")

        hashes = []
        for h in comp.get("hashes", []) or []:
            if isinstance(h, dict) and h.get("alg") and h.get("content"):
                hashes.append({"alg": h["alg"], "content": h["content"]})

        licenses = pick_license_strings(comp.get("licenses"))

        props = props_to_map(comp.get("properties"))
        locations = []
        for _, v in props.items():
            if "/" in v and len(v) <= 300:
                locations.append(v)

        pkg_id = make_pkg_id(purl, ptype, name, version)

        pkg_by_ref[bom_ref] = {
            "id": pkg_id,
            "name": name,
            "version": version,
            "type": ptype,
            "purl": purl,
            "cpe": cpe,
            "licenses": licenses,
            "supplier": supplier,
            "hashes": hashes,
            "locations": sorted(set(locations)),
            "dependencies": [],
            "dependency_depth": 0,
            "_bom_ref": bom_ref,
        }

    deps_by_ref: Dict[str, List[str]] = defaultdict(list)
    for d in data.get("dependencies", []) or []:
        if not isinstance(d, dict):
            continue
        ref = d.get("ref")
        depends_on = d.get("dependsOn") or []
        if ref and isinstance(depends_on, list):
            deps_by_ref[ref] = [x for x in depends_on if isinstance(x, str)]

    if not roots:
        all_nodes = set(pkg_by_ref.keys())
        depended = set()
        for _, deps in deps_by_ref.items():
            depended.update(deps)
        roots = list(all_nodes - depended)[:5]

    return pkg_by_ref, deps_by_ref, roots

def compute_depths(nodes: List[str], deps: Dict[str, List[str]], roots: List[str]) -> Dict[str, int]:
    depth: Dict[str, int] = {}
    q = deque()
    for r in roots:
        depth[r] = 0
        q.append(r)

    while q:
        cur = q.popleft()
        for nxt in deps.get(cur, []):
            if nxt not in nodes:
                continue
            nd = depth[cur] + 1
            if nxt not in depth or nd < depth[nxt]:
                depth[nxt] = nd
                q.append(nxt)

    for n in nodes:
        if n not in depth:
            depth[n] = 0
    return depth

def main(
    scan_dir: Path = typer.Option(..., "--scan-dir", help="Path to artifacts/<artifact_key>/"),
    force: bool = typer.Option(False, "--force", help="Regenerate packages.json even if it exists"),
):
    cdx_path = scan_dir / "sbom.cdx.json"
    meta_path = scan_dir / "sbom.meta.json"
    out_path = scan_dir / "packages.json"

    if out_path.exists() and not force:
        print(f"[yellow]packages.json already exists[/yellow]: {out_path}")
        return

    if not cdx_path.exists():
        raise RuntimeError(f"Missing: {cdx_path}")

    data = load_json(cdx_path)
    if not is_cyclonedx(data):
        raise RuntimeError("sbom.cdx.json does not look like CycloneDX.")

    pkg_map, deps_map, roots = parse_cyclonedx(data)
    node_refs = list(pkg_map.keys())
    depths = compute_depths(node_refs, deps_map, roots)

    for ref, pkg in pkg_map.items():
        pkg["dependencies"] = [pkg_map[d]["id"] for d in deps_map.get(ref, []) if d in pkg_map]
        pkg["dependency_depth"] = depths.get(ref, 0)

    meta = load_json(meta_path) if meta_path.exists() else {}
    output = {
        "source": {
            "image": meta.get("image_input", ""),
            "image_resolved": meta.get("image_resolved", ""),
            "digest": meta.get("digest", ""),
            "artifact_key": meta.get("artifact_key", ""),
            "sbom_format": "cyclonedx-json",
            "roots": roots,
        },
        "packages": sorted(
            list(pkg_map.values()),
            key=lambda x: (x["dependency_depth"], x["type"], x["name"], x.get("version") or "")
        )
    }

    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"[bold green]Wrote[/bold green]: {out_path}")

if __name__ == "__main__":
    typer.run(main)
