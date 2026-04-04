import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import typer
from rich import print

IST = timezone(timedelta(hours=5, minutes=30))

def run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed:\n  {' '.join(cmd)}\n\n{p.stderr.strip()}")
    return p.stdout

def strip_tag(image_ref: str) -> str:
    """
    Turn:
      nginx:1.27 -> nginx
      ghcr.io/org/app:tag -> ghcr.io/org/app
      localhost:5000/app:tag -> localhost:5000/app
      nginx@sha256:... -> nginx
    """
    base = image_ref.split("@", 1)[0]
    last_slash = base.rfind("/")
    last_colon = base.rfind(":")
    if last_colon > last_slash:
        return base[:last_colon]
    return base

def resolve_digest(image_ref: str) -> str:
    """
    Returns "sha256:...."
    """
    if "@sha256:" in image_ref:
        return image_ref.split("@", 1)[1]

    try:
        out = run(["skopeo", "inspect", f"docker://{image_ref}"])
        data = json.loads(out)
        digest = data.get("Digest")
        if digest:
            return digest
    except Exception:
        pass

    out = run(["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"])
    digest = out.strip()
    if not digest or not digest.startswith("sha256:"):
        raise RuntimeError("Could not resolve digest from skopeo or docker inspect output.")
    return digest

def load_images_from_tar(tar_path: Path) -> list[str]:
    out = run(["docker", "load", "-i", str(tar_path)])
    images: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Loaded image:"):
            images.append(line.split("Loaded image:", 1)[1].strip())
        elif line.startswith("Loaded image ID:"):
            images.append(line.split("Loaded image ID:", 1)[1].strip())
    return [name for name in images if name]

def digest_hex(full_digest: str) -> str:
    return full_digest.split(":", 1)[1]

def choose_artifact_key(full_digest: str, digests_dir: Path, initial_len: int = 16) -> str:
    """
    Picks a short key like sha256_<first16>, extends if collision.
    Uses digests/index.json to avoid mismapping.
    """
    digests_dir.mkdir(parents=True, exist_ok=True)
    index_path = digests_dir / "index.json"
    if index_path.exists():
        index = json.loads(index_path.read_text(encoding="utf-8"))
    else:
        index = {}

    full_hex = digest_hex(full_digest)

    # Try initial_len, then extend
    for n in (initial_len, 20, 24, 32, 40, 48, 64):
        key = f"sha256_{full_hex[:n]}"
        if key not in index:
            return key
        if index[key].get("full_digest") == full_digest:
            return key
    raise RuntimeError("Unable to choose unique artifact key (unexpected).")

def ensure_syft_image() -> None:
    run(["docker", "pull", "anchore/syft:latest"])

def syft_version() -> str:
    return run(["docker", "run", "--rm", "anchore/syft:latest", "version"]).strip()

def docker_pull(image_with_digest: str, platform: Optional[str]) -> None:
    cmd = ["docker", "pull"]
    if platform:
        cmd += ["--platform", platform]
    cmd.append(image_with_digest)
    run(cmd)

def syft_sbom(image_with_digest: str, out_path: Path, fmt: str) -> None:
    """
    fmt: cyclonedx-json | spdx-json
    """
    sbom_json = run([
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "anchore/syft:latest",
        image_with_digest,
        "-o", fmt
    ])
    out_path.write_text(sbom_json, encoding="utf-8")

def validate_json(path: Path) -> None:
    json.loads(path.read_text(encoding="utf-8"))

def write_digest_registry(project_root: Path, artifact_key: str, record: dict) -> None:
    digests_dir = project_root / "digests"
    digests_dir.mkdir(parents=True, exist_ok=True)

    # per key
    (digests_dir / f"{artifact_key}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")

    # global index
    index_path = digests_dir / "index.json"
    if index_path.exists():
        index = json.loads(index_path.read_text(encoding="utf-8"))
    else:
        index = {}
    index[artifact_key] = record
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")

def main(
    image: str = typer.Option("", "--image", "-i", help="Image ref (tag or digest), e.g. nginx:1.27-alpine"),
    tar_path: Optional[str] = typer.Option(None, "--tar-path", help="Path to local docker image tar archive"),
    tar_image: Optional[str] = typer.Option(None, "--tar-image", help="Image name from tar when archive has multiple images"),
    platform: str = typer.Option("linux/amd64", "--platform", help="Platform for reproducibility (default linux/amd64)"),
    short_len: int = typer.Option(16, "--short-len", help="Digest hex chars used in artifact folder name"),
    skip_pull: bool = typer.Option(False, "--skip-pull", help="Skip docker pull if image already available"),
):
    """
    Extract SBOMs into:
      artifacts/<artifact_key>/
    Register full digest in:
      digests/<artifact_key>.json + digests/index.json
    """
    project_root = Path(__file__).resolve().parent.parent  # riskybisky/riskybisky
    artifacts_dir = project_root / "artifacts"
    digests_dir = project_root / "digests"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    digests_dir.mkdir(parents=True, exist_ok=True)

    if tar_path:
        loaded_images = load_images_from_tar(Path(tar_path))
        if tar_image:
            image = tar_image.strip()
        elif len(loaded_images) == 1:
            image = loaded_images[0]
        elif len(loaded_images) > 1:
            available = ", ".join(loaded_images)
            raise RuntimeError(f"Tar contains multiple images. Provide tar_image. Available: {available}")
        else:
            raise RuntimeError("Could not detect any image names while loading tar archive")

    image = image.strip()
    if not image:
        raise RuntimeError("Image reference is required (image or tar_path must be provided)")

    full_digest = resolve_digest(image)  # sha256:...
    artifact_key = choose_artifact_key(full_digest, digests_dir, initial_len=short_len)

    repo = strip_tag(image)
    image_with_digest = image
    if "@sha256:" not in image and not image.startswith("sha256:"):
        image_with_digest = f"{repo}@{full_digest}"

    out_dir = artifacts_dir / artifact_key
    out_dir.mkdir(parents=True, exist_ok=True)

    cdx_path = out_dir / "sbom.cdx.json"
    spdx_path = out_dir / "sbom.spdx.json"
    meta_path = out_dir / "sbom.meta.json"

    # Cache hit
    if cdx_path.exists() and spdx_path.exists() and meta_path.exists():
        print(f"[yellow]Cache hit[/yellow]: {out_dir}")
        # still ensure digest registry exists
        record = {
            "artifact_key": artifact_key,
            "full_digest": full_digest,
            "image_input": image,
            "image_resolved": image_with_digest,
            "artifact_dir": f"artifacts/{artifact_key}",
            "created_at": datetime.now(IST).isoformat(),
        }
        write_digest_registry(project_root, artifact_key, record)
        return record

    print("[cyan]Ensuring Syft image...[/cyan]")
    ensure_syft_image()

    if not skip_pull:
        print(f"[cyan]Pulling image[/cyan]: {image_with_digest}")
        docker_pull(image_with_digest, platform)

    print("[green]Generating CycloneDX SBOM...[/green]")
    syft_sbom(image_with_digest, cdx_path, "cyclonedx-json")

    print("[green]Generating SPDX SBOM...[/green]")
    syft_sbom(image_with_digest, spdx_path, "spdx-json")

    validate_json(cdx_path)
    validate_json(spdx_path)

    meta = {
        "image_input": image,
        "image_resolved": image_with_digest,
        "digest": full_digest,
        "artifact_key": artifact_key,
        "artifact_dir": f"artifacts/{artifact_key}",
        "platform": platform,
        "generated_at": datetime.now(IST).isoformat(),
        "generator": {"name": "syft (docker)", "version": syft_version()},
        "outputs": {"cyclonedx_json": "sbom.cdx.json", "spdx_json": "sbom.spdx.json"},
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    record = {
        "artifact_key": artifact_key,
        "full_digest": full_digest,
        "image_input": image,
        "image_resolved": image_with_digest,
        "artifact_dir": f"artifacts/{artifact_key}",
        "created_at": datetime.now(IST).isoformat(),
    }
    write_digest_registry(project_root, artifact_key, record)

    print(f"[bold green]Done[/bold green] → {out_dir}")
    print(f"[bold green]Digest registry updated[/bold green] → {project_root / 'digests'}")
    return record

if __name__ == "__main__":
    typer.run(main)
