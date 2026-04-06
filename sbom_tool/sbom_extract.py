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


def is_digest_ref(image_ref: str) -> bool:
    return "@sha256:" in image_ref or image_ref.startswith("sha256:")


def docker_image_exists(image_ref: str) -> bool:
    p = subprocess.run(
        ["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
    )
    return p.returncode == 0


def resolve_digest_remote(image_ref: str) -> Optional[str]:
    """
    Try resolving digest from registry using skopeo.
    Returns "sha256:..." or None.
    """
    try:
        out = run(["skopeo", "inspect", f"docker://{image_ref}"])
        data = json.loads(out)
        digest = data.get("Digest")
        if digest and isinstance(digest, str) and digest.startswith("sha256:"):
            return digest
    except Exception:
        pass
    return None


def resolve_digest_local(image_ref: str) -> Optional[str]:
    """
    Try resolving digest from a local Docker image.
    Returns "sha256:..." or None.
    """
    try:
        out = run(["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"])
        digest = out.strip()
        if digest.startswith("sha256:"):
            return digest
    except Exception:
        pass
    return None


def resolve_digest(image_ref: str, *, allow_pull: bool, platform: Optional[str]) -> str:
    """
    Returns "sha256:...."

    Resolution order:
    1. If already digest-pinned, return it
    2. Try remote registry via skopeo
    3. Try local Docker image
    4. If allowed, docker pull the tag and inspect locally
    """
    if is_digest_ref(image_ref):
        if image_ref.startswith("sha256:"):
            return image_ref
        return image_ref.split("@", 1)[1]

    digest = resolve_digest_remote(image_ref)
    if digest:
        return digest

    digest = resolve_digest_local(image_ref)
    if digest:
        return digest

    if allow_pull:
        docker_pull(image_ref, platform)
        digest = resolve_digest_local(image_ref)
        if digest:
            return digest

    raise RuntimeError(
        f"Could not resolve digest for image: {image_ref}\n"
        "Tried registry lookup (skopeo), local Docker inspect, and optional pull."
    )


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


def docker_pull(image_ref: str, platform: Optional[str]) -> None:
    cmd = ["docker", "pull"]
    if platform:
        cmd += ["--platform", platform]
    cmd.append(image_ref)
    run(cmd)


def syft_sbom(image_ref: str, out_path: Path, fmt: str) -> None:
    """
    fmt: cyclonedx-json | spdx-json
    """
    sbom_json = run([
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "anchore/syft:latest",
        image_ref,
        "-o", fmt
    ])
    out_path.write_text(sbom_json, encoding="utf-8")


def validate_json(path: Path) -> None:
    json.loads(path.read_text(encoding="utf-8"))


def write_digest_registry(project_root: Path, artifact_key: str, record: dict) -> None:
    digests_dir = project_root / "digests"
    digests_dir.mkdir(parents=True, exist_ok=True)

    (digests_dir / f"{artifact_key}.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )

    index_path = digests_dir / "index.json"
    if index_path.exists():
        index = json.loads(index_path.read_text(encoding="utf-8"))
    else:
        index = {}

    index[artifact_key] = record
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")


def main(
    image: str = "",
    tar_path: Optional[str] = None,
    tar_image: Optional[str] = None,
    platform: str = "linux/amd64",
    short_len: int = 16,
    skip_pull: bool = False,
):
    """
    Extract SBOMs into:
      artifacts/<artifact_key>/
    Register full digest in:
      digests/<artifact_key>.json + digests/index.json

    This is a normal Python function so it is safe to call from the API code.
    """
    project_root = Path(__file__).resolve().parent.parent
    artifacts_dir = project_root / "artifacts"
    digests_dir = project_root / "digests"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    digests_dir.mkdir(parents=True, exist_ok=True)

    loaded_from_tar = False

    if tar_path:
        loaded_images = load_images_from_tar(Path(tar_path))
        loaded_from_tar = True

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

    # Resolve digest safely.
    # For tar-loaded images, or when pull is skipped, we don't want to blindly require a registry roundtrip.
    full_digest = resolve_digest(
        image,
        allow_pull=(not skip_pull and not loaded_from_tar),
        platform=platform,
    )

    artifact_key = choose_artifact_key(full_digest, digests_dir, initial_len=short_len)

    repo = strip_tag(image)
    image_with_digest = image
    if not is_digest_ref(image):
        image_with_digest = f"{repo}@{full_digest}"

    out_dir = artifacts_dir / artifact_key
    out_dir.mkdir(parents=True, exist_ok=True)

    cdx_path = out_dir / "sbom.cdx.json"
    spdx_path = out_dir / "sbom.spdx.json"
    meta_path = out_dir / "sbom.meta.json"

    # Cache hit
    if cdx_path.exists() and spdx_path.exists() and meta_path.exists():
        print(f"[yellow]Cache hit[/yellow]: {out_dir}")
        record = {
            "artifact_key": artifact_key,
            "full_digest": full_digest,
            "image_input": image,
            "image_resolved": image_with_digest,
            "image_scan_ref": image,
            "artifact_dir": f"artifacts/{artifact_key}",
            "created_at": datetime.now(IST).isoformat(),
        }
        write_digest_registry(project_root, artifact_key, record)
        return record

    print("[cyan]Ensuring Syft image...[/cyan]")
    ensure_syft_image()

    # Ensure the local image exists when scanning by tag.
    # If the image is already digest-pinned, pull that exact digest.
    if not skip_pull and not loaded_from_tar:
        if is_digest_ref(image):
            print(f"[cyan]Pulling image[/cyan]: {image}")
            docker_pull(image, platform)
        else:
            print(f"[cyan]Pulling image[/cyan]: {image}")
            docker_pull(image, platform)

    # Important:
    # Scan the original image reference (usually tag) once it is available locally.
    # Store the resolved digest separately in metadata/registry.
    scan_ref = image

    print("[green]Generating CycloneDX SBOM...[/green]")
    syft_sbom(scan_ref, cdx_path, "cyclonedx-json")

    print("[green]Generating SPDX SBOM...[/green]")
    syft_sbom(scan_ref, spdx_path, "spdx-json")

    validate_json(cdx_path)
    validate_json(spdx_path)

    meta = {
        "image_input": image,
        "image_resolved": image_with_digest,
        "image_scan_ref": scan_ref,
        "digest": full_digest,
        "artifact_key": artifact_key,
        "artifact_dir": f"artifacts/{artifact_key}",
        "platform": platform,
        "generated_at": datetime.now(IST).isoformat(),
        "generator": {"name": "syft (docker)", "version": syft_version()},
        "outputs": {
            "cyclonedx_json": "sbom.cdx.json",
            "spdx_json": "sbom.spdx.json",
        },
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    record = {
        "artifact_key": artifact_key,
        "full_digest": full_digest,
        "image_input": image,
        "image_resolved": image_with_digest,
        "image_scan_ref": scan_ref,
        "artifact_dir": f"artifacts/{artifact_key}",
        "created_at": datetime.now(IST).isoformat(),
    }
    write_digest_registry(project_root, artifact_key, record)

    print(f"[bold green]Done[/bold green] → {out_dir}")
    print(f"[bold green]Digest registry updated[/bold green] → {project_root / 'digests'}")
    return record


def cli(
    image: str = typer.Option("", "--image", "-i", help="Image ref (tag or digest), e.g. nginx:1.27-alpine"),
    tar_path: Optional[str] = typer.Option(None, "--tar-path", help="Path to local docker image tar archive"),
    tar_image: Optional[str] = typer.Option(None, "--tar-image", help="Image name from tar when archive has multiple images"),
    platform: str = typer.Option("linux/amd64", "--platform", help="Platform for reproducibility (default linux/amd64)"),
    short_len: int = typer.Option(16, "--short-len", help="Digest hex chars used in artifact folder name"),
    skip_pull: bool = typer.Option(False, "--skip-pull", help="Skip docker pull if image already available"),
):
    return main(
        image=image,
        tar_path=tar_path,
        tar_image=tar_image,
        platform=platform,
        short_len=short_len,
        skip_pull=skip_pull,
    )


if __name__ == "__main__":
    typer.run(cli)