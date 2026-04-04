from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
DIGESTS_DIR = PROJECT_ROOT / "digests"
JOBS_DIR = PROJECT_ROOT / "jobs"
DEFAULT_PLATFORM = "linux/amd64"
