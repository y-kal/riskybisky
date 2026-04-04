from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    image: str = Field(..., description="Container image reference, tag or digest")
    platform: str = Field(default="linux/amd64", description="Target platform")
    short_len: int = Field(default=16, ge=8, le=64, description="Artifact key length")
    skip_pull: bool = Field(default=False, description="Skip docker pull before SBOM generation")


class JobResponse(BaseModel):
    job_id: str
    status: str
    stage: str
    message: Optional[str] = None
    artifact_key: Optional[str] = None
    artifact_dir: Optional[str] = None
    created_at: str
    updated_at: str
    request: Dict[str, Any]
    outputs: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class ArtifactSummary(BaseModel):
    artifact_key: str
    artifact_dir: str
    image_input: Optional[str] = None
    image_resolved: Optional[str] = None
    digest: Optional[str] = None
    platform: Optional[str] = None
    generated_at: Optional[str] = None
    files: List[str] = Field(default_factory=list)
    counts: Dict[str, Any] = Field(default_factory=dict)


class ArtifactListResponse(BaseModel):
    items: List[ArtifactSummary]


class ArtifactDetailResponse(BaseModel):
    summary: ArtifactSummary
    meta: Dict[str, Any] = Field(default_factory=dict)
    packages: Dict[str, Any] = Field(default_factory=dict)
    vulns: Dict[str, Any] = Field(default_factory=dict)
    enriched_vulns: Dict[str, Any] = Field(default_factory=dict)
    attack_mapping: Dict[str, Any] = Field(default_factory=dict)
    attack_summary: Dict[str, Any] = Field(default_factory=dict)
    navigator_layer: Dict[str, Any] = Field(default_factory=dict)
