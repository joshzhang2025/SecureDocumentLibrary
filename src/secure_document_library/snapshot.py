"""Pinned published-release snapshots for one request."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .cache import KeyProvider
from .release import calculate_index_digest, validate_release


@dataclass(frozen=True)
class ReleaseSnapshot:
    build_id: str
    release_path: Path
    provider: KeyProvider
    digest: str
    search_key_id: str

    @property
    def chunks_path(self) -> Path:
        return self.release_path / "chunks.jsonl"


def open_snapshot(index_root: Path, *, provider: KeyProvider | None = None) -> ReleaseSnapshot:
    index_root = index_root.resolve(); current = index_root / "current"
    version_path = current / "version.json"
    if not version_path.is_file(): raise FileNotFoundError("INDEX_UNAVAILABLE")
    version = json.loads(version_path.read_text(encoding="utf-8")); build_id = version.get("build_id")
    if not isinstance(build_id, str): raise ValueError("INDEX_INVALID")
    release = index_root / "releases" / build_id
    if not release.is_dir(): raise ValueError("CURRENT_RELEASE_NOT_IMMUTABLE")
    active = provider or KeyProvider.from_environment()
    validation = validate_release(release, provider=active)
    digest = calculate_index_digest(current)
    if digest != validation["index_digest"]: raise ValueError("CURRENT_RELEASE_DIGEST_MISMATCH")
    return ReleaseSnapshot(build_id, release, active, digest, version["search_key_id"])
