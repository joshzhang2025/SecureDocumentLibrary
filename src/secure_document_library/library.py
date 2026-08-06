"""Stable public facade for the sealed generic document-library lifecycle."""
from __future__ import annotations

import heapq
from collections.abc import Iterable
from pathlib import Path

from .build import build_staging
from .cache import EncryptedCache
from .index_io import iter_jsonl
from .release import CACHE_VERIFY_BATCH_SIZE, calculate_index_digest, validate_release
from .snapshot import ReleaseSnapshot, open_snapshot
from .tokens import digest, tokenize


DEFAULT_SEARCH_LIMIT = 100


def build(source_root: Path, index_root: Path) -> int:
    """Compatibility wrapper: build, validate, and publish one complete release."""
    from .release import publish
    staging = build_staging(source_root, index_root)
    validation = validate_release(staging)
    publish(staging, index_root, expected_build_id=staging.name)
    return int(validation["chunks"])


def _search_records(records: Iterable[dict], query: str, authorized_sources: set[str], *, cache: EncryptedCache, limit: int | None = None) -> list[dict]:
    """Stream index records and retain only the requested top results."""
    if not authorized_sources or (limit is not None and limit <= 0): return []
    terms = tokenize(query)
    def matches() -> Iterable[dict]:
        for record in records:
            if record.get("source_id") not in authorized_sources: continue
            body = record.get("content_token_hashes", {})
            metadata = f"{record.get('title', '')} {record.get('section_title') or ''}".lower()
            title_hits = sum(term in metadata for term in terms)
            body_hits = sum(min(int(body.get(digest(term, cache.search_key), 0)), 4) for term in terms)
            score = title_hits * 10 + body_hits
            if score:
                fields = ("chunk_id", "document_id", "source_id", "classification", "title", "section_title", "source_relative_path", "document_type", "document_part", "chunk_index", "char_start", "char_end")
                result = {field: record.get(field) for field in fields}
                result.update({"score": score, "confidence": "high" if score >= 10 else "medium" if score >= 3 else "weak", "matched_fields": (["title_or_section"] if title_hits else []) + (["body_hmac_tokens"] if body_hits else []), "matched_terms": [term for term in terms if term in metadata or int(body.get(digest(term, cache.search_key), 0)) > 0]})
                yield result
    rank = lambda item: (-item["score"], item["chunk_id"])
    return sorted(matches(), key=rank) if limit is None else heapq.nsmallest(limit, matches(), key=rank)


def search(index_root: Path, query: str, authorized_sources: set[str], *, limit: int = DEFAULT_SEARCH_LIMIT) -> list[dict]:
    snapshot = open_snapshot(index_root)
    cache = EncryptedCache(Path(__import__("os").environ["SECURE_LIBRARY_CACHE_ROOT"]), snapshot.provider)
    cache.search_key = snapshot.provider.search_key(snapshot.search_key_id)
    return _search_records((record for _, record in iter_jsonl(snapshot.chunks_path)), query, authorized_sources, cache=cache, limit=limit)


def retrieve(index_root: Path, chunk_id: str, authorized_sources: set[str]) -> str:
    snapshot = open_snapshot(index_root)
    cache = EncryptedCache(Path(__import__("os").environ["SECURE_LIBRARY_CACHE_ROOT"]), snapshot.provider)
    for _, record in iter_jsonl(snapshot.chunks_path):
        if record.get("chunk_id") == chunk_id:
            if record.get("source_id") not in authorized_sources: raise PermissionError("Not authorized")
            return cache.get(record["cache_ref"])
    raise KeyError("Unknown chunk ID")


def validate_index(index_root: Path) -> dict:
    """Validate an explicitly supplied sealed staging or release directory."""
    return validate_release(index_root)


__all__ = ["CACHE_VERIFY_BATCH_SIZE", "DEFAULT_SEARCH_LIMIT", "ReleaseSnapshot", "build", "build_staging", "calculate_index_digest", "open_snapshot", "retrieve", "search", "validate_index"]
