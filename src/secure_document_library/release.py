"""Validation, publication, and rollback for sealed generic releases."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath

from .cache import EncryptedCache, KeyProvider
from .index_io import iter_file_blocks, iter_jsonl


REQUIRED_FILES = ("chunks.jsonl", "documents.jsonl", "files.jsonl", "sources.json", "version.json")
FORBIDDEN_FIELDS = frozenset({"content", "content_excerpt", "original_path", "absolute_path"})
CACHE_VERIFY_BATCH_SIZE = 1_000


def _absolute(value: object) -> bool:
    return isinstance(value, str) and (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute())


def calculate_index_digest(directory: Path) -> str:
    value = hashlib.sha256()
    for name in REQUIRED_FILES:
        path = directory / name
        if not path.is_file():
            raise ValueError(f"STAGING_INCOMPLETE:{name}")
        value.update(name.encode()); value.update(b"\0")
        if name == "version.json":
            version = json.loads(path.read_text(encoding="utf-8"))
            for mutable in ("status", "validation", "published_at", "rolled_back_at"):
                version.pop(mutable, None)
            value.update(json.dumps(version, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
        else:
            for block in iter_file_blocks(path): value.update(block)
        value.update(b"\0")
    return value.hexdigest()


def _required(record: dict, field: str, path: Path, line: int) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"INDEX_REQUIRED_FIELD_MISSING:{path.name}:{line}:{field}")
    return value


def validate_release(directory: Path, *, provider: KeyProvider | None = None) -> dict:
    directory = directory.resolve()
    if any(not (directory / name).is_file() for name in REQUIRED_FILES):
        raise ValueError("STAGING_INCOMPLETE")
    version = json.loads((directory / "version.json").read_text(encoding="utf-8"))
    active_provider = provider or KeyProvider.from_environment()
    content_id, search_id = version.get("content_key_id"), version.get("search_key_id")
    content_fingerprint, search_fingerprint = version.get("content_key_fingerprint"), version.get("search_key_fingerprint")
    if not all(isinstance(value, str) and value for value in (content_id, search_id, content_fingerprint, search_fingerprint)):
        raise ValueError("KEY_METADATA_MISSING")
    try:
        actual_content = active_provider.content_fingerprint(content_id)
        actual_search = active_provider.search_fingerprint(search_id)
    except ValueError as exc:
        raise ValueError("KEY_GENERATION_UNAVAILABLE") from exc
    if actual_content != content_fingerprint:
        raise ValueError("CONTENT_KEY_MATERIAL_CHANGED_WITHOUT_NEW_ID")
    if actual_search != search_fingerprint:
        raise ValueError("SEARCH_KEY_MATERIAL_CHANGED_WITHOUT_NEW_ID")
    cache = EncryptedCache(Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"]), active_provider)
    documents_path, chunks_path, files_path = directory / "documents.jsonl", directory / "chunks.jsonl", directory / "files.jsonl"
    documents: set[str] = set(); chunks: set[str] = set(); document_owner: set[str] = set(); chunk_owner: set[str] = set()
    for line, record in iter_jsonl(documents_path):
        if FORBIDDEN_FIELDS & record.keys() or _absolute(record.get("source_relative_path")): raise ValueError("PLAINTEXT_OR_ABSOLUTE_PATH_IN_INDEX")
        record_id = _required(record, "document_id", documents_path, line)
        _required(record, "source_id", documents_path, line)
        if record_id in documents: raise ValueError("DUPLICATE_DOCUMENT_ID")
        documents.add(record_id)
    refs: list[str] = []
    cache_verified = 0
    for line, record in iter_jsonl(chunks_path):
        if FORBIDDEN_FIELDS & record.keys() or _absolute(record.get("source_relative_path")): raise ValueError("PLAINTEXT_OR_ABSOLUTE_PATH_IN_INDEX")
        record_id = _required(record, "chunk_id", chunks_path, line)
        if record_id in chunks: raise ValueError("DUPLICATE_CHUNK_ID")
        if _required(record, "document_id", chunks_path, line) not in documents: raise ValueError("CHUNK_DOCUMENT_REFERENCE_INVALID")
        _required(record, "source_id", chunks_path, line)
        chunks.add(record_id); refs.append(_required(record, "cache_ref", chunks_path, line))
        if len(refs) >= CACHE_VERIFY_BATCH_SIZE:
            result = cache.verify(refs); cache_verified += int(result["checked"])
            if not result["ok"]: raise ValueError("CACHE_VERIFICATION_FAILED")
            refs.clear()
    if refs:
        result = cache.verify(refs); cache_verified += int(result["checked"])
        if not result["ok"]: raise ValueError("CACHE_VERIFICATION_FAILED")
    source_counts: dict[str, list[int]] = {}
    files = set()
    for line, record in iter_jsonl(files_path):
        file_identifier = _required(record, "file_id", files_path, line)
        if file_identifier in files: raise ValueError("DUPLICATE_FILE_ID")
        files.add(file_identifier)
        if record.get("status") != "success": raise ValueError("FILE_STATUS_INVALID")
        source_id = _required(record, "source_id", files_path, line)
        if _absolute(record.get("relative_path")): raise ValueError("PLAINTEXT_OR_ABSOLUTE_PATH_IN_INDEX")
        document_ids, chunk_ids = record.get("document_ids"), record.get("chunk_ids")
        if not isinstance(document_ids, list) or not isinstance(chunk_ids, list): raise ValueError("FILE_REFERENCE_INVALID")
        if not document_ids or not chunk_ids or not set(document_ids).issubset(documents) or not set(chunk_ids).issubset(chunks): raise ValueError("FILE_REFERENCE_INVALID")
        if document_owner.intersection(document_ids) or chunk_owner.intersection(chunk_ids): raise ValueError("RECORD_OWNERSHIP_INVALID")
        document_owner.update(document_ids); chunk_owner.update(chunk_ids)
        values = source_counts.setdefault(source_id, [0, 0, 0]); values[0] += 1; values[1] += len(document_ids); values[2] += len(chunk_ids)
    if not documents or not chunks or not files or document_owner != documents or chunk_owner != chunks: raise ValueError("INDEX_INCOMPLETE")
    expected_counts = (version.get("file_count"), version.get("document_count"), version.get("chunk_count"))
    if expected_counts != (len(files), len(documents), len(chunks)) or version.get("failed_file_count") != 0: raise ValueError("INDEX_COUNT_MISMATCH")
    if len(documents) < int(version.get("minimum_document_count", 1)): raise ValueError("MINIMUM_DOCUMENT_COUNT_NOT_MET")
    for source, counts in source_counts.items():
        if not all(counts) or version.get("source_file_counts", {}).get(source) != counts[0] or version.get("source_document_counts", {}).get(source) != counts[1] or version.get("source_chunk_counts", {}).get(source) != counts[2]: raise ValueError("SOURCE_CONTRIBUTION_INVALID")
    try:
        sources = json.loads((directory / "sources.json").read_text(encoding="utf-8")).get("sources")
    except (AttributeError, json.JSONDecodeError) as exc:
        raise ValueError("SOURCES_MANIFEST_INVALID") from exc
    if not isinstance(sources, list) or len(sources) != version.get("source_count") or {item.get("source_id") for item in sources if isinstance(item, dict)} != set(source_counts):
        raise ValueError("SOURCES_MANIFEST_INVALID")
    return {"files": len(files), "documents": len(documents), "chunks": len(chunks), "cache_verified": cache_verified, "index_digest": calculate_index_digest(directory)}


@contextmanager
def _lock(index_root: Path):
    path = index_root / ".publish.lock"; path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0); handle.write(b"0"); handle.flush(); msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        yield
    finally:
        if os.name == "nt":
            try: handle.seek(0); msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError: pass
        handle.close()


def _switch_current(index_root: Path, prepared: Path, build_id: str) -> None:
    current, backup = index_root / "current", index_root / f".previous-{build_id}"
    try:
        if current.exists(): current.rename(backup)
        prepared.rename(current)
        if backup.exists(): backup.rename(index_root / "releases" / f"previous-{build_id}")
    except Exception:
        if current.exists(): shutil.rmtree(current)
        if backup.exists(): backup.rename(current)
        if prepared.exists(): shutil.rmtree(prepared)
        raise


def publish(staging: Path, index_root: Path, *, expected_build_id: str | None = None, provider: KeyProvider | None = None) -> Path:
    staging, index_root = staging.resolve(), index_root.resolve()
    visible = validate_release(staging, provider=provider)
    version = json.loads((staging / "version.json").read_text(encoding="utf-8")); build_id = version.get("build_id")
    if not isinstance(build_id, str) or (expected_build_id and build_id != expected_build_id): raise ValueError("EXPECTED_BUILD_ID_MISMATCH")
    with _lock(index_root):
        publishing, release, prepared = index_root / f".publishing-{build_id}", index_root / "releases" / build_id, index_root / f".current-{build_id}"
        if publishing.exists() or release.exists() or prepared.exists(): raise FileExistsError("RELEASE_ALREADY_EXISTS")
        shutil.copytree(staging, publishing)
        private = validate_release(publishing, provider=provider)
        if private["index_digest"] != visible["index_digest"]: shutil.rmtree(publishing); raise ValueError("STAGING_CHANGED_DURING_PUBLICATION")
        shutil.copytree(publishing, prepared)
        if calculate_index_digest(prepared) != visible["index_digest"]: shutil.rmtree(prepared); shutil.rmtree(publishing); raise ValueError("PREPARED_RELEASE_DIGEST_MISMATCH")
        release.parent.mkdir(parents=True, exist_ok=True); publishing.rename(release)
        _switch_current(index_root, prepared, build_id)
    return release


def list_releases(index_root: Path) -> list[str]:
    releases = index_root.resolve() / "releases"
    return sorted(path.name for path in releases.iterdir() if path.is_dir()) if releases.is_dir() else []


def rollback(build_id: str, index_root: Path, *, provider: KeyProvider | None = None) -> Path:
    index_root = index_root.resolve(); release = index_root / "releases" / build_id
    validation = validate_release(release, provider=provider)
    with _lock(index_root):
        prepared = index_root / f".rollback-{build_id}"
        if prepared.exists(): shutil.rmtree(prepared)
        shutil.copytree(release, prepared)
        if calculate_index_digest(prepared) != validation["index_digest"]: shutil.rmtree(prepared); raise ValueError("PREPARED_RELEASE_DIGEST_MISMATCH")
        _switch_current(index_root, prepared, build_id)
    return index_root / "current"
