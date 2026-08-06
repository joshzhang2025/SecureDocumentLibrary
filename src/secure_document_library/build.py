"""Sealed full and incremental builders for the generic single-source library."""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .cache import EncryptedCache, KeyProvider
from .chunking import chunk_text
from .index_io import iter_file_blocks, iter_jsonl
from .library_ids import chunk_id, document_id, file_id
from .parsers import parse
from .tokens import frequencies


SUPPORTED = {".md", ".txt", ".yaml", ".yml", ".json", ".docx", ".xlsx"}


@dataclass(frozen=True)
class BuildOptions:
    minimum_document_count: int = 1
    parser_version: str = "generic-parser-v1"
    chunker_version: str = "heading-chunker-v1"


def _source_hash(path: Path) -> str:
    value = hashlib.sha256()
    for block in iter_file_blocks(path):
        value.update(block)
    return value.hexdigest()


def _build_id() -> str:
    return "GENERIC-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _write(handle, record: dict) -> None:
    handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def _baseline(current: Path, database: Path) -> sqlite3.Connection | None:
    if not current.is_dir():
        return None
    required = (current / "version.json", current / "files.jsonl", current / "documents.jsonl", current / "chunks.jsonl")
    if not all(path.is_file() for path in required):
        return None
    connection = sqlite3.connect(database)
    connection.execute("create table files (relative_path text primary key, payload text not null)")
    connection.execute("create table documents (record_id text primary key, payload text not null)")
    connection.execute("create table chunks (record_id text primary key, payload text not null)")
    for _, record in iter_jsonl(current / "files.jsonl"):
        connection.execute("insert into files values (?, ?)", (record.get("relative_path"), json.dumps(record, separators=(",", ":"))))
    for _, record in iter_jsonl(current / "documents.jsonl"):
        connection.execute("insert into documents values (?, ?)", (record.get("document_id"), json.dumps(record, separators=(",", ":"))))
    for _, record in iter_jsonl(current / "chunks.jsonl"):
        connection.execute("insert into chunks values (?, ?)", (record.get("chunk_id"), json.dumps(record, separators=(",", ":"))))
    connection.commit()
    return connection


def _compatible(record: dict, content_hash: str, options: BuildOptions, cache: EncryptedCache) -> bool:
    return (
        record.get("status") == "success"
        and record.get("content_hash") == content_hash
        and record.get("parser_version") == options.parser_version
        and record.get("chunker_version") == options.chunker_version
        and record.get("content_key_id") == cache.key_id
        and record.get("content_key_fingerprint") == cache.key_fingerprint
        and record.get("search_key_id") == cache.search_key_id
        and record.get("search_key_fingerprint") == cache.search_key_fingerprint
    )


def build_staging(source_root: Path, index_root: Path, *, mode: str = "full", options: BuildOptions | None = None, provider: KeyProvider | None = None) -> Path:
    """Build a private directory and expose it only after all invariants hold."""
    if mode not in {"full", "incremental"}:
        raise ValueError("BUILD_MODE_INVALID")
    options = options or BuildOptions()
    if options.minimum_document_count < 1:
        raise ValueError("MINIMUM_DOCUMENT_COUNT_INVALID")
    source_root, index_root = source_root.resolve(), index_root.resolve()
    cache_root = Path(__import__("os").environ["SECURE_LIBRARY_CACHE_ROOT"]).resolve()
    if index_root in cache_root.parents or cache_root in index_root.parents:
        raise ValueError("Cache and index must be separate")
    build_id = _build_id()
    building = index_root / "staging" / f".building-{build_id}"
    staging = index_root / "staging" / build_id
    building.mkdir(parents=True, exist_ok=False)
    cache = EncryptedCache(cache_root, provider)
    baseline: sqlite3.Connection | None = None
    parsed_files = reused_files = documents_count = chunks_count = files_count = 0
    try:
        if mode == "incremental":
            baseline = _baseline(index_root / "current", building / ".baseline.sqlite3")
        with (building / "documents.tmp").open("w", encoding="utf-8") as documents, (building / "chunks.tmp").open("w", encoding="utf-8") as chunks, (building / "files.tmp").open("w", encoding="utf-8") as files:
            selected = [path for path in sorted(source_root.rglob("*")) if path.is_file() and path.suffix.lower() in SUPPORTED]
            for path in selected:
                relative, content_hash = path.relative_to(source_root).as_posix(), _source_hash(path)
                prior = None
                if baseline is not None:
                    row = baseline.execute("select payload from files where relative_path = ?", (relative,)).fetchone()
                    prior = json.loads(row[0]) if row else None
                if prior is not None and _compatible(prior, content_hash, options, cache):
                    prior_documents = [json.loads(row[0]) for document_id_value in prior["document_ids"] for row in [baseline.execute("select payload from documents where record_id = ?", (document_id_value,)).fetchone()] if row]
                    prior_chunks = [json.loads(row[0]) for chunk_id_value in prior["chunk_ids"] for row in [baseline.execute("select payload from chunks where record_id = ?", (chunk_id_value,)).fetchone()] if row]
                    if len(prior_documents) == len(prior["document_ids"]) and len(prior_chunks) == len(prior["chunk_ids"]) and all(cache.verify([record["cache_ref"]])["ok"] for record in prior_chunks):
                        for record in prior_documents: _write(documents, record)
                        for record in prior_chunks: _write(chunks, record)
                        _write(files, prior)
                        reused_files += 1; files_count += 1; documents_count += len(prior_documents); chunks_count += len(prior_chunks)
                        continue
                file_documents: list[dict] = []
                file_chunks: list[dict] = []
                for part in parse(path):
                    document_id_value = document_id(relative, part.part_name)
                    document = {"document_id": document_id_value, "source_id": "default", "source_relative_path": relative, "document_type": part.document_type, "document_part": part.part_name}
                    part_chunks = []
                    for ordinal, chunk in enumerate(chunk_text(part.text)):
                        content_digest = hashlib.sha256(chunk.text.encode()).hexdigest()
                        part_chunks.append({"chunk_id": chunk_id(document_id_value, ordinal, content_digest), "document_id": document_id_value, "source_id": "default", "classification": "internal", "title": part.title, "section_title": chunk.section_title, "source_relative_path": relative, "document_type": part.document_type, "document_part": part.part_name, "chunk_index": ordinal, "char_start": chunk.char_start, "char_end": chunk.char_end, "content_hash": content_digest, "content_token_hashes": frequencies(chunk.text, cache.search_key), "cache_ref": cache.put(chunk.text)})
                    if not part_chunks:
                        raise ValueError(f"EMPTY_DOCUMENT_PART:{relative}")
                    file_documents.append(document); file_chunks.extend(part_chunks)
                if not file_documents or not file_chunks:
                    raise ValueError(f"EMPTY_FILE:{relative}")
                for record in file_documents: _write(documents, record)
                for record in file_chunks: _write(chunks, record)
                record = {"file_id": file_id(relative), "source_id": "default", "relative_path": relative, "content_hash": content_hash, "status": "success", "document_ids": [item["document_id"] for item in file_documents], "chunk_ids": [item["chunk_id"] for item in file_chunks], "parser_version": options.parser_version, "chunker_version": options.chunker_version, "content_key_id": cache.key_id, "content_key_fingerprint": cache.key_fingerprint, "search_key_id": cache.search_key_id, "search_key_fingerprint": cache.search_key_fingerprint}
                _write(files, record)
                parsed_files += 1; files_count += 1; documents_count += len(file_documents); chunks_count += len(file_chunks)
        if not files_count or not documents_count or not chunks_count or documents_count < options.minimum_document_count:
            raise ValueError("BUILD_CONTRIBUTION_REQUIREMENT_FAILED")
        for name in ("documents", "chunks", "files"):
            (building / f"{name}.tmp").replace(building / f"{name}.jsonl")
        sources = {"sources": [{"source_id": "default", "file_count": files_count, "document_count": documents_count, "chunk_count": chunks_count}]}
        (building / "sources.json").write_text(json.dumps(sources, separators=(",", ":")), encoding="utf-8")
        version = {"build_id": build_id, "generated_at": datetime.now(timezone.utc).isoformat(), "status": "staging", "source_count": 1, "file_count": files_count, "document_count": documents_count, "chunk_count": chunks_count, "failed_file_count": 0, "source_file_counts": {"default": files_count}, "source_document_counts": {"default": documents_count}, "source_chunk_counts": {"default": chunks_count}, "parsed_files": parsed_files, "reused_files": reused_files, "parser_version": options.parser_version, "chunker_version": options.chunker_version, "content_key_id": cache.key_id, "content_key_fingerprint": cache.key_fingerprint, "search_key_id": cache.search_key_id, "search_key_fingerprint": cache.search_key_fingerprint, "minimum_document_count": options.minimum_document_count}
        (building / "version.json").write_text(json.dumps(version, separators=(",", ":")), encoding="utf-8")
        if baseline is not None: baseline.close(); baseline = None
        (building / ".baseline.sqlite3").unlink(missing_ok=True)
        building.rename(staging)
        return staging
    except Exception:
        if baseline is not None: baseline.close()
        shutil.rmtree(building, ignore_errors=True)
        raise
