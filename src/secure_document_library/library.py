from __future__ import annotations

import hashlib
import heapq
import json
import os
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
from collections.abc import Iterable

from .cache import EncryptedCache
from .chunking import chunk_text
from .index_io import iter_file_blocks, iter_jsonl
from .parsers import parse
from .tokens import digest, frequencies, tokenize

SUPPORTED = {".md", ".txt", ".yaml", ".yml", ".json", ".docx", ".xlsx"}
INDEX_FILE = "chunks.jsonl"
CACHE_VERIFY_BATCH_SIZE = 1_000
DEFAULT_SEARCH_LIMIT = 100
FORBIDDEN_FIELDS = frozenset({"content", "content_excerpt", "original_path", "absolute_path"})

def _document_id(relative: str, part: str | None) -> str:
    return hashlib.sha256(f"default:{relative}:{part or ''}".encode()).hexdigest()[:24]


def _chunk_id(document_id: str, position: int, content_hash: str) -> str:
    return hashlib.sha256(f"{document_id}:{position}:{content_hash}".encode()).hexdigest()[:24]


def build(source_root: Path, index_root: Path) -> int:
    """Build a secure chunk index; source files remain unchanged."""
    root = Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"]).resolve()
    if index_root.resolve() in root.parents or root in index_root.resolve().parents: raise ValueError("Cache and index must be separate")
    index_root.mkdir(parents=True, exist_ok=True)
    destination = index_root / INDEX_FILE
    temporary = destination.with_suffix(".tmp")
    count, cache = 0, EncryptedCache(root)
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            for path in sorted(source_root.rglob("*")):
                if not path.is_file() or path.suffix.lower() not in SUPPORTED:
                    continue
                relative = path.relative_to(source_root).as_posix()
                for part in parse(path):
                    document_id = _document_id(relative, part.part_name)
                    for chunk_index, chunk in enumerate(chunk_text(part.text)):
                        content_hash = hashlib.sha256(chunk.text.encode()).hexdigest()
                        record = {
                            "chunk_id": _chunk_id(document_id, chunk_index, content_hash),
                            "document_id": document_id,
                            "source_id": "default",
                            "classification": "internal",
                            "title": part.title,
                            "section_title": chunk.section_title,
                            "source_relative_path": relative,
                            "document_type": part.document_type,
                            "document_part": part.part_name,
                            "chunk_index": chunk_index,
                            "char_start": chunk.char_start,
                            "char_end": chunk.char_end,
                            "content_hash": content_hash,
                            "content_token_hashes": frequencies(chunk.text, cache.search_key),
                            "cache_ref": cache.put(chunk.text),
                        }
                        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                        count += 1
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return count

def calculate_index_digest(index_root: Path) -> str:
    """Calculate a stable chunk-index digest without materializing its contents."""
    path = index_root.resolve() / INDEX_FILE
    if not path.is_file():
        raise FileNotFoundError("INDEX_UNAVAILABLE")
    digest_value = hashlib.sha256()
    for block in iter_file_blocks(path):
        digest_value.update(block)
    return digest_value.hexdigest()


def _required_string(record: dict, field: str, line_number: int) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"INDEX_REQUIRED_FIELD_MISSING:{INDEX_FILE}:{line_number}:{field}")
    return value


def _is_absolute_path(value: object) -> bool:
    return isinstance(value, str) and (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute())


def validate_index(index_root: Path) -> dict[str, int | str]:
    """Stream and validate a chunk index while authenticating cache objects in batches."""
    path = index_root.resolve() / INDEX_FILE
    if not path.is_file():
        raise FileNotFoundError("INDEX_UNAVAILABLE")
    cache = EncryptedCache(Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"]))
    chunk_ids: set[str] = set()
    document_ids: set[str] = set()
    cache_refs: list[str] = []
    chunks = cache_verified = 0
    for line_number, record in iter_jsonl(path):
        if FORBIDDEN_FIELDS & record.keys() or _is_absolute_path(record.get("source_relative_path")):
            raise ValueError("PLAINTEXT_OR_ABSOLUTE_PATH_IN_INDEX")
        chunk_id = _required_string(record, "chunk_id", line_number)
        document_id = _required_string(record, "document_id", line_number)
        cache_ref = _required_string(record, "cache_ref", line_number)
        _required_string(record, "source_id", line_number)
        if chunk_id in chunk_ids:
            raise ValueError("DUPLICATE_CHUNK_ID")
        chunk_ids.add(chunk_id)
        document_ids.add(document_id)
        chunks += 1
        cache_refs.append(cache_ref)
        if len(cache_refs) >= CACHE_VERIFY_BATCH_SIZE:
            verification = cache.verify(cache_refs)
            cache_verified += int(verification["checked"])
            if not verification["ok"]:
                raise ValueError("CACHE_VERIFICATION_FAILED")
            cache_refs.clear()
    if cache_refs:
        verification = cache.verify(cache_refs)
        cache_verified += int(verification["checked"])
        if not verification["ok"]:
            raise ValueError("CACHE_VERIFICATION_FAILED")
    if not chunks:
        raise ValueError("INDEX_EMPTY")
    return {"documents": len(document_ids), "chunks": chunks, "cache_verified": cache_verified, "index_digest": calculate_index_digest(index_root)}


def _search_records(records: Iterable[dict], query: str, authorized_sources: set[str], *, limit: int | None = None) -> list[dict]:
    """Stream safe index records and retain only a bounded top-result set."""
    if not authorized_sources:
        return []
    if limit is not None and limit <= 0:
        return []
    key = EncryptedCache(Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"])).search_key
    terms = tokenize(query)
    def matches() -> Iterable[dict]:
        for record in records:
            if record["source_id"] not in authorized_sources:
                continue
            body = record["content_token_hashes"]
            metadata = f"{record['title']} {record.get('section_title') or ''}".lower()
            title_hits = sum(term in metadata for term in terms)
            body_hits = sum(min(int(body.get(digest(term, key), 0)), 4) for term in terms)
            score = title_hits * 10 + body_hits
            if score:
                safe_fields = ("chunk_id", "document_id", "source_id", "classification", "title", "section_title", "source_relative_path", "document_type", "document_part", "chunk_index", "char_start", "char_end")
                result = {field: record.get(field) for field in safe_fields}
                result.update({"score": score, "confidence": "high" if score >= 10 else "medium" if score >= 3 else "weak", "matched_fields": (["title_or_section"] if title_hits else []) + (["body_hmac_tokens"] if body_hits else []), "matched_terms": [term for term in terms if term in metadata or int(body.get(digest(term, key), 0)) > 0]})
                yield result

    rank = lambda item: (-item["score"], item["chunk_id"])
    return sorted(matches(), key=rank) if limit is None else heapq.nsmallest(limit, matches(), key=rank)


def search(index_root: Path, query: str, authorized_sources: set[str], *, limit: int = DEFAULT_SEARCH_LIMIT) -> list[dict]:
    """Search metadata/HMAC chunk tokens only; cache decryption is not performed."""
    return _search_records((record for _, record in iter_jsonl(index_root.resolve() / INDEX_FILE)), query, authorized_sources, limit=limit)


def retrieve(index_root: Path, chunk_id: str, authorized_sources: set[str]) -> str:
    """Decrypt one authorized chunk, never an arbitrary source path."""
    for _, record in iter_jsonl(index_root.resolve() / INDEX_FILE):
        if record["chunk_id"] == chunk_id:
            if record["source_id"] not in authorized_sources: raise PermissionError("Not authorized")
            return EncryptedCache(Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"])).get(record["cache_ref"])
    raise KeyError("Unknown chunk ID")
