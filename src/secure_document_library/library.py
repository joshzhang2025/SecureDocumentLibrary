from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .cache import EncryptedCache
from .chunking import chunk_text
from .parsers import parse
from .tokens import digest, frequencies, tokenize

SUPPORTED = {".md", ".txt", ".yaml", ".yml", ".json", ".docx", ".xlsx"}

def _document_id(relative: str, part: str | None) -> str:
    return hashlib.sha256(f"default:{relative}:{part or ''}".encode()).hexdigest()[:24]


def _chunk_id(document_id: str, position: int, content_hash: str) -> str:
    return hashlib.sha256(f"{document_id}:{position}:{content_hash}".encode()).hexdigest()[:24]


def build(source_root: Path, index_root: Path) -> int:
    """Build a secure chunk index; source files remain unchanged."""
    root = Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"]).resolve()
    if index_root.resolve() in root.parents or root in index_root.resolve().parents: raise ValueError("Cache and index must be separate")
    cache, chunks = EncryptedCache(root), []
    for path in sorted(source_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED: continue
        relative = path.relative_to(source_root).as_posix()
        for part in parse(path):
            document_id = _document_id(relative, part.part_name)
            for chunk_index, chunk in enumerate(chunk_text(part.text)):
                content_hash = hashlib.sha256(chunk.text.encode()).hexdigest()
                cache_ref = cache.put(chunk.text)
                chunks.append({
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
                    "cache_ref": cache_ref,
                })
    index_root.mkdir(parents=True, exist_ok=True)
    with (index_root / "chunks.jsonl").open("w", encoding="utf-8") as handle:
        for item in chunks: handle.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
    return len(chunks)

def _search_records(records: list[dict] | tuple[dict, ...], query: str, authorized_sources: set[str]) -> list[dict]:
    """Search an already-pinned set of safe index records without decryption."""
    if not authorized_sources:
        return []
    key = EncryptedCache(Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"])).search_key
    terms = tokenize(query)
    hits = []
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
            hits.append(result)
    return sorted(hits, key=lambda item: (-item["score"], item["chunk_id"]))


def search(index_root: Path, query: str, authorized_sources: set[str]) -> list[dict]:
    """Search metadata/HMAC chunk tokens only; cache decryption is not performed."""
    records = [json.loads(line) for line in (index_root / "chunks.jsonl").read_text(encoding="utf-8").splitlines() if line]
    return _search_records(records, query, authorized_sources)


def retrieve(index_root: Path, chunk_id: str, authorized_sources: set[str]) -> str:
    """Decrypt one authorized chunk, never an arbitrary source path."""
    for line in (index_root / "chunks.jsonl").read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record["chunk_id"] == chunk_id:
            if record["source_id"] not in authorized_sources: raise PermissionError("Not authorized")
            return EncryptedCache(Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"])).get(record["cache_ref"])
    raise KeyError("Unknown chunk ID")
