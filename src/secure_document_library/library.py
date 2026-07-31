from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .cache import EncryptedCache
from .parsers import parse
from .tokens import digest, frequencies, tokenize

SUPPORTED = {".md", ".txt", ".yaml", ".yml", ".json", ".docx", ".xlsx"}

def _document_id(relative: str, part: str | None) -> str:
    return hashlib.sha256(f"default:{relative}:{part or ''}".encode()).hexdigest()[:24]

def build(source_root: Path, index_root: Path) -> int:
    """Build a generic lightweight index; source files remain unchanged."""
    root = Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"]).resolve()
    if index_root.resolve() in root.parents or root in index_root.resolve().parents: raise ValueError("Cache and index must be separate")
    cache, documents = EncryptedCache(root), []
    for path in sorted(source_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED: continue
        relative = path.relative_to(source_root).as_posix()
        for part in parse(path):
            document_id = _document_id(relative, part.part_name); cache_ref = cache.put(part.text)
            documents.append({"document_id": document_id, "source_id": "default", "title": part.title, "source_relative_path": relative, "document_type": part.document_type, "document_part": part.part_name, "content_hash": hashlib.sha256(part.text.encode()).hexdigest(), "content_token_hashes": frequencies(part.text, cache.key), "cache_ref": cache_ref})
    index_root.mkdir(parents=True, exist_ok=True)
    with (index_root / "documents.jsonl").open("w", encoding="utf-8") as handle:
        for item in documents: handle.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
    return len(documents)

def search(index_root: Path, query: str, authorized_sources: set[str]) -> list[dict]:
    """Search metadata/HMAC body tokens only; cache decryption is not performed."""
    if not authorized_sources: return []
    key = EncryptedCache(Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"])).key
    hits = []
    for line in (index_root / "documents.jsonl").read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record["source_id"] not in authorized_sources: continue
        terms = tokenize(query); body = record["content_token_hashes"]
        score = sum(term in record["title"].lower() for term in terms) * 10 + sum(int(body.get(digest(term, key), 0)) for term in terms)
        if score: hits.append(({field: record[field] for field in ("document_id", "source_id", "title", "source_relative_path", "document_type", "document_part")}, score))
    return [{**record, "score": score} for record, score in sorted(hits, key=lambda item: (-item[1], item[0]["document_id"]))]

def retrieve(index_root: Path, document_id: str, authorized_sources: set[str]) -> str:
    for line in (index_root / "documents.jsonl").read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record["document_id"] == document_id:
            if record["source_id"] not in authorized_sources: raise PermissionError("Not authorized")
            return EncryptedCache(Path(os.environ["SECURE_LIBRARY_CACHE_ROOT"])).get(record["cache_ref"])
    raise KeyError("Unknown document ID")

