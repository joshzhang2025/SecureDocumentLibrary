from __future__ import annotations

import hashlib


def document_id(relative: str, part: str | None) -> str:
    return hashlib.sha256(f"default:{relative}:{part or ''}".encode()).hexdigest()[:24]


def chunk_id(document: str, position: int, content_hash: str) -> str:
    return hashlib.sha256(f"{document}:{position}:{content_hash}".encode()).hexdigest()[:24]


def file_id(relative: str) -> str:
    return hashlib.sha256(f"default:{relative}".encode()).hexdigest()[:24]
