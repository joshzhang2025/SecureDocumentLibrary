"""Streaming helpers for the on-disk JSONL chunk index."""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path


def iter_jsonl(path: Path) -> Iterator[tuple[int, dict]]:
    """Yield JSON object records without loading the whole index into memory."""
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"INDEX_JSON_INVALID:{path.name}:{line_number}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"INDEX_RECORD_INVALID:{path.name}:{line_number}")
            yield line_number, record


def iter_file_blocks(path: Path, block_size: int = 1_048_576) -> Iterator[bytes]:
    """Yield fixed-size binary blocks for bounded-memory hashing."""
    if block_size <= 0:
        raise ValueError("BLOCK_SIZE_INVALID")
    with path.open("rb") as handle:
        while block := handle.read(block_size):
            yield block
