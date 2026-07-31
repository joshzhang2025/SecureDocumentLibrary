from __future__ import annotations

from dataclasses import dataclass


TARGET_CHARS = 1_400
MAX_CHARS = 2_000
OVERLAP_CHARS = 180


@dataclass(frozen=True)
class Chunk:
    text: str
    section_title: str | None
    char_start: int
    char_end: int


def _heading(line: str) -> str | None:
    stripped = line.lstrip()
    if not stripped.startswith("#"):
        return None
    marker, _, title = stripped.partition(" ")
    if marker and set(marker) == {"#"} and title.strip():
        return title.strip()
    return None


def _split_oversized(text: str, limit: int) -> list[str]:
    """Split only as a last resort, favouring a nearby whitespace boundary."""
    pieces: list[str] = []
    remaining = text
    while len(remaining) > limit:
        boundary = remaining.rfind(" ", 0, limit)
        if boundary < limit // 2:
            boundary = limit
        pieces.append(remaining[:boundary].rstrip())
        remaining = remaining[boundary:].lstrip()
    if remaining:
        pieces.append(remaining)
    return pieces


def chunk_text(
    text: str,
    *,
    target_chars: int = TARGET_CHARS,
    max_chars: int = MAX_CHARS,
    overlap_chars: int = OVERLAP_CHARS,
) -> list[Chunk]:
    """Create deterministic, heading-aware chunks without writing plaintext."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return []

    units: list[tuple[str, str | None]] = []
    current_section: str | None = None
    for line in normalized.splitlines(keepends=True):
        title = _heading(line)
        if title:
            current_section = title
        for piece in _split_oversized(line, max_chars):
            units.append((piece, current_section))

    chunks: list[Chunk] = []
    buffer = ""
    section_title: str | None = None
    cursor = 0

    def emit(value: str, title: str | None) -> None:
        nonlocal cursor
        value = value.strip()
        if not value:
            return
        start = normalized.find(value, cursor)
        if start < 0:
            start = cursor
        end = start + len(value)
        chunks.append(Chunk(value, title, start, end))
        cursor = end

    for unit, unit_section in units:
        if not buffer:
            buffer, section_title = unit, unit_section
            continue
        proposed = buffer + unit
        if len(proposed) <= max_chars and (len(buffer) < target_chars or not unit.lstrip().startswith("#")):
            buffer = proposed
            if unit_section:
                section_title = unit_section
            continue
        emit(buffer, section_title)
        overlap = buffer[-overlap_chars:].lstrip() if overlap_chars else ""
        buffer = (overlap + "\n" if overlap else "") + unit
        section_title = unit_section
    emit(buffer, section_title)
    return chunks
