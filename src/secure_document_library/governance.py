"""Evidence-governed answer preparation for Secure Document Library.

This module does not call an AI provider.  It prepares an authorized, bounded
evidence ledger and validates a provider's structured draft before rendering.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .cache import EncryptedCache
from .library import _search_records


class Intent(StrEnum):
    FACT_LOOKUP = "FACT_LOOKUP"
    SUMMARY = "SUMMARY"
    SOLUTION_DESIGN = "SOLUTION_DESIGN"


class MatchStatus(StrEnum):
    MATCHED = "MATCHED"
    WEAK_MATCHES = "WEAK_MATCHES"
    ZERO_RELEVANT_MATCHES = "ZERO_RELEVANT_MATCHES"


@dataclass(frozen=True)
class AuthorizationContext:
    """Caller-supplied trusted grants; user/model text never changes them."""
    principal_id: str
    authorized_source_ids: frozenset[str]
    allowed_classifications: frozenset[str] = frozenset()
    request_id: str = ""


@dataclass(frozen=True)
class IndexSnapshot:
    build_id: str
    index_path: Path
    records: tuple[dict, ...]


def snapshot_index(index_root: Path) -> IndexSnapshot:
    path = index_root.resolve() / "chunks.jsonl"
    if not path.is_file():
        raise FileNotFoundError("INDEX_UNAVAILABLE")
    raw = path.read_bytes()
    try:
        records = tuple(json.loads(line) for line in raw.decode("utf-8").splitlines() if line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("INDEX_INVALID") from exc
    if not records:
        raise ValueError("INDEX_EMPTY")
    return IndexSnapshot(hashlib.sha256(raw).hexdigest()[:24], index_root.resolve(), records)


def classify_intent(question: str, override: Intent | None = None) -> Intent:
    if override is not None:
        return override
    lowered = question.casefold()
    if any(term in lowered for term in ("design", "improve", "implement", "transform", "plan", "recommend", "proposal")):
        return Intent.SOLUTION_DESIGN
    if any(term in lowered for term in ("summar", "compare", "consolidate", "extract issue", "organize")):
        return Intent.SUMMARY
    return Intent.FACT_LOOKUP


def _plan(question: str, intent: Intent) -> tuple[tuple[str, str, int], ...]:
    if intent is Intent.FACT_LOOKUP:
        return (("fact_lookup", question, 5),)
    if intent is Intent.SUMMARY:
        return (("summary", question, 10),)
    return (
        ("current_state", f"{question} current behavior fields roles workflows constraints", 5),
        ("problems", f"{question} issues exceptions limitations risks", 5),
        ("related_implementation", f"{question} related interfaces modules permissions implementation", 5),
    )


def _safe_ledger(snapshot: IndexSnapshot, results: list[dict], context: AuthorizationContext, status: MatchStatus, maximum: int) -> list[dict]:
    records = {item["chunk_id"]: item for item in snapshot.records}
    selected: dict[str, dict] = {}
    for result in results:
        current = selected.get(result["chunk_id"])
        if current is None or result["score"] > current["score"]:
            selected[result["chunk_id"]] = result
    ordered = sorted(selected.values(), key=lambda item: (-item["score"], item["chunk_id"]))
    cache = EncryptedCache(Path(__import__("os").environ["SECURE_LIBRARY_CACHE_ROOT"]))
    entries: list[dict] = []
    per_document: dict[str, int] = {}
    for hit in ordered:
        if len(entries) >= maximum:
            break
        record = records[hit["chunk_id"]]
        if record["source_id"] not in context.authorized_source_ids:
            continue
        if context.allowed_classifications and record.get("classification", "internal") not in context.allowed_classifications:
            continue
        if per_document.get(record["document_id"], 0) >= 2:
            continue
        # Authenticate/decrypt only selected authorized content; retain it in memory
        # solely while the host prepares its model request.
        evidence_text = cache.get(record["cache_ref"])
        per_document[record["document_id"]] = per_document.get(record["document_id"], 0) + 1
        entries.append({"evidence_ref": f"E{len(entries) + 1}", "source_id": record["source_id"], "document_id": record["document_id"], "chunk_id": record["chunk_id"], "title": record["title"], "section": record.get("section_title") or "", "source_relative_path": record["source_relative_path"], "build_id": snapshot.build_id, "confidence": hit["confidence"], "match_status": status, "matched_fields": hit["matched_fields"], "matched_terms": hit["matched_terms"], "matched_subqueries": hit["matched_subqueries"], "_evidence_text": evidence_text})
    return entries


def _public_entry(entry: dict) -> dict:
    return {key: value for key, value in entry.items() if key != "_evidence_text"}


def _prepare_from_snapshot(snapshot: IndexSnapshot, question: str, context: AuthorizationContext, intent: Intent | None) -> tuple[dict, list[dict]]:
    """Return a pinned search plan and safe evidence ledger for an AI host.

    The return value deliberately contains no decrypted text. Use
    ``model_evidence`` only in trusted in-memory host code when calling a model.
    """
    if not context.authorized_source_ids:
        raise PermissionError("AUTHORIZATION_CONTEXT_MISSING")
    classified = classify_intent(question, intent)
    eligible_records = tuple(
        record for record in snapshot.records
        if not context.allowed_classifications or record.get("classification", "internal") in context.allowed_classifications
    )
    runs, all_results = [], []
    for purpose, query, limit in _plan(question, classified):
        hits = _search_records(eligible_records, query, set(context.authorized_source_ids))[:limit]
        for hit in hits:
            hit["matched_subqueries"] = [purpose]
        all_results.extend(hits)
        runs.append({"purpose": purpose, "query": query, "build_id": snapshot.build_id, "status": "MATCHED" if hits else "ZERO_RELEVANT_MATCHES", "result_count": len(hits), "error": None})
    status = MatchStatus.MATCHED if any(item["confidence"] in {"high", "medium"} for item in all_results) else MatchStatus.WEAK_MATCHES if all_results else MatchStatus.ZERO_RELEVANT_MATCHES
    ledger = _safe_ledger(snapshot, all_results, context, status, 10 if classified is not Intent.FACT_LOOKUP else 4)
    preview = {"success": True, "status": "preview", "question": question, "intent": classified, "build_id": snapshot.build_id, "match_status": status, "search_plan": {"intent": classified, "runs": runs}, "evidence_ledger": {"match_status": status, "entries": [_public_entry(item) for item in ledger]}, "model_request_schema": structured_answer_schema()}
    return preview, ledger


def prepare_answer(index_root: Path, question: str, context: AuthorizationContext, *, intent: Intent | None = None) -> dict:
    """Return a pinned search plan and safe evidence ledger for an AI host.

    The return value deliberately contains no decrypted text. Use
    ``model_evidence`` only in trusted in-memory host code when calling a model.
    """
    if not context.authorized_source_ids:
        raise PermissionError("AUTHORIZATION_CONTEXT_MISSING")
    preview, _ = _prepare_from_snapshot(snapshot_index(index_root), question, context, intent)
    return preview


def model_evidence(index_root: Path, question: str, context: AuthorizationContext, *, intent: Intent | None = None) -> tuple[dict, list[dict]]:
    """Trusted-host helper: prepare public metadata plus in-memory evidence text."""
    if not context.authorized_source_ids:
        raise PermissionError("AUTHORIZATION_CONTEXT_MISSING")
    preview, ledger = _prepare_from_snapshot(snapshot_index(index_root), question, context, intent)
    return preview, [{**_public_entry(entry), "evidence_text": entry["_evidence_text"]} for entry in ledger]


def structured_answer_schema() -> dict:
    claim = {
        "type": "object",
        "required": ["type", "text", "source_refs"],
        "properties": {
            "type": {"type": "string", "enum": ["CONFIRMED", "RECOMMENDATION", "TO_BUILD", "OPEN_QUESTION", "INFERENCE", "GENERAL_GUIDANCE"]},
            "text": {"type": "string"},
            "source_refs": {"type": "array", "items": {"type": "string"}},
        },
    }
    section = {
        "type": "object",
        "required": ["name", "claims"],
        "properties": {"name": {"type": "string"}, "claims": {"type": "array", "items": claim}},
    }
    return {
        "type": "object",
        "required": ["title", "intent", "sections"],
        "properties": {
            "title": {"type": "string"},
            "intent": {"type": "string"},
            "sections": {"type": "array", "items": section},
        },
    }


def validate_draft(draft: dict, preview: dict) -> list[str]:
    """Validate a model-produced structured draft against this request's ledger."""
    errors: list[str] = []
    references = {entry["evidence_ref"]: entry for entry in preview["evidence_ledger"]["entries"]}
    zero = preview["match_status"] == MatchStatus.ZERO_RELEVANT_MATCHES
    required = {
        "FACT_LOOKUP": {"conclusion", "supporting_evidence", "limitations", "sources"},
        "SUMMARY": {"core_conclusions", "confirmed_content", "main_issues", "conflicts_and_unknowns", "recommended_next_steps", "sources"},
        "SOLUTION_DESIGN": {"requirement_and_scope", "evidence_quality", "confirmed_current_state", "documented_problems_and_inferred_risks", "recommended_solution", "capabilities_to_build", "implementation_stages", "risks_and_controls", "open_questions", "acceptance_criteria", "sources"},
    }
    names = {str(section.get("name", "")) for section in draft.get("sections", [])}
    if required.get(str(preview["intent"]), set()) - names:
        errors.append("MISSING_REQUIRED_SECTIONS")
    for section in draft.get("sections", []):
        for claim in section.get("claims", []):
            kind, refs = claim.get("type"), claim.get("source_refs", [])
            if kind not in {"CONFIRMED", "RECOMMENDATION", "TO_BUILD", "OPEN_QUESTION", "INFERENCE", "GENERAL_GUIDANCE"}:
                errors.append("INVALID_CLAIM_TYPE")
            if zero and kind not in {"OPEN_QUESTION", "GENERAL_GUIDANCE"}:
                errors.append("ZERO_MATCH_CLAIM_NOT_ALLOWED")
            if kind == "CONFIRMED" and (not refs or not any(ref in references and references[ref]["confidence"] in {"high", "medium"} for ref in refs)):
                errors.append("CONFIRMED_REQUIRES_RELIABLE_EVIDENCE")
            if kind == "INFERENCE" and not refs:
                errors.append("INFERENCE_REQUIRES_SUPPORT")
            if any(ref not in references for ref in refs):
                errors.append("UNKNOWN_EVIDENCE_REF")
    return sorted(set(errors))


def repair_draft(draft: dict, preview: dict) -> dict:
    """One conservative repair pass; it never attaches invented evidence."""
    references = {entry["evidence_ref"]: entry for entry in preview["evidence_ledger"]["entries"]}
    zero = preview["match_status"] == MatchStatus.ZERO_RELEVANT_MATCHES
    repaired = {**draft, "sections": []}
    for section in draft.get("sections", []):
        claims = []
        for claim in section.get("claims", []):
            item = dict(claim); refs = [ref for ref in item.get("source_refs", []) if ref in references]
            item["source_refs"] = refs
            reliable = any(references[ref]["confidence"] in {"high", "medium"} for ref in refs)
            if (item.get("type") == "CONFIRMED" and not reliable) or (item.get("type") == "INFERENCE" and not refs) or (zero and item.get("type") not in {"OPEN_QUESTION", "GENERAL_GUIDANCE"}):
                item["type"], item["source_refs"] = "OPEN_QUESTION", []
            claims.append(item)
        repaired["sections"].append({**section, "claims": claims})
    return repaired


def gate_draft(draft: dict, preview: dict) -> dict:
    """Validate, perform exactly one safe repair, then fail closed if still invalid."""
    first = validate_draft(draft, preview)
    if not first:
        return {"success": True, "draft": draft, "repaired": False}
    repaired = repair_draft(draft, preview)
    second = validate_draft(repaired, preview)
    if not second:
        return {"success": True, "draft": repaired, "repaired": True}
    return {"success": False, "error": {"code": "RESPONSE_VALIDATION_FAILED", "message": "The answer failed validation after one repair attempt."}}
