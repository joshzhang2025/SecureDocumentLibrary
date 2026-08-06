from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_document_library.cache import EncryptedCache
from secure_document_library.library import build, calculate_index_digest, retrieve, search, validate_index
from secure_document_library.governance import AuthorizationContext, Intent, gate_draft, prepare_answer, validate_draft

class LibraryTest(unittest.TestCase):
    def test_large_jsonl_is_built_validated_and_searched_without_whole_file_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); index, cache = root / "index", root / "cache"; index.mkdir()
            old = dict(os.environ); os.environ.update({"SECURE_LIBRARY_CACHE_ROOT": str(cache), "SECURE_LIBRARY_CACHE_KEY": base64.b64encode(b"a" * 32).decode(), "SECURE_LIBRARY_SEARCH_KEY": base64.b64encode(b"b" * 32).decode()})
            try:
                encrypted = EncryptedCache(cache)
                cache_ref = encrypted.put("Large searchable evidence.")
                with (index / "chunks.jsonl").open("w", encoding="utf-8") as handle:
                    for ordinal in range(1_001):
                        handle.write(json.dumps({"chunk_id": f"chunk-{ordinal:04d}", "document_id": f"document-{ordinal:04d}", "source_id": "default", "classification": "internal", "title": "Large searchable evidence", "section_title": "", "source_relative_path": f"docs/{ordinal}.md", "document_type": "md", "document_part": None, "chunk_index": 0, "char_start": 0, "char_end": 26, "content_token_hashes": {}, "cache_ref": cache_ref}, separators=(",", ":")) + "\n")
                expected_digest = hashlib.sha256((index / "chunks.jsonl").read_bytes()).hexdigest()
                batches: list[int] = []
                original_verify, original_read_text, original_read_bytes = EncryptedCache.verify, Path.read_text, Path.read_bytes

                def verify(instance, object_ids):
                    batches.append(len(object_ids))
                    return original_verify(instance, object_ids)

                def reject_whole_jsonl_read(method):
                    def guarded(path, *args, **kwargs):
                        if path.suffix == ".jsonl":
                            raise AssertionError("JSONL indexes must be streamed")
                        return method(path, *args, **kwargs)
                    return guarded

                with patch.object(EncryptedCache, "verify", new=verify), patch.object(Path, "read_text", new=reject_whole_jsonl_read(original_read_text)), patch.object(Path, "read_bytes", new=reject_whole_jsonl_read(original_read_bytes)):
                    validation = validate_index(index)
                    hits = search(index, "searchable", {"default"}, limit=10)
                    evidence = retrieve(index, "chunk-0000", {"default"})
                self.assertEqual(validation["chunks"], 1_001)
                self.assertEqual(validation["cache_verified"], 1_001)
                self.assertEqual(validation["index_digest"], expected_digest)
                self.assertEqual(calculate_index_digest(index), expected_digest)
                self.assertEqual(batches, [1_000, 1])
                self.assertEqual(len(hits), 10)
                self.assertEqual(evidence, "Large searchable evidence.")
            finally: os.environ.clear(); os.environ.update(old)

    def test_encrypted_build_search_and_retrieval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, index, cache = root / "source", root / "index", root / "cache"; source.mkdir()
            source.joinpath("guide.md").write_text("# Generic Guide\nSearchable example content.", encoding="utf-8")
            old = dict(os.environ); os.environ.update({"SECURE_LIBRARY_CACHE_ROOT": str(cache), "SECURE_LIBRARY_CACHE_KEY": base64.b64encode(b"a" * 32).decode(), "SECURE_LIBRARY_SEARCH_KEY": base64.b64encode(b"b" * 32).decode()})
            try:
                self.assertEqual(build(source, index), 1)
                self.assertEqual(search(index, "example", set()), [])
                hits = search(index, "example", {"default"}); self.assertEqual(len(hits), 1); self.assertNotIn("cache_ref", hits[0]); self.assertIn("chunk_id", hits[0])
                self.assertIn("Searchable", retrieve(index, hits[0]["chunk_id"], {"default"}))
                self.assertNotIn("Searchable", next(cache.glob("objects/*/*.bin")).read_text())
            finally: os.environ.clear(); os.environ.update(old)

    def test_heading_aware_chunks_return_only_relevant_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, index, cache = root / "source", root / "index", root / "cache"; source.mkdir()
            source.joinpath("operations.md").write_text(
                "# Operations\n\n## Rollback procedure\n" + ("rollback-window checkpoint. " * 100) +
                "\n\n## Payroll notes\n" + ("UnrelatedDepositRecord. " * 100), encoding="utf-8"
            )
            old = dict(os.environ); os.environ.update({"SECURE_LIBRARY_CACHE_ROOT": str(cache), "SECURE_LIBRARY_CACHE_KEY": base64.b64encode(b"a" * 32).decode(), "SECURE_LIBRARY_SEARCH_KEY": base64.b64encode(b"b" * 32).decode()})
            try:
                self.assertGreaterEqual(build(source, index), 2)
                hits = search(index, "rollback-window", {"default"})
                self.assertEqual(hits[0]["section_title"], "Rollback procedure")
                evidence = retrieve(index, hits[0]["chunk_id"], {"default"})
                self.assertIn("rollback-window", evidence)
                self.assertNotIn("UnrelatedDepositRecord", evidence)
                self.assertNotIn("UnrelatedDepositRecord", (index / "chunks.jsonl").read_text(encoding="utf-8"))
            finally: os.environ.clear(); os.environ.update(old)

    def test_governed_preview_pins_evidence_and_rejects_unsupported_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, index, cache = root / "source", root / "index", root / "cache"; source.mkdir()
            source.joinpath("permissions.md").write_text("# Permissions\n\n## Assignment\nUse the role assignment endpoint.", encoding="utf-8")
            old = dict(os.environ); os.environ.update({"SECURE_LIBRARY_CACHE_ROOT": str(cache), "SECURE_LIBRARY_CACHE_KEY": base64.b64encode(b"a" * 32).decode(), "SECURE_LIBRARY_SEARCH_KEY": base64.b64encode(b"b" * 32).decode()})
            try:
                build(source, index)
                context = AuthorizationContext("test-user", frozenset({"default"}), request_id="test")
                preview = prepare_answer(index, "Which endpoint assigns a role?", context, intent=Intent.FACT_LOOKUP)
                self.assertEqual(preview["status"], "preview")
                self.assertTrue(preview["evidence_ledger"]["entries"])
                self.assertNotIn("evidence_text", preview["evidence_ledger"]["entries"][0])
                draft = {"sections": [
                    {"name": "conclusion", "claims": [{"type": "CONFIRMED", "text": "Unsupported", "source_refs": ["E404"]}]},
                    {"name": "supporting_evidence", "claims": []}, {"name": "limitations", "claims": []}, {"name": "sources", "claims": []},
                ]}
                self.assertEqual(validate_draft(draft, preview), ["CONFIRMED_REQUIRES_RELIABLE_EVIDENCE", "UNKNOWN_EVIDENCE_REF"])
                gated = gate_draft(draft, preview)
                self.assertTrue(gated["success"])
                self.assertTrue(gated["repaired"])
                self.assertEqual(gated["draft"]["sections"][0]["claims"][0]["type"], "OPEN_QUESTION")
            finally: os.environ.clear(); os.environ.update(old)

    def test_zero_match_disallows_internal_confirmed_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, index, cache = root / "source", root / "index", root / "cache"; source.mkdir()
            source.joinpath("guide.md").write_text("# Guide\nKnown evidence.", encoding="utf-8")
            old = dict(os.environ); os.environ.update({"SECURE_LIBRARY_CACHE_ROOT": str(cache), "SECURE_LIBRARY_CACHE_KEY": base64.b64encode(b"a" * 32).decode(), "SECURE_LIBRARY_SEARCH_KEY": base64.b64encode(b"b" * 32).decode()})
            try:
                build(source, index)
                preview = prepare_answer(index, "unrelatedterm", AuthorizationContext("test-user", frozenset({"default"})), intent=Intent.FACT_LOOKUP)
                self.assertEqual(preview["match_status"], "ZERO_RELEVANT_MATCHES")
                errors = validate_draft({"sections": [{"claims": [{"type": "CONFIRMED", "text": "Internal fact", "source_refs": []}]}]}, preview)
                self.assertIn("ZERO_MATCH_CLAIM_NOT_ALLOWED", errors)
            finally: os.environ.clear(); os.environ.update(old)
