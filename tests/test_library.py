from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_document_library.build import BuildOptions, build_staging
from secure_document_library.cache import EncryptedCache
from secure_document_library.governance import AuthorizationContext, Intent, gate_draft, prepare_answer, validate_draft
from secure_document_library.library import build, calculate_index_digest, retrieve, search
from secure_document_library.release import publish, rollback, validate_release


class LibraryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name); self.source, self.index, self.cache = self.root / "source", self.root / "index", self.root / "cache"; self.source.mkdir()
        self.old = dict(os.environ); os.environ.update({"SECURE_LIBRARY_CACHE_ROOT": str(self.cache), "SECURE_LIBRARY_CACHE_KEY": base64.b64encode(b"a" * 32).decode(), "SECURE_LIBRARY_SEARCH_KEY": base64.b64encode(b"b" * 32).decode()})

    def tearDown(self):
        os.environ.clear(); os.environ.update(self.old); self.temporary.cleanup()

    def test_large_jsonl_validation_streams_and_batches_cache_checks(self):
        for ordinal in range(1_001): self.source.joinpath(f"document-{ordinal:04d}.md").write_text("# Searchable\nLarge searchable evidence.", encoding="utf-8")
        staging = build_staging(self.source, self.index)
        expected_digest = calculate_index_digest(staging); batches: list[int] = []
        original_verify, original_read_text, original_read_bytes = EncryptedCache.verify, Path.read_text, Path.read_bytes
        def verify(instance, object_ids): batches.append(len(object_ids)); return original_verify(instance, object_ids)
        def deny(method):
            def guarded(path, *args, **kwargs):
                if path.suffix == ".jsonl": raise AssertionError("JSONL indexes must be streamed")
                return method(path, *args, **kwargs)
            return guarded
        with patch.object(EncryptedCache, "verify", new=verify), patch.object(Path, "read_text", new=deny(original_read_text)), patch.object(Path, "read_bytes", new=deny(original_read_bytes)):
            validation = validate_release(staging)
        self.assertEqual((validation["documents"], validation["chunks"], validation["cache_verified"]), (1_001, 1_001, 1_001))
        self.assertEqual(validation["index_digest"], expected_digest); self.assertEqual(batches, [1_000, 1])
        publish(staging, self.index, expected_build_id=staging.name)
        self.assertEqual(len(search(self.index, "searchable", {"default"}, limit=10)), 10)

    def test_build_publish_search_retrieve_and_governed_preview(self):
        self.source.joinpath("guide.md").write_text("# Generic Guide\nSearchable example content.", encoding="utf-8")
        self.assertEqual(build(self.source, self.index), 1)
        hits = search(self.index, "example", {"default"}); self.assertEqual(len(hits), 1); self.assertNotIn("cache_ref", hits[0])
        self.assertIn("Searchable", retrieve(self.index, hits[0]["chunk_id"], {"default"}))
        self.assertNotIn("Searchable", next(self.cache.glob("objects/*/*.bin")).read_text())
        preview = prepare_answer(self.index, "Which example content exists?", AuthorizationContext("test", frozenset({"default"})), intent=Intent.FACT_LOOKUP)
        self.assertTrue(preview["evidence_ledger"]["entries"])
        draft = {"sections": [{"name": "conclusion", "claims": [{"type": "CONFIRMED", "text": "Unsupported", "source_refs": ["E404"]}]}, {"name": "supporting_evidence", "claims": []}, {"name": "limitations", "claims": []}, {"name": "sources", "claims": []}]}
        self.assertEqual(validate_draft(draft, preview), ["CONFIRMED_REQUIRES_RELIABLE_EVIDENCE", "UNKNOWN_EVIDENCE_REF"])
        self.assertTrue(gate_draft(draft, preview)["success"])

    def test_incomplete_build_never_becomes_staging_or_current(self):
        self.source.joinpath("empty.md").write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "BUILD_CONTRIBUTION_REQUIREMENT_FAILED|EMPTY_FILE|EMPTY_DOCUMENT_PART"):
            build_staging(self.source, self.index)
        self.assertFalse((self.index / "current").exists())
        self.assertFalse(any((self.index / "staging").glob("*")) if (self.index / "staging").exists() else False)

    def test_incremental_build_reuses_release_and_rollback_is_validated(self):
        self.source.joinpath("guide.md").write_text("# Guide\nReusable evidence.", encoding="utf-8")
        first = build_staging(self.source, self.index); publish(first, self.index, expected_build_id=first.name)
        second = build_staging(self.source, self.index, mode="incremental")
        version = __import__("json").loads((second / "version.json").read_text(encoding="utf-8"))
        self.assertEqual((version["parsed_files"], version["reused_files"]), (0, 1)); self.assertFalse((second / ".baseline.sqlite3").exists())
        publish(second, self.index, expected_build_id=second.name)
        rollback(first.name, self.index)
        self.assertEqual(__import__("json").loads((self.index / "current" / "version.json").read_text())["build_id"], first.name)

    def test_minimum_document_count_is_enforced(self):
        self.source.joinpath("guide.md").write_text("# Guide\nEvidence.", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "BUILD_CONTRIBUTION_REQUIREMENT_FAILED"):
            build_staging(self.source, self.index, options=BuildOptions(minimum_document_count=2))

    def test_key_rotation_rebuilds_and_retained_release_uses_its_pinned_generation(self):
        old_content, old_search = base64.b64encode(b"a" * 32).decode(), base64.b64encode(b"b" * 32).decode()
        new_content, new_search = base64.b64encode(b"c" * 32).decode(), base64.b64encode(b"d" * 32).decode()
        os.environ.update({"SECURE_LIBRARY_CACHE_KEY": old_content, "SECURE_LIBRARY_CACHE_KEY_ID": "content-old", "SECURE_LIBRARY_SEARCH_KEY": old_search, "SECURE_LIBRARY_SEARCH_KEY_ID": "search-old"})
        self.source.joinpath("guide.md").write_text("# Guide\nRotation-safe searchable evidence.", encoding="utf-8")
        first = build_staging(self.source, self.index); publish(first, self.index, expected_build_id=first.name)
        os.environ.update({"SECURE_LIBRARY_CACHE_KEY": new_content, "SECURE_LIBRARY_CACHE_KEY_ID": "content-new", "SECURE_LIBRARY_CACHE_KEYS": json.dumps({"content-old": old_content, "content-new": new_content}), "SECURE_LIBRARY_SEARCH_KEY": new_search, "SECURE_LIBRARY_SEARCH_KEY_ID": "search-new", "SECURE_LIBRARY_SEARCH_KEYS": json.dumps({"search-old": old_search, "search-new": new_search})})
        self.assertTrue(search(self.index, "rotation-safe", {"default"}))
        second = build_staging(self.source, self.index, mode="incremental")
        version = json.loads((second / "version.json").read_text(encoding="utf-8"))
        self.assertEqual((version["parsed_files"], version["reused_files"]), (1, 0))
        publish(second, self.index, expected_build_id=second.name)
        rollback(first.name, self.index)
        self.assertTrue(search(self.index, "rotation-safe", {"default"}))


if __name__ == "__main__": unittest.main()
