from __future__ import annotations

import base64
import os
import tempfile
import unittest
from pathlib import Path

from secure_document_library.library import build, retrieve, search

class LibraryTest(unittest.TestCase):
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
