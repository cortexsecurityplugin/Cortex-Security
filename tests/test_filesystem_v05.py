import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from filesystem_scan import scan
from quarantine_manager import quarantine_copy

class FilesystemV05Tests(unittest.TestCase):
    def test_inventory_hash_and_heuristic_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('value = eval(user_input)\n', encoding="utf-8")
            report = scan(root, [], 5)
            self.assertEqual(report["files_scanned"], 1)
            self.assertEqual(len(report["inventory"][0]["sha256"]), 64)
            self.assertTrue(any(f["rule_id"] == "FS001" for f in report["findings"]))

    def test_excludes_named_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("secret", encoding="utf-8")
            report = scan(root, [".git"], 5)
            self.assertEqual(report["files_scanned"], 1)

    def test_quarantine_copy_verifies_hash_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.txt"
            source.write_text("safe test fixture", encoding="utf-8")
            quarantine = root / "evidence"
            manifest = quarantine_copy(source, quarantine)
            self.assertTrue(source.exists())
            self.assertEqual(manifest["operation"], "verified_copy_only")
            self.assertEqual(manifest["sha256"], json.loads(
                (quarantine / (manifest["sha256"] + "_sample.txt.manifest.json")).read_text(encoding="utf-8")
            )["sha256"])

    def test_evidence_copy_rejects_symlink(self):
        import os
        import tempfile
        from pathlib import Path
        from quarantine_manager import quarantine_copy

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original = root / "original.txt"
            link = root / "link.txt"
            evidence = root / "evidence"

            original.write_text("test evidence", encoding="utf-8")

            try:
                os.symlink(original, link)
            except (OSError, NotImplementedError):
                self.skipTest("Symbolic links are unavailable in this environment.")

            with self.assertRaises(ValueError):
                quarantine_copy(link, evidence)

            self.assertFalse(evidence.exists())
            self.assertTrue(original.exists())

if __name__ == "__main__":
    unittest.main()
