import os, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integrations" / "odysseus"))
import cortex_security_adapter as adapter

class OdysseusAdapterTests(unittest.TestCase):
    def test_rejects_target_outside_allowed_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root, outside = Path(temp) / "allowed", Path(temp) / "outside"
            root.mkdir(); outside.mkdir()
            with patch.dict(os.environ, {"CORTEX_SECURITY_ALLOWED_ROOTS": str(root)}):
                with self.assertRaises(ValueError):
                    adapter._validate_target(str(outside))

    def test_accepts_target_inside_allowed_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); child = root / "child"; child.mkdir()
            with patch.dict(os.environ, {"CORTEX_SECURITY_ALLOWED_ROOTS": str(root)}):
                self.assertEqual(adapter._validate_target(str(child)), child.resolve())

    def test_rejects_non_allowlisted_report(self):
        with self.assertRaises(ValueError):
            adapter.get_report("../secrets.txt")

if __name__ == "__main__":
    unittest.main()
