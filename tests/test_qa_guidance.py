import tempfile
import unittest
from pathlib import Path

from cochise.qa_guidance import load_qa_guidance


class QAGuidanceTests(unittest.TestCase):
    def test_loads_natural_language_guidance_with_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa.md"
            path.write_text(
                "# Threat-informed QA\n\nValidate the web-to-Linux pivot and sudo boundary.\n",
                encoding="utf-8",
            )
            guidance = load_qa_guidance(path)

        self.assertEqual(guidance.format, "markdown")
        self.assertEqual(guidance.length, len(guidance.raw_text))
        self.assertIn("sudo boundary", guidance.semantic_context())
        self.assertEqual(guidance.metadata()["source"], str(path))
        self.assertEqual(len(guidance.content_hash), 64)

    def test_empty_guidance_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.txt"
            path.write_text("\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_qa_guidance(path)


if __name__ == "__main__":
    unittest.main()
