import os
import unittest
from unittest.mock import patch

from cochise.cli.cochise import _parse_arguments, _qa_enabled


class CliModeTests(unittest.TestCase):
    def test_default_cli_keeps_qa_disabled(self):
        with patch.dict(os.environ, {}, clear=True):
            args = _parse_arguments([])

        self.assertFalse(_qa_enabled(args))

    def test_qa_flag_enables_optional_layer(self):
        with patch.dict(os.environ, {}, clear=True):
            args = _parse_arguments(["--qa"])

        self.assertTrue(_qa_enabled(args))

    def test_qa_instructions_enable_optional_layer(self):
        with patch.dict(os.environ, {}, clear=True):
            args = _parse_arguments(["--qa-instructions", "specs/qa.md"])

        self.assertTrue(_qa_enabled(args))

    def test_qa_environment_flag_enables_optional_layer(self):
        args = _parse_arguments([])
        with patch.dict(os.environ, {"QA_ENABLED": "1"}, clear=True):
            self.assertTrue(_qa_enabled(args))

    def test_empty_qa_environment_flag_keeps_default_disabled(self):
        args = _parse_arguments([])
        with patch.dict(os.environ, {"QA_ENABLED": ""}, clear=True):
            self.assertFalse(_qa_enabled(args))


if __name__ == "__main__":
    unittest.main()
