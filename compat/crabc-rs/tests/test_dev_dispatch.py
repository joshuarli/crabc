"""Regression coverage for the canonical Docker test dispatcher."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DISPATCHER = ROOT / "scripts" / "dev.sh"


class DevTestDispatchTests(unittest.TestCase):
    def test_workspace_tests_exclude_no_std_static_library_examples(self) -> None:
        """Examples own panic handlers and must stay in their isolated builder."""

        source = DISPATCHER.read_text(encoding="utf-8")
        match = re.search(r"^    test\)\n(?P<body>.*?)^        ;;$", source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, "dev.sh has no test command case")
        assert match is not None
        self.assertIn('run_workspace_tests "$@"', match.group("body"))
        self.assertIn(
            'run_in_container cargo test --workspace --tests "$@"',
            source,
        )
        self.assertIn('run_in_container cargo test --workspace "$@"', source)


if __name__ == "__main__":
    unittest.main()
