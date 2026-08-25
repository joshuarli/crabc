#!/usr/bin/env python3
"""Shell-syntax coverage for the sysroot release workflow."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "sysroot.yml"


def workflow_shell_block(step_name: str) -> str:
    """Extract one literal YAML ``run`` block as GitHub will pass it to Bash."""

    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    step = f"      - name: {step_name}"
    try:
        start = lines.index(step)
    except ValueError as error:
        raise AssertionError(f"missing workflow step: {step_name}") from error
    try:
        run = lines.index("        run: |", start)
    except ValueError as error:
        raise AssertionError(f"workflow step has no literal shell block: {step_name}") from error

    block: list[str] = []
    for line in lines[run + 1 :]:
        if line.startswith("      - name: "):
            break
        if not line:
            block.append("")
            continue
        if not line.startswith("          "):
            raise AssertionError(f"workflow shell line has an invalid indentation: {line!r}")
        block.append(line[10:])
    return "\n".join(block) + "\n"


class ReleaseWorkflowTests(unittest.TestCase):
    def test_immutable_prerelease_shell_is_valid_bash(self) -> None:
        script = workflow_shell_block("Create or verify the immutable prerelease")
        completed = subprocess.run(
            ["bash", "-n"],
            input=script,
            text=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
