#!/usr/bin/env python3
"""Focused behavior contracts for the x86 campaign aggregate runner."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "campaign_runner.py"
sys.path.insert(0, str(RUNNER.parent))
import campaign_report  # noqa: E402
import campaign_runner  # noqa: E402


class CampaignRunnerTests(unittest.TestCase):
    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(RUNNER), *arguments],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_static_gate_reports_declared_blockers_without_running_docker(self) -> None:
        completed = self.invoke("static")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["gate"], "static_product")
        self.assertEqual(payload["state"], "blocked")
        self.assertIn("sysroot.static-tls", payload["incomplete_families"])
        self.assertTrue(payload["machine_gate_defined"])
        self.assertEqual(completed.stderr, "")

    def test_qualification_gate_reports_family_blockers_without_running_native_cases(self) -> None:
        completed = self.invoke("qualification")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["gate"], "qualification")
        self.assertEqual(payload["state"], "blocked")
        self.assertIn("compat.abi-differential", payload["incomplete_families"])
        self.assertTrue(payload["machine_gate_defined"])
        self.assertEqual(completed.stderr, "")

    def test_qualification_machine_gate_is_closed_to_its_pinned_runner(self) -> None:
        self.assertEqual(
            campaign_runner.qualification_machine_gate_command(
                {"machine_gate_command": campaign_report.QUALIFICATION_RUNNER_COMMAND}
            ),
            ["python3", "compat/x86_64/run_qualification_manifest.py"],
        )
        with self.assertRaisesRegex(
            campaign_runner.CampaignRunnerError, "pinned qualification runner"
        ):
            campaign_runner.qualification_machine_gate_command(
                {"machine_gate_command": "./scripts/dev-x86_64.sh qualification"}
            )

    def test_dynamic_gate_runs_its_pinned_terminal_product_runner(self) -> None:
        report = {
            "families": [
                {
                    "id": "complete",
                    "commands": ["./scripts/dev-x86_64.sh musl-oracle"],
                }
            ],
            "gates": {
                "dynamic_product": {
                    "pass": True,
                    "required_families": ["complete"],
                    "machine_gate_command": "./scripts/dev-x86_64.sh owned-dynamic-sysroot",
                }
            },
        }
        passed = subprocess.CompletedProcess([], 0)
        with mock.patch.object(campaign_runner.subprocess, "run", return_value=passed) as run:
            self.assertEqual(campaign_runner.execute_gate(report, "dynamic_product"), 0)
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["./scripts/dev-x86_64.sh", "musl-oracle"],
                ["./scripts/dev-x86_64.sh", "owned-dynamic-sysroot"],
            ],
        )

    def test_product_machine_gates_reject_substituted_terminal_runners(self) -> None:
        with self.assertRaisesRegex(campaign_runner.CampaignRunnerError, "pinned dynamic_product runner"):
            campaign_runner.product_machine_gate_command(
                "dynamic_product", {"machine_gate_command": "./scripts/dev-x86_64.sh musl-oracle"}
            )

    def test_registered_commands_reject_symlinked_executables_and_parents(self) -> None:
        scratch = ROOT / ".work" / "campaign-command-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="command-", dir=scratch) as directory:
            fixture = Path(directory)
            (fixture / "runner.sh").symlink_to(ROOT / "scripts/dev-x86_64.sh")
            (fixture / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
            for path in (fixture / "runner.sh", fixture / "scripts/dev-x86_64.sh"):
                with self.subTest(path=path.name):
                    command = "./" + path.relative_to(ROOT).as_posix() + " musl-oracle"
                    with self.assertRaisesRegex(campaign_runner.CampaignRunnerError, "symlink"):
                        campaign_runner.verified_command_tokens(command)
        self.assertEqual(
            campaign_runner.verified_command_tokens("./scripts/dev-x86_64.sh musl-oracle"),
            ["./scripts/dev-x86_64.sh", "musl-oracle"],
        )

    def test_unknown_aggregate_command_is_rejected(self) -> None:
        completed = self.invoke("not-a-campaign-command")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("invalid choice", completed.stderr)


if __name__ == "__main__":
    unittest.main()
