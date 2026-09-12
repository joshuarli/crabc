#!/usr/bin/env python3
"""Exercise native ABI-ratchet dispatcher admission without replaying data."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / ".work/x86_64/native-abi-ratchet-dispatcher-tests"


class NativeAbiRatchetDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        WORK.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.temporary.cleanup)
        self.checkout = Path(self.temporary.name) / "checkout"
        self.work = self.checkout / ".work/x86_64"
        self.work.mkdir(parents=True)
        scripts = self.checkout / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "scripts/dev-x86_64.sh", scripts / "dev-x86_64.sh")
        self.inputs = self.checkout / ".work/retained-products"
        self.inputs.mkdir(parents=True)
        self.static_product = self.inputs / "static"
        self.dynamic_product = self.inputs / "dynamic"
        self.static_product.mkdir()
        self.dynamic_product.mkdir()
        self.static_preparation = self.inputs / "static-preparation.json"
        self.static_preparation.write_text("{}\n", encoding="utf-8")
        self.inventory_report = self.work / "inventory/report.json"
        self.inventory_report.parent.mkdir()
        self.inventory_report.write_text("{}\n", encoding="utf-8")
        self.ratchet_report = self.work / "check/ratchet.json"
        self.ratchet_report.parent.mkdir()
        self.ratchet_report.write_text("{}\n", encoding="utf-8")
        self.runner_log = self.work / "runner.json"
        runner = self.checkout / "compat/x86_64/native_abi_ratchet.py"
        runner.parent.mkdir(parents=True)
        runner.write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['ABI_RATCHET_DISPATCH_RUNNER_LOG']).write_text(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        binaries = self.work / "bin"
        binaries.mkdir()
        docker = binaries / "docker"
        docker.write_text(
            "#!/usr/bin/env sh\n"
            "echo docker-must-not-run >&2\n"
            "exit 97\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("CRABC_X86_64_")
        }
        self.environment.update({
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "ABI_RATCHET_DISPATCH_RUNNER_LOG": str(self.runner_log),
            "PYTHONDONTWRITEBYTECODE": "1",
        })

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.checkout / "scripts/dev-x86_64.sh"), "native-abi-ratchet", *arguments],
            cwd=self.checkout,
            env=self.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def input_arguments(self) -> list[str]:
        return [
            "--inventory-report", str(self.inventory_report.relative_to(self.checkout)),
            "--static-product", str(self.static_product.relative_to(self.checkout)),
            "--dynamic-product", str(self.dynamic_product.relative_to(self.checkout)),
            "--static-preparation", str(self.static_preparation.relative_to(self.checkout)),
        ]

    def recorded_arguments(self) -> list[str]:
        return json.loads(self.runner_log.read_text(encoding="utf-8"))

    def test_check_is_host_only_and_binds_every_supplied_input(self) -> None:
        output = self.work / "check/fresh"
        output.parent.mkdir(exist_ok=True)
        result = self.invoke("check", *self.input_arguments(), "--output", str(output.relative_to(self.checkout)))
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.recorded_arguments()
        self.assertEqual(arguments[0], "check")
        self.assertEqual(arguments[arguments.index("--inventory-report") + 1], str(self.inventory_report))
        self.assertEqual(arguments[arguments.index("--static-product") + 1], str(self.static_product))
        self.assertEqual(arguments[arguments.index("--dynamic-product") + 1], str(self.dynamic_product))
        self.assertEqual(arguments[arguments.index("--static-preparation") + 1], str(self.static_preparation))
        self.assertEqual(arguments[arguments.index("--output") + 1], str(output))

    def test_validate_report_is_host_only_and_has_no_baseline_selector(self) -> None:
        result = self.invoke(
            "validate-report", str(self.ratchet_report.relative_to(self.checkout)), *self.input_arguments(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.recorded_arguments()
        self.assertEqual(arguments[:2], ["validate-report", str(self.ratchet_report)])
        self.assertNotIn("--baseline", arguments)

        result = self.invoke("check", *self.input_arguments(), "--output", ".work/x86_64/check/other", "--baseline", "weaker.json")
        self.assertEqual(result.returncode, 2)

    def test_output_and_report_must_be_physical_checkout_work_paths(self) -> None:
        result = self.invoke("check", *self.input_arguments(), "--output", str(self.inputs / "outside-output"))
        self.assertEqual(result.returncode, 2)

        outside = Path(self.temporary.name) / "outside.json"
        outside.write_text("{}\n", encoding="utf-8")
        result = self.invoke("validate-report", str(outside), *self.input_arguments())
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
