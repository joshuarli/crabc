#!/usr/bin/env python3
"""Exercise native ABI inventory dispatcher admission without collecting data."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / ".work/x86_64/native-abi-inventory-dispatcher-tests"
IMAGE_ID = "sha256:" + "6" * 64


class NativeAbiInventoryDispatcherTests(unittest.TestCase):
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
        self.docker_log = self.work / "docker.jsonl"
        self.runner_log = self.work / "runner.json"
        binaries = self.work / "bin"
        binaries.mkdir()
        docker = binaries / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "with pathlib.Path(os.environ['ABI_DISPATCH_DOCKER_LOG']).open('a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[:2] == ['image', 'inspect']:\n"
            "    template = args[args.index('--format') + 1] if '--format' in args else ''\n"
            "    if template == '{{.Os}}/{{.Architecture}}': print('linux/amd64')\n"
            f"    elif template == '{{{{.Id}}}}': print({IMAGE_ID!r})\n"
            "    elif not template: pass\n"
            "    else: sys.exit(3)\n"
            "elif args[:1] != ['run']: sys.exit(3)\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("CRABC_X86_64_")
        }
        self.environment.update({
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "ABI_DISPATCH_DOCKER_LOG": str(self.docker_log),
            "ABI_DISPATCH_RUNNER_LOG": str(self.runner_log),
            "PYTHONDONTWRITEBYTECODE": "1",
        })

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.checkout / "scripts/dev-x86_64.sh"), "native-abi-inventory", *arguments],
            cwd=self.checkout,
            env=self.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def input_arguments(self) -> list[str]:
        return [
            "--static-product", str(self.static_product.relative_to(self.checkout)),
            "--dynamic-product", str(self.dynamic_product.relative_to(self.checkout)),
            "--static-preparation", str(self.static_preparation.relative_to(self.checkout)),
        ]

    def docker_run(self) -> list[str]:
        records = [json.loads(line) for line in self.docker_log.read_text(encoding="utf-8").splitlines()]
        runs = [record for record in records if record[0] == "run"]
        self.assertEqual(len(runs), 1)
        return runs[0]

    def test_collect_mounts_only_explicit_product_and_static_provenance_inputs_readonly(self) -> None:
        output = self.work / "abi/report"
        output.parent.mkdir()
        result = self.invoke("collect", *self.input_arguments(), "--output", str(output.relative_to(self.checkout)))
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.docker_run()
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertIn("--user", args)
        self.assertEqual(args[args.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
        self.assertIn(f"{self.static_product}:/inputs/static-product:ro", args)
        self.assertIn(f"{self.dynamic_product}:/inputs/dynamic-product:ro", args)
        self.assertIn(f"{self.static_preparation}:/inputs/static-preparation.json:ro", args)
        self.assertIn(f"CRABC_X86_ABI_IMAGE_ID=crabc-core-evidence@{IMAGE_ID}", args)
        image_position = args.index(IMAGE_ID)
        self.assertEqual(args[image_position + 1], "python3")
        self.assertNotIn("crabc-core-evidence:x86_64", args)
        self.assertEqual(args[args.index("--output") + 1], "/workspace/.work/x86_64/abi/report")
        self.assertEqual(args[args.index("--work-root") + 1], "/workspace/.work/x86_64")
        self.assertNotIn("--privileged", args)

    def test_validate_report_is_host_replay_without_docker(self) -> None:
        report = self.work / "abi/report.json"
        report.parent.mkdir()
        report.write_text("{}\n", encoding="utf-8")
        runner = self.checkout / "compat/x86_64/native_abi_inventory.py"
        runner.parent.mkdir(parents=True)
        runner.write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['ABI_DISPATCH_RUNNER_LOG']).write_text(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        result = self.invoke("validate-report", str(report.relative_to(self.checkout)), *self.input_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.docker_log.exists())
        arguments = json.loads(self.runner_log.read_text(encoding="utf-8"))
        self.assertEqual(arguments[arguments.index("--validate-report") + 1], str(report))
        self.assertEqual(arguments[arguments.index("--static-product") + 1], str(self.static_product))

    def test_external_or_symlink_input_is_rejected_before_docker(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        self.dynamic_product.rmdir()
        self.dynamic_product.symlink_to(outside, target_is_directory=True)
        result = self.invoke("collect", *self.input_arguments(), "--output", ".work/x86_64/abi/out")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.docker_log.exists())

    def test_output_must_stay_in_this_worktree_work_root(self) -> None:
        result = self.invoke("collect", *self.input_arguments(), "--output", str(self.inputs / "outside-output"))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.docker_log.exists())


if __name__ == "__main__":
    unittest.main()
