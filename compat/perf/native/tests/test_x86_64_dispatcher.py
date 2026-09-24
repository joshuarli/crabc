#!/usr/bin/env python3
"""Exercise native facade command routing without executing a benchmark.

Each case copies the dispatcher into a private checkout and gives it recording
Docker/runner fixtures. These checks cover the host/container path boundary;
the real runner's retained-evidence and native smoke checks live separately.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]
WORK = ROOT / ".work/x86_64/native-facade-dispatcher-tests"
IMAGE_ID = "sha256:" + "5" * 64


class NativeFacadeDispatcherTests(unittest.TestCase):
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
        self.sources = {}
        for name in ("rustybench", "rustix"):
            path = self.work / "inputs" / name
            path.mkdir(parents=True)
            self.sources[name] = path
        self.docker_log = self.work / "docker.jsonl"
        self.runner_log = self.work / "runner.json"
        binaries = self.work / "bin"
        binaries.mkdir()
        docker = binaries / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "with pathlib.Path(os.environ['DISPATCH_DOCKER_LOG']).open('a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[:2] == ['image', 'inspect']:\n"
            "    if '--format' in args:\n"
            "        template = args[args.index('--format') + 1]\n"
            "        if template == '{{.Os}}/{{.Architecture}}': print('linux/amd64')\n"
            f"        elif template == '{{{{.Id}}}}': print({IMAGE_ID!r})\n"
            "        else: sys.exit(3)\n"
            "elif args[:1] != ['run']: sys.exit(3)\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        runner = self.checkout / "compat/perf/native/x86_64_runner.py"
        runner.parent.mkdir(parents=True)
        runner.write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['DISPATCH_RUNNER_LOG']).write_text(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("CRABC_X86_64_")
        }
        self.environment.update({
            "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
            "DISPATCH_DOCKER_LOG": str(self.docker_log),
            "DISPATCH_RUNNER_LOG": str(self.runner_log),
            "PYTHONDONTWRITEBYTECODE": "1",
        })

    def source_arguments(self) -> list[str]:
        return [
            "--rustybench-source", str(self.sources["rustybench"].relative_to(self.checkout)),
            "--rustix-source", str(self.sources["rustix"].relative_to(self.checkout)),
        ]

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.checkout / "scripts/dev-x86_64.sh"), "perf-native", *arguments],
            cwd=self.checkout, env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )

    def docker_run(self) -> list[str]:
        records = [json.loads(line) for line in self.docker_log.read_text().splitlines()]
        runs = [record for record in records if record[0] == "run"]
        self.assertEqual(len(runs), 1)
        return runs[0]

    def test_smoke_uses_readonly_sources_offline_and_actual_image_identity(self) -> None:
        report = self.work / "result.json"
        result = self.invoke("--mode", "smoke", "--report", str(report.relative_to(self.checkout)), *self.source_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.docker_run()
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertIn(f"{self.sources['rustybench']}:/inputs/rustybench:ro", args)
        self.assertIn(f"{self.sources['rustix']}:/inputs/rustix:ro", args)
        self.assertIn(f"CRABC_PERF_X86_IMAGE_ID=crabc-core-evidence@{IMAGE_ID}", args)
        self.assertEqual(args[args.index("--report") + 1], "/workspace/.work/x86_64/result.json")
        self.assertNotIn("--privileged", args)
        self.assertFalse(any(arg.startswith("--cap-add") for arg in args))

    def test_prepare_has_network_and_uses_private_work_root(self) -> None:
        result = self.invoke("--prepare", *self.source_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.docker_run()
        self.assertNotIn("--network", args)
        self.assertEqual(args[args.index("--work-root") + 1], "/workspace/.work/x86_64")
        self.assertIn("--prepare", args)

    def test_container_retains_private_evidence_as_the_invoking_user(self) -> None:
        result = self.invoke("--prepare", *self.source_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.docker_run()
        self.assertIn("--user", args)
        self.assertEqual(args[args.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")

    def test_report_replay_maps_container_inputs_back_to_host_without_docker(self) -> None:
        report = self.work / "saved.json"
        report.write_text("{}", encoding="utf-8")
        result = self.invoke(
            "--validate-report", "/workspace/.work/x86_64/saved.json",
            "--rustybench-source", "/workspace/.work/x86_64/inputs/rustybench",
            "--rustix-source", "/workspace/.work/x86_64/inputs/rustix",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.docker_log.exists())
        args = json.loads(self.runner_log.read_text())
        self.assertEqual(args[args.index("--validate-report") + 1], str(report))
        self.assertEqual(args[args.index("--rustix-source") + 1], str(self.sources["rustix"]))

    def test_refused_full_admission_stops_before_input_or_docker_setup(self) -> None:
        runner = self.checkout / "compat/perf/native/x86_64_runner.py"
        runner.write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['DISPATCH_RUNNER_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
            "sys.exit(2)\n",
            encoding="utf-8",
        )
        result = self.invoke("--mode", "full")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.docker_log.exists())
        self.assertEqual(json.loads(self.runner_log.read_text()), ["--full-admission"])

    def test_admitted_full_mode_runs_the_smoke_container_route(self) -> None:
        report = self.work / "full.json"
        result = self.invoke("--mode", "full", "--report", str(report.relative_to(self.checkout)), *self.source_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.runner_log.read_text()), ["--full-admission"])
        args = self.docker_run()
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--mode") + 1], "full")
        self.assertEqual(args[args.index("--report") + 1], "/workspace/.work/x86_64/full.json")

    def test_source_symlink_escape_is_rejected_before_docker(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        self.sources["rustix"].rmdir()
        self.sources["rustix"].symlink_to(outside, target_is_directory=True)
        result = self.invoke("--prepare", *self.source_arguments())
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.docker_log.exists())

    def test_source_docker_mount_separator_is_rejected_before_docker(self) -> None:
        source = self.work / "inputs/rustix:unexpected"
        source.mkdir()
        self.sources["rustix"] = source
        result = self.invoke("--prepare", *self.source_arguments())
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.docker_log.exists())


if __name__ == "__main__":
    unittest.main()
