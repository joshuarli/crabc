#!/usr/bin/env python3
"""Behavior contracts for the opt-in cached native crabc-core test helper."""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "compat" / "x86_64" / "run_core_tests.py"
SCRATCH_ROOT = ROOT / ".work" / "x86_64" / "run-core-tests-tests"
sys.path.insert(0, str(HELPER.parent))
import run_core_tests  # noqa: E402


class CachedCoreTests(unittest.TestCase):
    """Run only fake Cargo/test children below the checkout-local `.work` tree."""

    def setUp(self) -> None:
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        self.fixture_root = Path(tempfile.mkdtemp(prefix="core-tests-", dir=SCRATCH_ROOT))
        self.state_root = self.fixture_root / "state"
        self.state_root.mkdir()
        self.addCleanup(self.remove_fixture_root)

    def remove_fixture_root(self) -> None:
        try:
            resolved = self.fixture_root.resolve(strict=True)
            scratch = SCRATCH_ROOT.resolve(strict=True)
        except OSError:
            return
        if (
            not self.fixture_root.is_symlink()
            and resolved == self.fixture_root
            and resolved.is_relative_to(scratch)
        ):
            shutil.rmtree(resolved, ignore_errors=True)

    def write_program(self, name: str, source: str) -> tuple[str, str]:
        path = self.fixture_root / name
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return (sys.executable, str(path))

    def write_objdump(self) -> tuple[str, str]:
        return self.write_program(
            "objdump.py",
            """
            print("  0: 90                    nop")
            """,
        )

    def cargo_program(self, test_body: str, *, executable: str = "current") -> tuple[str, str]:
        return self.write_program(
            f"cargo-{executable}.py",
            f"""
            import json
            import os
            from pathlib import Path

            target = Path(os.environ["CARGO_TARGET_DIR"])
            deps = target / "x86_64-unknown-linux-musl" / "debug" / "deps"
            deps.mkdir(parents=True, exist_ok=True)
            stale = deps / "crabc_core-stale"
            stale.write_text("#!/usr/bin/env python3\\nraise SystemExit(91)\\n", encoding="utf-8")
            stale.chmod(0o700)
            current = deps / "crabc_core-current"
            current.write_text({test_body!r}, encoding="utf-8")
            current.chmod(0o700)
            observation = os.environ.get("FAKE_CARGO_OBSERVATION")
            if observation:
                Path(observation).write_text(
                    json.dumps({{"argv": os.sys.argv[1:], "target": str(target)}}), encoding="utf-8"
                )
            print(json.dumps({{
                "reason": "compiler-artifact",
                "target": {{
                    "name": "crabc_core",
                    "kind": ["lib"],
                    "src_path": os.environ["CORE_TEST_SOURCE"],
                }},
                "profile": {{"test": True}},
                "executable": str(current),
            }}))
            """,
        )

    def invoke_helper(
        self,
        cargo: tuple[str, str],
        *,
        environment: dict[str, str] | None = None,
        objdump: tuple[str, str] | None = None,
        timeout: float = 2.0,
    ) -> run_core_tests.CoreTestRun:
        values = {"CORE_TEST_SOURCE": str(run_core_tests.CORE_LIB_SOURCE)}
        if environment:
            values.update(environment)
        return run_core_tests.run_core_tests(
            state_root=self.state_root,
            cargo=cargo,
            objdump=self.write_objdump() if objdump is None else objdump,
            environment=values,
            timeout_seconds=timeout,
            retain_success=True,
        )

    def test_json_selects_current_lib_artifact_not_a_stale_filename_match(self) -> None:
        observation = self.fixture_root / "cargo.json"
        marker = self.fixture_root / "test.json"
        cargo = self.cargo_program(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
Path(os.environ["FAKE_TEST_MARKER"]).write_text(
    json.dumps({"argv": os.sys.argv[1:], "tmpdir": os.environ["TMPDIR"]}), encoding="utf-8"
)
print("current executable")
"""
        )

        result = self.invoke_helper(
            cargo,
            environment={
                "FAKE_CARGO_OBSERVATION": str(observation),
                "FAKE_TEST_MARKER": str(marker),
            },
        )

        selected = result.test_executable
        self.assertEqual(selected.name, "crabc-core-tests")
        self.assertTrue(selected.is_file())
        self.assertNotIn("stale", selected.read_text(encoding="utf-8"))
        self.assertIn("current executable", (result.run_directory / "test.log").read_text(encoding="utf-8"))
        self.assertIn("nop", (result.run_directory / "fenv-disassembly").read_text(encoding="utf-8"))
        self.assertEqual(
            json.loads(marker.read_text(encoding="utf-8"))["argv"], ["--test-threads=1"]
        )
        self.assertTrue(
            Path(json.loads(marker.read_text(encoding="utf-8"))["tmpdir"]).is_relative_to(
                result.run_directory
            )
        )
        cargo_observation = json.loads(observation.read_text(encoding="utf-8"))
        self.assertEqual(
            cargo_observation["argv"],
            [
                "test",
                "--locked",
                "--target",
                "x86_64-unknown-linux-musl",
                "-p",
                "crabc-core",
                "--lib",
                "--no-default-features",
                "--no-run",
                "--message-format=json",
            ],
        )
        self.assertEqual(Path(cargo_observation["target"]), result.cache_target_directory)
        self.assertTrue(result.cache_target_directory.is_relative_to(self.state_root))

    def test_json_artifact_cannot_escape_the_checked_cache_target(self) -> None:
        outside = self.fixture_root / "outside-test"
        outside.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        outside.chmod(0o700)
        cargo = self.write_program(
            "cargo-escape.py",
            """
            import json
            import os

            print(json.dumps({
                "reason": "compiler-artifact",
                "target": {
                    "name": "crabc_core",
                    "kind": ["lib"],
                    "src_path": os.environ["CORE_TEST_SOURCE"],
                },
                "profile": {"test": True},
                "executable": os.environ["FAKE_OUTSIDE_TEST"],
            }))
            """,
        )

        with self.assertRaisesRegex(run_core_tests.CoreTestError, "escapes cached target") as raised:
            self.invoke_helper(cargo, environment={"FAKE_OUTSIDE_TEST": str(outside)})

        self.assertTrue(raised.exception.run_directory.is_dir())
        self.assertIn("cargo.log", [path.name for path in raised.exception.run_directory.iterdir()])

    def test_state_root_cannot_escape_checkout_x86_work_directory(self) -> None:
        escape_root = ROOT / ".work" / "core-test-cache-escape"
        escape_root.mkdir(exist_ok=True)
        self.addCleanup(shutil.rmtree, escape_root, True)

        with self.assertRaisesRegex(run_core_tests.CoreTestError, "stay below checkout .work/x86_64"):
            run_core_tests.prepare_state_root(escape_root)

    def test_parallel_builds_serialize_and_private_runs_do_not_collide(self) -> None:
        active = self.fixture_root / "cargo-active"
        cargo = self.write_program(
            "cargo-serialized.py",
            """
            import json
            import os
            import time
            from pathlib import Path

            active = Path(os.environ["FAKE_ACTIVE"])
            descriptor = os.open(active, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            try:
                time.sleep(0.2)
                target = Path(os.environ["CARGO_TARGET_DIR"])
                deps = target / "x86_64-unknown-linux-musl" / "debug" / "deps"
                deps.mkdir(parents=True, exist_ok=True)
                current = deps / "crabc_core-current"
                current.write_text("#!/usr/bin/env python3\\n", encoding="utf-8")
                current.chmod(0o700)
                print(json.dumps({
                    "reason": "compiler-artifact",
                    "target": {
                        "name": "crabc_core",
                        "kind": ["lib"],
                        "src_path": os.environ["CORE_TEST_SOURCE"],
                    },
                    "profile": {"test": True},
                    "executable": str(current),
                }))
            finally:
                active.unlink()
            """,
        )
        environment = {"FAKE_ACTIVE": str(active)}
        barrier = threading.Barrier(2)

        def run_one() -> run_core_tests.CoreTestRun:
            barrier.wait(timeout=2)
            return self.invoke_helper(cargo, environment=environment, timeout=3)

        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: run_one(), range(2)))

        self.assertGreaterEqual(time.monotonic() - started, 0.35)
        self.assertEqual(len({result.run_directory for result in results}), 2)
        self.assertEqual(len({result.test_executable for result in results}), 2)
        self.assertFalse(active.exists())
        self.assertEqual(
            {result.cache_target_directory for result in results},
            {self.state_root / "cache" / "target"},
        )

    def test_failure_retains_its_private_binary_and_log(self) -> None:
        cargo = self.cargo_program(
            """#!/usr/bin/env python3
print("test failed before cleanup")
raise SystemExit(17)
"""
        )

        with self.assertRaisesRegex(run_core_tests.CoreTestError, "test executable exited 17") as raised:
            self.invoke_helper(cargo)

        run_directory = raised.exception.run_directory
        self.assertTrue((run_directory / "crabc-core-tests").is_file())
        self.assertIn("test failed before cleanup", (run_directory / "test.log").read_text(encoding="utf-8"))

    def test_fenv_proof_rejects_fxrstor_in_the_private_copy_disassembly(self) -> None:
        cargo = self.cargo_program("#!/usr/bin/env python3\n")
        objdump = self.write_program(
            "objdump-fxrstor.py",
            """
            print("  0: 48 0f ae 08          fxrstor64 (%rax)")
            """,
        )

        with self.assertRaisesRegex(run_core_tests.CoreTestError, "must not reload XMM state") as raised:
            self.invoke_helper(cargo, objdump=objdump)

        self.assertIn(
            "fxrstor64",
            (raised.exception.run_directory / "fenv-disassembly").read_text(encoding="utf-8"),
        )

    def test_timeout_kills_the_owned_test_process_group(self) -> None:
        child_pid = self.fixture_root / "child.pid"
        cargo = self.cargo_program(
            """#!/usr/bin/env python3
import os
import subprocess
import sys
import time
from pathlib import Path

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(os.environ["FAKE_CHILD_PID"]).write_text(str(child.pid), encoding="utf-8")
time.sleep(60)
"""
        )

        with self.assertRaisesRegex(run_core_tests.CoreTestError, "timed out"):
            self.invoke_helper(cargo, environment={"FAKE_CHILD_PID": str(child_pid)}, timeout=0.1)

        deadline = time.monotonic() + 2.0
        status = Path(f"/proc/{child_pid.read_text(encoding='utf-8')}/stat")
        while status.exists() and time.monotonic() < deadline:
            try:
                if status.read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0] == "Z":
                    break
            except (IndexError, OSError):
                break
            time.sleep(0.02)
        self.assertFalse(status.exists() and " Z " not in status.read_text(encoding="utf-8"))

    def test_sigint_reaps_owned_test_descendants_and_retains_private_artifacts(self) -> None:
        grandchild_pid = self.fixture_root / "grandchild.pid"
        ready = self.fixture_root / "ready"
        cargo = self.cargo_program(
            """#!/usr/bin/env python3
import os
import subprocess
import sys
import time
from pathlib import Path

grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(os.environ["FAKE_GRANDCHILD_PID"]).write_text(str(grandchild.pid), encoding="utf-8")
Path(os.environ["FAKE_READY"]).write_text("ready", encoding="utf-8")
time.sleep(60)
"""
        )
        driver = self.write_program(
            "interrupt-driver.py",
            f"""
            import os
            import sys
            from pathlib import Path

            sys.path.insert(0, {str(HELPER.parent)!r})
            import run_core_tests

            try:
                with run_core_tests.cancellation_handlers():
                    run_core_tests.run_core_tests(
                        state_root=Path(os.environ["FAKE_STATE_ROOT"]),
                        cargo=(sys.executable, os.environ["FAKE_CARGO"]),
                        objdump=(sys.executable, os.environ["FAKE_OBJDUMP"]),
                        environment={{
                            "CORE_TEST_SOURCE": str(run_core_tests.CORE_LIB_SOURCE),
                            "FAKE_GRANDCHILD_PID": os.environ["FAKE_GRANDCHILD_PID"],
                            "FAKE_READY": os.environ["FAKE_READY"],
                        }},
                        timeout_seconds=30,
                        retain_success=True,
                    )
            except run_core_tests.CoreTestInterrupted as error:
                raise SystemExit(128 + error.signal_number)
            """,
        )
        objdump = self.write_objdump()
        environment = dict(os.environ)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "FAKE_STATE_ROOT": str(self.state_root),
                "FAKE_CARGO": cargo[1],
                "FAKE_OBJDUMP": objdump[1],
                "FAKE_GRANDCHILD_PID": str(grandchild_pid),
                "FAKE_READY": str(ready),
            }
        )
        process = subprocess.Popen(
            driver,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5.0
            while not ready.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    self.fail("helper did not start its owned test child")
                time.sleep(0.02)
            os.kill(process.pid, signal.SIGINT)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()

        self.assertEqual(process.returncode, 130, stdout.decode() + stderr.decode())
        status = Path(f"/proc/{grandchild_pid.read_text(encoding='utf-8')}/stat")
        deadline = time.monotonic() + 2.0
        while status.exists() and time.monotonic() < deadline:
            try:
                if status.read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0] == "Z":
                    break
            except (IndexError, OSError):
                break
            time.sleep(0.02)
        self.assertFalse(status.exists() and " Z " not in status.read_text(encoding="utf-8"))
        runs = list((self.state_root / "runs").iterdir())
        self.assertEqual(len(runs), 1)
        self.assertTrue((runs[0] / "crabc-core-tests").is_file())
        self.assertTrue((runs[0] / "fenv-disassembly").is_file())
        self.assertIn("timed out: false", (runs[0] / "test.log").read_text(encoding="utf-8"))

    def test_sigterm_uses_the_same_cancellation_path(self) -> None:
        with run_core_tests.cancellation_handlers():
            with self.assertRaises(run_core_tests.CoreTestInterrupted) as raised:
                os.kill(os.getpid(), signal.SIGTERM)

        self.assertEqual(raised.exception.signal_number, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
