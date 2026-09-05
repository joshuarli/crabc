"""Owned stress evidence rejects incomplete, normalized, or mutated results."""
import json
import os
import signal
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_pthread_stress as stress


class OwnedPthreadStressTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def test_cli_bounds_defaults_and_required_dynamic_product(self):
        options = stress.parse_arguments(["dynamic"])
        self.assertEqual((options.iterations, options.timeout), (10, 10.0))
        self.assertIsNone(options.static)
        self.assertEqual(options.dynamic, Path("dynamic"))
        options = stress.parse_arguments(["--iterations", "100", "--static-sysroot", "static", "--timeout", "300", "dynamic"])
        self.assertEqual((options.iterations, options.timeout, options.static), (100, 300.0, Path("static")))
        for arguments in ([], [""], ["--static-sysroot", "static"], ["--iterations", "0", "d"],
                          ["--iterations", "101", "d"], ["--iterations", "1", "--iterations", "2", "d"],
                          ["--iterations", "1.0", "d"], ["--timeout", "0", "d"], ["--timeout", "301", "d"],
                          ["--timeout", "nan", "d"], ["--timeout", "inf", "d"],
                          ["--static-sysroot", "--iterations", "2", "d"], ["d", "--iterations", "2"]):
            with self.subTest(arguments=arguments):
                with self.assertRaises(stress.ArgumentError):
                    stress.parse_arguments(arguments)

    def test_real_entrypoint_rejects_arguments_before_output(self):
        for arguments in ([], [""], ["--iterations", "101", "dynamic"], ["--static-sysroot", "static"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run(["bash", str(ROOT / "compat/x86_64/run_owned_pthread_stress.sh"), *arguments],
                    env=dict(os.environ, TMPDIR=str(self.work), PYTHONDONTWRITEBYTECODE="1"),
                    cwd=ROOT, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(list(self.work.iterdir()), [])

    def test_raw_streams_and_success_contract_are_not_normalized(self):
        success = stress.Observation(0, b"pthread stress ok\n", b"")
        self.assertTrue(stress.compare(success, success)["passed"])
        for changed in (stress.Observation(1, success.stdout, b""),
                        stress.Observation(0, b"pthread stress ok \n", b""),
                        stress.Observation(0, success.stdout, b"warning\n"),
                        stress.Observation("TIMEOUT", b"", b"")):
            self.assertFalse(stress.compare(success, changed)["passed"])
            self.assertFalse(stress.compare(changed, changed)["passed"])
        snapshot = stress.stream_snapshot(b"\x00\xff\n")
        self.assertEqual(snapshot["hex"], "00ff0a")
        self.assertEqual(snapshot["byte_length"], 3)

    def test_frozen_aarch64_source_exception_is_not_a_native_pass(self):
        source_failure = stress.Observation(1, b"pthread stress FAIL 4\n",
            b"FAIL: deferred stdio cancellation probe\nFAIL: deferred stdio cancellation probe\n"
            b"FAIL: asynchronous stdio cancellation probe\nFAIL: asynchronous stdio cancellation probe\n")
        success = stress.Observation(0, b"pthread stress ok\n", b"")
        self.assertFalse(stress.compare(source_failure, success)["passed"])
        self.assertFalse(stress.compare(source_failure, source_failure)["passed"])

    def test_each_observation_starts_a_fresh_group_and_keeps_exit_and_binary_streams(self):
        command = [sys.executable, "-c", "import os,sys; os.write(1,b'out\\x00\\xff'); os.write(2,b'err\\x00'); sys.exit(3)"]
        first = stress.observe(command, self.work, self.work / "first", 2)
        second = stress.observe(command, self.work, self.work / "second", 2)
        self.assertEqual((first.status, first.stdout, first.stderr), (3, b"out\x00\xff", b"err\x00"))
        self.assertEqual(first, second)
        one = json.loads((self.work / "first.status.json").read_text())
        two = json.loads((self.work / "second.status.json").read_text())
        self.assertEqual(one["pid"], one["process_group"])
        self.assertNotEqual(one["process_group"], two["process_group"])
        self.assertEqual((self.work / "first.stdout").read_bytes(), first.stdout)
        self.assertEqual((self.work / "first.stderr").read_bytes(), first.stderr)

    def test_timeout_kills_the_whole_process_group_and_keeps_partial_output(self):
        script = "import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); print(child.pid,flush=True); time.sleep(30)"
        observation = stress.observe([sys.executable, "-c", script], self.work, self.work / "timeout", 0.2)
        self.assertEqual(observation.status, "TIMEOUT")
        child = int(observation.stdout)
        status = Path(f"/proc/{child}/stat")
        if status.exists():
            self.assertEqual(status.read_text().rsplit(")", 1)[1].split()[0], "Z")
        self.assertEqual((self.work / "timeout.stdout").read_bytes(), observation.stdout)

    def test_interrupted_supervisor_reaps_group_and_retains_actual_status(self):
        for ignore_term in (False, True):
            with self.subTest(ignore_term=ignore_term):
                prefix = self.work / ("interrupted-kill" if ignore_term else "interrupted-term")
                ready = Path(str(prefix) + ".ready")
                term_setup = "signal.signal(signal.SIGTERM, signal.SIG_IGN);" if ignore_term else ""
                grandchild_code = "import signal,time;" + term_setup + "time.sleep(30)"
                child_code = ("import os,signal,subprocess,sys,time; from pathlib import Path;" + term_setup
                    + "child=subprocess.Popen([sys.executable,'-c'," + repr(grandchild_code) + "]);"
                    + "os.write(1,b'partial\\x00\\xff');os.write(2,b'error\\x00');"
                    + "Path(" + repr(str(ready)) + ").write_text(str(os.getpid())+' '+str(child.pid));time.sleep(30)")
                supervisor_code = ("import sys;from pathlib import Path;sys.path.insert(0,"
                    + repr(str(ROOT / "compat/x86_64")) + ");import owned_pthread_stress as stress;"
                    + "stress.observe([sys.executable,'-c'," + repr(child_code) + "],Path("
                    + repr(str(self.work)) + "),Path(" + repr(str(prefix)) + "),20)")
                supervisor = subprocess.Popen([sys.executable, "-B", "-c", supervisor_code],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                pids = []
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists(), "child did not announce its process group")
                    pids = list(map(int, ready.read_text().split()))
                    # Both children inherit the ignored disposition from their parent.
                    supervisor.send_signal(signal.SIGINT)
                    _, error = supervisor.communicate(timeout=6)
                    self.assertIn(b"KeyboardInterrupt", error)
                    record = json.loads(Path(str(prefix) + ".status.json").read_text())
                    self.assertEqual(record["status"], -signal.SIGKILL if ignore_term else -signal.SIGTERM)
                    self.assertEqual(record["returncode"], record["status"])
                    self.assertEqual(Path(str(prefix) + ".stdout").read_bytes(), b"partial\x00\xff")
                    self.assertEqual(Path(str(prefix) + ".stderr").read_bytes(), b"error\x00")
                    for pid in pids:
                        stat = Path(f"/proc/{pid}/stat")
                        if stat.exists():
                            self.assertEqual(stat.read_text().rsplit(")", 1)[1].split()[0], "Z")
                    self.assertFalse(Path(f"/proc/{pids[0]}").exists(), "direct child was not reaped")
                finally:
                    if pids:
                        try:
                            os.killpg(pids[0], signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if supervisor.poll() is None:
                        supervisor.kill()
                    supervisor.communicate()

    def test_matrix_requires_every_iteration_and_every_selected_cell(self):
        good = stress.Observation(0, b"pthread stress ok\n", b"")
        cells = stress.cells(include_static=True)
        records = [{cell: good for cell in cells} for _ in range(2)]
        report = stress.summarize(records, 2, True)
        self.assertTrue(report["passed"])
        self.assertEqual(report["observation_count"], 14)
        records[0].pop("static-pie")
        with self.assertRaisesRegex(stress.EvidenceError, "cell roster"):
            stress.summarize(records, 2, True)
        with self.assertRaisesRegex(stress.EvidenceError, "iteration roster"):
            stress.summarize([], 2, True)

    def test_pre_run_identities_reject_mutation_of_source_or_consumed_copy(self):
        source, copy = self.work / "source", self.work / "copy"
        source.write_bytes(b"same executable")
        copy.write_bytes(source.read_bytes())
        records = stress.identities([source, copy])
        stress.audit_identities(records)
        copy.write_bytes(b"changed executed binary")
        with self.assertRaisesRegex(stress.EvidenceError, "identity changed"):
            stress.audit_identities(records)
        copy.write_bytes(source.read_bytes())
        source.write_bytes(b"changed source binary")
        with self.assertRaisesRegex(stress.EvidenceError, "identity changed"):
            stress.audit_identities(records)

    def test_header_audit_records_exact_environment_and_compiler_identity(self):
        product = self.work / "product"
        include = product / "usr/include"
        include.mkdir(parents=True)
        headers = [include / name for name in ("pthread.h", "stdio.h", "signal.h", "unistd.h")]
        for path in headers:
            path.write_text("/* installed */")
        compiler = self.work / "compiler"
        compiler.write_bytes(b"pinned compiler bytes")
        source = self.work / "source.c"
        source.write_bytes(b"int main(void) { return 0; }")
        dependencies = ("source.o: " + " ".join(map(str, [source, *headers])) + "\n").encode()
        environment = stress.compiler_contract.clean_environment()
        with patch.object(stress, "SOURCE", source), patch.object(stress.compiler_contract, "compiler", return_value=str(compiler)), \
             patch.object(stress.subprocess, "check_output", side_effect=[dependencies, b"preprocessed bytes"]) as execution:
            record, _ = stress.header_audit(product, self.work)
        self.assertEqual(record["environment"], environment)
        self.assertEqual(record["compiler"], {"path": str(compiler), **stress.identities([compiler])[str(compiler)]})
        for invocation in execution.call_args_list:
            self.assertEqual(invocation.kwargs["env"], environment)
            self.assertEqual(invocation.args[0][0], str(compiler))

    def test_final_raw_audit_rejects_changed_stream_or_status(self):
        prefix = self.work / "raw"
        original = stress.observe([sys.executable, "-c", "print('retained')"], self.work, prefix, 2)
        stress.audit_raw_observation(prefix, original)
        (self.work / "raw.stdout").write_bytes(b"changed\n")
        with self.assertRaisesRegex(stress.EvidenceError, "raw observation changed"):
            stress.audit_raw_observation(prefix, original)
        (self.work / "raw.stdout").write_bytes(original.stdout)
        status = json.loads((self.work / "raw.status.json").read_text())
        status["status"] = 1
        (self.work / "raw.status.json").write_text(json.dumps(status))
        with self.assertRaisesRegex(stress.EvidenceError, "raw observation changed"):
            stress.audit_raw_observation(prefix, original)

    def test_shared_validator_rejects_link_failure_before_a_candidate_is_run(self):
        with patch.object(stress.product_evidence, "validate_link", side_effect=stress.product_evidence.ProductEvidenceError("forged input")):
            with self.assertRaisesRegex(stress.product_evidence.ProductEvidenceError, "forged input"):
                stress.audit_link(self.work, self.work / "object", self.work / "consumer", self.work / "receipt", "static")


if __name__ == "__main__":
    unittest.main()
