"""The supplied owned archive may extend the complete default-static roster."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_native_thread_signal_abi.sh"


class NativeThreadSignalRosterTests(unittest.TestCase):
    def test_integrated_default_provider_is_not_required_to_be_an_addition(self):
        scratch = ROOT / ".work/x86_64/native-thread-signal-roster-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            work = Path(directory)
            source = work / "fixture.c"
            source.write_text(
                "int tgkill(int group, int task, int signal) { return group + task + signal; }\n"
                "int owned_feature_fixture(void) { return 0; }\n"
            )
            member = work / "c.fixture.rcgu.o"
            subprocess.run(["/usr/bin/clang", "--target=x86_64-linux-musl", "-fno-stack-protector",
                            "-c", str(source), "-o", str(member)], check=True, capture_output=True)
            archive = work / "libc.a"
            subprocess.run(["/usr/bin/ar", "rcs", str(archive), str(member)], check=True, capture_output=True)
            roster = work / "default.txt"
            roster.write_text("tgkill\n")
            runner = RUNNER.read_text()
            marker = 'cat >"$work/local-default-static-delta.sh" <<\'SH\'\n'
            self.assertEqual(runner.count(marker), 1)
            body = runner.split(marker, 1)[1].split("\nSH\n", 1)[0]
            script = work / "compare.sh"
            script.write_text(body + "\n")
            result = subprocess.run(["bash", str(script), str(archive), str(roster), str(work)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "required-default-provider=tgkill\nowned-static-surplus=1\n")
            self.assertEqual((work / "local-default-static-additions.txt").read_text(), "owned_feature_fixture\n")
            self.assertEqual((work / "local-default-static-missing.txt").read_text(), "")


if __name__ == "__main__":
    unittest.main()
