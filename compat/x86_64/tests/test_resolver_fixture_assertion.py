"""Behavior checks for the static-sysroot resolver fixture assertion."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_static_sysroot.sh"
EXPECTED_HOSTS = b"192.0.2.44 host.fixture host-alias\n"
RESOLVER_CONFIG = (
    "nameserver 127.0.0.47\n"
    "nameserver ::1\n"
    "nameserver 127.0.0.1\n"
    "nameserver 127.0.0.2\n"
    "search fixture.test\n"
    "options ndots:1 timeout:1 attempts:1\n"
)


def assertion_function() -> str:
    source = RUNNER.read_text(encoding="utf-8")
    start = source.index("assert_resolver_fixture_result() {\n")
    end = source.index("\nrun_static_tbss() {", start)
    return source[start:end]


class ResolverFixtureAssertionTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "fixture"
        etc = self.root / "etc"
        etc.mkdir(parents=True)
        (etc / "hosts").write_bytes(EXPECTED_HOSTS)
        (etc / "resolv.conf").write_text(RESOLVER_CONFIG, encoding="ascii")

    def assert_fixture(self, expected_status: int) -> subprocess.CompletedProcess[str]:
        command = (
            assertion_function()
            + '\nassert_resolver_fixture_result "$1" "fixture test"'
        )
        result = subprocess.run(
            ["bash", "-c", command, "fixture-test", str(self.root)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected_status, result.stderr)
        return result

    def test_accepts_the_bounded_resolver_fixture(self) -> None:
        self.assert_fixture(0)

    def test_rejects_shared_or_malformed_nameservers(self) -> None:
        resolv = self.root / "etc/resolv.conf"
        malformed_configs = (
            RESOLVER_CONFIG.replace("127.0.0.47", "127.0.0.1"),
            RESOLVER_CONFIG.replace("nameserver ::1", "nameserver ::1 extra"),
        )
        for config in malformed_configs:
            with self.subTest(config=config):
                resolv.write_text(config, encoding="ascii")
                self.assert_fixture(1)

    def test_rejects_a_symlinked_resolver_file(self) -> None:
        resolv = self.root / "etc/resolv.conf"
        target = self.root / "resolver-target"
        target.write_text(RESOLVER_CONFIG, encoding="ascii")
        resolv.unlink()
        resolv.symlink_to(target)

        result = self.assert_fixture(1)
        self.assertIn("resolv.conf became a symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
