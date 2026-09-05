"""The native stress profile preserves the frozen source outside two main calls."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_pthread_stress_source as source_profile


class OwnedPthreadStressSourceTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "tests/fixtures/pthread_stress_test.c").read_bytes()

    def test_native_profile_changes_exactly_two_whole_main_call_lines(self):
        prepared, replacements = source_profile.prepare(self.source, "native-v1")
        old_lines, new_lines = self.source.splitlines(keepends=True), prepared.splitlines(keepends=True)
        self.assertEqual(len(old_lines), len(new_lines))
        changed = [(index + 1, old, new) for index, (old, new) in enumerate(zip(old_lines, new_lines)) if old != new]
        self.assertEqual([row[0] for row in changed], [811, 813])
        self.assertEqual(len(replacements), 2)
        self.assertEqual([row["source_function"] for row in replacements], ["deferred_stdio_probe", "asynchronous_stdio_probe"])
        for line, old, new in changed:
            record = next(row for row in replacements if row["line"] == line)
            self.assertEqual(bytes.fromhex(record["original_hex"]), old)
            self.assertEqual(bytes.fromhex(record["replacement_hex"]), new)
            self.assertTrue(new.startswith(b"    /* "))
            self.assertTrue(new.endswith(b" */\n"))
        self.assertIn(b'run_probe_with_timeout(asynchronous_read_probe, "asynchronous read cancellation probe");', prepared)
        self.assertNotIn(b"#define", b"".join(new for _, _, new in changed))

    def test_frozen_replay_is_byte_identical_and_remains_pinned(self):
        prepared, replacements = source_profile.prepare(self.source, "frozen")
        self.assertEqual(prepared, self.source)
        self.assertEqual(replacements, [])
        with self.assertRaisesRegex(source_profile.SourceProfileError, "SHA-256"):
            source_profile.prepare(self.source + b"\n", "frozen")

    def test_native_rejects_any_unrelated_source_drift(self):
        changed = self.source.replace(b"test_joinable_lifetimes();", b"test_detached_lifetimes();", 1)
        self.assertNotEqual(changed, self.source)
        with self.assertRaisesRegex(source_profile.SourceProfileError, "SHA-256"):
            source_profile.prepare(changed, "native-v1")

    def test_pinned_hash_alone_cannot_admit_missing_or_duplicate_call(self):
        for line in (b'    run_probe_with_timeout(deferred_stdio_probe, "deferred stdio cancellation probe");\n',
                     b'    run_probe_with_timeout(asynchronous_stdio_probe, "asynchronous stdio cancellation probe");\n'):
            for changed in (self.source.replace(line, b"", 1), self.source.replace(line, line + line, 1)):
                with self.subTest(line=line, size=len(changed)):
                    with patch.object(source_profile, "ORIGINAL_SHA256", hashlib.sha256(changed).hexdigest()):
                        with self.assertRaisesRegex(source_profile.SourceProfileError, "exactly one"):
                            source_profile.prepare(changed, "native-v1")

    def test_materialized_source_map_binds_original_preparer_and_generated_bytes(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            output = Path(directory) / "prepared.c"
            original = ROOT / "tests/fixtures/pthread_stress_test.c"
            record = source_profile.materialize(original, output, "native-v1")
            self.assertEqual(record["original"]["sha256"], hashlib.sha256(self.source).hexdigest())
            self.assertEqual(record["prepared"]["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(record["preparer"]["sha256"], hashlib.sha256(Path(source_profile.__file__).read_bytes()).hexdigest())
            self.assertEqual(record["profile"], "native-v1")
            self.assertEqual(len(record["replacements"]), 2)


if __name__ == "__main__":
    unittest.main()
