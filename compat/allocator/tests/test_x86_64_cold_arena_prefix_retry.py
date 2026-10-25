"""Reject incomplete or contradictory cold-arena retry observations."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x86_64_cold_arena_prefix_retry as producer


class ColdArenaPrefixRetryTrace(unittest.TestCase):
    def output(self, fields):
        return producer.BEGIN + "\n" + "\n".join(f"{key}={value}" for key, value in fields.items()) + "\n" + producer.END

    def test_rejects_missing_or_different_behavior(self):
        for key in producer.EXPECTED:
            for replacement in (None, "unexpected"):
                with self.subTest(key=key, replacement=replacement):
                    fields = dict(producer.EXPECTED)
                    if replacement is None:
                        del fields[key]
                    else:
                        fields[key] = replacement
                    with self.assertRaises(producer.harness.HarnessError):
                        producer.trace(self.output(fields))

    def test_rejects_duplicate_observation(self):
        output = self.output(producer.EXPECTED).replace(producer.END, "prefix.calls=2\n" + producer.END)
        with self.assertRaises(producer.harness.HarnessError):
            producer.trace(output)

    def test_requires_one_complete_trace(self):
        output = self.output(producer.EXPECTED)
        self.assertEqual(producer.trace(output), producer.EXPECTED)
        for invalid in (output + output, output.replace(producer.END, ""), ""):
            with self.assertRaises(producer.harness.HarnessError):
                producer.trace(invalid)


if __name__ == "__main__":
    unittest.main()
