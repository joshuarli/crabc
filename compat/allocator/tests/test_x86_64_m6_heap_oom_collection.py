"""Test the ordinary generic OOM collection trace reader."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))

import x86_64_m6_heap_oom_collection as producer


class GenericOomCollectionTraceTests(unittest.TestCase):
    def test_accepts_the_source_and_unit_test_line_forms(self):
        self.assertEqual(
            producer.observation("oom_retry_released_remote_empty_other_bin=1\n", "pinned C"),
            producer.OBSERVATION,
        )
        self.assertEqual(
            producer.observation(
                "test single_thread::tests::generic_oom_retry_collects_remote_frees_across_regular_bins "
                "... oom_retry_released_remote_empty_other_bin=1\nok\n",
                "Rust",
            ),
            producer.OBSERVATION,
        )

    def test_rejects_missing_failed_or_repeated_observations(self):
        for output in (
            "",
            "prefix oom_retry_released_remote_empty_other_bin=1\n",
            "oom_retry_released_remote_empty_other_bin=0\n",
            "oom_retry_released_remote_empty_other_bin=10\n",
            "oom_retry_released_remote_empty_other_bin=1 extra\n",
            "oom_retry_released_remote_empty_other_bin=1\n"
            "oom_retry_released_remote_empty_other_bin=1\n",
        ):
            with self.subTest(side="pinned C", output=output), self.assertRaises(producer.harness.HarnessError):
                producer.observation(output, "pinned C")
        for output in (
            "",
            "test " + producer.RUST_TEST + " ... " + producer.OBSERVATION + "0\n",
            "test " + producer.RUST_TEST + " ... " + producer.OBSERVATION + "0 extra\n",
            "test " + producer.RUST_TEST + " ... other_key=1\n",
            "test " + producer.RUST_TEST + " ... " + producer.OBSERVATION + "\n"
            "test other::test ... another_key=0\n",
        ):
            with self.subTest(side="Rust", output=output), self.assertRaises(producer.harness.HarnessError):
                producer.observation(output, "Rust")


if __name__ == "__main__":
    unittest.main()
