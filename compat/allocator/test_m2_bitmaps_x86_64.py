"""Host-only negative tests for the native bitmap transcript boundary."""

import unittest

from m2_bitmaps_x86_64 import transcript


class BitmapTranscriptTests(unittest.TestCase):
    def test_libtest_prefix_and_unsigned_max_are_preserved(self):
        self.assertEqual(transcript(
            "test bitmap::native_tests::emit_native_bitmap_component_trace ... "
            "m2.bitmap.native.0=0\nm2.bitmap.native.1=18446744073709551615\n"),
            [0, (1 << 64) - 1])

    def test_missing_duplicate_reordered_malformed_and_overflow_values_fail(self):
        for output in (
            "", "m2.bitmap.native.1=0", "m2.bitmap.native.0=1\nm2.bitmap.native.0=2",
            "m2.bitmap.native.1=1\nm2.bitmap.native.0=2",
            "m2.bitmap.native.0=1\nm2.bitmap.native.2=2",
            "m2.bitmap.native.0=1\nm2.bitmap.native.1=bad",
            "m2.bitmap.native.0=-1", "m2.bitmap.native.0=18446744073709551616",
            "m2.bitmap.native.0=1junk",
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                transcript(output)


if __name__ == "__main__":
    unittest.main()
