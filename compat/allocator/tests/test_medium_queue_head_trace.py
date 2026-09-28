"""The medium queue trace reader rejects altered fresh and repeated events."""

from __future__ import annotations

import unittest

from compat.allocator.medium_queue_head_trace import BLOCK_COUNT, read_trace


def valid_trace() -> str:
    lines = []
    for phase in ("fresh", "repeat"):
        lines.extend(f"alloc {phase} {index} usable=32768 align=0" for index in range(BLOCK_COUNT))
        lines.append(f"replace {phase} reused=1 usable=32768 align=0")
        lines.append(f"spill {phase} usable=32768 align=0")
        lines.append(f"drain {phase} count={BLOCK_COUNT}")
    return "\n".join(lines) + "\n"


class MediumQueueTraceTests(unittest.TestCase):
    def test_accepts_fresh_and_repeated_medium_allocations(self) -> None:
        self.assertEqual(len(read_trace(valid_trace())), 2 * (BLOCK_COUNT + 3))

    def test_rejects_missing_repeat_drain(self) -> None:
        with self.assertRaises(ValueError):
            read_trace(valid_trace().replace(f"drain repeat count={BLOCK_COUNT}\n", ""))

    def test_rejects_usable_size_or_alignment_divergence(self) -> None:
        with self.assertRaises(ValueError):
            read_trace(valid_trace().replace("usable=32768", "usable=32767", 1))
        with self.assertRaises(ValueError):
            read_trace(valid_trace().replace("align=0", "align=8", 1))

    def test_rejects_missing_local_free_reuse(self) -> None:
        with self.assertRaises(ValueError):
            read_trace(valid_trace().replace("reused=1", "reused=0", 1))

    def test_rejects_missing_next_page_allocation(self) -> None:
        with self.assertRaises(ValueError):
            read_trace(valid_trace().replace("spill fresh usable=32768 align=0\n", ""))


if __name__ == "__main__":
    unittest.main()
