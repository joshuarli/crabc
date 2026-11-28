#!/usr/bin/env python3
"""Compare the concurrent unown and unabandon interleavings of arena page abandonment against pinned C."""

from __future__ import annotations

from pathlib import Path

import m2_arena_abandonment_x86_64 as abandonment


RECEIVER = abandonment.Receiver(
    fixture=Path(__file__).with_suffix(".c"),
    rust_test_target="native_arena_abandonment_interleaving",
    target="abandonment_interleavings_match_the_pinned_source",
    prefix="m2.arena_interleave.",
    artifact="m2-arena-abandonment-interleaving",
    description="arena abandonment interleaving",
)


if __name__ == "__main__":
    abandonment.main(__doc__, RECEIVER)
