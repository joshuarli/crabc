#!/usr/bin/env python3
"""Compare multi-arena, multi-heap abandoned-page search against pinned C."""

from __future__ import annotations

from pathlib import Path

import m2_arena_abandonment_x86_64 as abandonment


RECEIVER = abandonment.Receiver(
    fixture=Path(__file__).with_suffix(".c"),
    rust_test_target="native_arena_abandoned_search",
    target="abandoned_page_search_follows_the_source_arena_and_heap_order",
    prefix="m2.arena_abandoned_search.",
    artifact="m2-arena-abandoned-search",
    description="abandoned-page search",
)


if __name__ == "__main__":
    abandonment.main(__doc__, RECEIVER)
