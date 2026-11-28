#!/usr/bin/env python3
"""Compare the unown release-CAS retry after full unmapped and OS-list abandonment against pinned C."""

from __future__ import annotations

from pathlib import Path

import m2_arena_abandonment_x86_64 as abandonment


RECEIVER = abandonment.Receiver(
    fixture=Path(__file__).with_suffix(".c"),
    rust_test_target="native_arena_unown_retry",
    target="unown_retry_after_a_remote_free_matches_the_pinned_source",
    prefix="m2.arena_unown_retry.",
    artifact="m2-arena-unown-retry",
    description="arena unown retry",
)


if __name__ == "__main__":
    abandonment.main(__doc__, RECEIVER)
