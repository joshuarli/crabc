#!/usr/bin/env python3
"""Host-only regressions for the focused runtime lifecycle receipt."""

from __future__ import annotations

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from x86_64_lifecycle_evidence import (  # type: ignore[attr-defined]
    EvidenceError,
    RUNTIME_THP_CONFIGURATION_IMAGE_IDS,
    RUNTIME_THP_CONFIGURATION_TRACE_BEGIN,
    RUNTIME_THP_CONFIGURATION_TRACE_END,
    parse_runtime_thp_configuration_trace,
)


def runtime_thp_trace(*, disabled_config: int, mode_two_config: int) -> str:
    """Render the fixed two-image scalar receipt used by parser regressions."""

    values = {
        "disabled": (0, 0, disabled_config),
        "mode-two": (2, 1, mode_two_config),
    }
    rows: list[str] = []
    for image_id in RUNTIME_THP_CONFIGURATION_IMAGE_IDS:
        raw, enabled, configuration = values[image_id]
        rows.extend(
            (
                RUNTIME_THP_CONFIGURATION_TRACE_BEGIN[image_id],
                f"selected_allow_thp_raw={raw}",
                f"vm_policy_allow_thp={enabled}",
                f"ready_memory_config_has_transparent_huge_pages={configuration}",
                RUNTIME_THP_CONFIGURATION_TRACE_END[image_id],
            )
        )
    return "\n".join(rows)


class RuntimeThpConfigurationTraceTests(unittest.TestCase):
    def test_two_clean_source_images_are_closed_and_mode_two_is_observed(self) -> None:
        trace = parse_runtime_thp_configuration_trace(
            runtime_thp_trace(disabled_config=0, mode_two_config=1)
        )
        self.assertEqual(tuple(trace), RUNTIME_THP_CONFIGURATION_IMAGE_IDS)
        self.assertEqual(trace["disabled"], {
            "selected_allow_thp_raw": 0,
            "vm_policy_allow_thp": 0,
            "ready_memory_config_has_transparent_huge_pages": 0,
        })
        self.assertEqual(trace["mode-two"], {
            "selected_allow_thp_raw": 2,
            "vm_policy_allow_thp": 1,
            "ready_memory_config_has_transparent_huge_pages": 1,
        })

    def test_trace_rejects_a_missing_duplicate_or_invalid_image_relation(self) -> None:
        good = runtime_thp_trace(disabled_config=0, mode_two_config=0)
        malformed = (
            good.replace("selected_allow_thp_raw=2\n", "", 1),
            good.replace("vm_policy_allow_thp=1", "vm_policy_allow_thp=1\nvm_policy_allow_thp=1", 1),
            good.replace("selected_allow_thp_raw=2", "selected_allow_thp_raw=3", 1),
            good.replace("ready_memory_config_has_transparent_huge_pages=0\nCRABC_MI_RUNTIME_THP_DISABLED_TRACE_END", "ready_memory_config_has_transparent_huge_pages=1\nCRABC_MI_RUNTIME_THP_DISABLED_TRACE_END", 1),
        )
        for trace in malformed:
            with self.subTest(trace=trace), self.assertRaises(EvidenceError):
                parse_runtime_thp_configuration_trace(trace)


if __name__ == "__main__":
    unittest.main()
