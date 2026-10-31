#!/usr/bin/env python3
"""The owned POSIX composition replay interface stays bounded."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_posix_composition.sh"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"
MANIFEST = ROOT / "libc/Cargo.toml"
STATIC_EXPORTS = ROOT / "compat/x86_64/static_c_abi_exports.txt"
PROBE = ROOT / "compat/x86_64/owned_posix_composition_probe.c"


def enabled_features(features, name):
    """Return every feature `name` enables, transitively."""
    enabled, pending = set(), list(features[name])
    while pending:
        feature = pending.pop()
        if feature in features and feature not in enabled:
            enabled.add(feature)
            pending.extend(features[feature])
    return enabled


class OwnedPosixCompositionTests(unittest.TestCase):
    def test_static_replay_parser_rejects_incomplete_or_ambiguous_arguments(
        self,
    ) -> None:
        invalid_arguments = (
            ("--static-sysroot",),
            ("--static-sysroot", ""),
            ("--static-sysroot", "--not-a-product"),
            ("--static-sysroot", "first", "--static-sysroot", "second"),
            ("first-dynamic", "second-dynamic"),
        )

        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    "usage: "
                    f"{RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
                )

    def test_static_replay_keeps_the_single_object_and_sealed_raw_matrix(
        self,
    ) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")

        for required in (
            "provided_static=''",
            "provided_dynamic=''",
            "dynamic_was_supplied=0",
            "realpath -e --",
            "owned POSIX composition {name} product must be a checkout .work directory",
            'static_product="$provided_static"',
            'elif [ "$dynamic_was_supplied" -eq 0 ]; then',
            '"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie',
            '"$static_product/bin/crabc-cc" "-$mode" --link-receipt',
            'audit_link "$static_product"',
            'audit_link "$provided_dynamic"',
            "dependency_audit_command",
            "validate_link",
            ".evidence.json",
            "for suffix in stdout stderr status",
            "cp \"$root/log-wire\"",
            "for mode in static static-pie",
            "for mode in pie non-pie",
            "for entry in kernel direct",
        ):
            self.assertIn(required, runner)
        self.assertLess(
            runner.index('audit_link "$static_product"'),
            runner.index('run_in_root "$execution_root" "$work/$mode.stdout"'),
        )
        self.assertLess(
            runner.index('audit_link "$provided_dynamic"'),
            runner.index('run_in_root "$execution_root" "$work/$mode-$entry.stdout"'),
        )
        self.assertIn(
            "owned-posix-composition [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]",
            dispatcher,
        )
        self.assertIn(
            "run_owned_posix_composition.sh \"$@\"",
            dispatcher,
        )
        self.assertNotIn(
            "owned-posix-composition takes at most one dynamic sysroot",
            dispatcher,
        )

    def test_existing_composition_object_keeps_scheduler_and_netdb_providers_selected(self) -> None:
        features = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))["features"]
        aggregate = enabled_features(features, "x86-owned-static-runtime")

        self.assertEqual(features["default"], [])
        self.assertEqual(features["x86-owned-dynamic-runtime"], ["x86-owned-static-runtime"])
        self.assertNotIn("x86-sched-rr-interval", aggregate)
        self.assertNotIn("x86-netdb-setent", aggregate)
        self.assertNotIn("x86-sched-rr-interval", features)
        self.assertNotIn("x86-netdb-setent", features)
        self.assertTrue(
            {"sched_rr_get_interval", "sethostent", "setnetent"} <=
            set(STATIC_EXPORTS.read_text(encoding="utf-8").splitlines())
        )

        probe = PROBE.read_text(encoding="utf-8")
        for required in (
            "#include <netdb.h>",
            "#include <sched.h>",
            "check_scheduler_netdb_boundary",
            "sched_rr_get_interval(0, &interval)",
            "sethostent",
            "setnetent",
            "endhostent",
            "endnetent",
            "set_host == set_net",
            "end_host == end_net",
        ):
            self.assertIn(required, probe)


if __name__ == "__main__":
    unittest.main()
