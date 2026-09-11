#!/usr/bin/env python3
"""Focused contract checks for the direct-loader libc identity fixture."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_loader_libc_identity.sh"


class OwnedLoaderLibcIdentityRunnerTests(unittest.TestCase):
    def test_fixture_closes_five_identity_layouts_before_callbacks(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for name in (
            "copied-prefix-root-libc",
            "prefix-only-libc",
            "hardlink-one-identity",
            "two-distinct-libc-identities",
            "override-without-canonical-identity",
        ):
            with self.subTest(name=name):
                self.assertIn("case_name=" + name, source)
        self.assertIn("for mode in pie non-pie", source)
        self.assertIn('printf \'libcidentity\\n\' >"$expected_stderr"', source)
        self.assertIn('[ "$status" -eq 127 ]', source)
        self.assertIn('[ ! -s "$stdout" ]', source)
        self.assertIn('cmp "$expected_stderr" "$stderr"', source)

    def test_fixture_binds_real_driver_elf_edges_and_device_inode_layouts(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            '"$driver" --dynamic-shared-object',
            '"$driver" "--dynamic-$mode"',
            '--application-dso "$root/plugins/libcli.so"',
            'readelf -dW "$binary"',
            'assert_runpath "$root/consumer" "$consumer_search_path" consumer',
            'assert_needed "$root/consumer" libcli.so consumer',
            'assert_needed "$root/consumer" libc.so consumer',
            'assert_needed "$root/consumer-mutated" p/libc.so mutated',
            'assert_same_identity "$root/p/libc.so" "$root/prefix/usr/lib/libc.so"',
            'assert_distinct_identity "$root/usr/lib/libc.so" "$root/p/libc.so"',
            'p/libc.so\\0',
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)

    def test_positive_layouts_observe_the_loaded_root_or_prefix_libc(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('#include <dlfcn.h>', source)
        self.assertIn('dlsym(RTLD_DEFAULT, "puts")', source)
        self.assertIn('dladdr(puts_address, &libc)', source)
        self.assertIn('identity libc %s', source)
        self.assertIn('/prefix/usr/lib:/usr/lib', source)
        self.assertIn('"identity libc $expected_libc"', source)
        self.assertIn('run_success "$root" /consumer /prefix/usr/lib/libc.so', source)
        self.assertIn('candidate-only negative', source)


if __name__ == "__main__":
    unittest.main()
