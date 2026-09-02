#!/usr/bin/env python3
"""Regression guards for the opt-in x86 resolver's musl ELF aliases."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNTIME = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "resolver_runtime.rs"
H_ERRNO = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "h_errno.rs"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_resolver_runtime.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_resolver_runtime_probe.c"
RESOLV_HEADER = ROOT / "include" / "resolv.h"
DEFAULT_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class ResolverRuntimeAliasTests(unittest.TestCase):
    def test_hidden_private_implementations_have_weak_public_aliases(self) -> None:
        runtime = RUNTIME.read_text(encoding="utf-8")

        for directive in (
            '".hidden __res_mkquery"',
            '".weak res_mkquery"',
            '".set res_mkquery, __res_mkquery"',
            '".hidden __res_send"',
            '".weak res_send"',
            '".set res_send, __res_send"',
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, runtime)

        for private in ("__res_mkquery", "__res_send"):
            with self.subTest(private=private):
                self.assertRegex(
                    runtime,
                    rf'(?s)#\[inline\(never\)\]\s*#\[no_mangle\]\s*'
                    rf'pub unsafe extern "C" fn {private}\s*\(',
                )
        self.assertRegex(
            runtime,
            r'(?s)#\[no_mangle\]\s*#\[linkage = "weak"\]\s*'
            r'pub unsafe extern "C" fn res_search\s*\(',
        )
        self.assertNotRegex(
            runtime,
            r'(?m)^pub unsafe extern "C" fn res_mkquery\s*\(',
        )
        self.assertNotRegex(
            runtime,
            r'(?m)^pub unsafe extern "C" fn res_send\s*\(',
        )

    def test_internal_paths_use_hidden_implementations_and_public_header_stays_public(self) -> None:
        runtime = RUNTIME.read_text(encoding="utf-8")
        header = RESOLV_HEADER.read_text(encoding="utf-8")

        query_response = runtime.split("unsafe fn query_response", 1)[1]
        query_response = query_response.split("#[no_mangle]", 1)[0]
        self.assertIn("__res_mkquery(", query_response)
        self.assertIn("__res_send(", query_response)
        for public in ("res_mkquery", "res_send"):
            self.assertRegex(header, rf'(?m)^int {public}\(')
        self.assertNotIn("__res_mkquery", header)
        self.assertNotIn("__res_send", header)

    def test_h_errno_uses_the_public_accessor_macro_and_per_thread_resolver_slot(self) -> None:
        runtime = RUNTIME.read_text(encoding="utf-8")
        h_errno = H_ERRNO.read_text(encoding="utf-8")
        netdb_header = (ROOT / "include" / "netdb.h").read_text(encoding="utf-8")
        fixture = PROBE.read_text(encoding="utf-8")

        self.assertIn("#define h_errno (*__h_errno_location())", netdb_header)
        self.assertRegex(
            netdb_header,
            r"(?s)#if defined\(__x86_64__\).*?"
            r"#define h_errno \(\*__h_errno_location\(\)\)",
        )
        self.assertRegex(
            netdb_header,
            r"(?s)#if !defined\(__x86_64__\).*?extern int h_errno;",
        )
        self.assertRegex(
            h_errno,
            r'(?s)pub extern "C" fn __h_errno_location\(\) -> \*mut c_int \{\s*'
            r'.*?unsafe \{ location\(\) \}',
        )
        for required in (
            "pub(super) unsafe fn resolver_worker_h_errno_location() -> *mut c_int",
            "static_tls::is_initial_thread_pointer(thread_pointer)",
            "core::ptr::addr_of_mut!(h_errno)",
            "core::ptr::addr_of_mut!(RESOLVER_RES_STATE.res_h_errno)",
            'extern int crabc_link_visible_h_errno __asm__("h_errno");',
            "__h_errno_location() != &crabc_link_visible_h_errno",
        ):
            with self.subTest(required=required):
                target = (
                    h_errno
                    if required in {
                        "static_tls::is_initial_thread_pointer(thread_pointer)",
                        "core::ptr::addr_of_mut!(h_errno)",
                    }
                    else runtime
                    if required.startswith("pub(super)")
                    or required == "core::ptr::addr_of_mut!(RESOLVER_RES_STATE.res_h_errno)"
                    else fixture
                )
                self.assertIn(required, target)
        self.assertNotIn("fn __h_errno_location", runtime)
        self.assertNotIn("static mut h_errno", runtime)
        for required in (
            "#include <pthread.h>",
            "check_h_errno_worker",
            "check_thread_local_h_errno",
            "context.worker_location == context.main_location",
            "h_errno != NO_RECOVERY",
        ):
            with self.subTest(required=required):
                self.assertIn(required, fixture)

    def test_native_runner_separates_oracle_aliases_public_calls_and_private_calls(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")

        for required in (
            "-print-file-name=libc.a",
            "pinned-musl archive",
            "assert_weak_hidden_alias_pair",
            "assert_weak_default_function",
            "public-resolver-calls.o",
            "public-resolver-calls-relocations",
            "fixture does not retain the public",
            "resolver implementation does not retain its hidden",
            "R_X86_64_PLT32",
            "__res_mkquery __res_send",
            "-pthread",
        ):
            with self.subTest(required=required):
                self.assertIn(required, runner)
        self.assertIn("query_length = res_mkquery(", probe)
        self.assertIn("res_send(query, query_length, answer, sizeof(answer))", probe)
        self.assertNotIn("__res_mkquery", probe)
        self.assertNotIn("__res_send", probe)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_default_static_export_ratchet_does_not_absorb_opt_in_resolver_aliases(self) -> None:
        default_exports = {
            line
            for line in DEFAULT_EXPORTS.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        self.assertFalse(
            default_exports & {"__res_mkquery", "res_mkquery", "__res_send", "res_send", "res_search"}
        )


if __name__ == "__main__":
    unittest.main()
