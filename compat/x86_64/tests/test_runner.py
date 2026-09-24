#!/usr/bin/env python3
"""Boundary contracts for the native x86_64 core-evidence launcher."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "scripts" / "dev-x86_64.sh"

_SELECTED_JOIN_INNER_SIGNATURE = "unsafe fn join_selected_worker_inner("
_SELECTED_JOIN_CLAIM = re.compile(
    r"let\s+Some\s*\(\s*control\s*\)\s*=\s*"
    r"claim_selected_worker_by_thread_pointer\s*\(\s*"
    r"thread\s*,\s*SelectedWorkerLifecycleState::JoinClaimed\s*,\s*"
    r"\)\s*else\s*\{\s*return\s+Err\s*\(\s*EINVAL\s*\)\s*;\s*\}\s*;",
    re.DOTALL,
)
_SELECTED_CONTROL_DEREFERENCE = re.compile(r"\(\s*\*\s*control\s*\)")


def _selected_join_inner_body(source: str) -> str:
    """Return the owning join block without swallowing a later helper.

    GNU join modes inserted wait helpers between the public join wrapper and
    the C ABI `pthread_join` leaf.  This counts the selected inner function's
    block nesting instead of using that former whole-file delimiter.
    """

    start = source.find(_SELECTED_JOIN_INNER_SIGNATURE)
    if start == -1:
        raise ValueError("missing selected-worker inner join function")
    opening_brace = source.find("{", start)
    if opening_brace == -1:
        raise ValueError("selected-worker inner join function has no body")

    depth = 0
    for index in range(opening_brace, len(source)):
        character = source[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise ValueError("selected-worker inner join function has an unclosed body")


def _selected_join_inner_claims_control_before_dereference(source: str) -> bool:
    """Check that the opaque handle is registry-claimed before control access."""

    body = _selected_join_inner_body(source)
    claim = _SELECTED_JOIN_CLAIM.search(body)
    dereference = _SELECTED_CONTROL_DEREFERENCE.search(body)
    return (
        claim is not None
        and dereference is not None
        and claim.start() < dereference.start()
    )


class X86_64CoreRunnerTests(unittest.TestCase):
    def assertIn(self, member: object, container: object, msg: object = None) -> None:
        """Keep source-contract failures actionable without rendering whole files."""

        if (
            isinstance(member, str)
            and isinstance(container, str)
            and len(container) > 4096
            and member not in container
        ):
            self.fail(
                msg
                or f"{member!r} is missing from a {len(container)}-byte source contract"
            )
        super().assertIn(member, container, msg)

    def assertNotIn(
        self, member: object, container: object, msg: object = None
    ) -> None:
        """Keep source-contract failures actionable without rendering whole files."""

        if (
            isinstance(member, str)
            and isinstance(container, str)
            and len(container) > 4096
            and member in container
        ):
            self.fail(
                msg
                or f"{member!r} is unexpectedly present in a {len(container)}-byte source contract"
            )
        super().assertNotIn(member, container, msg)

    def test_selected_join_source_judge_rejects_unclaimed_control_dereference(
        self,
    ) -> None:
        """Keep the source judge scoped to the owner of the control pointer."""

        guarded = """
unsafe fn preceding_wait_helper(control: *mut ThreadControl) {
    unsafe { (*control).child_tid.load(Ordering::Acquire) };
}
unsafe fn join_selected_worker_inner(thread: *mut c_void) {
    let Some(control) = claim_selected_worker_by_thread_pointer(
        thread,
        SelectedWorkerLifecycleState::JoinClaimed,
    ) else {
        return Err(EINVAL);
    };
    unsafe { (*control).child_tid.load(Ordering::Acquire) };
}
unsafe fn neighboring_wait_helper(control: *mut ThreadControl) {
    unsafe { (*control).child_tid.load(Ordering::Acquire) };
}
"""
        unguarded = """
unsafe fn join_selected_worker_inner(
    thread: *mut c_void,
    control: *mut ThreadControl,
) {
    unsafe { (*control).child_tid.load(Ordering::Acquire) };
    let Some(control) = claim_selected_worker_by_thread_pointer(
        thread,
        SelectedWorkerLifecycleState::JoinClaimed,
    ) else {
        return Err(EINVAL);
    };
}
"""

        self.assertTrue(
            _selected_join_inner_claims_control_before_dereference(guarded)
        )
        self.assertFalse(
            _selected_join_inner_claims_control_before_dereference(unguarded)
        )
        self.assertFalse(
            _selected_join_inner_claims_control_before_dereference(
                guarded.replace("JoinClaimed", "Detached", 1)
            )
        )
        with self.assertRaisesRegex(ValueError, "missing selected-worker inner join"):
            _selected_join_inner_body("unsafe fn unrelated() {}")

    def test_named_locale_multibyte_static_artifact_stays_closed(self) -> None:
        """One named-locale/multibyte archive artifact remains below parity."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "locale_multibyte.rs"
        ).read_text(encoding="utf-8")
        c_probe = (
            ROOT / "compat" / "x86_64" / "locale_multibyte_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cpp_probe = (
            ROOT / "compat" / "x86_64" / "locale_multibyte_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_locale_multibyte_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_locale_multibyte_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_locale_multibyte.sh"
        ).read_text(encoding="utf-8")
        exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        limits = (ROOT / "include" / "limits.h").read_text(encoding="utf-8")
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "locale_multibyte.rs"]', static_root)
        for symbol in (
            "setlocale",
            "localeconv",
            "__ctype_get_mb_cur_max",
            "mbrtowc",
            "mbrlen",
            "mbsinit",
            "wcrtomb",
            "mblen",
            "mbtowc",
            "wctomb",
            "mbsrtowcs",
            "wcsrtombs",
            "mbstowcs",
            "wcstombs",
            "btowc",
            "wctob",
        ):
            self.assertIn(f"fn {symbol}(", implementation)
            self.assertIn(f"\n{symbol}\n", exports)
        for snippet in (
            "LC_CTYPE_UTF8_MASK",
            "MBRTOWC_INTERNAL_STATE",
            "MBRLEN_INTERNAL_STATE",
            "noninitial UTF-8 resume with positive output capacity",
            "noninitial `mbsrtowcs` state with zero output capacity",
        ):
            self.assertIn(snippet, implementation)
        for probe in (c_probe, cpp_probe):
            for snippet in (
                "#include <limits.h>",
                "CHAR_MAX == 127 && CHAR_MIN == -128",
                "sizeof(mbstate_t) == 8",
                "sizeof(struct lconv) == 96",
                "__ctype_get_mb_cur_max",
                "mbrtowc",
                "wcsrtombs",
            ):
                self.assertIn(snippet, probe)
        for snippet in (
            "C11/C++17",
            "check_cxx_c_linkage",
            "locale_t",
            "limits.h",
            "unmangled C spellings",
        ):
            self.assertIn(snippet, header_runner)
        for snippet in (
            "CRABC_LOCALE_MULTIBYTE_FREESTANDING",
            "POSIX;C;C;C;C;C",
            "C;C;C;C;C;C",
            "C;C.UTF-8;C;C;C;C",
            "C.UTF-8;C;C;C;C;C",
            "C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8",
            "MB_CUR_MAX != 1",
            "mbstate_t split_state",
            "mbrtowc(&decoded[0], euro_lead, 1, &split_state)",
            "mbsrtowcs(decoded, &source, 1, &split_state)",
            "source != euro_tail + 2",
        ):
            self.assertIn(snippet, fixture)
        for snippet in (
            "run_locale_multibyte_header_abi.sh",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
            "locale-object",
            "wide-stream",
        ):
            self.assertIn(snippet, runner)
        self.assertIn("locale-multibyte-header-abi)", dispatcher)
        self.assertIn("libc-locale-multibyte)", dispatcher)
        self.assertIn("run_locale_multibyte_header_abi()", dispatcher)
        self.assertIn("#if '\\xff' > 0", limits)
        self.assertIn("#define CHAR_MAX 127", limits)

    def test_fixed_locale_profile_capability_slice_stays_narrow(self) -> None:
        """Selected locale.core proof stays at setlocale/localeconv only."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "locale_multibyte.rs"
        ).read_text(encoding="utf-8")
        c_probe = (
            ROOT / "compat" / "x86_64" / "locale_profile_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cpp_probe = (
            ROOT / "compat" / "x86_64" / "locale_profile_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_locale_profile_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_locale_profile_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_locale_profile.sh"
        ).read_text(encoding="utf-8")
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "locale_multibyte.rs"]', static_root)
        for required in (
            "src/locale/setlocale.c",
            "src/locale/locale_map.c",
            "src/locale/localeconv.c",
            "LC_ALL_RESULT",
            "POSIX_LCONV",
            "run_libc_locale_profile.sh",
            "fn setlocale(",
            "fn localeconv(",
        ):
            self.assertIn(required, implementation)
        for probe in (c_probe, cpp_probe):
            for required in (
                "#include <limits.h>",
                "#include <locale.h>",
                "LC_CTYPE == 0",
                "sizeof(struct lconv) == 96",
                "setlocale",
                "localeconv",
            ):
                self.assertIn(required, probe)
        for required in (
            "C11/C++17",
            "CXX_SYMBOLS=(setlocale localeconv)",
            "-nostdinc",
            "check_cxx_c_linkage",
            "no locale objects, `_l` APIs, conversion, collation",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "locale-profile-fnv1a64",
            "C.UTF-8;C;C;C;C;C",
            "CHAR_MAX",
            "CRABC_LOCALE_PROFILE_FREESTANDING",
            'setlocale(LC_ALL, "")',
            "en_US.UTF-8",
            "C;C;C;C;C;C",
            "C;C.UTF-8;C;C;C;C",
        ):
            self.assertIn(required, fixture)
        for required in (
            "run_locale_profile_header_abi.sh",
            "-nostdlib -static",
            "--gc-sections",
            "candidate retains TLS",
            "__ctype_get_mb_cur_max",
            "locale-object",
            "getenv",
            "setlocale-disassembly",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "locale.core-fixed-profile"', parity)
        self.assertIn('capabilities = ["locale.core"]', parity)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-locale-profile"', parity
        )
        self.assertIn("locale-profile-header-abi)", dispatcher)
        self.assertIn("libc-locale-profile)", dispatcher)
        self.assertIn("run_locale_profile_header_abi()", dispatcher)

    def test_sched_cpu_macro_family_stays_header_only(self) -> None:
        """Keep CPU-set syntax below affinity, scheduler, and allocator runtime work."""
        header = (ROOT / "include" / "sched.h").read_text(encoding="utf-8")
        c_probe = (
            ROOT / "compat" / "x86_64" / "sched_cpu_macros_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "sched_cpu_macros_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_sched_cpu_macros_header_abi.sh"
        ).read_text(encoding="utf-8")
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "int (memcmp)(const void *, const void *, size_t);",
            "void *(memset)(void *, int, size_t);",
            "void *(calloc)(size_t, size_t);",
            "void (free)(void *);",
            "#define __CPU_op_S(i, size, set, op)",
            "#define __CPU_op_func_S(func, op)",
            "__CPU_op_func_S(AND, &)",
            "__CPU_op_func_S(OR, |)",
            "__CPU_op_func_S(XOR, ^)",
            "#define CPU_ALLOC_SIZE(n)",
            "#define CPU_ALLOC(n)",
            "#define CPU_FREE(set)",
            "#define CPU_SETSIZE 1024",
            "#define CPU_SET(i, set)",
            "#define CPU_EQUAL(s1,s2)",
        ):
            self.assertIn(required, header)
        for probe in (c_probe, cxx_probe):
            for required in (
                "CRABC_EXPECT_CPU_MACROS",
                "CRABC_REQUIRE_CPU_MACROS_HIDDEN",
                "CPU_ALLOC_SIZE(65)",
                "__CPU_op_func_S(PROBE, ^)",
                "CPU_FREE(allocated)",
                "cpu_macro_expression_formation",
            ):
                self.assertIn(required, probe)
        for required in (
            "cxx_strict_definitions",
            "cxx_forced_hidden_definitions",
            "-U_GNU_SOURCE",
            "-fno-builtin",
            "declare -n definitions_ref",
            "CPU-set construction macro gate",
            "neither link nor run",
            "allocator, byte-string, affinity, or scheduler behavior",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-nostdlib", runner)
        self.assertNotIn("sched_setaffinity", runner)
        self.assertIn("sched-cpu-macros-header-abi", dispatcher)

    def test_fanotify_event_traversal_macros_stay_header_only(self) -> None:
        """Pin record traversal syntax without selecting a watcher runtime."""
        header = (ROOT / "include" / "sys" / "fanotify.h").read_text(
            encoding="utf-8"
        )
        c_probe = (
            ROOT / "compat" / "x86_64" / "fanotify_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "fanotify_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_fanotify_header_abi.sh"
        ).read_text(encoding="utf-8")
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "struct fanotify_event_metadata",
            "unsigned event_len;",
            "unsigned char vers;",
            "unsigned char reserved;",
            "unsigned short metadata_len;",
            "unsigned long long mask",
            "__attribute__((__aligned__(8)))",
            "#define FAN_EVENT_METADATA_LEN (sizeof(struct fanotify_event_metadata))",
            "#define FAN_EVENT_NEXT(meta, len)",
            "#define FAN_EVENT_OK(meta, len)",
        ):
            self.assertIn(required, header)
        for probe in (c_probe, cxx_probe):
            for required in (
                "FAN_EVENT_METADATA_LEN",
                "FAN_EVENT_NEXT",
                "FAN_EVENT_OK",
                "sizeof(struct fanotify_event_metadata) == 24",
                "metadata_len) == 6",
                "FAN_EVENT_NEXT(&first, remaining)",
                "FAN_EVENT_OK(&first, remaining)",
                "fanotify_macro_expression_formation",
            ):
                self.assertIn(required, probe)
            self.assertNotIn("fanotify_init", probe)
            self.assertNotIn("fanotify_mark", probe)
        for required in (
            "fanotify traversal macro ABI proof",
            "project-first/pinned-musl",
            "seven profiles",
            "FAN_EVENT_NEXT/FAN_EVENT_OK",
            "does not link or execute fanotify runtime calls",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-nostdlib", runner)
        self.assertNotIn("fanotify_init", runner)
        self.assertNotIn("fanotify_mark", runner)
        self.assertIn("fanotify-header-abi", dispatcher)

    def test_wide_character_artifact_stays_exact_and_non_promoting(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "wide_character.rs"
        ).read_text(encoding="utf-8")
        tables = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "wide_character_tables.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_wide_character_probe.c"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_wide_character_header_abi.sh"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_wide_character.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        symbols = (
            "wcslen", "wcsnlen", "wcpcpy", "wcpncpy", "wcscoll", "wcsxfrm",
            "wcstok", "wmemmove", "wcwidth", "wcswidth", "iswalpha",
            "iswpunct", "iswctype", "wctype", "towlower", "towupper",
            "towctrans", "wctrans",
        )
        self.assertIn('#[path = "wide_character.rs"]', static_root)
        self.assertIn('#[path = "wide_character_tables.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", implementation)
            self.assertIn(symbol, static_exports)
        for unselected in (
            "wcsdup", "fgetwc", "swprintf", "wcsftime", "malloc",
        ):
            self.assertNotIn(unselected, static_exports)
        for required in (
            "alpha,punct,casemap,nonspacing,wide",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "ALPHA", "PUNCT", "NONSPACING", "WIDE", "CASE_EXCEPTIONS",
        ):
            self.assertIn(required, tables)
        for required in (
            "C.UTF-8", "wmemmove", "wcstok", "wcsxfrm(NULL", "0x110000u",
            "write(STDOUT_FILENO",
        ):
            self.assertIn(required, probe)
        for required in (
            "C11/C++17", "wchar.h", "wctype.h", "nm --undefined-only",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "static_c_abi_exports.txt", "-nostdlib -static", "--no-undefined",
            "reference-fingerprint", "candidate-fingerprint", "wcsdup",
            "malloc",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn('id = "static-c-wide-character-core"', parity)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-wide-character"', parity
        )
        self.assertIn("wide-character-header-abi)", dispatcher)
        self.assertIn("libc-wide-character)", dispatcher)

    def test_locale_object_wide_artifact_stays_exact_and_non_promoting(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "locale_objects.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_locale_object_wide_probe.c"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_locale_object_wide_header_abi.sh"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_locale_object_wide.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")
        symbols = (
            "newlocale", "freelocale", "uselocale", "duplocale",
            "nl_langinfo", "nl_langinfo_l", "iswalnum_l", "iswctype_l",
            "wctype_l", "towlower_l", "towupper_l", "towctrans_l",
            "wctrans_l", "wcscasecmp_l", "wcsncasecmp_l", "wcscoll_l",
            "wcsxfrm_l",
        )
        self.assertIn('#[path = "locale_objects.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(symbol, implementation)
            self.assertIn(symbol, static_exports)
        for required in (
            "#[thread_local]", "THREAD_GLOBAL", "current_ctype_override",
            "TIME_STRINGS", "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        ):
            self.assertIn(required, implementation)
        for required in (
            "pthread_create", "uselocale(NULL)", "LC_GLOBAL_LOCALE",
            "0x110000u", "CRABC_LOCALE_OBJECT_WIDE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in ("C11/C++17", "nl_langinfo", "wcscoll_l", "unmangled"):
            self.assertIn(required, header_runner)
        for required in (
            "static_c_abi_exports.txt", "-nostdlib -static", "--no-undefined",
            "reference-fingerprint", "candidate-fingerprint", "pthread_create",
            "mbsnrtowcs wcsnrtombs", "R_X86_64_TPOFF",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn('id = "static-c-locale-object-localized-wide"', parity)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-locale-object-wide"', parity
        )
        self.assertIn("locale-object-wide-header-abi)", dispatcher)
        self.assertIn("libc-locale-object-wide)", dispatcher)

    def test_locale_narrow_artifact_stays_exact_and_non_promoting(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "locale_narrow.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_locale_narrow_probe.c"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_locale_narrow_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_probes = (
            (
                ROOT / "compat" / "x86_64" / "locale_narrow_header_abi_probe.c"
            ).read_text(encoding="utf-8"),
            (
                ROOT / "compat" / "x86_64" / "locale_narrow_header_abi_probe.cpp"
            ).read_text(encoding="utf-8"),
        )
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_locale_narrow.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")
        symbols = (
            "isalnum_l", "isalpha_l", "isblank_l", "iscntrl_l",
            "isdigit_l", "isgraph_l", "islower_l", "isprint_l",
            "ispunct_l", "isspace_l", "isupper_l", "isxdigit_l",
            "tolower_l", "toupper_l", "strcasecmp", "strcasecmp_l",
            "strncasecmp", "strncasecmp_l", "strcoll", "strcoll_l",
            "strxfrm", "strxfrm_l",
        )
        self.assertIn('#[path = "locale_narrow.rs"]', static_root)
        for symbol in symbols:
            self.assertTrue(
                f"fn {symbol}(" in implementation
                or f"localized_classifier!({symbol}," in implementation
            )
            self.assertIn(symbol, static_exports)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "copy the source including its NUL", "no locale database",
        ):
            self.assertIn(required, implementation)
        for required in (
            "C.UTF-8", "uselocale(NULL)", "strxfrm_l", "fingerprint",
        ):
            self.assertIn(required, probe)
        for required in ("C11/C++17", "unmangled"):
            self.assertIn(required, header_runner)
        for header_probe in header_probes:
            for required in ("ctype.h", "strings.h"):
                self.assertIn(required, header_probe)
        for required in (
            "static_c_abi_exports.txt", "-nostdlib -static", "--no-undefined",
            "reference-fingerprint", "candidate-fingerprint", "R_X86_64_TPOFF",
            "strtod_l", "malloc",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn('id = "static-c-locale-narrow-collation"', parity)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-locale-narrow"', parity
        )
        self.assertIn("locale-narrow-header-abi)", dispatcher)
        self.assertIn("libc-locale-narrow)", dispatcher)

    def test_locale_ctype_locator_artifact_stays_abi_only_and_non_promoting(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "locale_ctype.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_locale_ctype_locators_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_locale_ctype_locators.sh"
        ).read_text(encoding="utf-8")
        ctype_header = (ROOT / "include" / "ctype.h").read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")
        symbols = (
            "__ctype_b_loc",
            "__ctype_tolower_loc",
            "__ctype_toupper_loc",
        )
        self.assertIn('#[path = "locale_ctype.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", implementation)
            self.assertIn(symbol, static_exports)
            self.assertNotIn(symbol, ctype_header)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "384-entry table", "network-byte-order", "not public `<ctype.h>`",
        ):
            self.assertIn(required, implementation)
        for required in (
            "extern const unsigned short **__ctype_b_loc(void);",
            "character = -128; character != 256", "UINT16_C(0xd508)",
            "raw_write_stdout", "fingerprint",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt", "-nostdlib -static", "--no-undefined",
            "reference-fingerprint", "candidate-fingerprint",
            "[[:space:]]TLS[[:space:]]", "strfmon", "strxfrm",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn('id = "static-c-locale-ctype-locators"', parity)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-locale-ctype-locators"',
            parity,
        )
        self.assertIn("libc-locale-ctype-locators)", dispatcher)

    def test_locale_error_strings_artifact_stays_abi_only_and_non_promoting(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "locale_error_strings.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_locale_error_strings_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_locale_error_strings.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_error_strings_header_abi.sh"
        ).read_text(encoding="utf-8")
        string_header = (ROOT / "include" / "string.h").read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "locale_error_strings.rs"]', static_root)
        for symbol in ("__strerror_l", "strerror_l"):
            self.assertIn(symbol, static_exports)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/errno/strerror.c::__strerror_l",
            "weak_alias(__strerror_l, strerror_l)",
            ".weak strerror_l",
            ".set strerror_l, __strerror_l",
            "fn __strerror_l(",
            "error_strings::strerror(error)",
            "LC_GLOBAL_LOCALE",
            "general locale database",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "static mut",
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn strfmon(",
        ):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "#include <locale.h>",
            "extern char *__strerror_l(int, locale_t);",
            "strerror_l != __strerror_l",
            "newlocale(LC_ALL_MASK, \"C.UTF-8\", NULL)",
            "uselocale(LC_GLOBAL_LOCALE)",
            "error <= 134",
            "errno != EINTR",
            "locale-error-strings-fnv1a64",
        ):
            self.assertIn(required, probe)
        for required in (
            "CRABC_EXPECT_STRERROR_L",
            "CRABC_REQUIRE_STRERROR_L_HIDDEN",
            "strerror_l",
            "C++ probe does not retain C linkage",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("char *strerror_l(int, locale_t);", string_header)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "--no-undefined",
            "strong __strerror_l",
            "weak strerror_l",
            "same-address __strerror_l alias",
            "candidate lacks PT_TLS",
            "locale-error-strings-fnv1a64",
            "strfmon",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-locale-error-strings"', parity)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-locale-error-strings"',
            parity,
        )
        self.assertIn("libc-locale-error-strings)", dispatcher)

    def test_script_is_valid_and_has_a_closed_command_set(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('readonly PLATFORM="linux/amd64"', source)
        self.assertIn("    madvise-reference) ;;", source)
        self.assertIn(
            "    ctype-header-abi|locale-profile-header-abi|locale-multibyte-header-abi|iconv-header-abi|wide-character-header-abi|wcswcs-header-abi|locale-object-wide-header-abi|locale-narrow-header-abi|c32rtomb-header-abi|uchar-stateful-header-abi) ;;",
            source,
        )
        self.assertIn("    ffs-header-abi) ;;", source)
        self.assertIn("    byte-strings-header-abi) ;;", source)
        self.assertIn("    memory-search-header-abi) ;;", source)
        self.assertIn("    string-copy-header-abi) ;;", source)
        self.assertIn("    string-duplication-header-abi) ;;", source)
        self.assertIn("    linux-5-10-uapi) ;;", source)
        self.assertIn("    candidate-header-closure) ;;", source)
        self.assertIn("    headers-layouts-aggregate) ;;", source)
        self.assertIn("    installed-header-tree-closure) ;;", source)
        self.assertIn("    selected-header-install-projection) ;;", source)
        self.assertIn("    header-callable-visibility-matrix) ;;", source)
        self.assertIn("    header-callable-disposition) ;;", source)
        self.assertIn("    project-header-extension-policy) ;;", source)
        self.assertIn(
            "run_in_container bash /workspace/compat/x86_64/run_project_header_extension_policy.sh \"$@\"",
            source,
        )
        self.assertIn("    header-abi-matrix) ;;", source)
        self.assertIn("    header-record-layout-matrix) ;;", source)
        self.assertIn(
            "    posix-spawn-file-actions-header-abi|libc-posix-spawn-file-actions|process-exec-header-abi|libc-process-exec) ;;",
            source,
        )
        self.assertIn("    header-declaration-macro-visibility-matrix) ;;", source)
        self.assertIn("    dirent-header-abi) ;;", source)
        self.assertIn("    ftw-header-abi) ;;", source)
        self.assertIn("    stat-ftw-header-source-form) ;;", source)
        self.assertIn("    param-header-source-form) ;;", source)
        self.assertIn("    math-tgmath-source-form) ;;", source)
        self.assertIn("    mman-mcl-onfault-header-source-form) ;;", source)
        self.assertIn("    mount-header-source-form) ;;", source)
        self.assertIn("    klog-header-source-form) ;;", source)
        self.assertIn("    cachectl-header-source-form) ;;", source)
        self.assertIn("    sysmacros-header-source-form) ;;", source)
        self.assertIn("    pthread-header-source-form) ;;", source)
        self.assertIn("    ioctl-header-source-form) ;;", source)
        self.assertIn("    tcp-header-abi) ;;", source)
        self.assertIn("    stddef-header-abi) ;;", source)
        self.assertIn(
            "    inet-address-header-abi|nameser-header-abi|quota-header-abi|endservent-header-abi|service-lifecycle-header-abi) ;;",
            source,
        )
        self.assertIn(
            "    libc-network-byte-order|libc-dn-skipname|libc-dn-expand|libc-ns-flagdata|libc-ns-get16|libc-ns-get32|libc-ns-put16|libc-ns-put32|libc-ns-skiprr|libc-nameser-wire-aggregate|libc-nameser-message-parser) ;;",
            source,
        )
        self.assertIn("    libc-in6addr-any)", source)
        self.assertIn("    libc-in6addr-loopback)", source)
        self.assertIn("    libc-inet-ntoa)", source)
        self.assertIn("    libc-inet-classful)", source)
        self.assertIn("    libc-hstrerror)", source)
        self.assertIn("    libc-dn-skipname)", source)
        self.assertIn("    libc-ns-get16)", source)
        self.assertIn("    libc-ns-get32)", source)
        self.assertIn("    libc-ns-put16)", source)
        self.assertIn("    math-special-header-abi|libc-math-special) ;;", source)
        self.assertIn(
            "    math-elementary-long-double-header-abi|libc-math-elementary-long-double) ;;",
            source,
        )
        self.assertIn("    ldso-fixed-graph-dlfcn) ;;", source)
        self.assertIn("    ldso-public-dlfcn|ldso-dladdr-symbol-bounds) ;;", source)
        self.assertIn("    ldso-bounded-dlopen) ;;", source)
        self.assertIn("    math-complex-header-abi)", source)
        self.assertIn("    math-complex-complete-header-abi)", source)
        self.assertIn("    math-special-header-abi)", source)
        self.assertIn("    libc-math-complex)", source)
        self.assertIn("    libc-math-complex-complete)", source)
        self.assertIn("    libc-elementary-sqrt-fenv)", source)
        self.assertIn("    libc-fenv-rounding) ;;", source)
        self.assertIn("    libc-math-minmax) ;;", source)
        self.assertIn("    libc-math-bit-sign) ;;", source)
        self.assertIn("    libc-math-trunc) ;;", source)
        self.assertIn("    libc-math-fmod) ;;", source)
        self.assertIn("    libc-math-cbrt) ;;", source)
        self.assertIn("    libc-math-x87-extended)", source)
        self.assertIn("    libc-math-special)", source)
        self.assertIn("    libc-fdim) ;;", source)
        # Helpers contain their own indented command cases. The dispatcher
        # owns three top-level cases: admission, argument preparation, and
        # execution; audit those boundaries independently.
        command_cases = re.findall(
            r'^case "\$command" in\n(.*?)^esac$', source, re.MULTILINE | re.DOTALL
        )
        self.assertEqual(len(command_cases), 3)
        preflight = command_cases[0]
        actual_groups = tuple(
            re.findall(r"^    ([a-z0-9-]+(?:\|[a-z0-9-]+)*)\) ;;$", preflight, re.MULTILINE)
        )
        # Every admitted no-argument command must reach an execution handler.
        expected_groups = actual_groups

        expected_commands = {
            command
            for group in expected_groups
            for command in group.split("|")
        }
        handlers = command_cases[2]
        handler_groups = re.findall(
            r"^    ([a-z0-9-]+(?:\|[a-z0-9-]+)*)\)$", handlers, re.MULTILINE
        )
        handled_commands = {
            command
            for group in handler_groups
            for command in group.split("|")
        }
        self.assertLessEqual(expected_commands, handled_commands)
        self.assertIn("libc-stat-compat", source)
        self.assertIn("libc-credentials", source)
        self.assertIn("libc-bootstrap-primitives", source)
        self.assertIn("libc-signal-control", source)
        self.assertIn("libc-signal-execution", source)
        self.assertIn("libc-signal-altstack", source)
        self.assertIn("libc-static-tls-v1", source)
        self.assertIn("libc-crt-static-tls", source)
        self.assertIn("libc-pthread-create-join-tls", source)
        self.assertIn("libc-pthread-detach", source)
        self.assertIn("libc-thrd-sleep", source)
        self.assertIn("libc-pthread-mutex-normal", source)
        self.assertIn("libc-pthread-rwlock", source)
        self.assertIn("libc-pthread-cond-private", source)
        self.assertIn("libc-pthread-tls-aggregate", source)
        self.assertIn("libc-static-c-abi-same-object-differential", source)
        self.assertIn("qualification-posix-abi-admission", source)
        self.assertIn("libc-pthread-c11-once", source)
        self.assertIn("libc-pthread-c11-tsd", source)
        self.assertIn("pthread-cancellation-header-abi", source)
        self.assertIn("libc-pthread-cancel-deferred", source)
        self.assertIn("libc-pthread-atfork", source)
        self.assertIn("libc-pthread-cpuclock", source)
        self.assertIn("libc-pthread-name", source)
        self.assertIn("libc-pthread-attributes", source)
        self.assertIn("libc-pthread-barrierattr-pshared", source)
        self.assertIn("libc-pthread-barrier", source)
        self.assertIn("pthread-spin-destroy-header-abi", source)
        self.assertIn("libc-pthread-spin-destroy", source)
        self.assertIn("pthread-spin-operations-header-abi", source)
        self.assertIn("libc-pthread-spin-operations", source)
        self.assertIn("libc-interval-timers", source)
        self.assertIn("libc-termios-control", source)
        self.assertIn("ctermid-header-abi", source)
        self.assertIn("libc-ctermid", source)
        self.assertIn("grantpt-header-abi", source)
        self.assertIn("libc-grantpt", source)
        self.assertIn("tcsetpgrp-header-abi", source)
        self.assertIn("libc-tcsetpgrp", source)
        self.assertIn("getpass-header-abi", source)
        self.assertIn("libc-getpass", source)
        self.assertIn("mkfifo-header-abi", source)
        self.assertIn("libc-mkfifo", source)
        self.assertIn("mkdirat-header-abi", source)
        self.assertIn("libc-mkdirat", source)
        self.assertIn("mkfifoat-header-abi", source)
        self.assertIn("libc-mkfifoat", source)
        self.assertIn("mktemp-header-abi", source)
        self.assertIn("libc-mktemp", source)
        self.assertIn("temporary-names-header-abi", source)
        self.assertIn("libc-temporary-names", source)
        self.assertIn("file-handles-header-abi", source)
        self.assertIn("libc-file-handles", source)
        self.assertIn("posix-spawn-file-actions-header-abi", source)
        self.assertIn("libc-posix-spawn-file-actions", source)
        self.assertIn("process-exec-header-abi", source)
        self.assertIn("libc-process-exec", source)
        self.assertIn("libc-process-context", source)
        self.assertIn("libc-environment", source)
        self.assertIn("libc-secure-environment", source)
        self.assertIn("libc-descriptor-io", source)
        self.assertIn("libc-descriptor-lifecycle", source)
        self.assertIn("libc-timestamp-updates", source)
        self.assertIn("libc-sysv-semaphore", source)
        self.assertIn("libc-sysv-message-shared-memory", source)
        self.assertIn("libc-event-descriptors", source)
        self.assertIn("libc-pathname-lifecycle", source)
        self.assertIn("libc-directory-streams", source)
        self.assertIn("libc-filesystem-traversal", source)
        self.assertIn("libc-filesystem-directory", source)
        self.assertIn("libc-filesystem-extensions", source)
        self.assertIn("libc-lchmod-unsupported", source)
        self.assertIn("libc-process-resources", source)
        self.assertIn("libc-sched-priority-bounds", source)
        self.assertIn("libc-sched-yield", source)
        self.assertIn("readlinkat-header-abi", source)
        self.assertIn("libc-readlinkat", source)
        self.assertIn("linkat-header-abi", source)
        self.assertIn("libc-linkat", source)
        self.assertIn("lchown-header-abi", source)
        self.assertIn("libc-lchown", source)
        self.assertIn("hasmntopt-header-abi", source)
        self.assertIn("libc-hasmntopt", source)
        self.assertIn("libc-readiness-waits", source)
        self.assertIn("libc-socket-transport", source)
        self.assertIn("libc-system-observation", source)
        self.assertIn("libc-system-information", source)
        self.assertIn("libc-getloadavg", source)
        self.assertIn("libc-fcntl-record-locks", source)
        self.assertIn("libc-uts-identity", source)
        self.assertIn('run_musl_oracle()', source)
        self.assertIn('compat/x86_64/run_musl_oracle.sh', source)
        self.assertIn('run_linux_5_10_uapi()', source)
        self.assertIn('compat/x86_64/run_linux_5_10_uapi.sh', source)
        self.assertIn('run_header_abi_reference()', source)
        self.assertIn('compat/x86_64/run_header_abi_reference.sh', source)
        self.assertIn('run_feature_profile_control_plane_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_feature_profile_control_plane_header_abi.sh', source
        )
        self.assertIn('run_terminal_streams_header_topology()', source)
        self.assertIn(
            'compat/x86_64/run_terminal_streams_header_topology.sh', source
        )
        self.assertIn('run_link_header_source_form()', source)
        self.assertIn(
            'compat/x86_64/run_link_header_source_form.sh', source
        )
        self.assertIn('run_reboot_header_source_form()', source)
        self.assertIn(
            'compat/x86_64/run_reboot_header_source_form.sh', source
        )
        self.assertIn('run_mount_header_source_form()', source)
        self.assertIn(
            'compat/x86_64/run_mount_header_source_form.sh', source
        )
        self.assertIn('run_klog_header_source_form()', source)
        self.assertIn(
            'compat/x86_64/run_klog_header_source_form.sh', source
        )
        self.assertIn('run_cachectl_header_source_form()', source)
        self.assertIn(
            'compat/x86_64/run_cachectl_header_source_form.sh', source
        )
        self.assertIn('run_pthread_header_source_form()', source)
        self.assertIn(
            'compat/x86_64/run_pthread_header_source_form.sh', source
        )
        self.assertIn('run_ioctl_header_source_form()', source)
        self.assertIn(
            'compat/x86_64/run_ioctl_header_source_form.sh', source
        )
        self.assertIn('run_fcntl_event_header_topology()', source)
        self.assertIn(
            'compat/x86_64/run_fcntl_event_header_topology.sh', source
        )
        self.assertIn('run_public_header_surface()', source)
        self.assertIn('compat/x86_64/run_public_header_surface.sh', source)
        self.assertIn('run_candidate_header_closure()', source)
        self.assertIn('compat/x86_64/run_candidate_header_closure.sh', source)
        self.assertIn('run_installed_header_tree_closure()', source)
        self.assertIn('compat/x86_64/run_installed_header_tree_closure.sh', source)
        self.assertIn('run_uapi_wrapper_matrix()', source)
        self.assertIn('compat/x86_64/run_uapi_wrapper_matrix.sh', source)
        self.assertIn('run_epoll_header_abi()', source)
        self.assertIn('compat/x86_64/run_epoll_header_abi.sh', source)
        self.assertIn('run_event_descriptors_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_event_descriptors_header_abi.sh', source
        )
        self.assertIn('run_dirent_header_abi()', source)
        self.assertIn('compat/x86_64/run_dirent_header_abi.sh', source)
        self.assertIn('run_pathname_lifecycle_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_pathname_lifecycle_header_abi.sh', source
        )
        self.assertIn('run_timeval_transitive_header_abi()', source)
        self.assertIn('compat/x86_64/run_timeval_transitive_header_abi.sh', source)
        self.assertIn('run_sys_time_direct_header_abi()', source)
        self.assertIn('compat/x86_64/run_sys_time_direct_header_abi.sh', source)
        self.assertIn('run_access_header_abi()', source)
        self.assertIn('compat/x86_64/run_access_header_abi.sh', source)
        self.assertIn('run_header_abi_project()', source)
        self.assertIn('compat/x86_64/run_project_header_abi.sh', source)
        self.assertIn('run_math_complex_header_abi()', source)
        self.assertIn('compat/x86_64/run_math_complex_header_abi.sh', source)
        self.assertIn('run_sys_reg_header_abi()', source)
        self.assertIn('compat/x86_64/run_sys_reg_header_abi.sh', source)
        self.assertIn('run_machine_context_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_machine_context_header_abi.sh', source
        )
        self.assertIn('run_types_header_abi()', source)
        self.assertIn('compat/x86_64/run_types_header_abi.sh', source)
        self.assertIn('run_stddef_header_abi()', source)
        self.assertIn('compat/x86_64/run_stddef_header_abi.sh', source)
        self.assertIn('run_stat_header_abi()', source)
        self.assertIn('compat/x86_64/run_stat_header_abi.sh', source)
        self.assertIn('run_utime_header_abi()', source)
        self.assertIn('compat/x86_64/run_utime_header_abi.sh', source)
        self.assertIn('run_pthread_c11_header_abi()', source)
        self.assertIn('compat/x86_64/run_pthread_c11_header_abi.sh', source)
        self.assertIn('run_pthread_cancellation_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_pthread_cancellation_header_abi.sh', source
        )
        self.assertIn('run_stdlib_header_abi()', source)
        self.assertIn('compat/x86_64/run_stdlib_header_abi.sh', source)
        self.assertIn('run_stdio_standard_header_abi()', source)
        self.assertIn('compat/x86_64/run_stdio_standard_header_abi.sh', source)
        self.assertIn('run_stdio_header_source_form()', source)
        self.assertIn('compat/x86_64/run_stdio_header_source_form.sh', source)
        self.assertIn('run_ctype_header_abi()', source)
        self.assertIn('compat/x86_64/run_ctype_header_abi.sh', source)
        self.assertIn('run_integer_arithmetic_header_abi()', source)
        self.assertIn('compat/x86_64/run_integer_arithmetic_header_abi.sh', source)
        self.assertIn('run_credential_observation_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_credential_observation_header_abi.sh', source
        )
        self.assertIn('run_ffs_header_abi()', source)
        self.assertIn('compat/x86_64/run_ffs_header_abi.sh', source)
        self.assertIn('run_byte_strings_header_abi()', source)
        self.assertIn('compat/x86_64/run_byte_strings_header_abi.sh', source)
        self.assertIn('run_memory_search_header_abi()', source)
        self.assertIn('compat/x86_64/run_memory_search_header_abi.sh', source)
        self.assertIn('run_memccpy_header_abi()', source)
        self.assertIn('compat/x86_64/run_memccpy_header_abi.sh', source)
        self.assertIn('run_string_copy_header_abi()', source)
        self.assertIn('compat/x86_64/run_string_copy_header_abi.sh', source)
        self.assertIn('run_random_entropy_header_abi()', source)
        self.assertIn('compat/x86_64/run_random_entropy_header_abi.sh', source)
        self.assertIn('run_time_header_abi()', source)
        self.assertIn('compat/x86_64/run_time_header_abi.sh', source)
        self.assertIn('run_poll_header_abi()', source)
        self.assertIn('compat/x86_64/run_poll_header_abi.sh', source)
        self.assertIn('run_select_header_abi()', source)
        self.assertIn('compat/x86_64/run_select_header_abi.sh', source)
        self.assertIn('run_fcntl_header_abi()', source)
        self.assertIn('compat/x86_64/run_fcntl_header_abi.sh', source)
        self.assertIn('run_file_handles_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_file_handles_header_abi.sh', source
        )
        self.assertIn('run_descriptor_advice_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_descriptor_advice_header_abi.sh', source
        )
        self.assertIn('run_ioctl_header_abi()', source)
        self.assertIn('compat/x86_64/run_ioctl_header_abi.sh', source)
        self.assertIn('run_ioctl_header_source_form()', source)
        self.assertIn('compat/x86_64/run_ioctl_header_source_form.sh', source)
        self.assertIn('run_unistd_header_abi()', source)
        self.assertIn('compat/x86_64/run_unistd_header_abi.sh', source)
        self.assertIn('run_system_header_abi()', source)
        self.assertIn('compat/x86_64/run_system_header_abi.sh', source)
        self.assertIn('run_syscall_header_abi()', source)
        self.assertIn('compat/x86_64/run_x86_syscall_header.sh', source)
        self.assertIn('run_signal_header_abi()', source)
        self.assertIn('compat/x86_64/run_signal_header_abi.sh', source)
        self.assertIn('run_termios_header_abi()', source)
        self.assertIn('compat/x86_64/run_termios_header_abi.sh', source)
        self.assertIn('run_mman_header_abi()', source)
        self.assertIn('compat/x86_64/run_mman_header_abi.sh', source)
        self.assertIn('run_resource_header_abi()', source)
        self.assertIn('compat/x86_64/run_resource_header_abi.sh', source)
        self.assertIn('run_mm_abi_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mm_reference.sh', source)
        self.assertIn('run_mapping_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mapping_reference.sh', source)
        self.assertIn('--test x86_64_memory_mapping', source)
        self.assertIn('--example mapping_direct_probe', source)
        mapping_reference = source.split('run_mapping_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_container cargo test', mapping_reference)
        self.assertIn('--test x86_64_memory_mapping', mapping_reference)
        self.assertIn('-- --test-threads=1', mapping_reference)
        self.assertIn('run_in_container cargo build', mapping_reference)
        self.assertIn('--example mapping_direct_probe', mapping_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_mapping_reference.sh',
            mapping_reference,
        )
        self.assertIn('run_memory_vm_reference()', source)
        self.assertIn('compat/x86_64/run_x86_memory_vm_reference.sh', source)
        self.assertIn('--test x86_64_memory_vm', source)
        self.assertIn('--example memory_vm_direct_probe', source)
        memory_vm_reference = source.split('run_memory_vm_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_container cargo test', memory_vm_reference)
        self.assertIn('--test x86_64_memory_vm', memory_vm_reference)
        self.assertIn('-- --test-threads=1', memory_vm_reference)
        self.assertIn('run_in_container cargo build', memory_vm_reference)
        self.assertIn('--example memory_vm_direct_probe', memory_vm_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_memory_vm_reference.sh',
            memory_vm_reference,
        )
        self.assertNotIn('run_in_chroot_cap_container', memory_vm_reference)
        self.assertNotIn('--cap-add=SYS_ADMIN', memory_vm_reference)
        self.assertIn('run_pty_basic_reference()', source)
        self.assertIn('compat/x86_64/run_x86_pty_basic_reference.sh', source)
        self.assertIn('--test x86_64_pty_basic', source)
        self.assertIn('--example pty_basic_direct_probe', source)
        pty_basic_reference = source.split('run_pty_basic_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertEqual(pty_basic_reference.count('run_in_container cargo test'), 2)
        self.assertIn(
            '-p crabc-rs --no-default-features --test x86_64_pty_basic',
            pty_basic_reference,
        )
        self.assertIn(
            '-p crabc-rs --no-default-features --features alloc --test x86_64_pty_basic',
            pty_basic_reference,
        )
        self.assertIn('-- --test-threads=1', pty_basic_reference)
        self.assertIn('run_in_container cargo build', pty_basic_reference)
        self.assertIn('--example pty_basic_direct_probe', pty_basic_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_pty_basic_reference.sh',
            pty_basic_reference,
        )
        self.assertNotIn('run_in_chroot_cap_container', pty_basic_reference)
        self.assertNotIn('--cap-add=SYS_ADMIN', pty_basic_reference)
        self.assertIn('run_terminal_reference()', source)
        self.assertIn('compat/x86_64/run_x86_terminal_reference.sh', source)
        terminal_reference = source.split('run_terminal_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertEqual(terminal_reference.count('run_in_container cargo test'), 2)
        self.assertIn('-p crabc-rs --no-default-features --test x86_64_terminal', terminal_reference)
        self.assertIn(
            '-p crabc-rs --no-default-features --features alloc --test x86_64_terminal',
            terminal_reference,
        )
        self.assertIn('--example x86_64_terminal_direct_probe', terminal_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_terminal_reference.sh',
            terminal_reference,
        )
        self.assertNotIn('run_in_chroot_cap_container', terminal_reference)
        self.assertNotIn('--cap-add=SYS_ADMIN', terminal_reference)
        self.assertIn('run_mlock_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mlock_reference.sh', source)
        self.assertIn('run_msync_reference()', source)
        self.assertIn('compat/x86_64/run_x86_msync_reference.sh', source)
        self.assertIn('run_madvise_reference()', source)
        self.assertIn('compat/x86_64/run_x86_madvise_reference.sh', source)
        self.assertIn('run_mincore_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mincore_reference.sh', source)
        self.assertIn('run_fs_advice_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fs_advice_reference.sh', source)
        self.assertIn('run_memfd_reference()', source)
        self.assertIn('compat/x86_64/run_x86_memfd_reference.sh', source)
        self.assertIn('run_ftruncate_reference()', source)
        self.assertIn('compat/x86_64/run_x86_ftruncate_reference.sh', source)
        self.assertIn('run_timestamp_reference()', source)
        self.assertIn('compat/x86_64/run_x86_timestamp_reference.sh', source)
        self.assertIn('--test x86_64_futimens', source)
        self.assertIn('--test x86_64_timestamp_paths', source)
        self.assertNotIn('futimens-reference', source)
        self.assertNotIn('run_x86_futimens_reference.sh', source)
        self.assertIn('run_posix_fallocate_reference()', source)
        self.assertIn('compat/x86_64/run_x86_posix_fallocate_reference.sh', source)
        self.assertIn('--test x86_64_posix_fallocate -- --test-threads=1', source)
        self.assertIn('run_fallocate_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fallocate_reference.sh', source)
        self.assertIn('--test x86_64_fallocate -- --test-threads=1', source)
        self.assertIn('run_file_position_reference()', source)
        self.assertIn('compat/x86_64/run_x86_file_position_reference.sh', source)
        self.assertIn('run_sync_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sync_reference.sh', source)
        self.assertIn('--test x86_64_sync -- --test-threads=1', source)
        self.assertIn('run_syncfs_reference()', source)
        self.assertIn('compat/x86_64/run_x86_syncfs_reference.sh', source)
        self.assertIn('--test x86_64_syncfs -- --test-threads=1', source)
        self.assertIn('run_sync_file_range_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sync_file_range_reference.sh', source)
        self.assertIn('--test x86_64_sync_file_range -- --test-threads=1', source)
        self.assertIn('run_rand_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rand_reference.sh', source)
        self.assertIn('run_time_abi_reference()', source)
        self.assertIn('compat/x86_64/run_x86_time_reference.sh', source)
        self.assertIn('run_time_observation_reference()', source)
        self.assertIn('compat/x86_64/run_x86_time_observation_reference.sh', source)
        self.assertIn('run_calendar_time_reference()', source)
        self.assertIn('compat/x86_64/run_x86_calendar_time_reference.sh', source)
        self.assertIn(
            'x86_64_gettimeofday_writes_one_normalized_private_record',
            source,
        )
        self.assertIn('--test time --test calendar_utc --test x86_64_calendar_time', source)
        self.assertIn('--test timezone_rules --test calendar_local', source)
        self.assertIn('--example time_direct_probe --example calendar_utc_direct_probe', source)
        self.assertIn('--example calendar_local_direct_probe', source)
        self.assertIn('run_advanced_time_reference()', source)
        self.assertIn('compat/x86_64/run_x86_advanced_time_reference.sh', source)
        self.assertIn(
            'x86_64_posix_timer_writes_exact_id_and_old_setting_records',
            source,
        )
        self.assertIn('--test x86_64_advanced_time', source)
        self.assertIn('--example time_dynamic_direct_probe', source)
        self.assertIn('--example process_clock_id_direct_probe', source)
        self.assertIn('--example time_settime_direct_probe', source)
        self.assertIn('--example time_timers_direct_probe', source)
        self.assertIn('run_relative_sleep_reference()', source)
        self.assertIn('compat/x86_64/run_x86_relative_sleep_reference.sh', source)
        self.assertIn('run_clock_nanosleep_reference()', source)
        self.assertIn('compat/x86_64/run_x86_clock_nanosleep_reference.sh', source)
        self.assertIn('run_getitimer_reference()', source)
        self.assertIn('compat/x86_64/run_x86_getitimer_reference.sh', source)
        self.assertIn('run_setitimer_reference()', source)
        self.assertIn('compat/x86_64/run_x86_setitimer_reference.sh', source)
        self.assertIn('run_timerfd_reference()', source)
        self.assertIn('compat/x86_64/run_x86_timerfd_reference.sh', source)
        self.assertIn('run_pselect_reference()', source)
        self.assertIn('compat/x86_64/run_x86_pselect_reference.sh', source)
        self.assertIn('run_poll_reference()', source)
        self.assertIn('compat/x86_64/run_x86_poll_reference.sh', source)
        self.assertIn('run_ppoll_reference()', source)
        self.assertIn('compat/x86_64/run_x86_ppoll_reference.sh', source)
        self.assertIn('run_epoll_reference()', source)
        self.assertIn('compat/x86_64/run_x86_epoll_reference.sh', source)
        self.assertIn('run_process_identity_reference()', source)
        self.assertIn('compat/x86_64/run_x86_process_identity_reference.sh', source)
        self.assertIn('run_child_ownership_reference()', source)
        self.assertIn('compat/x86_64/run_x86_child_ownership_reference.sh', source)
        self.assertIn('--test x86_64_child_ownership -- --test-threads=1', source)
        self.assertIn('run_getgroups_reference()', source)
        self.assertIn('compat/x86_64/run_x86_getgroups_reference.sh', source)
        self.assertIn('run_process_session_reference()', source)
        self.assertIn('compat/x86_64/run_x86_process_session_reference.sh', source)
        self.assertIn('run_pidfd_open_reference()', source)
        self.assertIn('compat/x86_64/run_x86_pidfd_open_reference.sh', source)
        self.assertIn('run_fcntl_getlk_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fcntl_getlk_reference.sh', source)
        self.assertIn('run_fcntl_status_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fcntl_status_reference.sh', source)
        self.assertIn('--test x86_64_fcntl_flags -- --test-threads=1', source)
        self.assertIn('run_flock_reference()', source)
        self.assertIn('compat/x86_64/run_x86_flock_reference.sh', source)
        self.assertIn('--test x86_64_flock -- --test-threads=1', source)
        self.assertIn('run_sendfile_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sendfile_reference.sh', source)
        self.assertIn('--test x86_64_sendfile -- --test-threads=1', source)
        self.assertIn('run_copy_file_range_reference()', source)
        self.assertIn('compat/x86_64/run_x86_copy_file_range_reference.sh', source)
        self.assertIn('--test x86_64_copy_file_range -- --test-threads=1', source)
        self.assertIn('run_scheduler_priority_bounds_reference()', source)
        self.assertIn('compat/x86_64/run_x86_scheduler_priority_bounds_reference.sh', source)
        self.assertIn('run_priority_reference()', source)
        self.assertIn('compat/x86_64/run_x86_priority_reference.sh', source)
        self.assertIn('run_setpriority_reference()', source)
        self.assertIn('compat/x86_64/run_x86_setpriority_reference.sh', source)
        self.assertIn('run_rlimit_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rlimit_reference.sh', source)
        self.assertIn('run_rlimit_targeted_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_rlimit_targeted_reference.sh',
            source,
        )
        self.assertIn('--test x86_64_rlimit_targeted -- --test-threads=1', source)
        self.assertIn('run_setrlimit_reference()', source)
        self.assertIn('compat/x86_64/run_x86_setrlimit_reference.sh', source)
        self.assertIn('run_umask_reference()', source)
        self.assertIn('compat/x86_64/run_x86_umask_reference.sh', source)
        self.assertIn('run_rusage_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rusage_reference.sh', source)
        self.assertIn('run_times_reference()', source)
        self.assertIn('compat/x86_64/run_x86_times_reference.sh', source)
        self.assertIn('run_fstat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fstat_reference.sh', source)
        self.assertIn('run_statfs_reference()', source)
        self.assertIn('compat/x86_64/run_x86_statfs_reference.sh', source)
        self.assertIn('--test x86_64_fs_capacity -- --test-threads=1', source)
        self.assertIn('run_path_lifecycle_reference()', source)
        self.assertIn('compat/x86_64/run_x86_path_lifecycle_reference.sh', source)
        self.assertIn('--test x86_64_path_lifecycle -- --test-threads=1', source)
        self.assertIn('run_namespace_reference()', source)
        self.assertIn('compat/x86_64/run_x86_namespace_reference.sh', source)
        self.assertIn('--test x86_64_namespace -- --test-threads=1', source)
        self.assertIn('run_path_core_reference()', source)
        self.assertIn('run_fstat_reference', source)
        self.assertIn('run_statat_reference', source)
        self.assertIn('run_path_lifecycle_reference', source)
        self.assertIn('run_namespace_reference', source)
        self.assertIn('run_timestamp_reference', source)
        self.assertIn('run_readlinkat_reference', source)
        self.assertIn('--features std', source)
        self.assertIn('--test x86_64_readlink', source)
        self.assertIn('--example path_core_owned_direct_probe', source)
        self.assertIn('run_xattr_reference()', source)
        self.assertIn('compat/x86_64/run_x86_xattr_reference.sh', source)
        self.assertIn('--test x86_64_xattr -- --test-threads=1', source)
        self.assertIn('--example xattr_direct_probe', source)
        self.assertIn('run_directory_reference()', source)
        self.assertIn('compat/x86_64/run_x86_directory_reference.sh', source)
        self.assertIn('--test x86_64_raw_directory', source)
        self.assertIn('--test x86_64_directory', source)
        self.assertIn('--test x86_64_directory_position', source)
        self.assertIn('--example directory_direct_probe', source)
        self.assertIn('--example directory_position_direct_probe', source)
        self.assertIn('run_temporary_object_reference()', source)
        self.assertIn('compat/x86_64/run_x86_temporary_object_reference.sh', source)
        self.assertIn('--test x86_64_temporary_objects', source)
        self.assertIn('--features alloc --test x86_64_temporary_objects', source)
        self.assertIn('--example fs_named_tempfile_direct_probe', source)
        self.assertIn('--example fs_tempfile_direct_probe', source)
        self.assertIn('--example fs_tempdir_direct_probe', source)
        self.assertIn('run_statx_reference()', source)
        self.assertIn('compat/x86_64/run_x86_statx_reference.sh', source)
        self.assertIn('--test x86_64_statx -- --test-threads=1', source)
        self.assertIn('--example statx_direct_probe', source)
        self.assertIn('run_cwd_canonicalize_reference()', source)
        self.assertIn('compat/x86_64/run_x86_cwd_canonicalize_reference.sh', source)
        self.assertIn('--test x86_64_canonicalize', source)
        self.assertIn('--test x86_64_cwd_mutation', source)
        self.assertIn('--example fs_canonicalize_direct_probe', source)
        self.assertIn('--example process_cwd_direct_probe', source)
        self.assertIn('run_root_change_reference()', source)
        self.assertIn('compat/x86_64/run_x86_root_change_reference.sh', source)
        self.assertIn('--test x86_64_chroot -- --test-threads=1', source)
        self.assertIn('--example process_chroot_direct_probe', source)
        chroot_cap_container = source.split('run_in_chroot_cap_container() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('--cap-add=SYS_CHROOT', chroot_cap_container)
        root_change_reference = source.split('run_root_change_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_chroot_cap_container cargo test', root_change_reference)
        self.assertIn(
            '--test x86_64_chroot -- --test-threads=1',
            root_change_reference,
        )
        self.assertIn(
            'run_in_chroot_cap_container bash /workspace/compat/x86_64/run_x86_root_change_reference.sh',
            root_change_reference,
        )
        self.assertIn('run_in_container cargo build', root_change_reference)
        self.assertIn('--example process_chroot_direct_probe', root_change_reference)
        self.assertIn('run_mount_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mount_reference.sh', source)
        self.assertIn('--test x86_64_mount', source)
        self.assertIn('--example mount_direct_probe', source)
        mount_reference = source.split('run_mount_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_container cargo test', mount_reference)
        self.assertIn('--test x86_64_mount', mount_reference)
        self.assertIn('-- --test-threads=1', mount_reference)
        self.assertIn('run_in_container cargo build', mount_reference)
        self.assertIn('--example mount_direct_probe', mount_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_mount_reference.sh',
            mount_reference,
        )
        self.assertNotIn('run_in_chroot_cap_container', mount_reference)
        self.assertNotIn('--cap-add=SYS_ADMIN', mount_reference)
        self.assertIn('run_thread_kill_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_thread_kill_reference.sh',
            source,
        )
        self.assertIn('--test x86_64_thread_kill', source)
        self.assertIn('--example thread_kill_direct_probe', source)
        thread_kill_reference = source.split('run_thread_kill_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_container cargo test', thread_kill_reference)
        self.assertIn('--test x86_64_thread_kill', thread_kill_reference)
        self.assertIn('-- --test-threads=1', thread_kill_reference)
        self.assertIn('run_in_container cargo build', thread_kill_reference)
        self.assertIn('--example thread_kill_direct_probe', thread_kill_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_thread_kill_reference.sh',
            thread_kill_reference,
        )
        self.assertIn('run_ipc_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mqueue_reference.sh', source)
        self.assertIn('--test x86_64_ipc -- --test-threads=1', source)
        self.assertIn('--example ipc_direct_probe', source)
        self.assertIn('run_shm_reference()', source)
        self.assertIn('compat/x86_64/run_x86_shm_reference.sh', source)
        self.assertIn('--test x86_64_shm -- --test-threads=1', source)
        self.assertIn('--example shm_direct_probe', source)
        self.assertIn('run_inotify_reference()', source)
        self.assertIn('compat/x86_64/run_x86_inotify_reference.sh', source)
        self.assertIn('--lib --no-default-features system::inotify::', source)
        self.assertIn('--test x86_64_inotify -- --test-threads=1', source)
        self.assertIn('--example inotify_direct_probe', source)
        self.assertIn('run_socket_transport_reference()', source)
        self.assertIn('compat/x86_64/run_x86_socket_transport_reference.sh', source)
        self.assertIn('--test x86_64_socket_transport -- --test-threads=1', source)
        self.assertIn('run_interface_device_reference()', source)
        self.assertIn('compat/x86_64/run_x86_interface_device_reference.sh', source)
        self.assertIn('--test x86_64_interface_device -- --test-threads=1', source)
        self.assertIn('--lib --no-default-features --features alloc net::netdevice::', source)
        self.assertIn('--example interface_names_direct_probe', source)
        self.assertIn('--example interface_addresses_direct_probe', source)
        self.assertIn('run_resolver_transport_reference()', source)
        self.assertIn(
            '-p crabc-core --no-default-features --test x86_64_resolver_transport', source
        )
        self.assertIn('run_resolver_facade_reference()', source)
        self.assertIn(
            '-p crabc-rs --no-default-features --features alloc --test x86_64_resolver',
            source,
        )
        self.assertIn('--example resolver_hosts_direct_probe', source)
        self.assertIn('run_netdb_reference()', source)
        self.assertIn(
            '-p crabc-rs --no-default-features --features alloc --test x86_64_netdb',
            source,
        )
        self.assertIn('--example resolver_direct_probe', source)
        self.assertIn('run_users_databases_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_users_databases_reference.sh',
            source,
        )
        self.assertIn('--test x86_64_users_databases', source)
        self.assertIn('--example users_databases_direct_probe', source)
        users_databases_reference = source.split(
            'run_users_databases_reference() {',
            1,
        )[1].split('\n}\n', 1)[0]
        self.assertIn('run_in_container cargo test', users_databases_reference)
        self.assertIn('--no-default-features --features alloc', users_databases_reference)
        self.assertIn('--test x86_64_users_databases', users_databases_reference)
        self.assertIn('-- --test-threads=1', users_databases_reference)
        self.assertIn('run_in_container cargo build', users_databases_reference)
        self.assertIn('--example users_databases_direct_probe', users_databases_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_users_databases_reference.sh',
            users_databases_reference,
        )
        path_lifecycle_runner = (
            ROOT / 'compat/x86_64/run_x86_path_lifecycle_reference.sh'
        ).read_text(encoding='utf-8')
        namespace_runner = (
            ROOT / 'compat/x86_64/run_x86_namespace_reference.sh'
        ).read_text(encoding='utf-8')
        path_lifecycle_test = (
            ROOT / 'crabc-rs/tests/x86_64_path_lifecycle.rs'
        ).read_text(encoding='utf-8')
        namespace_test = (
            ROOT / 'crabc-rs/tests/x86_64_namespace.rs'
        ).read_text(encoding='utf-8')
        xattr_runner = (
            ROOT / 'compat/x86_64/run_x86_xattr_reference.sh'
        ).read_text(encoding='utf-8')
        xattr_probe = (
            ROOT / 'compat/x86_64/x86_xattr_reference_probe.c'
        ).read_text(encoding='utf-8')
        xattr_test = (ROOT / 'crabc-rs/tests/x86_64_xattr.rs').read_text(encoding='utf-8')
        xattr_direct_probe = (
            ROOT / 'crabc-rs/examples/xattr_direct_probe.rs'
        ).read_text(encoding='utf-8')
        directory_runner = (
            ROOT / 'compat/x86_64/run_x86_directory_reference.sh'
        ).read_text(encoding='utf-8')
        directory_probe = (
            ROOT / 'compat/x86_64/x86_directory_reference_probe.c'
        ).read_text(encoding='utf-8')
        raw_directory_test = (
            ROOT / 'crabc-rs/tests/x86_64_raw_directory.rs'
        ).read_text(encoding='utf-8')
        directory_test = (
            ROOT / 'crabc-rs/tests/x86_64_directory.rs'
        ).read_text(encoding='utf-8')
        directory_position_test = (
            ROOT / 'crabc-rs/tests/x86_64_directory_position.rs'
        ).read_text(encoding='utf-8')
        directory_direct_probe = (
            ROOT / 'crabc-rs/examples/directory_direct_probe.rs'
        ).read_text(encoding='utf-8')
        directory_position_direct_probe = (
            ROOT / 'crabc-rs/examples/directory_position_direct_probe.rs'
        ).read_text(encoding='utf-8')
        temporary_object_runner = (
            ROOT / 'compat/x86_64/run_x86_temporary_object_reference.sh'
        ).read_text(encoding='utf-8')
        temporary_object_probe = (
            ROOT / 'compat/x86_64/x86_temporary_object_reference_probe.c'
        ).read_text(encoding='utf-8')
        temporary_object_test = (
            ROOT / 'crabc-rs/tests/x86_64_temporary_objects.rs'
        ).read_text(encoding='utf-8')
        named_tempfile_direct_probe = (
            ROOT / 'crabc-rs/examples/fs_named_tempfile_direct_probe.rs'
        ).read_text(encoding='utf-8')
        tempfile_direct_probe = (
            ROOT / 'crabc-rs/examples/fs_tempfile_direct_probe.rs'
        ).read_text(encoding='utf-8')
        tempdir_direct_probe = (
            ROOT / 'crabc-rs/examples/fs_tempdir_direct_probe.rs'
        ).read_text(encoding='utf-8')
        statx_runner = (
            ROOT / 'compat/x86_64/run_x86_statx_reference.sh'
        ).read_text(encoding='utf-8')
        statx_probe = (
            ROOT / 'compat/x86_64/x86_statx_reference_probe.c'
        ).read_text(encoding='utf-8')
        statx_test = (ROOT / 'crabc-rs/tests/x86_64_statx.rs').read_text(encoding='utf-8')
        statx_direct_probe = (
            ROOT / 'crabc-rs/examples/statx_direct_probe.rs'
        ).read_text(encoding='utf-8')
        cwd_canonicalize_runner = (
            ROOT / 'compat/x86_64/run_x86_cwd_canonicalize_reference.sh'
        ).read_text(encoding='utf-8')
        cwd_canonicalize_probe = (
            ROOT / 'compat/x86_64/x86_cwd_canonicalize_reference_probe.c'
        ).read_text(encoding='utf-8')
        canonicalize_test = (
            ROOT / 'crabc-rs/tests/x86_64_canonicalize.rs'
        ).read_text(encoding='utf-8')
        cwd_mutation_test = (
            ROOT / 'crabc-rs/tests/x86_64_cwd_mutation.rs'
        ).read_text(encoding='utf-8')
        canonicalize_direct_probe = (
            ROOT / 'crabc-rs/examples/fs_canonicalize_direct_probe.rs'
        ).read_text(encoding='utf-8')
        cwd_direct_probe = (
            ROOT / 'crabc-rs/examples/process_cwd_direct_probe.rs'
        ).read_text(encoding='utf-8')
        root_change_runner = (
            ROOT / 'compat/x86_64/run_x86_root_change_reference.sh'
        ).read_text(encoding='utf-8')
        root_change_probe = (
            ROOT / 'compat/x86_64/x86_root_change_reference_probe.c'
        ).read_text(encoding='utf-8')
        chroot_test = (ROOT / 'crabc-rs/tests/x86_64_chroot.rs').read_text(encoding='utf-8')
        chroot_direct_probe = (
            ROOT / 'crabc-rs/examples/process_chroot_direct_probe.rs'
        ).read_text(encoding='utf-8')
        mount_runner = (
            ROOT / 'compat/x86_64/run_x86_mount_reference.sh'
        ).read_text(encoding='utf-8')
        mount_probe = (
            ROOT / 'compat/x86_64/x86_mount_reference_probe.c'
        ).read_text(encoding='utf-8')
        mount_test = (ROOT / 'crabc-rs/tests/x86_64_mount.rs').read_text(encoding='utf-8')
        mount_direct_probe = (
            ROOT / 'crabc-rs/examples/mount_direct_probe.rs'
        ).read_text(encoding='utf-8')
        thread_kill_runner = (
            ROOT / 'compat/x86_64/run_x86_thread_kill_reference.sh'
        ).read_text(encoding='utf-8')
        thread_kill_probe = (
            ROOT / 'compat/x86_64/x86_thread_kill_reference_probe.c'
        ).read_text(encoding='utf-8')
        thread_kill_test = (
            ROOT / 'crabc-rs/tests/x86_64_thread_kill.rs'
        ).read_text(encoding='utf-8')
        thread_kill_direct_probe = (
            ROOT / 'crabc-rs/examples/thread_kill_direct_probe.rs'
        ).read_text(encoding='utf-8')
        mapping_reference_runner = (
            ROOT / 'compat/x86_64/run_x86_mapping_reference.sh'
        ).read_text(encoding='utf-8')
        mapping_reference_probe = (
            ROOT / 'compat/x86_64/x86_mapping_reference_probe.c'
        ).read_text(encoding='utf-8')
        memory_mapping_test = (
            ROOT / 'crabc-rs/tests/x86_64_memory_mapping.rs'
        ).read_text(encoding='utf-8')
        mapping_direct_probe = (
            ROOT / 'crabc-rs/examples/mapping_direct_probe.rs'
        ).read_text(encoding='utf-8')
        memory_vm_reference_runner = (
            ROOT / 'compat/x86_64/run_x86_memory_vm_reference.sh'
        ).read_text(encoding='utf-8')
        memory_vm_reference_probe = (
            ROOT / 'compat/x86_64/x86_memory_vm_reference_probe.c'
        ).read_text(encoding='utf-8')
        memory_vm_test = (
            ROOT / 'crabc-rs/tests/x86_64_memory_vm.rs'
        ).read_text(encoding='utf-8')
        memory_vm_direct_probe = (
            ROOT / 'crabc-rs/examples/memory_vm_direct_probe.rs'
        ).read_text(encoding='utf-8')
        pty_basic_reference_runner = (
            ROOT / 'compat/x86_64/run_x86_pty_basic_reference.sh'
        ).read_text(encoding='utf-8')
        pty_basic_reference_probe = (
            ROOT / 'compat/x86_64/x86_pty_basic_reference_probe.c'
        ).read_text(encoding='utf-8')
        pty_basic_test = (
            ROOT / 'crabc-rs/tests/x86_64_pty_basic.rs'
        ).read_text(encoding='utf-8')
        pty_basic_direct_probe = (
            ROOT / 'crabc-rs/examples/pty_basic_direct_probe.rs'
        ).read_text(encoding='utf-8')
        terminal_reference_runner = (
            ROOT / 'compat/x86_64/run_x86_terminal_reference.sh'
        ).read_text(encoding='utf-8')
        terminal_reference_probe = (
            ROOT / 'compat/x86_64/x86_terminal_reference_probe.c'
        ).read_text(encoding='utf-8')
        terminal_test = (
            ROOT / 'crabc-rs/tests/x86_64_terminal.rs'
        ).read_text(encoding='utf-8')
        terminal_direct_probe = (
            ROOT / 'crabc-rs/examples/x86_64_terminal_direct_probe.rs'
        ).read_text(encoding='utf-8')
        mqueue_runner = (
            ROOT / 'compat/x86_64/run_x86_mqueue_reference.sh'
        ).read_text(encoding='utf-8')
        mqueue_probe = (
            ROOT / 'compat/x86_64/x86_mqueue_reference_probe.c'
        ).read_text(encoding='utf-8')
        ipc_test = (ROOT / 'crabc-rs/tests/x86_64_ipc.rs').read_text(encoding='utf-8')
        ipc_direct_probe = (
            ROOT / 'crabc-rs/examples/ipc_direct_probe.rs'
        ).read_text(encoding='utf-8')
        shm_runner = (
            ROOT / 'compat/x86_64/run_x86_shm_reference.sh'
        ).read_text(encoding='utf-8')
        shm_probe = (
            ROOT / 'compat/x86_64/x86_shm_reference_probe.c'
        ).read_text(encoding='utf-8')
        shm_test = (ROOT / 'crabc-rs/tests/x86_64_shm.rs').read_text(encoding='utf-8')
        shm_direct_probe = (
            ROOT / 'crabc-rs/examples/shm_direct_probe.rs'
        ).read_text(encoding='utf-8')
        inotify_runner = (
            ROOT / 'compat/x86_64/run_x86_inotify_reference.sh'
        ).read_text(encoding='utf-8')
        inotify_probe = (
            ROOT / 'compat/x86_64/x86_inotify_reference_probe.c'
        ).read_text(encoding='utf-8')
        inotify_test = (ROOT / 'crabc-rs/tests/x86_64_inotify.rs').read_text(encoding='utf-8')
        inotify_direct_probe = (
            ROOT / 'crabc-rs/examples/inotify_direct_probe.rs'
        ).read_text(encoding='utf-8')
        calendar_time_runner = (
            ROOT / 'compat/x86_64/run_x86_calendar_time_reference.sh'
        ).read_text(encoding='utf-8')
        calendar_time_probe = (
            ROOT / 'compat/x86_64/x86_calendar_time_reference_probe.c'
        ).read_text(encoding='utf-8')
        advanced_time_runner = (
            ROOT / 'compat/x86_64/run_x86_advanced_time_reference.sh'
        ).read_text(encoding='utf-8')
        advanced_time_probe = (
            ROOT / 'compat/x86_64/x86_advanced_time_reference_probe.c'
        ).read_text(encoding='utf-8')
        advanced_time_test = (
            ROOT / 'crabc-rs/tests/x86_64_advanced_time.rs'
        ).read_text(encoding='utf-8')
        calendar_oracle = (
            'syscall=gettimeofday:96 abi=rdi-timeval:rsi-null '
            'layout=timeval16/8:offsets=0,8 raw=normalized:record-bounded '
            'utc=gmtime_r:timegm:epoch:pre-epoch:leap:400-year '
            'tz=POSIX-EST5EDT4-M3.2.0-M11.1.0 dst=start-gap:end-fold '
            'native=rule-input-only:no-c-time-abi:no-TZ-global '
            'c-api-selection=excluded'
        )
        advanced_time_oracle = (
            'layout=timespec16/8 itimerspec32/8 sigevent64/8 '
            'offsets=timespec0,8/itimerspec0,16/sigevent0,8,12,16 '
            'syscalls=timer:222,223,224,225,226/clock:227,229 '
            'process-clock=encoded,current,missing:raw-EINVAL,musl-ESRCH '
            'getres=musl+raw-normalized '
            'settime=monotonic-no-mutate:EINVAL|EPERM '
            'timers=SIGEV_NONE:initial,one-shot,periodic,'
            'disarm-interval-zero:stale-value,delete '
            'flags=ABSTIME+0x2,0x4,0x80000000-forwarded-ignored '
            'errors=invalid-nsec-EINVAL'
        )
        socket_transport_runner = (
            ROOT / 'compat/x86_64/run_x86_socket_transport_reference.sh'
        ).read_text(encoding='utf-8')
        socket_transport_probe = (
            ROOT / 'compat/x86_64/x86_socket_transport_reference_probe.c'
        ).read_text(encoding='utf-8')
        socket_transport_test = (
            ROOT / 'crabc-rs/tests/x86_64_socket_transport.rs'
        ).read_text(encoding='utf-8')
        interface_device_runner = (
            ROOT / 'compat/x86_64/run_x86_interface_device_reference.sh'
        ).read_text(encoding='utf-8')
        interface_device_probe = (
            ROOT / 'compat/x86_64/x86_interface_device_reference_probe.c'
        ).read_text(encoding='utf-8')
        interface_device_test = (
            ROOT / 'crabc-rs/tests/x86_64_interface_device.rs'
        ).read_text(encoding='utf-8')
        resolver_transport_test = (
            ROOT / 'crabc-core/tests/x86_64_resolver_transport.rs'
        ).read_text(encoding='utf-8')
        resolver_facade_test = (
            ROOT / 'crabc-rs/tests/x86_64_resolver.rs'
        ).read_text(encoding='utf-8')
        resolver_hosts_probe = (
            ROOT / 'crabc-rs/examples/resolver_hosts_direct_probe.rs'
        ).read_text(encoding='utf-8')
        netdb_test = (
            ROOT / 'crabc-rs/tests/x86_64_netdb.rs'
        ).read_text(encoding='utf-8')
        resolver_direct_probe = (
            ROOT / 'crabc-rs/examples/resolver_direct_probe.rs'
        ).read_text(encoding='utf-8')
        self.assertIn('x86_path_lifecycle_reference_probe.c', path_lifecycle_runner)
        self.assertIn('x86_namespace_reference_probe.c', namespace_runner)
        self.assertIn('x86_64_path_lifecycle_is_descriptor_relative_and_typed', path_lifecycle_test)
        self.assertIn('x86_64_namespace_lifecycle_is_descriptor_relative', namespace_test)
        self.assertIn('x86_xattr_reference_probe.c', xattr_runner)
        self.assertIn('SYS_setxattr == 188', xattr_probe)
        self.assertIn('SYS_fremovexattr == 199', xattr_probe)
        self.assertIn('XATTR_CREATE == 1', xattr_probe)
        self.assertIn('XATTR_REPLACE == 2', xattr_probe)
        self.assertIn('x86_64_xattr_preserves_path_nofollow_fd_and_caller_buffer_contracts', xattr_test)
        self.assertIn('crabc_rs_xattr_direct_probe', xattr_direct_probe)
        self.assertIn('x86_directory_reference_probe.c', directory_runner)
        self.assertIn('SYS_getdents64 == 217', directory_probe)
        self.assertIn('SYS_lseek == 8', directory_probe)
        self.assertIn('SYS_openat == 257', directory_probe)
        self.assertIn('LINUX_DIRENT64_HEADER_SIZE = 19', directory_probe)
        self.assertIn('opendir', directory_probe)
        self.assertIn('fdopendir', directory_probe)
        self.assertIn('seekdir', directory_probe)
        self.assertIn('rewinddir', directory_probe)
        self.assertIn('x86_64_raw_dir_preserves_unaligned_buffer_borrowed_names_and_small_buffer_error', raw_directory_test)
        self.assertIn('x86_64_dir_owns_close_on_exec_descriptor_and_preserves_byte_names', directory_test)
        self.assertIn('x86_64_dir_rewind_and_seek_discard_buffered_records', directory_position_test)
        self.assertIn('crabc_rs_directory_direct_probe', directory_direct_probe)
        self.assertIn('crabc_rs_directory_position_direct_probe', directory_position_direct_probe)
        self.assertIn('x86_temporary_object_reference_probe.c', temporary_object_runner)
        self.assertIn('anonymous=unavailable:EOPNOTSUPP', temporary_object_runner)
        self.assertIn('SYS_openat == 257', temporary_object_probe)
        self.assertIn('SYS_mkdirat == 258', temporary_object_probe)
        self.assertIn('SYS_unlinkat == 263', temporary_object_probe)
        self.assertIn('O_TMPFILE == 0x00410000', temporary_object_probe)
        self.assertIn('stable-parent-unlink', temporary_object_probe)
        self.assertIn('named_tempfile_is_private_cloexec_and_drop_unlinks', temporary_object_test)
        self.assertIn('anonymous_tempfile_is_cloexec_unlinked_and_read_write', temporary_object_test)
        self.assertIn('temporary_directories_are_private_byte_preserving_and_descriptor_relative', temporary_object_test)
        self.assertIn('crabc_rs_fs_named_tempfile_direct_probe', named_tempfile_direct_probe)
        self.assertIn('crabc_rs_fs_tempfile_direct_probe', tempfile_direct_probe)
        self.assertIn('crabc_rs_fs_tempdir_direct_probe', tempdir_direct_probe)
        self.assertIn('fs::rmdir(&output[..length])', tempdir_direct_probe)
        self.assertIn('x86_statx_reference_probe.c', statx_runner)
        self.assertIn('raw=ENOSYS-musl-fallback', statx_runner)
        self.assertIn('SYS_statx == 332', statx_probe)
        self.assertIn('sizeof(struct statx) == 256', statx_probe)
        self.assertIn('AT_EMPTY_PATH == 0x1000', statx_probe)
        self.assertIn('STATX__RESERVED == 0x80000000U', statx_probe)
        self.assertIn('AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC', statx_probe)
        self.assertIn('x86_64_statx_observes_descriptor_relative_metadata_only_when_masked_in', statx_test)
        self.assertIn('x86_64_statx_keeps_operation_specific_nofollow_and_empty_path_semantics', statx_test)
        self.assertIn('x86_64_statx_preserves_direct_validation_and_bounded_path_contracts', statx_test)
        self.assertIn('crabc_rs_statx_direct_probe', statx_direct_probe)
        self.assertIn('x86_cwd_canonicalize_reference_probe.c', cwd_canonicalize_runner)
        self.assertIn('SYS_getcwd == 79', cwd_canonicalize_probe)
        self.assertIn('SYS_chdir == 80', cwd_canonicalize_probe)
        self.assertIn('SYS_fchdir == 81', cwd_canonicalize_probe)
        self.assertIn('realpath', cwd_canonicalize_probe)
        self.assertIn('cwd_mutation_child', cwd_canonicalize_probe)
        self.assertIn('x86_64_canonicalize_into_is_physical_byte_preserving_and_noalloc', canonicalize_test)
        self.assertIn('x86_64_cwd_mutation_is_child_contained_and_descriptor_restorable', cwd_mutation_test)
        self.assertIn('crabc_rs_fs_canonicalize_direct_probe', canonicalize_direct_probe)
        self.assertIn('crabc_rs_process_cwd_direct_probe', cwd_direct_probe)
        self.assertIn('x86_root_change_reference_probe.c', root_change_runner)
        self.assertIn('CAP_SYS_CHROOT', root_change_runner)
        self.assertIn('SYS_chroot == 161', root_change_probe)
        self.assertIn('root_change_child', root_change_probe)
        self.assertIn(
            'x86_64_chroot_is_child_contained_and_preserves_existing_cwd',
            chroot_test,
        )
        self.assertIn('process::chroot', chroot_test)
        self.assertIn('crabc_rs_process_chroot_direct_probe', chroot_direct_probe)
        self.assertIn('x86_mount_reference_probe.c', mount_runner)
        self.assertIn('mount=165 umount2=166', mount_runner)
        self.assertIn('SYS_mount == 165', mount_probe)
        self.assertIn('SYS_umount2 == 166', mount_probe)
        self.assertIn('matching_missing_target_failure', mount_probe)
        self.assertIn('run_in_child', mount_probe)
        self.assertIn(
            'x86_64_mount_basic_checks_paths_and_preserves_direct_missing_target_errors',
            mount_test,
        )
        self.assertIn('mount::mount', mount_test)
        self.assertIn('mount::unmount', mount_test)
        self.assertIn('crabc_rs_mount_direct_probe', mount_direct_probe)
        self.assertIn('x86_thread_kill_reference_probe.c', thread_kill_runner)
        self.assertIn('pinned-musl/raw exact-thread signal-delivery reference', thread_kill_runner)
        self.assertIn('SYS_tgkill == 234', thread_kill_probe)
        self.assertIn('SYS_gettid == 186', thread_kill_probe)
        self.assertIn('pthread_kill', thread_kill_probe)
        self.assertIn('raw_missing_tid_is_esrch', thread_kill_probe)
        self.assertIn('raw_invalid_signal_is_einval', thread_kill_probe)
        self.assertIn('run_in_child', thread_kill_probe)
        self.assertIn(
            'x86_64_kill_thread_targets_the_selected_live_worker_and_preserves_errors',
            thread_kill_test,
        )
        self.assertIn('signal::kill_thread', thread_kill_test)
        self.assertIn('crabc_rs_thread_kill_direct_probe', thread_kill_direct_probe)
        self.assertIn('x86_mapping_reference_probe.c', mapping_reference_runner)
        self.assertIn(
            'mmap=9 mprotect=10 munmap=11 raw+musl=anonymous-private rw=write '
            'ro=readback rw-restored=write raw-unaligned-mprotect=EINVAL '
            'unmap=exact child-contained',
            mapping_reference_runner,
        )
        self.assertIn('SYS_mmap == 9', mapping_reference_probe)
        self.assertIn('SYS_mprotect == 10', mapping_reference_probe)
        self.assertIn('SYS_munmap == 11', mapping_reference_probe)
        self.assertIn('raw_unaligned_mprotect_is_einval', mapping_reference_probe)
        self.assertIn('run_in_child', mapping_reference_probe)
        self.assertIn(
            'x86_64_memory_mapping_preserves_protection_and_unique_unmap_lifetime',
            memory_mapping_test,
        )
        self.assertIn(
            'x86_64_memory_mapping_file_backed_boundary_and_direct_errors_are_precise',
            memory_mapping_test,
        )
        self.assertIn('mm::mmap_anonymous', memory_mapping_test)
        self.assertIn('mm::mprotect', memory_mapping_test)
        self.assertIn('mm::munmap', memory_mapping_test)
        self.assertIn('crabc_rs_mapping_direct_probe', mapping_direct_probe)
        self.assertIn('x86_memory_vm_reference_probe.c', memory_vm_reference_runner)
        self.assertIn(
            'brk=12 raw=query+same-address-replay musl=sbrk(0)-query+brk=ENOMEM '
            'mlockall=151 munlockall=152',
            memory_vm_reference_runner,
        )
        self.assertIn('SYS_brk == 12', memory_vm_reference_probe)
        self.assertIn('SYS_mlockall == 151', memory_vm_reference_probe)
        self.assertIn('SYS_munlockall == 152', memory_vm_reference_probe)
        self.assertIn('SYS_remap_file_pages == 216', memory_vm_reference_probe)
        self.assertIn('check_brk_query_and_replay', memory_vm_reference_probe)
        self.assertIn('check_mlockall_cleanup', memory_vm_reference_probe)
        self.assertIn('check_anonymous_remap_rejected', memory_vm_reference_probe)
        self.assertIn('run_in_child', memory_vm_reference_probe)
        self.assertIn(
            'x86_64_kernel_brk_queries_and_replays_without_allocator_mutation',
            memory_vm_test,
        )
        self.assertIn(
            'x86_64_mlockall_flags_are_the_closed_linux_vocabulary',
            memory_vm_test,
        )
        self.assertIn(
            'x86_64_mlockall_is_child_contained_and_unlocked_after_success',
            memory_vm_test,
        )
        self.assertIn(
            'x86_64_remap_file_pages_keeps_legacy_anonymous_error_typed',
            memory_vm_test,
        )
        self.assertIn('process::kernel_brk', memory_vm_test)
        self.assertIn('mm::mlockall', memory_vm_test)
        self.assertIn('mm::munlockall', memory_vm_test)
        self.assertIn('mm::remap_file_pages', memory_vm_test)
        self.assertIn('crabc_rs_memory_vm_direct_probe', memory_vm_direct_probe)
        self.assertIn('x86_pty_basic_reference_probe.c', pty_basic_reference_runner)
        self.assertIn(
            'ioctls=TIOCGPTN:0x80045430,TIOCSPTLCK:0x40045431,TIOCGPTPEER:0x5441',
            pty_basic_reference_runner,
        )
        self.assertIn('c-api-selection=excluded', pty_basic_reference_runner)
        self.assertIn('nonpty=raw-ENOTTY+musl-grant-noop', pty_basic_reference_runner)
        self.assertIn('SYS_ioctl == 16', pty_basic_reference_probe)
        self.assertIn('TIOCGPTN == 0x80045430UL', pty_basic_reference_probe)
        self.assertIn('TIOCSPTLCK == 0x40045431UL', pty_basic_reference_probe)
        self.assertIn('TIOCGPTPEER == 0x5441UL', pty_basic_reference_probe)
        self.assertIn('run_pty_lifecycle', pty_basic_reference_probe)
        self.assertIn('check_nonpty_rejection', pty_basic_reference_probe)
        self.assertIn('if (grantpt(null_fd) != 0)', pty_basic_reference_probe)
        self.assertIn('ptsname_r(master, short_name, sizeof(short_name)) != ERANGE', pty_basic_reference_probe)
        self.assertIn(
            'x86_64_pair_requires_read_write_before_touching_devpts',
            pty_basic_test,
        )
        self.assertIn(
            'x86_64_grantpt_validates_a_non_pty_descriptor',
            pty_basic_test,
        )
        self.assertIn("musl's C grantpt no-op wrapper", pty_basic_test)
        self.assertIn(
            'x86_64_pair_owns_both_descriptors_and_resolves_slave_name',
            pty_basic_test,
        )
        self.assertIn('x86_64_ptsname_into_rejects_short_caller_storage', pty_basic_test)
        self.assertIn('x86_64_slave_output_reaches_its_owned_master', pty_basic_test)
        self.assertIn('pty::PtyPair::open', pty_basic_test)
        self.assertIn('pty::ptsname_into', pty_basic_test)
        self.assertIn('crabc_rs_pty_basic_direct_probe', pty_basic_direct_probe)
        self.assertIn('PtyPair::open', pty_basic_direct_probe)
        self.assertIn('pty::ptsname_into', pty_basic_direct_probe)
        self.assertIn('x86_terminal_reference_probe.c', terminal_reference_runner)
        self.assertIn('kernel-termios=36/4@0,4,8,12,16,17', terminal_reference_runner)
        self.assertIn('raw+musl=pty-rawmode-termios-queue-exclusive-ttyname-session', terminal_reference_runner)
        self.assertIn('sizeof(struct kernel_termios_x86) == 36', terminal_reference_probe)
        self.assertIn('sizeof(struct termios) == 60', terminal_reference_probe)
        self.assertIn('NCCS == 32', terminal_reference_probe)
        self.assertIn('SYS_ioctl == 16', terminal_reference_probe)
        self.assertIn('SYS_setsid == 112', terminal_reference_probe)
        self.assertIn('compare_kernel_and_public', terminal_reference_probe)
        self.assertIn('make_kernel_raw', terminal_reference_probe)
        self.assertIn('terminal_session_child', terminal_reference_probe)
        self.assertIn(
            'x86_64_terminal_attributes_queue_special_codes_and_window_size_round_trip',
            terminal_test,
        )
        self.assertIn('x86_64_explicit_session_handoff_is_confined_to_a_child', terminal_test)
        self.assertIn('pair.establish_session_and_controlling_terminal(false)', terminal_test)
        self.assertIn('termios::ttyname_into', terminal_test)
        self.assertIn('raw.make_raw()', terminal_test)
        self.assertIn('changed.set_input_speed(0)', terminal_test)
        self.assertIn('crabc_rs_x86_64_terminal_direct_probe', terminal_direct_probe)
        self.assertIn('termios::tcgetattr', terminal_direct_probe)
        self.assertIn('termios::ioctl_tiocexcl', terminal_direct_probe)
        self.assertIn('changed.make_raw()', terminal_direct_probe)
        self.assertIn('changed.set_input_speed(0)', terminal_direct_probe)
        self.assertIn('pair.establish_session_and_controlling_terminal(false)', terminal_direct_probe)
        self.assertIn('x86_mqueue_reference_probe.c', mqueue_runner)
        self.assertIn('SYS_mq_open == 240', mqueue_probe)
        self.assertIn('SYS_mq_getsetattr == 245', mqueue_probe)
        self.assertIn('sizeof(struct mq_attr) == 64', mqueue_probe)
        self.assertIn('mq_unlink', mqueue_probe)
        self.assertIn('x86_64_ipc_owns_attributes_priorities_nonblocking_and_unlink_lifetime', ipc_test)
        self.assertIn('x86_64_ipc_uses_absolute_realtime_deadlines_and_validates_inputs', ipc_test)
        self.assertIn('crabc_rs_ipc_direct_probe', ipc_direct_probe)
        self.assertIn('x86_shm_reference_probe.c', shm_runner)
        self.assertIn('SYS_openat == 257', shm_probe)
        self.assertIn('SYS_unlinkat == 263', shm_probe)
        self.assertIn('O_CLOEXEC == 0x00080000', shm_probe)
        self.assertIn('O_NOFOLLOW', shm_probe)
        self.assertIn('O_NONBLOCK', shm_probe)
        self.assertIn('shm_open', shm_probe)
        self.assertIn('x86_64_shm_owns_cloexec_descriptors_and_unlink_after_open_lifetime', shm_test)
        self.assertIn('x86_64_shm_validates_posix_names_before_the_direct_syscall', shm_test)
        self.assertIn('crabc_rs_shm_direct_probe', shm_direct_probe)
        self.assertIn('x86_inotify_reference_probe.c', inotify_runner)
        self.assertIn('SYS_inotify_init1 == 294', inotify_probe)
        self.assertIn('SYS_inotify_add_watch == 254', inotify_probe)
        self.assertIn('SYS_inotify_rm_watch == 255', inotify_probe)
        self.assertIn('sizeof(struct inotify_event) == 16', inotify_probe)
        self.assertIn('IN_NONBLOCK == 0x00000800', inotify_probe)
        self.assertIn('x86_64_inotify_owns_nonblocking_cloexec_watches_and_byte_events', inotify_test)
        self.assertIn('x86_64_inotify_preserves_direct_validation_and_noalloc_path_boundaries', inotify_test)
        self.assertIn('crabc_rs_inotify_direct_probe', inotify_direct_probe)
        self.assertIn('x86_calendar_time_reference_probe.c', calendar_time_runner)
        self.assertIn('civil-time reference', calendar_time_runner)
        self.assertIn('run_musl_oracle.sh', calendar_time_runner)
        self.assertNotIn('-p crabc-libc', calendar_time_runner)
        self.assertIn(calendar_oracle, calendar_time_runner)
        self.assertIn(calendar_oracle, calendar_time_probe)
        self.assertIn('SYS_gettimeofday == 96', calendar_time_probe)
        self.assertIn('gmtime_r', calendar_time_probe)
        self.assertIn('timegm', calendar_time_probe)
        self.assertIn('setenv("TZ"', calendar_time_probe)
        self.assertIn('tzset();', calendar_time_probe)
        self.assertIn('x86_advanced_time_reference_probe.c', advanced_time_runner)
        self.assertIn('advanced-time reference', advanced_time_runner)
        self.assertIn('run_musl_oracle.sh', advanced_time_runner)
        self.assertNotIn('-p crabc-libc', advanced_time_runner)
        self.assertIn(advanced_time_oracle, advanced_time_runner)
        self.assertIn(advanced_time_oracle, advanced_time_probe)
        self.assertIn('SYS_timer_create == 222', advanced_time_probe)
        self.assertIn('SYS_clock_settime == 227', advanced_time_probe)
        self.assertIn('sizeof(struct sigevent) == 64', advanced_time_probe)
        self.assertIn('clock_getcpuclockid', advanced_time_probe)
        self.assertIn('INT_MAX - 1', advanced_time_probe)
        self.assertIn('SIGEV_NONE', advanced_time_probe)
        self.assertIn('forwarded_ignored_timer_settime_flags', advanced_time_probe)
        self.assertIn('0x00000004', advanced_time_probe)
        self.assertIn('INT_MIN', advanced_time_probe)
        self.assertIn('itimerspec_has_zero_interval', advanced_time_probe)
        self.assertIn('x86_64_advanced_clock_ids_are_validated_and_direct', advanced_time_test)
        self.assertIn('x86_64_clock_settime_preflights_and_never_mutates_realtime', advanced_time_test)
        self.assertIn('x86_64_posix_timer_owns_a_sigev_none_lifecycle', advanced_time_test)
        self.assertIn('TimerSetFlags::from_bits_retain(2)', advanced_time_test)
        self.assertIn('x86_socket_transport_reference_probe.c', socket_transport_runner)
        self.assertIn('SYS_accept4 == 288', socket_transport_probe)
        self.assertIn('SYS_accept == 43', socket_transport_probe)
        self.assertIn('SYS_ioctl == 16', socket_transport_probe)
        self.assertIn('SIOCATMARK', socket_transport_probe)
        self.assertIn('ipv6_case', socket_transport_probe)
        self.assertIn('raw_recvmmsg', socket_transport_probe)
        self.assertIn('socketpair_transports_vectored_bytes_and_shutdown_is_typed', socket_transport_test)
        self.assertIn('ipv6_datagram_round_trip_preserves_native_endpoint_encoding', socket_transport_test)
        self.assertIn('x86_interface_device_reference_probe.c', interface_device_runner)
        self.assertIn('sizeof(struct ifreq) == 40', interface_device_probe)
        self.assertIn('SIOCGIFNAME == 0x8910', interface_device_probe)
        self.assertIn('RTM_GETLINK == 18', interface_device_probe)
        self.assertIn('RTM_GETADDR == 22', interface_device_probe)
        self.assertIn('SYS_recvmsg == 47', interface_device_probe)
        self.assertIn('MSG_TRUNC == 0x20', interface_device_probe)
        self.assertIn('AF_INET6', interface_device_probe)
        self.assertIn('raw and musl loopback indexes agree', interface_device_probe)
        self.assertIn('x86_64_interface_names_are_owned_and_self_consistent', interface_device_test)
        self.assertIn('x86_64_interface_address_snapshot_keeps_the_two_netlink_phases_owned', interface_device_test)
        self.assertIn(
            'x86_64_udp_ignores_short_wrong_id_malformed_and_oversized_packets_before_an_answer',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_udp_truncation_retries_the_exact_query_over_partial_tcp',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_dns_response_rejects_an_out_of_bounds_compressed_record_owner',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_dns_response_rejects_a_compressed_record_owner_in_the_header',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_exchange_rejects_a_header_compression_pointer_in_the_caller_query',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_failed_first_nameserver_advances_in_configured_order',
            resolver_transport_test,
        )
        self.assertIn('x86_64_all_nameserver_failures_are_bounded', resolver_transport_test)
        self.assertIn(
            'x86_64_hosts_snapshot_is_owned_case_insensitive_and_precedes_dns',
            resolver_facade_test,
        )
        self.assertIn(
            'x86_64_resolver_search_cname_and_ptr_use_the_local_configured_server',
            resolver_facade_test,
        )
        self.assertIn(
            'x86_64_resolver_aaaa_and_timeout_map_through_the_facade',
            resolver_facade_test,
        )
        self.assertIn('crabc_rs_resolver_hosts_direct_probe', resolver_hosts_probe)
        self.assertNotIn('ServiceDatabase', resolver_hosts_probe)
        self.assertNotIn('ProtocolDatabase', resolver_hosts_probe)
        self.assertIn(
            'x86_64_hosts_snapshot_is_owned_and_system_loader_matches_direct_snapshot',
            netdb_test,
        )
        self.assertIn(
            'x86_64_service_and_protocol_snapshots_are_owned_typed_and_ordered',
            netdb_test,
        )
        self.assertIn(
            'x86_64_service_and_protocol_malformed_records_reject_the_complete_snapshot',
            netdb_test,
        )
        self.assertIn(
            'x86_64_service_and_protocol_system_loaders_match_direct_snapshots',
            netdb_test,
        )
        self.assertIn('crabc_rs_resolver_direct_probe', resolver_direct_probe)
        self.assertIn('ServiceDatabase::from_bytes', resolver_direct_probe)
        self.assertIn('ProtocolDatabase::from_bytes', resolver_direct_probe)
        self.assertIn('run_statat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_statat_reference.sh', source)
        self.assertIn('run_getcwd_reference()', source)
        self.assertIn('compat/x86_64/run_x86_getcwd_reference.sh', source)
        self.assertIn(
            '--no-default-features --features alloc --test x86_64_getcwd',
            source,
        )
        self.assertIn('--test x86_64_current_dir_name -- --test-threads=1', source)
        self.assertIn('run_readlinkat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_readlinkat_reference.sh', source)
        self.assertIn('run_access_reference()', source)
        self.assertIn('compat/x86_64/run_x86_access_reference.sh', source)
        self.assertIn('--test x86_64_access -- --test-threads=1', source)
        self.assertIn('run_rr_interval_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sched_rr_interval_reference.sh', source)
        self.assertIn('run_sched_affinity_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sched_affinity_reference.sh', source)
        self.assertIn('run_sched_affinity_set_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sched_setaffinity_reference.sh', source)
        self.assertIn('run_system_reference()', source)
        self.assertIn('compat/x86_64/run_x86_system_reference.sh', source)
        self.assertIn('run_thread_reference()', source)
        self.assertIn('compat/x86_64/run_x86_thread_reference.sh', source)
        self.assertIn('run_thread_credentials_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_thread_credentials_reference.sh',
            source,
        )
        self.assertIn('run_fs_credentials_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_fs_credentials_reference.sh',
            source,
        )
        self.assertIn('run_core_tests()', source)
        self.assertIn('CARGO_TARGET_DIR="$target_dir" cargo test --locked', source)
        self.assertIn('-p crabc-core --lib --no-default-features -- --test-threads=1', source)
        self.assertIn('objdump -d -- "$test_binary"', source)
        self.assertIn('fxrstor(64)?', source)
        self.assertIn(
            '-p crabc-rs --lib --no-default-features --test fenv --test futex --test x86_64_foundation',
            source,
        )
        self.assertIn('--test x86_64_eventfd', source)
        self.assertIn('--test x86_64_epoll', source)
        self.assertIn('--test x86_64_fcntl_getlk', source)
        self.assertIn('--test x86_64_fcntl_flags', source)
        self.assertIn('--test x86_64_flock', source)
        self.assertIn('--test x86_64_sendfile', source)
        self.assertIn('--test x86_64_copy_file_range', source)
        self.assertIn('--test x86_64_fs', source)
        self.assertIn('--test x86_64_fs_advice', source)
        self.assertIn('--test x86_64_file_position', source)
        self.assertIn('--test x86_64_sync', source)
        self.assertIn('--test x86_64_syncfs', source)
        self.assertIn('--test x86_64_sync_file_range', source)
        self.assertIn('--test x86_64_ftruncate', source)
        self.assertIn('--test x86_64_futimens', source)
        self.assertIn('--test x86_64_timestamp_paths', source)
        self.assertIn('--test x86_64_fs_credentials', source)
        self.assertIn('--test x86_64_memfd', source)
        self.assertIn('--test x86_64_getgroups', source)
        self.assertIn('--test x86_64_getitimer', source)
        self.assertIn('--test x86_64_setitimer', source)
        self.assertIn('--test x86_64_io', source)
        self.assertIn('--test x86_64_mm', source)
        self.assertIn('--test x86_64_memory_mapping', source)
        self.assertIn('--test x86_64_memory_vm', source)
        self.assertIn('--test x86_64_pty_basic', source)
        self.assertIn('--test x86_64_terminal', source)
        self.assertIn('--test x86_64_mount', source)
        self.assertIn('--test x86_64_param', source)
        self.assertIn('--test x86_64_pipe', source)
        self.assertIn('--test x86_64_poll', source)
        self.assertIn('--test x86_64_priority', source)
        self.assertIn('--test x86_64_setpriority', source)
        self.assertIn('--test x86_64_process_identity', source)
        self.assertIn('--test x86_64_child_ownership', source)
        self.assertIn('--test x86_64_process_session', source)
        self.assertIn('--test x86_64_pidfd_open', source)
        self.assertIn('--test x86_64_rand', source)
        self.assertIn('--test x86_64_rlimit', source)
        self.assertIn('--test x86_64_rlimit_targeted', source)
        self.assertIn('--test x86_64_setrlimit', source)
        self.assertIn('--test x86_64_umask', source)
        self.assertIn('--test x86_64_rusage', source)
        self.assertIn('--test x86_64_times', source)
        self.assertIn('--test x86_64_scheduler_priority_bounds', source)
        self.assertIn('--test x86_64_sleep', source)
        self.assertIn('--test x86_64_clock_nanosleep', source)
        self.assertIn('--test x86_64_statat', source)
        self.assertIn('--test x86_64_access', source)
        self.assertIn('--test x86_64_getcwd', source)
        self.assertIn('--test x86_64_current_dir_name', source)
        self.assertIn('--test x86_64_readlink', source)
        self.assertIn('--test x86_64_xattr', source)
        self.assertIn('--test x86_64_raw_directory', source)
        self.assertIn('--test x86_64_directory', source)
        self.assertIn('--test x86_64_directory_position', source)
        self.assertIn('--test x86_64_temporary_objects', source)
        self.assertIn('--test x86_64_statx', source)
        self.assertIn('--test x86_64_ipc', source)
        self.assertIn('--test x86_64_shm', source)
        self.assertIn('--test x86_64_inotify', source)
        self.assertIn('--test x86_64_sched_rr_interval', source)
        self.assertIn('--test x86_64_sched_affinity', source)
        self.assertIn('--test x86_64_sched_setaffinity', source)
        self.assertIn('--test x86_64_system', source)
        self.assertIn('--test x86_64_thread', source)
        self.assertIn('--test x86_64_thread_kill', source)
        self.assertIn('--test x86_64_thread_credentials', source)
        self.assertIn('--test x86_64_time', source)
        self.assertIn('--test time', source)
        self.assertIn('--test calendar_utc', source)
        self.assertIn('--test x86_64_calendar_time', source)
        self.assertIn('--test x86_64_advanced_time', source)
        self.assertIn('--test timezone_rules', source)
        self.assertIn('--test calendar_local', source)
        self.assertIn('--test x86_64_users_databases', source)
        self.assertIn('--test x86_64_timerfd', source)
        self.assertIn('--test x86_64_pselect', source)
        facade = source.split('    facade)\n', 1)[1].split('    libc-syscall)', 1)[0]
        self.assertIn('--test x86_64_rlimit_targeted', facade)
        self.assertIn('--test x86_64_child_ownership', facade)
        self.assertIn('run_in_chroot_cap_container cargo test', facade)
        self.assertIn('--test x86_64_chroot', facade)
        self.assertIn('--test x86_64_thread_kill', facade)
        self.assertIn('--test x86_64_memory_mapping', facade)
        self.assertIn('--test x86_64_memory_vm', facade)
        self.assertIn('--test x86_64_pty_basic', facade)
        self.assertIn('--test x86_64_terminal', facade)
        self.assertIn('--test x86_64_mount', facade)
        self.assertIn('--test x86_64_users_databases', facade)
        self.assertIn(
            '  facade-record-owning  run the closed native x86_64 record-owning facade aggregate',
            source,
        )
        self.assertIn(
            '    facade-record-owning)\n        [ "$#" -eq 0 ] || fail "facade-record-owning takes no arguments"',
            source,
        )
        aggregate = source.split('run_facade_record_owning() {\n', 1)[1].split(
            '\n}\n\nrun_relative_sleep_reference', 1
        )[0]
        self.assertEqual(
            [
                line.strip()
                for line in aggregate.splitlines()
                if line.strip().startswith('run_')
                and not line.strip().startswith('run_in_container')
            ],
            [
                'run_root_change_reference',
                'run_child_ownership_reference',
                'run_thread_kill_reference',
                'run_mapping_reference',
                'run_memory_vm_reference',
                'run_pty_basic_reference',
                'run_terminal_reference',
                'run_interface_device_reference',
                'run_resolver_transport_reference',
                'run_resolver_facade_reference',
                'run_netdb_reference',
                'run_users_databases_reference',
                'run_mount_reference',
                'run_path_core_reference',
                'run_xattr_reference',
                'run_directory_reference',
                'run_temporary_object_reference',
                'run_statx_reference',
                'run_cwd_canonicalize_reference',
                'run_ipc_reference',
                'run_shm_reference',
                'run_inotify_reference',
                'run_calendar_time_reference',
                'run_advanced_time_reference',
            ],
        )
        self.assertEqual(
            aggregate.count(
                'run_in_container cargo check --locked --target x86_64-unknown-linux-musl'
            ),
            2,
        )
        self.assertIn('-p crabc-rs --no-default-features\n', aggregate)
        self.assertIn('-p crabc-rs --no-default-features --features alloc', aggregate)
        self.assertIn('run_libc_syscall_probe()', source)
        self.assertIn('compat/x86_64/libc_syscall_probe.rs', source)
        self.assertIn('run_libc_errno_tls_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_errno_tls.sh', source)
        self.assertIn('run_libc_stat_compat_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_stat_compat.sh', source)
        self.assertIn('run_libc_credentials_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_credentials.sh', source)
        self.assertIn('run_libc_bootstrap_primitives_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_bootstrap_primitives.sh', source
        )
        self.assertIn(
            '    libc-credentials)\n        [ "$#" -eq 0 ] || fail "libc-credentials takes no arguments"',
            source,
        )
        self.assertIn(
            '    libc-bootstrap-primitives)\n        [ "$#" -eq 0 ] || fail "libc-bootstrap-primitives takes no arguments"',
            source,
        )
        self.assertIn('run_libc_signal_control_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_signal_control.sh', source
        )
        self.assertIn(
            '    libc-signal-control)\n        [ "$#" -eq 0 ] || fail "libc-signal-control takes no arguments"',
            source,
        )
        self.assertIn('run_libc_signal_execution_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_signal_execution.sh', source
        )
        self.assertIn(
            '    libc-signal-execution)\n        [ "$#" -eq 0 ] || fail "libc-signal-execution takes no arguments"',
            source,
        )
        self.assertIn('run_libc_sigpause_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_sigpause.sh', source)
        self.assertIn(
            '    libc-sigpause)\n        [ "$#" -eq 0 ] || fail "libc-sigpause takes no arguments"',
            source,
        )
        self.assertIn('run_libc_static_tls_v1_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_static_tls_v1.sh', source
        )
        self.assertIn(
            '    libc-static-tls-v1)\n        [ "$#" -eq 0 ] || fail "libc-static-tls-v1 takes no arguments"',
            source,
        )
        self.assertIn('run_libc_crt_static_tls_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_crt_static_tls.sh', source
        )
        self.assertIn(
            '    libc-crt-static-tls)\n        [ "$#" -eq 0 ] || fail "libc-crt-static-tls takes no arguments"',
            source,
        )
        self.assertIn('run_libc_pthread_create_join_tls_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_pthread_create_join_tls.sh', source
        )
        self.assertIn(
            '    libc-pthread-create-join-tls)\n        [ "$#" -eq 0 ] || fail "libc-pthread-create-join-tls takes no arguments"',
            source,
        )
        self.assertIn('run_libc_termios_control_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_termios_control.sh', source
        )
        self.assertIn(
            '    libc-termios-control)\n        [ "$#" -eq 0 ] || fail "libc-termios-control takes no arguments"',
            source,
        )
        self.assertIn('run_ctermid_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_ctermid_header_abi.sh', source
        )
        self.assertIn('run_libc_ctermid_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_ctermid.sh', source
        )
        self.assertIn(
            '    libc-ctermid)\n        [ "$#" -eq 0 ] || fail "libc-ctermid takes no arguments"',
            source,
        )
        self.assertIn('run_grantpt_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_grantpt_header_abi.sh', source
        )
        self.assertIn('run_libc_grantpt_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_grantpt.sh', source
        )
        self.assertIn(
            '    libc-grantpt)\n        [ "$#" -eq 0 ] || fail "libc-grantpt takes no arguments"',
            source,
        )
        self.assertIn('run_isatty_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_isatty_header_abi.sh', source
        )
        self.assertIn('run_libc_isatty_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_isatty.sh', source
        )
        self.assertIn(
            '    libc-isatty)\n        [ "$#" -eq 0 ] || fail "libc-isatty takes no arguments"',
            source,
        )
        self.assertIn('run_ttyname_r_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_ttyname_r_header_abi.sh', source
        )
        self.assertIn('run_libc_ttyname_r_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_ttyname_r.sh', source
        )
        self.assertIn(
            '    libc-ttyname-r)\n        [ "$#" -eq 0 ] || fail "libc-ttyname-r takes no arguments"',
            source,
        )
        self.assertIn('run_tcgetpgrp_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_tcgetpgrp_header_abi.sh', source
        )
        self.assertIn('run_libc_tcgetpgrp_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_tcgetpgrp.sh', source
        )
        self.assertIn(
            '    libc-tcgetpgrp)\n        [ "$#" -eq 0 ] || fail "libc-tcgetpgrp takes no arguments"',
            source,
        )
        self.assertIn('run_tcsetpgrp_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_tcsetpgrp_header_abi.sh', source
        )
        self.assertIn('run_libc_tcsetpgrp_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_tcsetpgrp.sh', source
        )
        self.assertIn(
            '    libc-tcsetpgrp)\n        [ "$#" -eq 0 ] || fail "libc-tcsetpgrp takes no arguments"',
            source,
        )
        self.assertIn('run_getpass_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_getpass_header_abi.sh', source
        )
        self.assertIn('run_libc_getpass_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_getpass.sh', source
        )
        self.assertIn(
            '    libc-getpass)\n        [ "$#" -eq 0 ] || fail "libc-getpass takes no arguments"',
            source,
        )
        self.assertIn('run_mktemp_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_mktemp_header_abi.sh', source
        )
        self.assertIn('run_libc_mktemp_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_mktemp.sh', source
        )
        self.assertIn(
            '    libc-mktemp)\n        [ "$#" -eq 0 ] || fail "libc-mktemp takes no arguments"',
            source,
        )
        self.assertIn('run_temporary_names_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_temporary_names_header_abi.sh',
            source,
        )
        self.assertIn(
            '    temporary-names-header-abi)\n        [ "$#" -eq 0 ] || fail "temporary-names-header-abi takes no arguments"',
            source,
        )
        self.assertIn('run_libc_temporary_names_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_temporary_names.sh',
            source,
        )
        self.assertIn(
            '    libc-temporary-names)\n        [ "$#" -eq 0 ] || fail "libc-temporary-names takes no arguments"',
            source,
        )
        self.assertIn('run_file_handles_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_file_handles_header_abi.sh', source
        )
        self.assertIn('run_libc_file_handles_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_file_handles.sh', source
        )
        self.assertIn(
            '    libc-file-handles)\n        [ "$#" -eq 0 ] || fail "libc-file-handles takes no arguments"',
            source,
        )
        self.assertIn('run_posix_spawn_file_actions_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_posix_spawn_file_actions_header_abi.sh',
            source,
        )
        self.assertIn('run_libc_posix_spawn_file_actions()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_posix_spawn_file_actions.sh',
            source,
        )
        self.assertIn(
            '    libc-posix-spawn-file-actions)\n        [ "$#" -eq 0 ] || fail "libc-posix-spawn-file-actions takes no arguments"',
            source,
        )
        self.assertIn('run_libc_process_context_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_process_context.sh', source
        )
        self.assertIn(
            '    libc-process-context)\n        [ "$#" -eq 0 ] || fail "libc-process-context takes no arguments"',
            source,
        )
        self.assertIn('run_libc_environment_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_environment.sh', source
        )
        self.assertIn(
            '    libc-environment)\n        [ "$#" -eq 0 ] || fail "libc-environment takes no arguments"',
            source,
        )
        self.assertIn('run_libc_secure_environment_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_secure_environment.sh', source
        )
        self.assertIn(
            '    libc-secure-environment)\n        [ "$#" -eq 0 ] || fail "libc-secure-environment takes no arguments"',
            source,
        )
        self.assertIn('run_libc_descriptor_io_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_descriptor_io.sh', source
        )
        self.assertIn(
            '    libc-descriptor-io)\n        [ "$#" -eq 0 ] || fail "libc-descriptor-io takes no arguments"',
            source,
        )
        self.assertIn('run_libc_descriptor_lifecycle_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_descriptor_lifecycle.sh', source
        )
        self.assertIn(
            '    libc-descriptor-lifecycle)\n        [ "$#" -eq 0 ] || fail "libc-descriptor-lifecycle takes no arguments"',
            source,
        )
        self.assertIn('run_libc_process_resources_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_process_resources.sh', source
        )
        self.assertIn(
            '    libc-process-resources)\n        [ "$#" -eq 0 ] || fail "libc-process-resources takes no arguments"',
            source,
        )
        self.assertIn('run_libc_sched_yield_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_sched_yield.sh', source)
        self.assertIn(
            '    libc-sched-yield)\n        [ "$#" -eq 0 ] || fail "libc-sched-yield takes no arguments"',
            source,
        )
        self.assertIn('run_libc_readiness_waits_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_readiness_waits.sh', source
        )
        self.assertIn(
            '    libc-readiness-waits)\n        [ "$#" -eq 0 ] || fail "libc-readiness-waits takes no arguments"',
            source,
        )
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_libc_socket_transport.sh',
            source,
        )
        self.assertIn(
            '    libc-socket-transport)\n        [ "$#" -eq 0 ] || fail "libc-socket-transport takes no arguments"',
            source,
        )
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_libc_socket_messages.sh',
            source,
        )
        self.assertIn(
            '    libc-socket-messages)\n        [ "$#" -eq 0 ] || fail "libc-socket-messages takes no arguments"',
            source,
        )
        self.assertIn('run_libc_system_observation_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_system_observation.sh', source
        )
        self.assertIn(
            '    libc-system-observation)\n        [ "$#" -eq 0 ] || fail "libc-system-observation takes no arguments"',
            source,
        )
        self.assertIn('run_libc_uts_identity_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_uts_identity.sh', source)
        self.assertIn('run_in_uts_cap_container()', source)
        self.assertIn('--cap-add=SYS_ADMIN', source)
        self.assertIn(
            '    libc-uts-identity)\n        [ "$#" -eq 0 ] || fail "libc-uts-identity takes no arguments"',
            source,
        )
        self.assertIn('libc-ctype', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_ctype.sh', source)
        self.assertIn(
            '    libc-ctype)\n        [ "$#" -eq 0 ] || fail "libc-ctype takes no arguments"',
            source,
        )
        self.assertIn('libc-integer-arithmetic', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_integer_arithmetic.sh', source,
        )
        self.assertIn(
            '    libc-integer-arithmetic)\n        [ "$#" -eq 0 ] || fail "libc-integer-arithmetic takes no arguments"',
            source,
        )
        self.assertIn('integer-parse-header-abi', source)
        self.assertIn('run_integer_parse_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_integer_parse_header_abi.sh', source,
        )
        self.assertIn(
            '    integer-parse-header-abi)\n        [ "$#" -eq 0 ] || fail "integer-parse-header-abi takes no arguments"',
            source,
        )
        self.assertIn('libc-integer-parse', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_integer_parse.sh', source,
        )
        self.assertIn(
            '    libc-integer-parse)\n        [ "$#" -eq 0 ] || fail "libc-integer-parse takes no arguments"',
            source,
        )
        self.assertIn('float-parse-header-abi', source)
        self.assertIn('run_float_parse_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_float_parse_header_abi.sh', source,
        )
        self.assertIn(
            '    float-parse-header-abi)\n        [ "$#" -eq 0 ] || fail "float-parse-header-abi takes no arguments"',
            source,
        )
        self.assertIn('libc-float-parse', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_float_parse.sh', source,
        )
        self.assertIn(
            '    libc-float-parse)\n        [ "$#" -eq 0 ] || fail "libc-float-parse takes no arguments"',
            source,
        )
        self.assertIn('getsubopt-header-abi', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_getsubopt_header_abi.sh', source,
        )
        self.assertIn(
            '    getsubopt-header-abi)\n        [ "$#" -eq 0 ] || fail "getsubopt-header-abi takes no arguments"',
            source,
        )
        self.assertIn('libc-getsubopt', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_getsubopt.sh', source,
        )
        self.assertIn(
            '    libc-getsubopt)\n        [ "$#" -eq 0 ] || fail "libc-getsubopt takes no arguments"',
            source,
        )
        self.assertIn('libc-credential-observation', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_credential_observation.sh', source,
        )
        self.assertIn(
            '    libc-credential-observation)\n        [ "$#" -eq 0 ] || fail "libc-credential-observation takes no arguments"',
            source,
        )
        self.assertIn('libc-ffs', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_ffs.sh', source)
        self.assertIn(
            '    libc-ffs)\n        [ "$#" -eq 0 ] || fail "libc-ffs takes no arguments"',
            source,
        )
        self.assertIn('libc-byte-strings', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_byte_strings.sh', source)
        self.assertIn(
            '    libc-byte-strings)\n        [ "$#" -eq 0 ] || fail "libc-byte-strings takes no arguments"',
            source,
        )
        self.assertIn('run_libc_legacy_memory()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_legacy_memory.sh', source
        )
        self.assertIn(
            '    libc-legacy-memory)\n        [ "$#" -eq 0 ] || fail "libc-legacy-memory takes no arguments"',
            source,
        )
        self.assertIn('run_libc_memccpy()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_memccpy.sh', source)
        self.assertIn(
            '    libc-memccpy)\n        [ "$#" -eq 0 ] || fail "libc-memccpy takes no arguments"',
            source,
        )
        self.assertIn('run_libc_rand_r()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_rand_r.sh', source)
        self.assertIn(
            '    libc-rand-r)\n        [ "$#" -eq 0 ] || fail "libc-rand-r takes no arguments"',
            source,
        )
        self.assertIn('libc-random-entropy', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_random_entropy.sh', source)
        self.assertIn(
            '    libc-random-entropy)\n        [ "$#" -eq 0 ] || fail "libc-random-entropy takes no arguments"',
            source,
        )
        self.assertIn('libc-memory-search', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_memory_search.sh', source)
        self.assertIn(
            '    libc-memory-search)\n        [ "$#" -eq 0 ] || fail "libc-memory-search takes no arguments"',
            source,
        )
        self.assertIn('libc-string-copy', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_string_copy.sh', source)
        self.assertIn(
            '    libc-string-copy)\n        [ "$#" -eq 0 ] || fail "libc-string-copy takes no arguments"',
            source,
        )
        self.assertIn('libc-allocator-string-duplication', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_allocator_string_duplication.sh',
            source,
        )
        self.assertIn(
            '    libc-allocator-string-duplication)\n        [ "$#" -eq 0 ] || fail "libc-allocator-string-duplication takes no arguments"',
            source,
        )
        self.assertIn('string-duplication-header-abi', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_string_duplication_header_abi.sh',
            source,
        )
        self.assertIn('run_libc_thread_pointer_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_thread_pointer.sh', source)
        self.assertIn('run_libc_foundation_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_foundation.sh', source)
        self.assertIn('run_libc_fenv_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_fenv.sh', source)
        self.assertIn('run_libc_math_complex_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_math_complex.sh', source)
        self.assertIn('run_libc_elementary_sqrt_fenv_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_elementary_sqrt_fenv.sh', source
        )
        self.assertIn('run_libc_fenv_rounding_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_fenv_rounding.sh', source)
        self.assertIn('run_libc_math_x87_extended_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_math_x87_extended.sh', source)
        self.assertIn(
            '    libc-math-x87-extended)\n        [ "$#" -eq 0 ] || fail "libc-math-x87-extended takes no arguments"',
            source,
        )
        self.assertIn('run_math_special_header_abi()', source)
        self.assertIn('/workspace/compat/x86_64/run_math_special_header_abi.sh', source)
        self.assertIn(
            '    math-special-header-abi)\n        [ "$#" -eq 0 ] || fail "math-special-header-abi takes no arguments"',
            source,
        )
        self.assertIn('run_libc_math_special_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_math_special.sh', source)
        self.assertIn(
            '    libc-math-special)\n        [ "$#" -eq 0 ] || fail "libc-math-special takes no arguments"',
            source,
        )
        self.assertIn('run_math_complex_complete_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_math_complex_complete_header_abi.sh',
            source,
        )
        self.assertIn(
            '    math-complex-complete-header-abi)\n        [ "$#" -eq 0 ] || fail "math-complex-complete-header-abi takes no arguments"',
            source,
        )
        self.assertIn('run_libc_math_complex_complete_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_math_complex_complete.sh',
            source,
        )
        self.assertIn(
            '    libc-math-complex-complete)\n        [ "$#" -eq 0 ] || fail "libc-math-complex-complete takes no arguments"',
            source,
        )
        self.assertIn('run_math_elementary_long_double_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_math_elementary_long_double_header_abi.sh',
            source,
        )
        self.assertIn(
            '    math-elementary-long-double-header-abi)\n        [ "$#" -eq 0 ] || fail "math-elementary-long-double-header-abi takes no arguments"',
            source,
        )
        self.assertIn('run_libc_math_elementary_long_double_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_math_elementary_long_double.sh',
            source,
        )
        self.assertIn(
            '    libc-math-elementary-long-double)\n        [ "$#" -eq 0 ] || fail "libc-math-elementary-long-double takes no arguments"',
            source,
        )
        self.assertIn('run_libc_memory_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_memory.sh', source)
        self.assertIn('run_libc_setjmp_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_setjmp.sh', source)
        self.assertIn('run_libc_atomic_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_atomic.sh', source)
        self.assertIn('run_libc_clone_raw_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_clone_raw.sh', source)
        self.assertIn('run_libc_signal_foundation_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_signal_foundation.sh', source)
        self.assertIn('run_ldso_relocation_tests()', source)
        self.assertIn('ldso/src/x86_64_relocation.rs', source)
        self.assertIn('rustup run "$(python3 /workspace/scripts/rust_toolchain.py)" rustc --edition=2021 --test', source)
        self.assertIn('run_ldso_image_tests()', source)
        self.assertIn('/workspace/ldso/run-x86_64-image.sh test', source)
        self.assertIn('run_ldso_initial_graph_tests()', source)
        self.assertIn('/workspace/compat/x86_64/run_ldso_initial_graph.sh', source)
        self.assertIn('run_ldso_initial_tls_tests()', source)
        self.assertIn('/workspace/compat/x86_64/run_ldso_initial_tls.sh', source)
        self.assertIn('run_ldso_owned_crt_handoff_tests()', source)
        self.assertIn('/workspace/compat/x86_64/run_ldso_owned_crt_handoff.sh', source)
        self.assertIn('run_ldso_dynamic_admission_tests()', source)
        self.assertIn('/workspace/compat/x86_64/run_ldso_dynamic_admission.sh', source)
        self.assertNotIn('"$ROOT_DIR/compat/allocator/run-x86_64.sh"', source)
        self.assertNotIn('cargo "$@"', source)
        self.assertNotIn('-p crabc-ldso', source)

    def test_x86_parity_ledger_is_a_required_contract_check(self) -> None:
        validator = ROOT / "compat" / "x86_64" / "validate_parity_ledger.py"
        completed = subprocess.run(
            [sys.executable, str(validator), "--check"],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("x86 parity ledger: PASS", completed.stdout)

    def test_libc_static_c_abi_timerfd_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        timerfd = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "timer_fd.rs"
        ).read_text(encoding="utf-8")
        header_c_path = ROOT / "compat" / "x86_64" / "timerfd_header_abi_probe.c"
        header_cxx_path = ROOT / "compat" / "x86_64" / "timerfd_header_abi_probe.cpp"
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_timerfd_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_timerfd_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_timerfd_start.S"
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_timerfd.sh"
        for path in (
            header_c_path,
            header_cxx_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing timerfd input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        header_c = header_c_path.read_text(encoding="utf-8")
        header_cxx = header_cxx_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        timerfd_header = (ROOT / "include" / "sys" / "timerfd.h").read_text(
            encoding="utf-8"
        )
        time_header = (ROOT / "include" / "time.h").read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "timer_fd.rs"]', static_root)
        for required in (
            "src/linux/timerfd.c",
            "PublicTimespec",
            "PublicItimerspec",
            "size_of::<PublicItimerspec>() == 32",
            "align_of::<PublicItimerspec>() == 8",
            "offset_of!(PublicItimerspec, value) == 16",
            "raw_syscall::SYS_TIMERFD_CREATE",
            "raw_syscall::SYS_TIMERFD_SETTIME",
            "raw_syscall::SYS_TIMERFD_GETTIME",
            "raw_syscall::syscall4(",
            'pub unsafe extern "C" fn timerfd_settime',
            "c_status",
        ):
            self.assertIn(required, timerfd)
        for forbidden in ("timer_create(", "signalfd(", "pthread_", "epoll_", "eventfd"):
            self.assertNotIn(forbidden, timerfd)

        for header_source in (header_c, header_cxx):
            for required in (
                "sys/timerfd.h",
                "TFD_NONBLOCK",
                "TFD_CLOEXEC",
                "TFD_TIMER_ABSTIME",
                "TFD_TIMER_CANCEL_ON_SET",
                "itimerspec",
                "timerfd_create",
                "timerfd_settime",
                "timerfd_gettime",
            ):
                self.assertIn(required, header_source)
        for required in (
            "struct itimerspec;",
            "timerfd_create",
            "timerfd_settime",
            "timerfd_gettime",
        ):
            self.assertIn(required, timerfd_header)
        self.assertIn("struct itimerspec", time_header)
        for required in (
            "c11-strict",
            "c11-posix-2008",
            "cxx17-strict",
            '"$rows" -eq 16',
            "-nostdinc",
            "-nostdinc++",
            "unmangled ${symbol}",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "sizeof(struct itimerspec) == 32",
            "SYS_timerfd_create == 283",
            "SYS_timerfd_settime == 286",
            "SYS_timerfd_gettime == 287",
            "test_create_and_control",
            "test_realtime_cancel_on_set_flag",
            "poll(&ready, 1, 1000)",
            "CRABC_TIMERFD_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_timerfd_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_timerfd_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "timer_create timer_delete timer_getoverrun timer_gettime timer_settime",
            "assert_named_syscall timerfd_create 11b",
            "assert_named_syscall timerfd_settime 11e",
            "assert_named_syscall timerfd_gettime 11f",
            "timerfd_settime lacks fourth-argument r10 path",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("timerfd_create", "timerfd_settime", "timerfd_gettime"):
            self.assertIn(symbol, static_exports)
        self.assertIn('id = "static-c-timerfd"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-timerfd"', parity_ledger
        )
        self.assertIn("run_timerfd_header_abi()", dispatcher)
        self.assertIn("run_libc_timerfd_probe()", dispatcher)
        self.assertIn("timerfd-header-abi)", dispatcher)
        self.assertIn("libc-timerfd)", dispatcher)

    def test_libc_static_c_abi_signalfd_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        signalfd = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_fd.rs"
        ).read_text(encoding="utf-8")
        header_c_path = ROOT / "compat" / "x86_64" / "signalfd_header_abi_probe.c"
        header_cxx_path = (
            ROOT / "compat" / "x86_64" / "signalfd_header_abi_probe.cpp"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_signalfd_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_signalfd_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_signalfd_start.S"
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_signalfd.sh"
        for path in (
            header_c_path,
            header_cxx_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing signalfd input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        header_c = header_c_path.read_text(encoding="utf-8")
        header_cxx = header_cxx_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        signalfd_header = (ROOT / "include" / "sys" / "signalfd.h").read_text(
            encoding="utf-8"
        )
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_fd.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 signalfd C boundary",
            "src/linux/signalfd.c",
            "KERNEL_SIGSET_SIZE",
            "raw_syscall::SYS_SIGNALFD4",
            "raw_syscall::syscall4(",
            'pub unsafe extern "C" fn signalfd',
            "c_status",
        ):
            self.assertIn(required, signalfd)
        for forbidden in (
            "sigprocmask(",
            "sigaction(",
            "timerfd_",
            "epoll_",
            "eventfd",
            "pthread_",
        ):
            self.assertNotIn(forbidden, signalfd)

        for header_source in (header_c, header_cxx):
            for required in (
                "sys/signalfd.h",
                "SFD_NONBLOCK",
                "SFD_CLOEXEC",
                "signalfd_siginfo",
                "signalfd",
                "ssi_signo",
                "ssi_arch",
            ):
                self.assertIn(required, header_source)
        for required in ("SFD_CLOEXEC", "SFD_NONBLOCK", "signalfd", "ssi_arch"):
            self.assertIn(required, signalfd_header)
        for required in (
            "c11-strict",
            "c11-posix-2008",
            "cxx17-strict",
            '"$rows" -eq 16',
            "-nostdinc",
            "-nostdinc++",
            "unmangled ${symbol}",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "sizeof(struct signalfd_siginfo) == 128",
            "SYS_signalfd4 == 289",
            "test_create_read_and_update",
            "SFD_NONBLOCK | SFD_CLOEXEC",
            "CRABC_SIGNALFD_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_signalfd_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        for required in (
            "run_musl_oracle.sh",
            "run_signalfd_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall signalfd 121",
            "signalfd lacks fourth-argument r10 path",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("signalfd", static_exports)
        self.assertNotIn("signalfd4", static_exports)
        self.assertIn('id = "static-c-signalfd"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-signalfd"', parity_ledger
        )
        self.assertIn("run_signalfd_header_abi()", dispatcher)
        self.assertIn("run_libc_signalfd_probe()", dispatcher)
        self.assertIn("signalfd-header-abi)", dispatcher)
        self.assertIn("libc-signalfd)", dispatcher)

    def test_libc_static_c_abi_sigisemptyset_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_set_isempty.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sigisemptyset_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sigisemptyset_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sigisemptyset.sh"
        )
        for path in (source_path, probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing sigisemptyset input: {path}")
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        signal_header_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_set_isempty.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 GNU `sigisemptyset` C boundary",
            "src/signal/sigisemptyset.c",
            "SST_SIZE",
            "pub unsafe extern \"C\" fn sigisemptyset",
            "read_unaligned",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "raw_syscall",
            "errno",
            "sigaction",
            "sigprocmask",
            "pthread_",
            "signalfd",
            "timerfd",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "sigisemptyset(&tail_only)",
            "sigisemptyset(&first_word)",
            "tail-only",
            "errno = ERANGE",
            "CRABC_SIGISEMPTYSET_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sigisemptyset_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "--disassemble=sigisemptyset",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sigisemptyset", static_exports)
        self.assertIn("__typeof__(&sigisemptyset)", signal_header_probe)
        self.assertIn('id = "static-c-sigisemptyset"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sigisemptyset"', parity_ledger
        )
        self.assertIn("run_libc_sigisemptyset_probe()", dispatcher)
        self.assertIn("libc-sigisemptyset)", dispatcher)

    def test_libc_static_c_abi_sigandset_sigorset_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_set_binary.rs"
        )
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_sigandset_sigorset_probe.c"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_sigandset_sigorset_start.S"
        )
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "signal_set_binary_header_abi_probe.cpp"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sigandset_sigorset.sh"
        )
        for path in (
            source_path,
            probe_path,
            start_path,
            cxx_header_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing signal-set binary input: {path}")
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        signal_header_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_set_binary.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 GNU `sigandset`/`sigorset` C boundary",
            "src/signal/sigandset.c",
            "src/signal/sigorset.c",
            "SST_SIZE",
            'pub unsafe extern "C" fn sigandset',
            'pub unsafe extern "C" fn sigorset',
            "read_unaligned",
            "write_unaligned",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "raw_syscall",
            "errno",
            "sigaction",
            "sigprocmask",
            "pthread_",
            "signalfd",
            "timerfd",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "sigandset(&and_dest",
            "sigorset(&or_dest",
            "sigandset(&and_left_alias",
            "sigorset(&or_right_alias",
            "tail sentinel",
            "errno = ERANGE",
            "CRABC_SIGANDSET_SIGORSET_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sigandset_sigorset_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        for required in (
            "decltype(&sigandset)",
            "decltype(&sigorset)",
            "CRABC_REQUIRE_GNU_SIGNAL_SET_BINARY_HIDDEN",
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "C++",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "--disassemble=sigandset",
            "--disassemble=sigorset",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sigandset", static_exports)
        self.assertIn("sigorset", static_exports)
        self.assertIn("__typeof__(&sigandset)", signal_header_probe)
        self.assertIn("__typeof__(&sigorset)", signal_header_probe)
        self.assertIn('id = "static-c-sigandset-sigorset"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sigandset-sigorset"',
            parity_ledger,
        )
        self.assertIn("run_libc_sigandset_sigorset_probe()", dispatcher)
        self.assertIn("libc-sigandset-sigorset)", dispatcher)

    def test_libc_static_c_abi_sigset_mutation_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_set_mutation.rs"
        )
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_sigaddset_sigdelset_sigfillset_probe.c"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_sigaddset_sigdelset_sigfillset_start.S"
        )
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "signal_set_mutation_header_abi_probe.cpp"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sigaddset_sigdelset_sigfillset.sh"
        )
        for path in (
            source_path,
            probe_path,
            start_path,
            cxx_header_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing signal-set mutation input: {path}")
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        signal_header_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        signal_header_posix_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_posix_abi_probe.c"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_set_mutation.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 POSIX signal-set mutation C boundary",
            "src/signal/sigaddset.c",
            "src/signal/sigdelset.c",
            "src/signal/sigfillset.c",
            "SST_SIZE",
            'pub unsafe extern "C" fn sigaddset',
            'pub unsafe extern "C" fn sigdelset',
            'pub unsafe extern "C" fn sigfillset',
            "read_unaligned",
            "write_unaligned",
            "errno::set_errno",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "raw_syscall",
            "sigaction",
            "sigprocmask",
            "pthread_",
            "signalfd",
            "timerfd",
            "sigpending",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "sigfillset(&filled)",
            "sigaddset(&added, SIGUSR1)",
            "sigdelset(&deleted, SIGUSR2)",
            "SIGRTMIN - 3",
            "tail sentinel",
            "errno = ERANGE",
            "CRABC_SIGSET_MUTATION_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sigset_mutation_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        for required in (
            "decltype(&sigaddset)",
            "decltype(&sigdelset)",
            "decltype(&sigfillset)",
            "CRABC_EXPECT_POSIX_SIGNAL_SET_MUTATION",
        ):
            self.assertIn(required, cxx_header)
        for signal_header in (signal_header_probe, signal_header_posix_probe):
            for signature in (
                "__typeof__(&sigaddset)",
                "__typeof__(&sigdelset)",
                "__typeof__(&sigfillset)",
            ):
                self.assertIn(signature, signal_header)
        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "C++ POSIX/GNU feature matrix",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "for symbol in sigaddset sigdelset sigfillset; do",
            '--disassemble="$symbol"',
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("sigaddset", "sigdelset", "sigfillset"):
            self.assertIn(symbol, static_exports)
        self.assertIn('id = "static-c-sigset-mutation"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sigaddset-sigdelset-sigfillset"',
            parity_ledger,
        )
        self.assertIn("run_libc_sigset_mutation_probe()", dispatcher)
        self.assertIn("libc-sigaddset-sigdelset-sigfillset)", dispatcher)

    def test_libc_static_c_abi_sigrtmax_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        signal_control_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_control.rs"
        )
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_realtime_max.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sigrtmax_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sigrtmax_start.S"
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sigrtmax_header_abi_probe.cpp"
        )
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_sigrtmax.sh"
        for path in (
            source_path,
            probe_path,
            start_path,
            cxx_header_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing sigrtmax input: {path}")
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        signal_control = signal_control_path.read_text(encoding="utf-8")
        source = source_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        signal_header_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        signal_header_posix_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_posix_abi_probe.c"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_realtime_max.rs"]', static_root)
        self.assertNotIn("fn __libc_current_sigrtmax(", signal_control)
        for required in (
            "Selected static Linux/x86-64 realtime signal maximum C ABI boundary",
            "src/signal/sigrtmax.c",
            "_NSIG-1",
            "X86_NSIG",
            'pub extern "C" fn __libc_current_sigrtmax() -> c_int',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "raw_syscall",
            "errno",
            "sigaction",
            "sigprocmask",
            "sigpending",
            "sigwait",
            "signalfd",
            "timerfd",
            "pthread_",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "__libc_current_sigrtmax()",
            "SIGRTMAX",
            "errno = ERANGE",
            "CRABC_SIGRTMAX_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sigrtmax_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        for required in (
            "decltype(&__libc_current_sigrtmax)",
            "SIGRTMAX",
            "CRABC_EXPECT_SIGRTMAX",
        ):
            self.assertIn(required, cxx_header)
        for signal_header in (signal_header_probe, signal_header_posix_probe):
            self.assertIn("__typeof__(&__libc_current_sigrtmax)", signal_header)

        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "C++ POSIX/GNU feature matrix",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            '--disassemble="__libc_current_sigrtmax"',
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("__libc_current_sigrtmax", static_exports)
        self.assertIn('id = "static-c-sigrtmax"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sigrtmax"', parity_ledger
        )
        self.assertIn("run_libc_sigrtmax_probe()", dispatcher)
        self.assertIn("libc-sigrtmax)", dispatcher)

    def test_libc_static_c_abi_sigrtmin_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_realtime_min.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sigrtmin_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sigrtmin_start.S"
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sigrtmin_header_abi_probe.cpp"
        )
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_sigrtmin.sh"
        for path in (
            source_path,
            probe_path,
            start_path,
            cxx_header_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing sigrtmin input: {path}")
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        signal_header_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        signal_header_posix_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_posix_abi_probe.c"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_realtime_min.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 realtime signal minimum C ABI boundary",
            "src/signal/sigrtmin.c",
            "X86_SIGRTMIN",
            'pub extern "C" fn __libc_current_sigrtmin() -> c_int',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "raw_syscall",
            "errno",
            "sigaction",
            "sigprocmask",
            "sigpending",
            "sigwait",
            "signalfd",
            "timerfd",
            "pthread_",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "__libc_current_sigrtmin()",
            "SIGRTMIN",
            "errno = ERANGE",
            "CRABC_SIGRTMIN_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sigrtmin_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        for required in (
            "decltype(&__libc_current_sigrtmin)",
            "SIGRTMIN",
            "CRABC_EXPECT_SIGRTMIN",
        ):
            self.assertIn(required, cxx_header)
        for signal_header in (signal_header_probe, signal_header_posix_probe):
            self.assertIn("__typeof__(&__libc_current_sigrtmin)", signal_header)

        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "C++ POSIX/GNU feature matrix",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            '--disassemble="__libc_current_sigrtmin"',
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("__libc_current_sigrtmin", static_exports)
        self.assertIn('id = "static-c-sigrtmin"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sigrtmin"', parity_ledger
        )
        self.assertIn("run_libc_sigrtmin_probe()", dispatcher)
        self.assertIn("libc-sigrtmin)", dispatcher)

    def test_libc_static_c_abi_sched_getscheduler_artifact_stays_musl_enosys(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_getscheduler.rs"
        )
        c_header_path = (
            ROOT / "compat" / "x86_64" / "sched_getscheduler_header_abi_probe.c"
        )
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sched_getscheduler_header_abi_probe.cpp"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_sched_getscheduler_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sched_getscheduler_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sched_getscheduler_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sched_getscheduler.sh"
        )
        process_resources_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_process_resources.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing sched_getscheduler input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        process_resources_runner = process_resources_runner_path.read_text(
            encoding="utf-8"
        )
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "sched_getscheduler.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static POSIX scheduler-policy observation boundary",
            "src/sched/sched_getscheduler.c::sched_getscheduler",
            "__syscall_ret(-ENOSYS)",
            "raw syscall `sched_getscheduler=145`",
            "c_status(-ENOSYS)",
            'pub extern "C" fn sched_getscheduler(_pid: c_int) -> c_int',
        ):
            self.assertIn(required, source)
        for forbidden in ("raw_syscall::", "SYS_SCHED_GETSCHEDULER"):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&sched_getscheduler)",
            "sched_getscheduler_signature)(pid_t)",
            "sizeof(pid_t) == 4",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&sched_getscheduler)",
            "sched_getscheduler_signature",
            "extern \"C\" void crabc_sched_getscheduler_linkage_witness",
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "strict posix xopen gnu",
            "sched_getscheduler_header_abi_probe.c",
            "sched_getscheduler_header_abi_probe.cpp",
            "unmangled sched_getscheduler",
            "project trace omitted",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "SYS_sched_getscheduler == 145",
            "raw_sched_getscheduler",
            "raw_sched_getscheduler((pid_t)-1) != -EINVAL",
            "check_musl_process_api",
            "errno != ENOSYS",
            "CRABC_SCHED_GETSCHEDULER_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sched_getscheduler_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_sched_getscheduler_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_musl_enosys_boundary",
            "sched_getscheduler forwarded raw Linux syscall 145",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sched_getscheduler", static_exports)
        self.assertNotIn("times sched_getscheduler", process_resources_runner)
        self.assertNotIn("sched_setscheduler", process_resources_runner)
        self.assertIn('id = "static-c-sched-getscheduler"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sched-getscheduler"',
            parity_ledger,
        )
        self.assertIn("run_sched_getscheduler_header_abi()", dispatcher)
        self.assertIn("run_libc_sched_getscheduler_probe()", dispatcher)
        self.assertIn("sched-getscheduler-header-abi)", dispatcher)
        self.assertIn("libc-sched-getscheduler)", dispatcher)
    def test_libc_static_c_abi_alarm_artifact_stays_bounded(self) -> None:
        """Keep the historical SIGALRM timer adapter below timer promotion."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_alarm.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_alarm_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_alarm_start.S"
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_alarm.sh"
        unistd_c_path = ROOT / "compat" / "x86_64" / "unistd_header_abi_probe.c"
        unistd_cxx_path = ROOT / "compat" / "x86_64" / "unistd_header_abi_probe.cpp"
        for path in (
            source_path,
            probe_path,
            start_path,
            artifact_runner_path,
            unistd_c_path,
            unistd_cxx_path,
        ):
            self.assertTrue(path.is_file(), f"missing alarm artifact input: {path}")
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        unistd_c = unistd_c_path.read_text(encoding="utf-8")
        unistd_cxx = unistd_cxx_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_alarm.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 alarm C boundary",
            "src/unistd/alarm.c",
            "src/signal/setitimer.c",
            "raw_syscall::SYS_SETITIMER",
            "raw_syscall::syscall3(",
            "c_status(result)",
            'pub extern "C" fn alarm(seconds: c_uint) -> c_uint',
        ):
            self.assertIn(required, source)
        for forbidden in (
            'pub extern "C" fn setitimer',
            'pub extern "C" fn ualarm',
            "sigaction",
            "sigprocmask",
            "sigtimedwait",
            "timerfd",
            "pthread_",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "raw_setitimer_real",
            "SYS_setitimer == 38",
            "alarm(120U)",
            "604801U",
            "errno = ERANGE",
            "CRABC_ALARM_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_alarm_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        self.assertIn("&alarm", unistd_c)
        self.assertIn("alarm declaration", unistd_c)
        self.assertIn("decltype(&alarm)", unistd_cxx)
        self.assertIn("C++ alarm declaration", unistd_cxx)

        for required in (
            "run_musl_oracle.sh",
            "run_unistd_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_named_syscall alarm 26",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("alarm", static_exports)
        self.assertIn('id = "static-c-alarm"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-alarm"', parity_ledger
        )
        self.assertIn("run_libc_alarm_probe()", dispatcher)
        self.assertIn("libc-alarm)", dispatcher)

    def test_libc_static_c_abi_sigpending_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_pending.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sigpending_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sigpending_start.S"
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sigpending_header_abi_probe.cpp"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sigpending.sh"
        )
        for path in (
            source_path,
            probe_path,
            start_path,
            cxx_header_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing sigpending input: {path}")
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        signal_header_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        signal_header_posix_probe = (
            ROOT / "compat" / "x86_64" / "signal_header_posix_abi_probe.c"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_pending.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 `sigpending` C boundary",
            "src/signal/sigpending.c",
            "raw_syscall::SYS_RT_SIGPENDING",
            "raw_syscall::syscall2(",
            "size_of::<u64>()",
            'pub unsafe extern "C" fn sigpending',
            "c_status",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "sigaction(",
            "signal(",
            "sigprocmask(",
            "sigsuspend(",
            "sigwait",
            "signalfd",
            "timerfd",
            "pthread_",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "sigpending(&pending)",
            "SYS_rt_sigprocmask == 14",
            "SYS_rt_sigpending == 127",
            "SYS_tgkill == 234",
            "SIGUSR1",
            "errno = ERANGE",
            "EFAULT",
            "tail sentinels",
            "CRABC_SIGPENDING_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sigpending_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        for required in (
            "decltype(&sigpending)",
            "CRABC_EXPECT_SIGPENDING",
            "CRABC_REQUIRE_SIGPENDING",
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "C++",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "-Wl,--gc-sections",
            "R_X86_64_TPOFF",
            "--disassemble=sigpending",
            "assert_named_syscall sigpending 7f",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sigpending", static_exports)
        self.assertIn("__typeof__(&sigpending)", signal_header_probe)
        self.assertIn("__typeof__(&sigpending)", signal_header_posix_probe)
        self.assertIn('id = "static-c-sigpending"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sigpending"', parity_ledger
        )
        self.assertIn("run_libc_sigpending_probe()", dispatcher)
        self.assertIn("libc-sigpending)", dispatcher)

    def test_libc_static_c_abi_pthread_c11_once_artifact_stays_private_and_exact(
        self,
    ) -> None:
        """Keep normal-return once evidence separate from pthread/TLS parity."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        once_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_once.rs"
        probe_path = ROOT / "compat" / "x86_64" / "libc_pthread_c11_once_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_pthread_c11_once_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_c11_once.sh"
        )
        c_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_pthread_c11_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        for path in (once_path, probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing pthread/C11 once input: {path}")
        once = once_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_once.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "src/thread/pthread_once.c::{__pthread_once,__pthread_once_full}",
            "src/thread/call_once.c",
            "src/thread/__wait.c::__wait",
            "src/internal/pthread_impl.h::__wake",
            "ONCE_INITIAL: c_int = 0",
            "ONCE_INITIALIZING: c_int = 1",
            "ONCE_COMPLETE: c_int = 2",
            "ONCE_WAITERS: c_int = 3",
            "FUTEX_WAIT_PRIVATE",
            "FUTEX_WAKE_PRIVATE",
            "raw_syscall::SYS_FUTEX",
            "raw_syscall::syscall4(",
            "raw_syscall::syscall3(",
            "c_int::MAX as i64",
            "x86_64_load_acquire_i32",
            "x86_64_compare_exchange_acqrel_i32",
            "x86_64_swap_acqrel_i32",
            "run_selected_once",
            "dynamic/loader TLS",
        ):
            self.assertIn(required, once)
        once_exports = set(
            re.findall(
                r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                once,
            )
        )
        self.assertSetEqual(once_exports, {"pthread_once", "call_once"})
        for forbidden in (
            'pub unsafe extern "C" fn pthread_cancel',
            'pub unsafe extern "C" fn pthread_exit',
            'pub unsafe extern "C" fn thrd_exit',
            'pub unsafe extern "C" fn tss_',
            "__tls_get_addr",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, once)
        call_once_body = once.split('pub unsafe extern "C" fn call_once', 1)[1]
        self.assertIn("run_selected_once(flag, function)", call_once_body)
        self.assertNotRegex(call_once_body, r"\bpthread_once\s*\(")

        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "#include <threads.h>",
            "sizeof(pthread_once_t) == 4",
            "sizeof(once_flag) == 4",
            "PTHREAD_ONCE_INIT == 0 && ONCE_FLAG_INIT == 0",
            "CONTENDING_WORKER_COUNT = 2",
            "ONCE_COMPLETE = 2",
            "ONCE_WAITERS = 3",
            "run_static_initializer_round",
            "run_pthread_contention_round",
            "run_c11_contention_round",
            "wait_for_contended_state",
            "initializer_calls",
            "initializer_effect",
            "__ATOMIC_RELAXED",
            "errno != E2BIG",
            "CRABC_PTHREAD_C11_ONCE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            ".global _start",
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_c11_once_probe",
            "mov $231, %eax",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "run_pthread_c11_header_abi.sh",
            "assert_private_once_futex_path",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_C11_ONCE_FREESTANDING",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "lock[[:space:]]+cmpxchg",
            "atomic exchange release",
            "FUTEX_WAIT_PRIVATE",
            "FUTEX_WAKE_PRIVATE",
            "INT_MAX",
            "(call|jmp).*pthread_once",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue({"pthread_once", "call_once"} <= static_exports)
        self.assertNotIn("pthread_cond_timedwait", static_exports)
        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "crabc_once_init_signature",
                "crabc_pthread_once_signature",
                "crabc_call_once_signature",
                "pthread_once signature",
                "call_once signature",
            ):
                self.assertIn(required, header_probe)
        self.assertIn("crabc_force_pthread_once", cxx_header_probe)
        self.assertIn("crabc_force_call_once", cxx_header_probe)
        for required in (
            "pthread_cond_signal pthread_cond_broadcast\n        pthread_rwlock_init pthread_rwlock_destroy pthread_rwlock_rdlock",
            "thrd_create thrd_detach thrd_join thrd_exit thrd_sleep thrd_yield thrd_current thrd_equal",
            "call_once",
            "pthread_rwlockattr_getpshared|pthread_barrierattr_setpshared|pthread_barrierattr_getpshared|pthread_barrierattr_init|pthread_barrierattr_destroy|pthread_barrier_init|pthread_barrier_destroy|pthread_barrier_wait|pthread_once",
            "thrd_equal|call_once|tss_create|tss_delete|tss_get|tss_set|mtx_init",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('id = "static-c-pthread-c11-once"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-pthread-c11-once"',
            parity_ledger,
        )
        self.assertIn("run_libc_pthread_c11_once_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_c11_once.sh", runner
        )
        self.assertIn(
            '    libc-pthread-c11-once)\n        [ "$#" -eq 0 ] || fail "libc-pthread-c11-once takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_c11_tsd_artifact_stays_private_and_bounded(
        self,
    ) -> None:
        """Keep the selected key/TSS lifecycle below pthread/TLS promotion."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        tsd_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_tsd.rs"
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        probe_path = ROOT / "compat" / "x86_64" / "libc_pthread_c11_tsd_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_pthread_c11_tsd_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_c11_tsd.sh"
        )
        c_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_pthread_c11_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        for path in (tsd_path, probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing pthread/C11 TSD input: {path}")
        tsd = tsd_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_tsd.rs"]', static_root)
        for required in (
            "pinned musl 1.2.6",
            "src/thread/pthread_key_create.c::{__pthread_key_create,",
            "__pthread_key_delete,__pthread_tsd_run_dtors}",
            "src/thread/pthread_getspecific.c::__pthread_getspecific",
            "src/thread/pthread_setspecific.c::pthread_setspecific",
            "src/thread/tss_create.c",
            "src/thread/tss_delete.c",
            "src/thread/tss_set.c",
            "PTHREAD_KEYS_MAX: usize = 128",
            "PTHREAD_DESTRUCTOR_ITERATIONS: usize = 4",
            "SelectedTsdValues",
            "MAIN_SELECTED_TSD_VALUES",
            "current_selected_values().is_none()",
            "run_selected_worker_tsd_destructors",
            "clear-before-destructor",
            "process-exit destructors",
            "concurrent deletion/destructor interaction",
            "dynamic or loader TLS/DTV",
        ):
            self.assertIn(required, tsd)
        tsd_exports = set(
            re.findall(
                r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                tsd,
            )
        )
        self.assertSetEqual(
            tsd_exports,
            {
                "pthread_key_create",
                "pthread_key_delete",
                "pthread_getspecific",
                "pthread_setspecific",
                "tss_create",
                "tss_delete",
                "tss_set",
            },
        )
        for required in (
            '".weak pthread_getspecific"',
            '".set pthread_getspecific, __pthread_getspecific"',
            '".weak tss_get"',
            '".set tss_get, __pthread_getspecific"',
            '#[linkage = "internal"]',
        ):
            self.assertIn(required, tsd)
        for forbidden in (
            'pub unsafe extern "C" fn pthread_cancel',
            'pub unsafe extern "C" fn pthread_exit',
            'pub unsafe extern "C" fn thrd_exit',
            "__tls_get_addr",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, tsd)

        selected_tsd_entries = (
            (
                "pthread_key_create",
                tsd.split('pub unsafe extern "C" fn pthread_key_create', 1)[1].split(
                    "/// Delete one selected key", 1
                )[0],
            ),
            (
                "pthread_key_delete",
                tsd.split('pub unsafe extern "C" fn pthread_key_delete', 1)[1].split(
                    "/// Read one selected current-thread value", 1
                )[0],
            ),
            (
                "pthread_getspecific",
                tsd.split('pub unsafe extern "C" fn pthread_getspecific', 1)[1].split(
                    "/// Store one selected current-thread value", 1
                )[0],
            ),
            (
                "pthread_setspecific",
                tsd.split('pub unsafe extern "C" fn pthread_setspecific', 1)[1].split(
                    "/// Run the selected worker's private TSD destructor phase", 1
                )[0],
            ),
        )
        for entry_name, entry in selected_tsd_entries:
            self.assertIn("current_selected_values()", entry, entry_name)
            self.assertLess(
                entry.index("current_selected_values()"),
                entry.index("lock_selected_tsd()"),
                entry_name,
            )

        for wrapper_name, pthread_entry in (
            ("tss_create", "pthread_key_create(key, destructor)"),
            ("tss_delete", "pthread_key_delete(key)"),
            ("tss_set", "pthread_setspecific(key, value)"),
        ):
            wrapper = tsd.split(
                f'pub unsafe extern "C" fn {wrapper_name}', 1
            )[1]
            self.assertIn(pthread_entry, wrapper, wrapper_name)

        for required in (
            "tsd: pthread_tsd::SelectedTsdValues",
            "current_selected_worker_tsd_values",
            "clear_selected_worker_tsd_key",
            "pthread_tsd::run_selected_worker_tsd_destructors",
            "publish_selected_worker_result",
        ):
            self.assertIn(required, pthread_create_join)
        normal_exit = pthread_create_join.split('unsafe extern "C" fn worker_entry', 1)[
            1
        ].split("/// Create one default-attribute", 1)[0]
        self.assertLess(
            normal_exit.index("run_selected_worker_tsd_destructors"),
            normal_exit.index("publish_selected_worker_result"),
        )
        explicit_exit = pthread_create_join.split("unsafe fn exit_selected_worker", 1)[
            1
        ].split("/// End one selected pthread-mode worker", 1)[0]
        self.assertLess(
            explicit_exit.index("run_selected_worker_tsd_destructors"),
            explicit_exit.index("publish_selected_worker_result"),
        )

        for required in (
            "#include <errno.h>",
            "#include <limits.h>",
            "#include <pthread.h>",
            "#include <threads.h>",
            "PTHREAD_KEYS_MAX == 128 && PTHREAD_DESTRUCTOR_ITERATIONS == 4",
            "TSS_DTOR_ITERATIONS == PTHREAD_DESTRUCTOR_ITERATIONS",
            "pthread_key_create declaration",
            "pthread_key_delete declaration",
            "pthread_getspecific declaration",
            "pthread_setspecific declaration",
            "tss_create declaration",
            "tss_delete declaration",
            "tss_get declaration",
            "tss_set declaration",
            "run_pthread_return_round",
            "run_pthread_exit_round",
            "run_c11_return_round",
            "run_c11_exit_round",
            "run_deletion_round",
            "run_capacity_round",
            "PTHREAD_DESTRUCTOR_ITERATIONS",
            "pthread_getspecific(pthread_dtor_key) != 0",
            "tss_get(c11_dtor_key) != 0",
            "errno != E2BIG",
            "CRABC_PTHREAD_C11_TSD_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            ".global _start",
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_c11_tsd_probe",
            "mov $231, %eax",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "run_pthread_c11_header_abi.sh",
            "assert_selected_tsd_sources",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_C11_TSD_FREESTANDING",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "pthread_key_create pthread_key_delete pthread_getspecific pthread_setspecific",
            "tss_create tss_delete tss_get tss_set",
            "private atomic key-table lock",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(tsd_exports <= static_exports)
        self.assertNotIn("pthread_cond_timedwait", static_exports)

        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "crabc_pthread_key_create_signature",
                "crabc_pthread_key_delete_signature",
                "crabc_pthread_getspecific_signature",
                "crabc_pthread_setspecific_signature",
                "crabc_tss_create_signature",
                "crabc_tss_delete_signature",
                "crabc_tss_get_signature",
                "crabc_tss_set_signature",
                "pthread_key_create signature",
                "pthread_key_delete signature",
                "pthread_getspecific signature",
                "pthread_setspecific signature",
                "tss_create signature",
                "tss_delete signature",
                "tss_get signature",
                "tss_set signature",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "crabc_force_pthread_key_create",
            "crabc_force_pthread_key_delete",
            "crabc_force_pthread_getspecific",
            "crabc_force_pthread_setspecific",
            "crabc_force_tss_create",
            "crabc_force_tss_delete",
            "crabc_force_tss_get",
            "crabc_force_tss_set",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "pthread_key_create pthread_key_delete pthread_getspecific pthread_setspecific",
            "call_once tss_create tss_delete tss_get tss_set",
            "pthread_key_create|pthread_key_delete|pthread_getspecific|pthread_setspecific",
            "call_once|tss_create|tss_delete|tss_get|tss_set",
        ):
            self.assertIn(required, header_runner)

        self.assertIn('id = "static-c-pthread-c11-tsd"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-pthread-c11-tsd"',
            parity_ledger,
        )
        self.assertIn("run_libc_pthread_c11_tsd_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_c11_tsd.sh", runner
        )
        self.assertIn(
            '    libc-pthread-c11-tsd)\n        [ "$#" -eq 0 ] || fail "libc-pthread-c11-tsd takes no arguments"',
            runner,
        )

    def test_libc_static_initial_tls_v1_artifact_stays_narrow(self) -> None:
        """Keep the isolated x86 initial-TLS template distinct from composition.

        This contract requires the private static entry hook to validate and
        materialize the final executable's complete PT_TLS image before the
        bounded pthread leaf can use it.  It remains a private static-artifact
        gate, not the separately proved CRT handoff, loader implementation, or
        promotion claim.
        """

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        static_tls = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_tls.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_static_tls_v1_probe.c"
        ).read_text(encoding="utf-8")
        peer = (
            ROOT / "compat" / "x86_64" / "libc_static_tls_v1_peer.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_static_tls_v1_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_static_tls_v1.sh"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn(
            '#[cfg_attr(not(crabc_x86_dynamic_runtime), path = "static_tls.rs")]',
            static_root,
        )
        self.assertIn(
            '#[cfg_attr(crabc_x86_dynamic_runtime, path = "dynamic_tls.rs")]',
            static_root,
        )
        for required in (
            "StaticInitialTlsPlan",
            "StaticInitialTlsBlock",
            "AT_PHDR",
            "PT_TLS",
            "PT_PHDR",
            "ET_EXEC",
            "ELF64_HEADER_SIZE",
            "variant_ii_image_offset",
            "ARCH_SET_FS",
            "SYS_ARCH_PRCTL",
            "from_initial_stack",
            "bootstrap_initial_thread",
            "allocate_thread",
            "release_thread",
            "__crabc_x86_static_tls_bootstrap",
            ".hidden __crabc_x86_static_tls_bootstrap",
            "TLS_STATE_READY",
            "CLONE_SETTLS",
            "STATIC_INITIAL_TLS_STATE",
            "STATIC_INITIAL_TLS_PLAN",
            "STATIC_INITIAL_TLS_MAIN_THREAD_POINTER",
            "STATIC_INITIAL_TLS_MAIN_THREAD_ID",
            "is_initial_thread_pointer",
            "raw_syscall::SYS_GETTID",
        ):
            self.assertIn(required, static_tls)
        main_identity_bootstrap = static_tls.split(
            "pub(super) unsafe fn bootstrap_initial_thread", 1
        )[1].split("/// Private freestanding entry hook", 1)[0]
        for identity_store in (
            "STATIC_INITIAL_TLS_MAIN_THREAD_POINTER.store",
            "STATIC_INITIAL_TLS_MAIN_THREAD_ID.store",
        ):
            self.assertLess(
                main_identity_bootstrap.index(identity_store),
                main_identity_bootstrap.index(
                    "STATIC_INITIAL_TLS_STATE.store(TLS_STATE_READY"
                ),
                identity_store,
            )
        main_identity_check = static_tls.split(
            "pub(super) fn is_initial_thread_pointer", 1
        )[1].split("/// Materialize one independent child", 1)[0]
        for required in (
            "STATIC_INITIAL_TLS_MAIN_THREAD_POINTER.load",
            "raw_syscall::SYS_GETTID",
            "STATIC_INITIAL_TLS_MAIN_THREAD_ID.load",
        ):
            self.assertIn(required, main_identity_check)
        load_bias_selection = static_tls.split(
            "let load_bias = match program_header_virtual_address", 1
        )[1].split("let (image, filesz, memsz, tls_alignment)", 1)[0]
        self.assertIn("Some(program_header_virtual_address)", load_bias_selection)
        self.assertIn(
            "static_executable_load_bias_without_pt_phdr", load_bias_selection
        )
        et_exec_fallback = static_tls.split(
            "unsafe fn static_executable_load_bias_without_pt_phdr", 1
        )[1].split("/// Locate the auxiliary vector", 1)[0]
        for required in (
            "ET_EXEC",
            "ELF64_HEADER_SIZE",
            "ELF64_CLASS",
            "ELFDATA2LSB",
            "EV_CURRENT",
            "EM_X86_64",
            "virtual_range_within_readable_file_load",
            "Some(0)",
        ):
            self.assertIn(required, et_exec_fallback)
        self.assertIn("!= ET_EXEC", et_exec_fallback)
        static_tls_exports = set(
            re.findall(
                r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                static_tls,
            )
        )
        self.assertSetEqual(
            static_tls_exports, {"__crabc_x86_static_tls_bootstrap"}
        )
        self.assertIn("__crabc_x86_static_tls_bootstrap", static_exports)
        for forbidden in (
            "TLSDESC",
            "TLSGD",
            "TLSLD",
            "dlopen",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, static_tls)

        self.assertIn("static_tls::allocate_thread", pthread_create_join)
        self.assertIn("static_tls::release_thread", pthread_create_join)
        for forbidden in (
            "initial_errno_offset",
            "INITIAL_TLS_REGION_SIZE",
            "child_errno",
            "child_thread_pointer",
            "SYS_ARCH_PRCTL",
            "ARCH_SET_FS",
        ):
            self.assertNotIn(forbidden, pthread_create_join)

        for required in (
            "__thread",
            "aligned(4096)",
            "ARCH_GET_FS",
            "arch_get_fs",
            "kernel_thread_pointer",
            "initial_tls_value",
            "tbss",
            "pthread_create",
            "pthread_join",
            "CRABC_STATIC_TLS_V1_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in ("__thread", "peer_initial_tls_value", "peer_tbss"):
            self.assertIn(required, peer)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "run_musl_oracle.sh",
            "-pthread",
            "-nostdlib -static",
            "__crabc_x86_static_tls_bootstrap",
            "R_X86_64_TPOFF",
            "PT_TLS",
            "ET_EXEC no-PT_PHDR",
            "candidate execution exited",
            "expect_bootstrap_rejection",
            "fallback ELF version",
            "PT_TLS p_filesz",
            "__tls_get_addr",
            "libc_static_tls_v1_peer.c",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)

        self.assertIn('id = "static-c-initial-tls-v1"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-static-tls-v1"',
            parity_ledger,
        )
        pthread_tls_family = parity_ledger.split(
            '[[family]]\nid = "libc.pthread-tls"', 1
        )[1].split("\n[[family]]", 1)[0]
        self.assertIn('status = "planned"', pthread_tls_family)
        self.assertIn("public x86 support", pthread_tls_family)
        self.assertIn("libc-static-tls-v1", runner)

    def test_owned_static_sysroot_is_reproducible_and_rejects_ambient_inputs(self) -> None:
        builder = (
            ROOT / "scripts" / "build_x86_64_owned_sysroot.py"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_owned_static_sysroot.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "owned_static_sysroot_builtins.c"
        ).read_text(encoding="utf-8")
        dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(
            encoding="utf-8"
        )
        evidence = (
            ROOT / "compat" / "x86_64" / "owned-static-sysroot.md"
        ).read_text(encoding="utf-8")
        normalized_evidence = " ".join(evidence.split())

        for required in (
            "crabc-x86-64-owned-static-sysroot-v1",
            "pinned_toolchain(ROOT)",
            "c.*.rcgu.o",
            "stock_compiler_builtins_members_installed",
            "ambient_target_crt_or_library_installed",
            "private-static-pthread-tls-consumer-slice",
            "sysroot.static-tls family completion",
            "sysroot.owned-artifact family completion",
            "staged_output.replace(output)",
        ):
            self.assertTrue(required in builder, f"owned sysroot builder omits {required!r}")
        for required in (
            "-nostdinc",
            "audit_header_dependencies",
            "audit_link_receipt",
            "without-builtins",
            "/usr/lib/crt1.o",
            "/opt/musl-1.2.6/lib/libc.a",
            "libgcc.a",
            "/lib/ld-musl-x86_64.so.1",
            "GNU_RELRO",
            "GNU_STACK",
            "PIMBCAF",
            "assert_malformed_tls_rejected",
        ):
            self.assertTrue(required in runner, f"owned sysroot runner omits {required!r}")
        self.assertNotIn("--whole-archive", runner)
        self.assertIn("__udivti3", fixture)
        self.assertIn("owned-static-sysroot", dispatcher)
        self.assertIn("still-planned `sysroot.static-tls`", normalized_evidence)
        self.assertIn("still-planned `sysroot.owned-artifact`", normalized_evidence)
        self.assertIn("not public x86-64 support", normalized_evidence)

    def test_libc_static_c_abi_secure_environment_stays_startup_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        startup = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_startup.rs"
        ).read_text(encoding="utf-8")
        security = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "startup_security.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "secure_environment.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_secure_environment_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_secure_environment_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_secure_environment.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            '#[path = "startup_security.rs"]',
            '#[path = "secure_environment.rs"]',
        ):
            self.assertIn(required, static_root)
        raw_install = "unsafe { auxv_observation::install_initial(vectors.auxv) };"
        secure_install = "unsafe { startup_security::install_initial(vectors.auxv) };"
        environment_install = "unsafe { environment::install_initial(vectors.envp) };"
        init_call = "if let Some(init) = init {"
        for call in (raw_install, secure_install, environment_install):
            self.assertIn(call, startup)
        self.assertLess(startup.index(raw_install), startup.index(secure_install))
        self.assertLess(startup.index(secure_install), startup.index(environment_install))
        self.assertLess(startup.index(environment_install), startup.index(init_call))
        for required in (
            "musl 1.2.6 release commit",
            "src/env/__libc_start_main.c",
            "AT_UID",
            "AT_EUID",
            "AT_GID",
            "AT_EGID",
            "AT_SECURE",
            "MAX_AUXV_ENTRIES",
            "last matching auxiliary-vector value",
            "AtomicBool",
            "Ordering::Release",
            "Ordering::Acquire",
        ):
            self.assertIn(required, security)
        self.assertNotIn("AtomicUsize", security)
        for required in (
            "src/env/secure_getenv.c",
            'pub unsafe extern "C" fn secure_getenv',
            "startup_security::is_secure",
            "environment::getenv",
            "auxv_observation",
        ):
            self.assertIn(required, leaf)
        for forbidden in ("fn __getauxval", ".weak getauxval", "global_asm!"):
            self.assertNotIn(forbidden, leaf)
        for required in (
            "CRABC_SECURE_ENVIRONMENT_SYNTHETIC",
            "secure_getenv((const char *)1)",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("getauxval(", probe)
        for required in ("AT_SECURE", "AT_UID", "AT_EUID", "AT_GID", "AT_EGID"):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_stdlib_header_abi.sh",
            "assert_selected_c_abi_surface",
            "-nostdlib -static",
            "CRABC_SECURE_ENVIRONMENT_SYNTHETIC_AT_SECURE",
            "CRABC_SECURE_ENVIRONMENT_SYNTHETIC_UID_MISMATCH",
            "secure_getenv",
            "raw-auxv dependency",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("run_machine_context_header_abi.sh", artifact_runner)
        self.assertIn("secure_getenv", static_export_names)
        self.assertIn('id = "static-c-secure-environment"', (ROOT / "compat" / "x86_64" / "parity.toml").read_text(encoding="utf-8"))
        self.assertIn("libc-secure-environment)", dispatcher)
        self.assertIn("run_libc_secure_environment.sh", dispatcher)

    def test_libc_static_c_abi_network_byte_order_artifact_stays_isolated(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        network_byte_order = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "network_byte_order.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_network_byte_order_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_network_byte_order_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_network_byte_order.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "network_byte_order.rs"]', static_root)
        for symbol in ("htonl", "htons", "ntohl", "ntohs"):
            self.assertIn(f"fn {symbol}", network_byte_order)
            self.assertIn(symbol, static_export_names)
        self.assertEqual(network_byte_order.count("swap_bytes()"), 4)
        for required in (
            "musl 1.2.6 release commit",
            "src/network/htonl.c",
            "src/network/htons.c",
            "src/network/ntohl.c",
            "src/network/ntohs.c",
            "runtime endian-union branch",
            "bswap_16",
            "bswap_32",
        ):
            self.assertIn(required, network_byte_order)
        for forbidden in (
            "raw_syscall",
            "__errno_location",
            "crabc_core",
            "mimalloc",
            "std::",
        ):
            self.assertNotIn(forbidden, network_byte_order)
        for required in (
            "#include <arpa/inet.h>",
            "network_u32_function",
            "network_u16_function",
            "host_to_network_u32",
            "network_to_host_u32",
            "host_to_network_u16",
            "network_to_host_u16",
            "0x01020304",
            "0x0102",
            "wire.bytes[0] != 0x01",
            "CRABC_NETWORK_BYTE_ORDER_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_network_byte_order_probe", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate unexpectedly selects TLS",
            "candidate accidentally selects",
            "unexpectedly calls an ambient runtime",
            "arpa/inet.h",
            "sys/socket.h",
            "htonl htons ntohl ntohs",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-network-byte-order"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-network-byte-order"',
            parity_ledger,
        )
        self.assertIn("libc-network-byte-order)", dispatcher)

    def test_libc_static_c_abi_in6addr_any_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "in6addr_any.rs"
        ).read_text(encoding="utf-8")
        header = (ROOT / "include" / "netinet" / "in.h").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "libc_in6addr_any_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_in6addr_any_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_in6addr_any.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "in6addr_any.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/in6addr_any.c",
            "src/network/in6addr_loopback.c",
            "pub struct In6Addr",
            "pub union In6AddrUnion",
            "[u8; 16]",
            "[u16; 8]",
            "[u32; 4]",
            "#[no_mangle]",
            "pub static in6addr_any",
            "[0; 16]",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(r"(?m)^pub\s+static\s+(\w+)\s*:", leaf),
            ["in6addr_any"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "getaddrinfo",
            "gethostby",
            "if_nameindex",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, leaf)
        for required in (
            'extern "C" {',
            "uint8_t __s6_addr[16]",
            "uint16_t __s6_addr16[8]",
            "uint32_t __s6_addr32[4]",
            "#define s6_addr __in6_union.__s6_addr",
            "extern const struct in6_addr in6addr_any",
        ):
            self.assertIn(required, header)
        for required in (
            "sizeof(struct in6_addr) == 16",
            "_Alignof(struct in6_addr) == 4",
            "offsetof(struct in6_addr, s6_addr) == 0",
            "in6addr_any_pointer",
            "all_zero",
            "IN6_IS_ADDR_UNSPECIFIED",
            "IN6_IS_ADDR_LOOPBACK",
            "CRABC_IN6ADDR_ANY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_in6addr_any_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "in6addr_any.lo",
            "in6addr_loopback.lo",
            "in6addr_any.c",
            "in6addr_loopback.c",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "in6addr_any archive member also defines in6addr_loopback",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate unexpectedly selects TLS",
            "in6addr_loopback htonl htons ntohl ntohs",
            "getaddrinfo",
            "if_indextoname",
            "if_nameindex",
            "if_nametoindex",
            "socket bind connect send recv",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("in6addr_any", static_exports.splitlines())
        self.assertIn("in6addr_loopback", static_exports.splitlines())
        self.assertIn('id = "static-c-in6addr-any"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-in6addr-any"', parity_ledger
        )
        self.assertIn("libc-in6addr-any)", dispatcher)

    def test_libc_static_c_abi_in6addr_loopback_artifact_stays_private(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "in6addr_loopback.rs"
        ).read_text(encoding="utf-8")
        header = (ROOT / "include" / "netinet" / "in.h").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "libc_in6addr_loopback_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_in6addr_loopback_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_in6addr_loopback.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "in6addr_loopback.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/in6addr_loopback.c",
            "src/network/in6addr_any.c",
            "pub struct In6Addr",
            "pub union In6AddrUnion",
            "[u8; 16]",
            "[u16; 8]",
            "[u32; 4]",
            "#[no_mangle]",
            "pub static in6addr_loopback",
            "0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(r"(?m)^pub\s+static\s+(\w+)\s*:", leaf),
            ["in6addr_loopback"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "getaddrinfo",
            "gethostby",
            "if_nameindex",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, leaf)
        for required in (
            'extern "C" {',
            "uint8_t __s6_addr[16]",
            "uint16_t __s6_addr16[8]",
            "uint32_t __s6_addr32[4]",
            "#define s6_addr __in6_union.__s6_addr",
            "extern const struct in6_addr in6addr_loopback",
        ):
            self.assertIn(required, header)
        for required in (
            "sizeof(struct in6_addr) == 16",
            "_Alignof(struct in6_addr) == 4",
            "offsetof(struct in6_addr, s6_addr) == 0",
            "in6addr_loopback_pointer",
            "is_loopback",
            "IN6_IS_ADDR_LOOPBACK",
            "IN6_IS_ADDR_UNSPECIFIED",
            "CRABC_IN6ADDR_LOOPBACK_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_in6addr_loopback_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "in6addr_loopback.lo",
            "in6addr_any.lo",
            "in6addr_loopback.c",
            "in6addr_any.c",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "in6addr_loopback archive member also defines in6addr_any",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate unexpectedly selects TLS",
            "in6addr_any htonl htons ntohl ntohs",
            "getaddrinfo",
            "if_indextoname",
            "if_nameindex",
            "if_nametoindex",
            "socket bind connect send recv",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("in6addr_any", static_exports.splitlines())
        self.assertIn("in6addr_loopback", static_exports.splitlines())
        self.assertIn('id = "static-c-in6addr-loopback"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-in6addr-loopback"',
            parity_ledger,
        )
        self.assertIn("libc-in6addr-loopback)", dispatcher)

    def test_libc_static_c_abi_endservent_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "endservent.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_endservent_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_endservent_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_endservent.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_endservent_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "endservent_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "endservent_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        netdb_header = (ROOT / "include" / "netdb.h").read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "endservent.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 legacy service-database terminator C ABI boundary",
            "musl 1.2.6 release commit",
            "src/network/serv.c::endservent",
            "System V AMD64 ABI",
            'pub extern "C" fn endservent()',
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "static_tls::",
            "crabc_core",
            "crabc_mimalloc",
            "fn getservent",
            "fn setservent",
            "fn getservbyname",
            "fn getservbyport",
        ):
            self.assertNotIn(forbidden, implementation)
        self.assertIn("endservent", static_exports)
        self.assertFalse(
            static_exports
            & {
                "getservbyname",
                "getservbyport",
            }
        )

        for required in (
            "#include <netdb.h>",
            "typedef void (*endservent_signature)(void)",
            "const endservent_signature function = endservent",
            "endservent();",
            "function();",
            "CRABC_ENDSERVENT_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "crabc_x86_64_endservent_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        self.assertNotIn("ARCH_SET_FS", start)

        for header in (header_c, header_cxx):
            self.assertIn("endservent_signature", header)
            self.assertIn("endservent_function", header)
        self.assertIn('#ifdef __cplusplus\nextern "C" {', netdb_header)
        self.assertIn('#ifdef __cplusplus\n}\n#endif', netdb_header)
        for required in (
            "endservent_header_abi_probe.c",
            "endservent_header_abi_probe.cpp",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-gnu",
            "cxx17-strict",
            "cxx17-gnu",
            "nm --undefined-only",
            "retained a mangled endservent reference",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "run_endservent_header_abi.sh",
            "serv.lo",
            "static_c_abi_exports.txt",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "endservent archive member also defines a service, netdb, or resolver sibling",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate selects errno, h_errno, or TLS",
            "endservent unexpectedly performs a call or syscall",
            "archive-free candidate accidentally selects",
            "getservent setservent getservbyname getservbyport",
            "res_init res_query res_querydomain res_search",
            "dn_comp dn_expand dn_skipname ns_get16 ns_get32 ns_put16 ns_put32",
            "getaddrinfo freeaddrinfo",
            "socket bind connect send recv",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-endservent"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-endservent"', parity_ledger
        )
        self.assertIn("endservent-header-abi)", dispatcher)
        self.assertIn("run_endservent_header_abi()", dispatcher)
        self.assertIn("libc-endservent)", dispatcher)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_endservent.sh", dispatcher
        )

    def test_libc_static_c_abi_protocol_database_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "protocol_database.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_protocol_database_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_protocol_database_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_protocol_database.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_protocol_database_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "protocol_database_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "protocol_database_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        netdb_header = (ROOT / "include" / "netdb.h").read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "protocol_database.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 legacy protocol-database C ABI",
            "musl 1.2.6 release commit",
            "src/network/proto.c",
            "network_databases_exports.rs",
            "static PROTOCOLS",
            "static mut PROTOCOL_INDEX",
            "static mut PROTOCOL_RESULT",
            "static mut PROTOCOL_ALIASES",
            "core::ptr::read_volatile",
            'pub unsafe extern "C" fn endprotoent',
            'pub unsafe extern "C" fn getprotobyname',
            'pub unsafe extern "C" fn getprotobynumber',
            'pub unsafe extern "C" fn getprotoent',
            'pub unsafe extern "C" fn setprotoent',
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "static_tls::",
            "crabc_core",
            "crabc_mimalloc",
            "alloc::",
            'pub unsafe extern "C" fn gethostent',
            'pub unsafe extern "C" fn getnetent',
            'pub unsafe extern "C" fn getservent',
        ):
            self.assertNotIn(forbidden, implementation)

        protocol_database_symbols = {
            "endprotoent",
            "getprotobyname",
            "getprotobynumber",
            "getprotoent",
            "setprotoent",
        }
        self.assertTrue(protocol_database_symbols <= static_exports)

        for required in (
            "#include <netdb.h>",
            "sizeof(struct protoent) == 24",
            "offsetof(struct protoent, p_aliases) == 8",
            "endprotoent_signature",
            "getprotobyname_signature",
            "getprotobynumber_signature",
            "getprotoent_signature",
            "setprotoent_signature",
            "expected_protocols[]",
            "entry->p_aliases[0] == NULL",
            "check_enumeration",
            "check_lookup_state",
            "CRABC_PROTOCOL_DATABASE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "crabc_x86_64_protocol_database_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        self.assertNotIn("ARCH_SET_FS", start)

        for header in (header_c, header_cxx):
            for required in (
                "endprotoent_signature",
                "getprotobyname_signature",
                "getprotobynumber_signature",
                "getprotoent_signature",
                "setprotoent_signature",
                "endprotoent_function",
                "getprotobyname_function",
                "getprotobynumber_function",
                "getprotoent_function",
                "setprotoent_function",
            ):
                self.assertIn(required, header)
        self.assertIn(
            "void endhostent(void); void endnetent(void); void endprotoent(void); void endservent(void);",
            netdb_header,
        )
        self.assertIn(
            "struct protoent *getprotobyname(const char *); struct protoent *getprotobynumber(int); struct protoent *getprotoent(void);",
            netdb_header,
        )
        self.assertIn('#ifdef __cplusplus\nextern "C" {', netdb_header)
        self.assertIn('#ifdef __cplusplus\n}\n#endif', netdb_header)
        for required in (
            "protocol_database_header_abi_probe.c",
            "protocol_database_header_abi_probe.cpp",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-gnu",
            "c11-bsd",
            "cxx17-strict",
            "cxx17-gnu",
            "nm --undefined-only",
            "retained a mangled $symbol reference",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "run_protocol_database_header_abi.sh",
            "proto.lo",
            "static_c_abi_exports.txt",
            "assert_musl_proto_oracle",
            "extract_protocol_member",
            "strict subset of the proto.c provider block",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "--no-undefined",
            "candidate selects errno, h_errno, or TLS",
            "strcmp|strlen",
            "/etc/protocols",
            "getprotoent unexpectedly performs a syscall",
            "endhostent endnetent gethostent sethostent getnetent setnetent",
            "res_init res_query res_querydomain res_search",
            "socket bind connect accept listen send sendto sendmsg recv recvfrom recvmsg shutdown",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-protocol-database"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-protocol-database"',
            parity_ledger,
        )
        self.assertIn("run_protocol_database_header_abi()", dispatcher)
        self.assertIn(
            "/workspace/compat/x86_64/run_protocol_database_header_abi.sh", dispatcher
        )
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_protocol_database.sh", dispatcher
        )
        self.assertIn(
            '    protocol-database-header-abi)\n        [ "$#" -eq 0 ] || fail "protocol-database-header-abi takes no arguments"',
            dispatcher,
        )
        self.assertIn(
            '    libc-protocol-database)\n        [ "$#" -eq 0 ] || fail "libc-protocol-database takes no arguments"',
            dispatcher,
        )

    def test_libc_static_c_abi_dn_skipname_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dn_skipname.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_dn_skipname_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_dn_skipname_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_dn_skipname.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "dn_skipname.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/dn_skipname.c",
            "core::ptr::read",
            "label >= 192",
            "label as usize + 1",
            'pub unsafe extern "C" fn dn_skipname',
            "source..end",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(
                r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                leaf,
            ),
            ["dn_skipname"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "__h_errno_location",
            "getaddrinfo",
            "gethostby",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
            "fn dn_expand",
        ):
            self.assertNotIn(forbidden, leaf)

        for required in (
            "#include <resolv.h>",
            "dn_skipname_signature",
            "NS_CMPRSFLGS == 0xc0",
            "NS_MAXLABEL == 63",
            "NS_MAXCDNAME == 255",
            "NS_MAXDNAME == 1025",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cpp)
        for required in (
            "check_cxx_c_linkage",
            "nm --undefined-only",
            "_Z.*dn_skipname",
            "STRICT_C_PROJECT_HEADERS",
            "DNS packet I/O",
            "netdb",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <resolv.h>",
            "dn_skipname_signature",
            "NS_CMPRSFLGS == 0xc0",
            "static const unsigned char compressed",
            "truncated_pointer",
            "truncated_label",
            "label_64",
            "label_191",
            "CRABC_DN_SKIPNAME_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_dn_skipname_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "dn_skipname.lo",
            "dn_skipname.c",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "dn_skipname archive member also defines a parser sibling",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate unexpectedly selects TLS",
            "__h_errno_location",
            "dn_expand ns_get16 ns_get32",
            "res_query res_querydomain res_search",
            "getaddrinfo freeaddrinfo",
            "socket bind connect send recv",
            "call|syscall",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("dn_skipname", static_exports.splitlines())
        self.assertFalse(
            set(static_exports.splitlines())
            & {"res_query", "res_querydomain", "res_search"}
        )
        self.assertIn('id = "static-c-dn-skipname"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-dn-skipname"',
            parity_ledger,
        )
        self.assertIn("nameser-header-abi)", dispatcher)
        self.assertIn("libc-dn-skipname)", dispatcher)

    def test_libc_static_c_abi_dn_expand_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dn_expand.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_dn_expand_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_dn_expand_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_dn_expand.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "dn_expand.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/dn_expand.c",
            'pub unsafe extern "C" fn __dn_expand',
            "label & 0xc0 != 0",
            "space > 254",
            "iteration += 2",
            ".hidden __dn_expand",
            ".weak dn_expand",
            ".set dn_expand, __dn_expand",
            "output may overlap",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(
                r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                leaf,
            ),
            ["__dn_expand"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "__h_errno_location",
            "getaddrinfo",
            "gethostby",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
            "fn dn_skipname",
            "fn ns_get16",
            "fn ns_get32",
            "fn ns_put16",
            "fn ns_put32",
        ):
            self.assertNotIn(forbidden, leaf)

        for required in (
            "#include <resolv.h>",
            "dn_expand_signature",
            "NS_CMPRSFLGS == 0xc0",
            "NS_MAXLABEL == 63",
            "NS_MAXCDNAME == 255",
            "NS_MAXDNAME == 1025",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cpp)
        for required in (
            "check_cxx_c_linkage",
            "nm --undefined-only",
            "_Z.*dn_expand",
            "STRICT_C_PROJECT_HEADERS",
            "DNS packet I/O",
            "netdb",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <resolv.h>",
            "dn_expand_signature",
            "static const unsigned char compressed",
            "noncanonical_pointer",
            "high_offset_pointer",
            "truncated_pointer",
            "invalid_pointer",
            "pointer_loop",
            "source==end",
            "254 bytes",
            "CRABC_DN_EXPAND_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_dn_expand_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "dn_expand.lo",
            "dn_expand.c",
            "292",
            "assert_selected_c_abi_surface",
            "assert_dn_expand_alias",
            "extract_selected_member",
            "dn_expand archive member also defines a nameserver sibling",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate unexpectedly selects TLS",
            "__h_errno_location",
            "dn_skipname ns_get16 ns_get32 ns_put16 ns_put32",
            "res_query res_querydomain res_search",
            "htonl htons ntohl ntohs",
            "getaddrinfo freeaddrinfo",
            "socket bind connect send recv",
            "call|syscall",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("__dn_expand", static_exports.splitlines())
        self.assertIn("dn_expand", static_exports.splitlines())
        self.assertIn('id = "static-c-dn-expand"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-dn-expand"',
            parity_ledger,
        )
        self.assertIn("nameser-header-abi)", dispatcher)
        self.assertIn("libc-dn-expand)", dispatcher)

    def test_libc_static_c_abi_ns_flagdata_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ns_flagdata.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ns_flagdata_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_ns_flagdata_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ns_flagdata.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "ns_flagdata.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/ns_parse.c",
            ".rodata._ns_flagdata",
            "no relocations",
            "#[repr(C)]",
            "pub struct NsFlagData",
            "pub static _ns_flagdata: [NsFlagData; 16]",
            "mask: 0x8000, shift: 15",
            "mask: 0x000f, shift: 0",
            "NsFlagData { mask: 0, shift: 0 }",
            "ns_msg_getflag",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(r"(?m)^pub\s+static\s+(\w+)\s*:", leaf),
            ["_ns_flagdata"],
        )
        self.assertNotRegex(leaf, r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+')
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "__h_errno_location",
            "getaddrinfo",
            "gethostby",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
            "fn dn_expand",
            "fn dn_skipname",
            "fn ns_get16",
            "fn ns_get32",
            "fn ns_put16",
            "fn ns_put32",
        ):
            self.assertNotIn(forbidden, leaf)

        for required in (
            "#include <resolv.h>",
            "ns_flagdata_pointer",
            "sizeof(struct _ns_flagdata) == 8",
            "offsetof(struct _ns_flagdata, mask) == 0",
            "offsetof(struct _ns_flagdata, shift) == 4",
            "_ns_flagdata + 0",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cpp)
        self.assertIn("_Alignof(struct _ns_flagdata) == 4", header_c)
        self.assertIn("alignof(struct _ns_flagdata) == 4", header_cpp)
        self.assertIn('extern "C" const struct _ns_flagdata _ns_flagdata[];', header_cpp)
        for required in (
            "check_cxx_c_linkage",
            "nm --undefined-only",
            "_ns_flagdata",
            "_Z.*_ns_flagdata",
            "DNS packet I/O",
            "netdb",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <arpa/nameser.h>",
            "ns_flagdata_pointer",
            "expected[16]",
            "table_matches",
            "flags_match",
            "ns_msg_getflag",
            "0xffff",
            "0x2905",
            "CRABC_NS_FLAGDATA_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_ns_flagdata_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "ns_parse.lo",
            "ns_parse.c",
            ".rodata._ns_flagdata",
            "128",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "_ns_flagdata archive member also defines a resolver sibling",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "does not retain its 128-byte ABI",
            "candidate selects errno, h_errno, or TLS",
            "dn_comp dn_expand dn_skipname ns_get16 ns_get32 ns_put16 ns_put32",
            "res_query res_querydomain res_search",
            "getaddrinfo freeaddrinfo",
            "socket bind connect send recv",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("_ns_flagdata", static_exports.splitlines())
        self.assertFalse(
            set(static_exports.splitlines())
            & {"res_query", "res_querydomain", "res_search"}
        )
        self.assertIn('id = "static-c-ns-flagdata"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-ns-flagdata"',
            parity_ledger,
        )
        self.assertIn("nameser-header-abi)", dispatcher)
        self.assertIn("libc-ns-flagdata)", dispatcher)

    def test_libc_static_c_abi_ns_get16_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ns_get16.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ns_get16_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_ns_get16_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ns_get16.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "ns_get16.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/ns_parse.c",
            "core::ptr::read",
            "bytes.add(1)",
            'pub unsafe extern "C" fn ns_get16',
            "at least two readable bytes",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(
                r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                leaf,
            ),
            ["ns_get16"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "__h_errno_location",
            "getaddrinfo",
            "gethostby",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
            "fn ns_get32",
            "fn ns_put16",
            "fn ns_put32",
        ):
            self.assertNotIn(forbidden, leaf)

        for required in (
            "#include <resolv.h>",
            "ns_get16_signature",
            "NS_CMPRSFLGS == 0xc0",
            "NS_MAXLABEL == 63",
            "NS_MAXCDNAME == 255",
            "NS_MAXDNAME == 1025",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cpp)
        for required in (
            "check_cxx_c_linkage",
            "nm --undefined-only",
            "_Z.*ns_get16",
            "STRICT_C_PROJECT_HEADERS",
            "DNS packet I/O",
            "netdb",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <resolv.h>",
            "ns_get16_signature",
            "NS_INT16SZ == 2",
            "static const unsigned char octets",
            "NS_GET16(value, cursor)",
            "CRABC_NS_GET16_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_ns_get16_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "ns_parse.lo",
            "ns_parse.c",
            "11",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "ns_get16 archive member also defines a nameserver sibling",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate unexpectedly selects TLS",
            "__h_errno_location",
            "dn_expand dn_skipname ns_get32 ns_put16 ns_put32",
            "res_query res_querydomain res_search",
            "htonl htons ntohl ntohs",
            "getaddrinfo freeaddrinfo",
            "socket bind connect send recv",
            "call|syscall",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("ns_get16", static_exports.splitlines())
        self.assertIn('id = "static-c-ns-get16"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-ns-get16"',
            parity_ledger,
        )
        self.assertIn("nameser-header-abi)", dispatcher)
        self.assertIn("libc-ns-get16)", dispatcher)

    def test_libc_static_c_abi_ns_get32_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ns_get32.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ns_get32_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_ns_get32_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ns_get32.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "ns_get32.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/ns_parse.c",
            "core::ptr::read",
            "bytes.add(3)",
            'pub unsafe extern "C" fn ns_get32',
            "at least four readable bytes",
            "decoded low 32 bits set",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(
                r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                leaf,
            ),
            ["ns_get32"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "__h_errno_location",
            "getaddrinfo",
            "gethostby",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
            "fn ns_get16",
            "fn ns_put16",
            "fn ns_put32",
        ):
            self.assertNotIn(forbidden, leaf)

        for required in (
            "#include <resolv.h>",
            "ns_get32_signature",
            "NS_CMPRSFLGS == 0xc0",
            "NS_MAXLABEL == 63",
            "NS_MAXCDNAME == 255",
            "NS_MAXDNAME == 1025",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cpp)
        for required in (
            "check_cxx_c_linkage",
            "nm --undefined-only",
            "_Z.*ns_get32",
            "STRICT_C_PROJECT_HEADERS",
            "DNS packet I/O",
            "netdb",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <resolv.h>",
            "ns_get32_signature",
            "NS_INT32SZ == 4",
            "static const unsigned char octets",
            "0x001234abUL",
            "NS_GET32(value, cursor)",
            "CRABC_NS_GET32_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_ns_get32_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "ns_parse.lo",
            "ns_parse.c",
            "7",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "ns_get32 archive member also defines a nameserver sibling",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate unexpectedly selects TLS",
            "__h_errno_location",
            "dn_expand dn_skipname ns_get16 ns_put16 ns_put32",
            "res_query res_querydomain res_search",
            "htonl htons ntohl ntohs",
            "getaddrinfo freeaddrinfo",
            "socket bind connect send recv",
            "call|syscall",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("ns_get32", static_exports.splitlines())
        self.assertIn('id = "static-c-ns-get32"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-ns-get32"',
            parity_ledger,
        )
        self.assertIn("nameser-header-abi)", dispatcher)
        self.assertIn("libc-ns-get32)", dispatcher)

    def test_libc_static_c_abi_ns_put16_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ns_put16.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ns_put16_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_ns_put16_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ns_put16.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "ns_put16.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/ns_parse.c",
            "core::ptr::write",
            "value >> 8",
            "bytes.add(1)",
            'pub unsafe extern "C" fn ns_put16',
            "at least two writable bytes",
            "truncates `value` to its low 16",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(
                r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                leaf,
            ),
            ["ns_put16"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "__h_errno_location",
            "getaddrinfo",
            "gethostby",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
            "fn ns_get16",
            "fn ns_get32",
            "fn ns_put32",
        ):
            self.assertNotIn(forbidden, leaf)

        for required in (
            "#include <resolv.h>",
            "ns_put16_signature",
            "NS_CMPRSFLGS == 0xc0",
            "NS_MAXLABEL == 63",
            "NS_MAXCDNAME == 255",
            "NS_MAXDNAME == 1025",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cpp)
        for required in (
            "check_cxx_c_linkage",
            "nm --undefined-only",
            "_Z.*ns_put16",
            "STRICT_C_PROJECT_HEADERS",
            "DNS packet I/O",
            "netdb",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <resolv.h>",
            "ns_put16_signature",
            "NS_INT16SZ == 2",
            "unsigned char direct",
            "0xbeefcafeU",
            "NS_PUT16(0xdeadU, cursor)",
            "CRABC_NS_PUT16_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_ns_put16_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "ns_parse.lo",
            "ns_parse.c",
            "10",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "ns_put16 archive member also defines a nameserver sibling",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate unexpectedly selects TLS",
            "__h_errno_location",
            "dn_expand dn_skipname ns_get16 ns_get32 ns_put32",
            "res_query res_querydomain res_search",
            "htonl htons ntohl ntohs",
            "getaddrinfo freeaddrinfo",
            "socket bind connect send recv",
            "call|syscall",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("ns_put16", static_exports.splitlines())
        self.assertIn('id = "static-c-ns-put16"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-ns-put16"',
            parity_ledger,
        )
        self.assertIn("nameser-header-abi)", dispatcher)
        self.assertIn("libc-ns-put16)", dispatcher)

    def test_system_information_syscall_judge_accepts_the_owned_raw_wrapper(
        self,
    ) -> None:
        """A public helper may call the selected raw-syscall leaf instead of inlining it."""

        source = (
            ROOT / "compat" / "x86_64" / "run_libc_system_information.sh"
        ).read_text(encoding="utf-8")
        signature = "assert_named_syscall()"
        start = source.index(signature)
        opening_brace = source.index("{", start)
        depth = 0
        closing_brace = None
        for index in range(opening_brace, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    closing_brace = index
                    break
        self.assertIsNotNone(closing_brace)
        helper = source[start : closing_brace + 1]

        def invoke(
            disassembly: str, raw_syscall_disassembly: str = ""
        ) -> subprocess.CompletedProcess[str]:
            temporary_root = Path(
                os.environ.get("TMPDIR", ROOT / ".work" / "x86_64" / "tmp")
            )
            temporary_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
                temporary_path = Path(temporary)
                fake_objdump = temporary_path / "objdump"
                fake_objdump.write_text(
                    """#!/usr/bin/env bash
case "$*" in
    *--disassemble=get_nprocs*) printf '%s' "$CRABC_FAKE_PUBLIC_OBJDUMP" ;;
    *--disassemble=*) printf '%s' "$CRABC_FAKE_RAW_SYSCALL_OBJDUMP" ;;
esac
""",
                    encoding="utf-8",
                )
                fake_objdump.chmod(fake_objdump.stat().st_mode | stat.S_IXUSR)
                script = "\n".join(
                    (
                        "set -euo pipefail",
                        "fail() { printf 'ERROR: %s\\n' \"$*\" >&2; exit 1; }",
                        f"work_dir={temporary_path!s}",
                        f"candidate={temporary_path / 'candidate'!s}",
                        helper,
                        "assert_named_syscall get_nprocs cc",
                    )
                )
                environment = os.environ | {
                    "PATH": f"{temporary_path}:{os.environ['PATH']}",
                    "CRABC_FAKE_PUBLIC_OBJDUMP": disassembly,
                    "CRABC_FAKE_RAW_SYSCALL_OBJDUMP": raw_syscall_disassembly,
                }
                return subprocess.run(
                    ["bash", "-c", script],
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )

        delegated = invoke(
            """00000000004014f0 <get_nprocs>:
 401535: bf cc 00 00 00        mov    $0xcc,%edi
  401541: e8 ca 16 00 00        call   402c10 <_RNvNtNtCraw_syscall8syscall3B5_>
""",
            """0000000000402c10 <_RNvNtNtCraw_syscall8syscall3B5_>:
  402c1c: 0f 05                 syscall
""",
        )
        self.assertEqual(delegated.returncode, 0, delegated.stderr)

        wrapper_without_syscall = invoke(
            """00000000004014f0 <get_nprocs>:
  401535: bf cc 00 00 00        mov    $0xcc,%edi
  401541: e8 ca 16 00 00        call   402c10 <_RNvNtNtCraw_syscall8syscall3B5_>
""",
            """0000000000402c10 <_RNvNtNtCraw_syscall8syscall3B5_>:
  402c1c: c3                    ret
""",
        )
        self.assertNotEqual(wrapper_without_syscall.returncode, 0)
        self.assertIn(
            "matched owned raw-syscall target lacks the kernel instruction",
            wrapper_without_syscall.stderr,
        )

        missing = invoke(
            """00000000004014f0 <get_nprocs>:
  401535: bf cc 00 00 00        mov    $0xcc,%edi
  401541: e8 ca 16 00 00        call   402c10 <unowned_runtime_path>
"""
        )
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("owned raw-syscall path", missing.stderr)

    @unittest.skipUnless(
        subprocess.run(["realpath", "-e", "/"], capture_output=True).returncode == 0,
        "the runner needs GNU realpath -e, as in the pinned image",
    )
    def test_system_information_tmpdir_must_be_a_physical_checkout_descendant(
        self,
    ) -> None:
        """The runner must reject symlink and traversal aliases before `mktemp`."""

        source = (
            ROOT / "compat" / "x86_64" / "run_libc_system_information.sh"
        ).read_text(encoding="utf-8")
        signature = "checkout_local_tmpdir()"
        start = source.index(signature)
        opening_brace = source.index("{", start)
        depth = 0
        closing_brace = None
        for index in range(opening_brace, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    closing_brace = index
                    break
        self.assertIsNotNone(closing_brace)
        helper = source[start : closing_brace + 1]

        temporary_root = Path(
            os.environ.get("TMPDIR", ROOT / ".work" / "x86_64" / "tmp")
        )
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
            workspace = Path(temporary)
            checkout_tmpdir = workspace / ".work" / "x86_64" / "tmp"
            checkout_tmpdir.mkdir(parents=True)
            symlink_tmpdir = workspace / "tmp-via-symlink"
            symlink_tmpdir.symlink_to(checkout_tmpdir, target_is_directory=True)

            def invoke(tmpdir: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        "bash",
                        "-c",
                        "\n".join(
                            (
                                "set -euo pipefail",
                                "fail() { printf 'ERROR: %s\\n' \"$*\" >&2; exit 1; }",
                                "ROOT_DIR=\"$CRABC_TEST_ROOT\"",
                                helper,
                                "checkout_local_tmpdir",
                            )
                        ),
                    ],
                    env=os.environ
                    | {
                        "CRABC_TEST_ROOT": str(workspace),
                        "TMPDIR": tmpdir,
                    },
                    text=True,
                    capture_output=True,
                    check=False,
                )

            accepted = invoke(str(checkout_tmpdir))
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout, f"{checkout_tmpdir}\n")

            for escaped_tmpdir in (
                str(symlink_tmpdir),
                f"{checkout_tmpdir}/../tmp",
            ):
                rejected = invoke(escaped_tmpdir)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("physical checkout .work directory", rejected.stderr)

    def test_libc_static_c_abi_random_entropy_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        random_entropy = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "random_entropy.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_random_entropy_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_random_entropy_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_random_entropy.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "random_entropy.rs"]', static_root)
        for symbol in ("fn getrandom(", "fn getentropy("):
            self.assertIn(symbol, random_entropy)
        for required in (
            "musl 1.2.6 release commit",
            "src/linux/getrandom.c",
            "src/misc/getentropy.c",
            "raw_syscall::SYS_GETRANDOM",
            "raw_syscall::syscall3(",
            "GETENTROPY_MAX_BYTES: usize = 256",
            "errno::set_errno(EIO)",
            "errno::get_errno()",
            "c_ssize_status(result)",
            "syscall_cp",
            "pthread_setcancelstate",
        ):
            self.assertIn(required, random_entropy)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn random(",
            "fn srandom(",
            "fn pthread_",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, random_entropy)
        for required in (
            "#include <sys/random.h>",
            "#include <unistd.h>",
            "GRND_NONBLOCK",
            "getrandom",
            "getentropy",
            "256",
            "CRABC_RANDOM_ENTROPY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("libc_random_entropy_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall getrandom 13e",
            "sys/random.h",
            "unistd.h",
        ):
            self.assertIn(required, artifact_runner)
        archive_prng_exclusion = re.search(
            r"for unselected in(?P<symbols>.*?); do\n"
            r'    if grep -Eq [^\n]*"\$archive_symbols"; then',
            artifact_runner,
            re.DOTALL,
        )
        self.assertIsNotNone(archive_prng_exclusion)
        assert archive_prng_exclusion is not None
        archive_excluded_symbols = set(
            archive_prng_exclusion.group("symbols").replace("\\", " ").split()
        )
        self.assertSetEqual(
            set(static_export_names) & archive_excluded_symbols,
            set(),
            "the aggregate archive's PRNG exclusion rejects a selected leaf",
        )
        candidate_prng_exclusion = re.search(
            r"for unselected in(?P<symbols>.*?); do\n"
            r'    if grep -Eq [^\n]*"\$candidate_symbols"; then',
            artifact_runner,
            re.DOTALL,
        )
        self.assertIsNotNone(candidate_prng_exclusion)
        assert candidate_prng_exclusion is not None
        candidate_excluded_symbols = set(
            candidate_prng_exclusion.group("symbols").replace("\\", " ").split()
        )
        for symbol in (
            "rand_r",
            "drand48",
            "erand48",
            "jrand48",
            "lcong48",
            "lrand48",
            "mrand48",
            "nrand48",
            "seed48",
            "srand48",
        ):
            self.assertIn(symbol, candidate_excluded_symbols)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("getrandom", "getentropy"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-random-entropy"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-random-entropy"',
            parity_ledger,
        )
        self.assertIn("libc-random-entropy", runner)

    def test_libc_owned_bsd_random_stays_feature_selected_and_provenanced(self) -> None:
        """The legacy BSD generator is the narrowly selected musl semantic port."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "bsd_random.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_bsd_random_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_bsd_random_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_bsd_random.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        entropy_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_random_entropy.sh"
        ).read_text(encoding="utf-8")
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "bsd_random.rs"]', static_root)
        self.assertIn('#[cfg(crabc_x86_owned_runtime)]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/prng/random.c",
            "3a47a757115e2a2ea7b1242a0000100ad802c27c2a398b4d8b8360d768780209",
            "Copyright © 2005-2020 Rich Felker, et al.",
            "src/thread/__lock.c",
            "AtomicI32",
            "read_unaligned",
            "write_unaligned",
            "pub extern \"C\" fn random",
            "pub extern \"C\" fn srandom",
            "pub unsafe extern \"C\" fn initstate",
            "pub unsafe extern \"C\" fn setstate",
            "pthread_fork_prepare",
            "pthread_fork_parent",
            "pthread_fork_child",
            "never an entropy, secret, allocator",
        ):
            self.assertIn(required, implementation)
        for forbidden in ("getrandom", "getentropy", "crabc_mimalloc"):
            self.assertNotIn(forbidden, implementation)

        for required in (
            "random_signature",
            "srandom_signature",
            "initstate_signature",
            "setstate_signature",
            "0x80000000U",
            "0xffffffffU",
            "index < 8",
            "8, 31, 32, 63, 64, 127, 128, 255, 256, 272",
            "record_stream(130)",
            "Saving before loading makes setstate(active_state) return itself.",
            "restore the original static state",
        ):
            self.assertIn(required, probe)
        for required in (
            "crabc_x86_64_bsd_random_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "--expect-missing",
            "red link did not expose missing",
            "raw_syscall.*syscall3",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "-Wl,--gc-sections",
            "readelf -lW",
            "cmp \"$work_dir/reference.trace\" \"$work_dir/candidate.trace\"",
            "chmod -R a+rX \"$work_dir\"",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("trap", artifact_runner)

        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        for symbol in ("random", "srandom", "initstate", "setstate"):
            self.assertNotIn(symbol, static_export_names)

        archive_prng_exclusion = re.search(
            r"for unselected in(?P<symbols>.*?); do\n"
            r'    if grep -Eq [^\n]*"\$archive_symbols"; then',
            entropy_runner,
            re.DOTALL,
        )
        self.assertIsNotNone(archive_prng_exclusion)
        assert archive_prng_exclusion is not None
        entropy_excluded_symbols = set(
            archive_prng_exclusion.group("symbols").replace("\\", " ").split()
        )
        for symbol in ("random", "srandom", "initstate", "setstate"):
            self.assertIn(symbol, entropy_excluded_symbols)

        candidate_prng_exclusion = re.search(
            r"for unselected in(?P<symbols>.*?); do\n"
            r'    if grep -Eq [^\n]*"\$candidate_symbols"; then',
            entropy_runner,
            re.DOTALL,
        )
        self.assertIsNotNone(candidate_prng_exclusion)
        assert candidate_prng_exclusion is not None
        entropy_candidate_excluded_symbols = set(
            candidate_prng_exclusion.group("symbols").replace("\\", " ").split()
        )
        for symbol in ("random", "srandom", "initstate", "setstate"):
            self.assertIn(symbol, entropy_candidate_excluded_symbols)

        for required in (
            "libc-bsd-random [--expect-missing]",
            "run_libc_bsd_random()",
            "/workspace/compat/x86_64/run_libc_bsd_random.sh",
            "libc-bsd-random takes no more than --expect-missing",
            "libc-bsd-random only accepts --expect-missing",
            "    libc-bsd-random)\n        ensure_image\n        run_libc_bsd_random \"$@\"",
        ):
            self.assertIn(required, dispatcher)

    def test_libc_static_c_abi_bounded_regex_artifact_stays_non_promoting(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "regex.rs"
        ).read_text(encoding="utf-8")
        header = (ROOT / "include" / "regex.h").read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_regex_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_regex.sh"
        ).read_text(encoding="utf-8")
        parity_ledger = (
            ROOT / "compat" / "x86_64" / "parity.toml"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        dispatcher = RUNNER.read_text(encoding="utf-8")

        symbols = ("regcomp", "regexec", "regerror", "regfree")
        self.assertIn('#[path = "regex.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", implementation)
            self.assertIn(symbol, static_exports)
        for unselected in ("wordexp", "wordfree", "glob", "globfree", "fnmatch"):
            self.assertNotIn(unselected, static_exports)
        for required in (
            "MAX_TOKENS: usize = 128",
            "MAX_PATTERN_BYTES: usize = 4_096",
            "MAX_INPUT_BYTES: usize = 4_096",
            "COMPILED_MAPPING_BYTES: usize = 8_192",
            "raw_syscall::SYS_MMAP",
            "raw_syscall::SYS_MUNMAP",
            "leftmost-longest",
            "not complete `pattern.regex`",
        ):
            self.assertIn(required, implementation)
        for required in (
            "typedef struct re_pattern_buffer",
        ):
            self.assertIn(required, header)
        for macro, value in (("REG_NEWLINE", 4), ("REG_NOSUB", 8), ("REG_ENOSYS", -1)):
            self.assertTrue(
                re.search(rf"(?m)^#define {macro}\s+{value}$", header),
                f"regex header must retain {macro} value {value}",
            )
        for required in (
            "a.*a",
            "[]a]+",
            "REG_NEWLINE",
            "REG_NOSUB",
            "[[:digit:]]",
            "too_many_atoms",
            "too_long_input",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "--no-undefined",
            "wordexp wordfree malloc calloc realloc free",
            "raw_syscall::SYS_MMAP",
            "raw_syscall::SYS_MUNMAP",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn('id = "static-c-bounded-regex"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-regex"',
            parity_ledger,
        )
        self.assertIn("does not complete `pattern.regex`", parity_ledger)
        self.assertIn("select `pattern.wordexp`", parity_ledger)
        self.assertIn("libc-regex)", dispatcher)

    def test_libc_static_c_abi_stdio_standard_streams_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "stdio_standard_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "stdio_standard_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_stdio_standard_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_stdio_standard_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_stdio_standard_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_stdio_standard.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        data_symbols = ("stdin", "stdout", "stderr")
        function_symbols = (
            "clearerr",
            "feof",
            "ferror",
            "fflush",
            "fgetc",
            "fileno",
            "fputc",
            "fread",
            "fwrite",
            "getc",
            "getchar",
            "putc",
            "putchar",
            "ungetc",
        )
        self.assertIn(
            '#[cfg_attr(not(crabc_x86_owned_runtime), path = "stdio_standard.rs")]',
            static_root,
        )
        self.assertIn(
            '#[cfg_attr(crabc_x86_owned_runtime, path = "owned_static_stdio.rs")]',
            static_root,
        )
        for symbol in data_symbols:
            self.assertIn(f"pub static mut {symbol}:", implementation)
            self.assertIn(symbol, static_export_names)
        for symbol in function_symbols:
            self.assertIn(f'pub unsafe extern "C" fn {symbol}', implementation)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/internal/stdio_impl.h",
            "src/stdio/{stdin,stdout,stderr}.c",
            "src/stdio/{__stdio_read,__uflow,__toread}.c",
            "src/stdio/{__stdio_write,__overflow,__towrite}.c",
            "const BUFSIZ: usize = 1024;",
            "const UNGET: usize = 8;",
            "The only valid non-null `FILE *` arguments",
            "terminal-sensitive automatic",
            "ordinary-exit flushing",
            "raw_syscall::SYS_READ",
            "raw_syscall::SYS_READV",
            "raw_syscall::SYS_WRITE",
        ):
            self.assertIn(required, implementation)
        for probe in (header_c_probe, header_cxx_probe):
            for symbol in (*data_symbols, *function_symbols):
                self.assertIn(symbol, probe)
        for required in (
            "sizeof(FILE) == 1",
            "__alignof__(FILE) == 1",
            "CRABC_STDIO_STANDARD_C99_STRICT",
            "CRABC_STDIO_STANDARD_C11_POSIX_2008",
            "CRABC_STDIO_STANDARD_REQUIRE_FILENO_HIDDEN",
        ):
            self.assertIn(required, header_c_probe)
        for required in (
            "CRABC_STDIO_STANDARD_CXX17_STRICT",
            "CRABC_STDIO_STANDARD_CXX17_POSIX_2008",
            "unmangled C spellings",
            "crabc_stdio_fileno_reference",
        ):
            self.assertIn(required, header_cxx_probe)
        for required in (
            "c99-strict",
            "c11-strict",
            "c11-posix-2008",
            "cxx17-strict",
            "cxx17-posix-2008",
            "-nostdinc",
            "-nostdinc++",
            "check_cxx_c_linkage",
            "one-byte opaque struct _IO_FILE placeholder",
            "strict fileno hidden witness",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "CRABC_STDIO_STANDARD_FREESTANDING",
            "check_standard_globals",
            "check_stdin_buffering_and_ebadf",
            "check_stdout_explicit_flush",
            "check_stderr_immediate",
            "expect_pipe_empty",
            "fflush_entry(stdout)",
            "fflush_entry(NULL)",
            "No fflush call precedes this read",
        ):
            self.assertIn(required, fixture)
        for required in (
            "untouched Linux entry stack",
            "__crabc_x86_static_tls_bootstrap",
            "Linux x86-64 exit_group",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_stdio_standard_header_abi.sh",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
            "__crabc_x86_static_tls_bootstrap",
            "fdopen freopen",
            "ordinary-exit",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-stdio-standard-streams"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-standard"',
            parity_ledger,
        )
        self.assertIn("stdio-standard-header-abi", dispatcher)
        self.assertIn("libc-stdio-standard", dispatcher)
        self.assertIn("run_stdio_standard_header_abi()", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_format_scan_is_opt_in(self) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_format_scan_wave_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_format_scan_wave.sh"
        ).read_text(encoding="utf-8")
        dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(encoding="utf-8")
        for required in (
            "pub unsafe extern \"C\" fn printf",
            "pub unsafe extern \"C\" fn vprintf",
            "pub unsafe extern \"C\" fn fprintf",
            "pub unsafe extern \"C\" fn vfprintf",
            "pub unsafe extern \"C\" fn scanf",
            "pub unsafe extern \"C\" fn vscanf",
            "pub unsafe extern \"C\" fn fscanf",
            "pub unsafe extern \"C\" fn vfscanf",
            "is_permanent_stream",
            "allow_errno_message",
        ):
            self.assertIn(required, implementation)
        for required in (
            "call_vfprintf(stdout, \"vf=%d\\n\", 12)",
            "%*c%c",
            "(FILE *)(uintptr_t)1",
            "errno != EINVAL",
        ):
            self.assertIn(required, fixture)
        for required in (
            "x86-stdio-permanent-format-scan",
            "default archive export surface drifted",
            "feature-delta",
            "--no-undefined",
            "-nostdlib -static",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn('id = "static-c-stdio-permanent-format-scan"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-format-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-permanent-format-scan", dispatcher)
        self.assertIn("run_libc_stdio_permanent_format_scan_wave.sh", dispatcher)

    def test_libc_static_c_abi_stdio_integer_scan_stays_narrow(self) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_integer_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_integer_scan_start.S"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_integer_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "const ERANGE: c_int = 34;",
            "track_source_overflow",
            "u64::MAX",
            "overflowed = true",
            "negative = false",
            "ScanBase::Octal",
            "ScanBase::HexUpper",
            "static-c-stdio-integer-scan",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf",
            '"18446744073709551615!"',
            '"18446744073709551616!"',
            '"-0x10000000000000000?"',
            '"-18446744073709551616;"',
            '"10000000000000000."',
            '"%20u#"',
            "ULLONG_MAX",
            "UINT_MAX",
            "ERANGE",
            "CRABC_STDIO_INTEGER_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=integer-scan", wrapper
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "integer-scan)",
            "CRABC_STDIO_INTEGER_SCAN_FREESTANDING",
            "libc_stdio_integer_scan_probe.c",
            "libc_stdio_integer_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "source-overflow path clears a negative sign",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn('id = "static-c-stdio-integer-scan"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-integer-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-integer-scan", dispatcher)
        self.assertIn("run_libc_stdio_integer_scan.sh", dispatcher)

    def test_libc_static_c_abi_stdio_octal_hex_scan_stays_narrow(self) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_octal_hex_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_octal_hex_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_octal_hex_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_octal_hex_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_octal_hex_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_octal_hex_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "track_source_overflow",
            "ScanBase::Octal",
            "ScanBase::HexUpper",
            "overflowed = true",
            "negative = false",
            "static-c-stdio-octal-hex-scan",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf",
            '"1777777777777777777777!"',
            '"FFFFFFFFFFFFFFFF?"',
            '"-2000000000000000000000;"',
            '"1000000000000000A."',
            '"%22o#"',
            '"%17X#"',
            "ULLONG_MAX",
            "UINT_MAX",
            "ERANGE",
            "CRABC_STDIO_OCTAL_HEX_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_OCTAL_HEX_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_OCTAL_HEX_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=octal-hex-scan", wrapper
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "octal-hex-scan)",
            "CRABC_STDIO_OCTAL_HEX_SCAN_FREESTANDING",
            "libc_stdio_octal_hex_scan_probe.c",
            "libc_stdio_octal_hex_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "complete `%X` consumption",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn('id = "static-c-stdio-octal-hex-scan"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-octal-hex-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-octal-hex-scan", dispatcher)
        self.assertIn("run_libc_stdio_octal_hex_scan.sh", dispatcher)
        self.assertIn("stdio-octal-hex-scan-header-abi", dispatcher)
        self.assertIn("run_stdio_octal_hex_scan_header_abi.sh", dispatcher)

    def test_libc_static_c_abi_stdio_fixed_percent_scan_stays_narrow(
        self,
    ) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_percent_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_percent_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_percent_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_percent_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_fixed_percent_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_fixed_percent_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "static-c-stdio-fixed-percent-scan",
            "if unsafe { read_byte(directive) } == b'%'",
            "skip_input_space(cursor)",
            "if unsafe { read_byte(cursor) } != b'%'",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf",
            r'" \t\n\r\v\f%"',
            r'"%%!"',
            r'"\v\f"',
            "without an assignment",
            "CRABC_STDIO_FIXED_PERCENT_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FIXED_PERCENT_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_FIXED_PERCENT_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-percent-scan", wrapper
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "fixed-percent-scan)",
            "CRABC_STDIO_FIXED_PERCENT_SCAN_FREESTANDING",
            "libc_stdio_fixed_percent_scan_probe.c",
            "libc_stdio_fixed_percent_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "literal-percent scanner branch is no longer selected",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn('id = "static-c-stdio-fixed-percent-scan"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-fixed-percent-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-fixed-percent-scan", dispatcher)
        self.assertIn("run_libc_stdio_fixed_percent_scan.sh", dispatcher)
        self.assertIn("stdio-fixed-percent-scan-header-abi", dispatcher)
        self.assertIn("run_stdio_fixed_percent_scan_header_abi.sh", dispatcher)

    def test_libc_static_c_abi_stdio_fixed_format_whitespace_scan_stays_narrow(
        self,
    ) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_format_whitespace_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_format_whitespace_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_format_whitespace_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_format_whitespace_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_fixed_format_whitespace_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_fixed_format_whitespace_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "static-c-stdio-fixed-format-whitespace-scan",
            "if ascii_space(format_byte)",
            "while ascii_space(unsafe { read_byte(directive) })",
            "cursor = unsafe { skip_input_space(cursor) };",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf",
            r'" \t\n\r\v\f!"',
            r'"\v\f?"',
            "zero input whitespace",
            "result != EOF",
            "CRABC_STDIO_FIXED_FORMAT_WHITESPACE_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FIXED_FORMAT_WHITESPACE_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_FIXED_FORMAT_WHITESPACE_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-format-whitespace-scan",
            wrapper,
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "fixed-format-whitespace-scan)",
            "CRABC_STDIO_FIXED_FORMAT_WHITESPACE_SCAN_FREESTANDING",
            "libc_stdio_fixed_format_whitespace_scan_probe.c",
            "libc_stdio_fixed_format_whitespace_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "format-whitespace scanner branch is no longer selected",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn(
            'id = "static-c-stdio-fixed-format-whitespace-scan"', parity_ledger
        )
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-fixed-format-whitespace-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-fixed-format-whitespace-scan", dispatcher)
        self.assertIn("run_libc_stdio_fixed_format_whitespace_scan.sh", dispatcher)
        self.assertIn("stdio-fixed-format-whitespace-scan-header-abi", dispatcher)
        self.assertIn(
            "run_stdio_fixed_format_whitespace_scan_header_abi.sh", dispatcher
        )

    def test_libc_static_c_abi_stdio_fixed_literal_scan_stays_narrow(
        self,
    ) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_literal_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_literal_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_literal_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_literal_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_fixed_literal_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_fixed_literal_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "static-c-stdio-fixed-literal-scan",
            "if format_byte != b'%'",
            "if unsafe { read_byte(cursor) } == 0",
            "if unsafe { read_byte(cursor) } != format_byte",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf",
            '"crate/42", "crate/42"',
            '"stop!", "stop?"',
            "zero-assignment raw literal",
            "result != EOF",
            "CRABC_STDIO_FIXED_LITERAL_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FIXED_LITERAL_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_FIXED_LITERAL_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-literal-scan", wrapper)
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "fixed-literal-scan)",
            "CRABC_STDIO_FIXED_LITERAL_SCAN_FREESTANDING",
            "libc_stdio_fixed_literal_scan_probe.c",
            "libc_stdio_fixed_literal_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "raw-literal scanner branch is no longer selected",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn('id = "static-c-stdio-fixed-literal-scan"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-fixed-literal-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-fixed-literal-scan", dispatcher)
        self.assertIn("run_libc_stdio_fixed_literal_scan.sh", dispatcher)
        self.assertIn("stdio-fixed-literal-scan-header-abi", dispatcher)
        self.assertIn("run_stdio_fixed_literal_scan_header_abi.sh", dispatcher)

    def test_libc_static_c_abi_stdio_fixed_empty_format_scan_stays_narrow(
        self,
    ) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_empty_format_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_empty_format_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_empty_format_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_empty_format_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_fixed_empty_format_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_fixed_empty_format_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "static-c-stdio-fixed-empty-format-scan",
            "if format_byte == 0",
            "without entering a scanner state",
            "or accessing va_list",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf_empty_format",
            'sscanf("", "")',
            'sscanf("unread bytes", "")',
            "zero-assignment empty format",
            "trailing = va_arg(arguments, int)",
            "CRABC_STDIO_FIXED_EMPTY_FORMAT_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FIXED_EMPTY_FORMAT_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_FIXED_EMPTY_FORMAT_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-empty-format-scan", wrapper
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "fixed-empty-format-scan)",
            "CRABC_STDIO_FIXED_EMPTY_FORMAT_SCAN_FREESTANDING",
            "libc_stdio_fixed_empty_format_scan_probe.c",
            "libc_stdio_fixed_empty_format_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "empty-format scanner termination is no longer selected",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn(
            'id = "static-c-stdio-fixed-empty-format-scan"', parity_ledger
        )
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-fixed-empty-format-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-fixed-empty-format-scan", dispatcher)
        self.assertIn("run_libc_stdio_fixed_empty_format_scan.sh", dispatcher)
        self.assertIn("stdio-fixed-empty-format-scan-header-abi", dispatcher)
        self.assertIn(
            "run_stdio_fixed_empty_format_scan_header_abi.sh", dispatcher
        )

    def test_libc_static_c_abi_stdio_fixed_suppressed_character_scan_stays_narrow(
        self,
    ) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_suppressed_character_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_suppressed_character_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_suppressed_character_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_suppressed_character_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_fixed_suppressed_character_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_fixed_suppressed_character_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "static-c-stdio-fixed-suppressed-character-scan",
            "let suppress = if unsafe { read_byte(directive) } == b'*'",
            "destination = if suppress",
            "With the sealed `%*3c` profile's suppress flag",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf_suppressed_character",
            '"%*3c!"',
            "zero-assignment suppressed character",
            "trailing = va_arg(arguments, int)",
            "CRABC_STDIO_FIXED_SUPPRESSED_CHARACTER_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FIXED_SUPPRESSED_CHARACTER_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_FIXED_SUPPRESSED_CHARACTER_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-suppressed-character-scan",
            wrapper,
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "fixed-suppressed-character-scan)",
            "CRABC_STDIO_FIXED_SUPPRESSED_CHARACTER_SCAN_FREESTANDING",
            "libc_stdio_fixed_suppressed_character_scan_probe.c",
            "libc_stdio_fixed_suppressed_character_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "suppressed-character scanner state is no longer selected",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn(
            'id = "static-c-stdio-fixed-suppressed-character-scan"',
            parity_ledger,
        )
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-character-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-fixed-suppressed-character-scan", dispatcher)
        self.assertIn(
            "run_libc_stdio_fixed_suppressed_character_scan.sh", dispatcher
        )
        self.assertIn(
            "stdio-fixed-suppressed-character-scan-header-abi", dispatcher
        )
        self.assertIn(
            "run_stdio_fixed_suppressed_character_scan_header_abi.sh", dispatcher
        )

    def test_libc_static_c_abi_stdio_fixed_suppressed_string_scan_stays_narrow(
        self,
    ) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_suppressed_string_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_suppressed_string_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_suppressed_string_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_suppressed_string_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_fixed_suppressed_string_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_fixed_suppressed_string_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "static-c-stdio-fixed-suppressed-string-scan",
            "let suppress = if unsafe { read_byte(directive) } == b'*'",
            "With the sealed `%*3s` profile's suppress flag",
            "destination = if suppress",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf_suppressed_string",
            '"%*3s!"',
            "zero-assignment suppressed token",
            "trailing = va_arg(arguments, int)",
            '"%*3ls"',
            "CRABC_STDIO_FIXED_SUPPRESSED_STRING_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FIXED_SUPPRESSED_STRING_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_FIXED_SUPPRESSED_STRING_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-suppressed-string-scan",
            wrapper,
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "fixed-suppressed-string-scan)",
            "CRABC_STDIO_FIXED_SUPPRESSED_STRING_SCAN_FREESTANDING",
            "libc_stdio_fixed_suppressed_string_scan_probe.c",
            "libc_stdio_fixed_suppressed_string_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "suppressed-string scanner state is no longer selected",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn(
            'id = "static-c-stdio-fixed-suppressed-string-scan"',
            parity_ledger,
        )
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-string-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-fixed-suppressed-string-scan", dispatcher)
        self.assertIn(
            "run_libc_stdio_fixed_suppressed_string_scan.sh", dispatcher
        )
        self.assertIn(
            "stdio-fixed-suppressed-string-scan-header-abi", dispatcher
        )
        self.assertIn(
            "run_stdio_fixed_suppressed_string_scan_header_abi.sh", dispatcher
        )

    def test_libc_static_c_abi_stdio_fixed_suppressed_scanset_scan_stays_narrow(
        self,
    ) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_suppressed_scanset_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_suppressed_scanset_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_suppressed_scanset_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_suppressed_scanset_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_fixed_suppressed_scanset_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_fixed_suppressed_scanset_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "static-c-stdio-fixed-suppressed-scanset-scan artifact",
            "let width_start = directive;",
            "&& suppress",
            "parsed_width == 3",
            "read_byte(width_start) } == b'3'",
            "b'a' | b'b' | b'c'",
            "no-destination state",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf_suppressed_scanset",
            '"%*3[abc]!"',
            "shorter than width three succeeds",
            "does not skip leading C-locale input",
            "high_format",
            '"%*[abc]"',
            '"%*03[abc]"',
            '"%*3[a-z]"',
            '"%*3[^abc]"',
            '"%*3l[abc]"',
            "CRABC_STDIO_FIXED_SUPPRESSED_SCANSET_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FIXED_SUPPRESSED_SCANSET_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_FIXED_SUPPRESSED_SCANSET_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-suppressed-scanset-scan",
            wrapper,
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "fixed-suppressed-scanset-scan)",
            "CRABC_STDIO_FIXED_SUPPRESSED_SCANSET_SCAN_FREESTANDING",
            "libc_stdio_fixed_suppressed_scanset_scan_probe.c",
            "libc_stdio_fixed_suppressed_scanset_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "suppressed-scanset scanner state is no longer selected",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn(
            'id = "static-c-stdio-fixed-suppressed-scanset-scan"',
            parity_ledger,
        )
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-scanset-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-fixed-suppressed-scanset-scan", dispatcher)
        self.assertIn(
            "run_libc_stdio_fixed_suppressed_scanset_scan.sh", dispatcher
        )
        self.assertIn(
            "stdio-fixed-suppressed-scanset-scan-header-abi", dispatcher
        )
        self.assertIn(
            "run_stdio_fixed_suppressed_scanset_scan_header_abi.sh", dispatcher
        )

    def test_libc_static_c_abi_stdio_fixed_suppressed_count_scan_stays_narrow(
        self,
    ) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_suppressed_count_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_fixed_suppressed_count_scan_start.S"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_suppressed_count_scan_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_fixed_suppressed_count_scan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_fixed_suppressed_count_scan_header_abi.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_fixed_suppressed_count_scan.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "static-c-stdio-fixed-suppressed-count-scan artifact",
            "With the sealed",
            "count state sees no destination",
            "neither VaList::next_arg nor assign_count",
            "if !suppress",
        ):
            self.assertIn(required, implementation)
        self.assertIn("sscanf", static_export_names)
        self.assertIn("vsscanf", static_export_names)
        for unselected in ("scanf", "fscanf", "vfscanf", "fwscanf", "swscanf"):
            self.assertNotIn(unselected, static_export_names)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&sscanf)",
            "call_vsscanf_suppressed_count",
            '"%*n"',
            '"a%*nb"',
            "zero-assignment suppressed count",
            "does not consume input",
            "CRABC_STDIO_FIXED_SUPPRESSED_COUNT_SCAN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FIXED_SUPPRESSED_COUNT_SCAN_HEADER_C11",
            "crabc_sscanf_signature",
            "crabc_vsscanf_signature",
        ):
            self.assertIn(required, c_header_probe)
        for required in (
            "CRABC_STDIO_FIXED_SUPPRESSED_COUNT_SCAN_HEADER_CXX17",
            "decltype(&sscanf)",
            "decltype(&vsscanf)",
            "crabc_sscanf_reference",
            "crabc_vsscanf_reference",
        ):
            self.assertIn(required, cxx_header_probe)
        for required in (
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "sscanf vsscanf",
            "mangled scanf reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=fixed-suppressed-count-scan",
            wrapper,
        )
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        for required in (
            "fixed-suppressed-count-scan)",
            "CRABC_STDIO_FIXED_SUPPRESSED_COUNT_SCAN_FREESTANDING",
            "libc_stdio_fixed_suppressed_count_scan_probe.c",
            "libc_stdio_fixed_suppressed_count_scan_start.S",
            "REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)",
            "suppressed-count scanner state is no longer selected",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn(
            'id = "static-c-stdio-fixed-suppressed-count-scan"',
            parity_ledger,
        )
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-count-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-fixed-suppressed-count-scan", dispatcher)
        self.assertIn(
            "run_libc_stdio_fixed_suppressed_count_scan.sh", dispatcher
        )
        self.assertIn(
            "stdio-fixed-suppressed-count-scan-header-abi", dispatcher
        )
        self.assertIn(
            "run_stdio_fixed_suppressed_count_scan_header_abi.sh", dispatcher
        )

    def test_libc_static_c_abi_stdio_float_hex_output_stays_narrow(self) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_float_hex_output_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_float_hex_output_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_float_hex_output.sh"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "unsafe fn write_hex_float",
            "value.to_bits()",
            "ties-to-even",
            "should_round_hexadecimal",
            "fegetround()",
            "emitted_length",
            "0x2...pE",
            "args.next_arg::<f64>()",
            "b'a' | b'A' if output.allow_float() && matches!(length, Length::None | Length::L)",
        ):
            self.assertIn(required, implementation)
        self.assertNotIn("libm::", implementation)
        for required in (
            '"[%a][%A][%+a][% a][%#a]"',
            '"%#.0a|%.0a|%.1a|%.3a|%.14a"',
            '"%#.0a|%.1a|%#.0a|%.1a"',
            '"%.2147483647a"',
            "FE_UPWARD",
            "FE_DOWNWARD",
            "FE_TOWARDZERO",
            '"[0x1p-1074][0x1p-1022][-0x0p+0]"',
            '"[%a][%+a][% a][%020a]"',
            '"%a/%a/%a/%a/%a/%a/%a/%a/%a"',
            '"[%*.*a/%d/%la]"',
            '"%3$a"',
            '"a%a%n"',
            "CRABC_STDIO_FLOAT_HEX_OUTPUT_FREESTANDING",
            '"%La"',
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        self.assertIn(
            "CRABC_STDIO_FORMAT_SCAN_PROFILE=float-hex-output", runner
        )
        self.assertIn("run_libc_stdio_format_scan.sh", runner)
        for required in (
            "float-hex-output)",
            "CRABC_STDIO_FLOAT_HEX_OUTPUT_FREESTANDING",
            "libc_stdio_float_hex_output_probe.c",
            "libc_stdio_float_hex_output_start.S",
            "write_hex_float",
            "fenv.h",
            "decimal libm formatting edge",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
        ):
            self.assertIn(required, shared_runner)
        self.assertNotIn("--whole-archive", shared_runner)
        self.assertIn('id = "static-c-stdio-float-hex-output"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-float-hex-output"',
            ledger,
        )
        self.assertIn("libc-stdio-float-hex-output", dispatcher)
        self.assertIn("run_libc_stdio_float_hex_output.sh", dispatcher)

    def test_libc_static_c_abi_stdio_errno_output_stays_narrow(self) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        error_strings = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "error_strings.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_errno_output_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_errno_output_start.S"
        ).read_text(encoding="utf-8")
        shared_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_stdio_format_scan.sh"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "compat" / "x86_64" / "run_libc_stdio_errno_output.sh"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "b'm' if output.allow_errno_message() && length == Length::None",
            "error_strings::error_message",
            "errno::get_errno()",
            "Bare `%m` consumes",
        ):
            self.assertIn(required, implementation)
        self.assertNotIn("strerror(", implementation)
        self.assertIn("pub(super) fn error_message", error_strings)
        self.assertIn("interposable C `strerror` call", error_strings)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&snprintf)",
            "call_vsnprintf",
            '"[%-20.8m][%020m][%#.0m]"',
            '"%m/%d/%m"',
            '"[%*.*m]"',
            '"%lm"',
            '"%1$m"',
            "CRABC_STDIO_ERRNO_OUTPUT_FREESTANDING",
            "check_candidate_limitations",
        ):
            self.assertIn(required, fixture)
        for required in (
            "arch_prctl(ARCH_SET_FS",
            "%fs:0",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "CRABC_STDIO_FORMAT_SCAN_PROFILE",
            "errno-output)",
            "CRABC_STDIO_ERRNO_OUTPUT_FREESTANDING",
            "libc_stdio_errno_output_probe.c",
            "b'm' if output.allow_errno_message() && length == Length::None",
            "error_strings::error_message",
            "errno::get_errno()",
            "-nostdlib -static",
            "R_X86_64_TPOFF",
        ):
            self.assertIn(required, shared_runner)
        self.assertIn("CRABC_STDIO_FORMAT_SCAN_PROFILE=errno-output", wrapper)
        self.assertIn("run_libc_stdio_format_scan.sh", wrapper)
        self.assertIn('id = "static-c-stdio-errno-output"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-errno-output"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-errno-output", dispatcher)
        self.assertIn("run_libc_stdio_errno_output.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_line_io_stays_bounded(self) -> None:
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_line_io_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_line_io_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_line_io_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_line_io_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_line_io_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_line_io.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in ("fgets", "fputs", "puts"):
            self.assertIn(symbol, exports)
            self.assertIn(f'pub unsafe extern "C" fn {symbol}', implementation)
        for symbol in (
            "fgets_unlocked",
            "fputs_unlocked",
            "gets",
            "getw",
            "putw",
            "getdelim",
            "getline",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/{fgets,fputs,puts}.c",
            "if !is_permanent_stream(stream)",
            "count <= 1",
            "character == c_int::from(b'\\n')",
            "fputs keeps this call inside the permanent stdout boundary",
            "flush_output(ptr::addr_of_mut!(STDOUT_STREAM))",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("fgets", "fputs", "puts", "FILE"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_LINE_IO_C11",
            "CRABC_STDIO_PERMANENT_LINE_IO_CXX17",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "mangled permanent-line-I/O reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "fgets_entry(line, 3, stdin)",
            "fgets_entry(line, 1, stdin)",
            "fgets_entry(line, 4, stdin) != NULL",
            'fputs_entry("first", stdout)',
            'puts_entry("second")',
            'fputs_entry("third\\n", stdout)',
            'fputs_entry("tail", stdout)',
            "fflush_entry(stdout)",
            "fputs_entry(expected, stderr)",
            "CRABC_STDIO_PERMANENT_LINE_IO_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_line_io_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_line_io_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong ${symbol}",
            "fgets_unlocked fputs_unlocked gets getw putw getdelim getline",
            "-nostdlib -static",
            "dynamic TLS model",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-line-io"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-line-io"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-line-io-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-line-io", dispatcher)
        self.assertIn("run_stdio_permanent_line_io_header_abi.sh", dispatcher)
        self.assertIn("run_libc_stdio_permanent_line_io.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_byte_io_stays_bounded(self) -> None:
        """Permanent byte aliases are not pathname or general stream proof."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_byte_io_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_byte_io_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_byte_io_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_byte_io_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_byte_io_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_byte_io.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in (
            "fgetc",
            "getc",
            "getchar",
            "fputc",
            "putc",
            "putchar",
            "ungetc",
        ):
            self.assertIn(symbol, exports)
            self.assertIn(f'pub unsafe extern "C" fn {symbol}', implementation)
        for symbol in (
            "fgetc_unlocked",
            "fputc_unlocked",
            "getc_unlocked",
            "getchar_unlocked",
            "putc_unlocked",
            "putchar_unlocked",
            "gets",
            "getw",
            "putw",
            "getdelim",
            "getline",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/{fgetc,getc,getchar,fputc,putc,putchar,ungetc}.c",
            "raw_syscall::SYS_READ",
            "raw_syscall::SYS_WRITE",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in (
                "fgetc",
                "getc",
                "getchar",
                "fputc",
                "putc",
                "putchar",
                "ungetc",
                "FILE",
            ):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_BYTE_IO_C11",
            "CRABC_STDIO_PERMANENT_BYTE_IO_CXX17",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "mangled permanent-byte-I/O reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "fgetc_entry(stdin) != 'A'",
            "getc_entry(stdin) != 'B'",
            "getchar_entry() != EOF",
            "ungetc_entry(-2, stdin) != 254 || getchar_entry() != 254",
            "fgetc_entry(stdin) != EOF",
            "fputc_entry(-2, stderr) != 254",
            "putc_entry('C', stderr) != 'C'",
            "putchar_entry('P') != 'P'",
            "fflush_entry(stdout) != 0",
            "CRABC_STDIO_PERMANENT_BYTE_IO_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_byte_io_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_byte_io_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong ${symbol}",
            "fgetc_unlocked fputc_unlocked getc_unlocked getchar_unlocked",
            "-nostdlib -static",
            "dynamic TLS model",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-byte-io"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-byte-io"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-byte-io-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-byte-io", dispatcher)
        self.assertIn("run_stdio_permanent_byte_io_header_abi.sh", dispatcher)
        self.assertIn("run_libc_stdio_permanent_byte_io.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_status_stays_bounded(self) -> None:
        """Status predicates observe stdin only; they are not general FILE state."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_status_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_status_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_status_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_status_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_status_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_status.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in ("feof", "ferror", "clearerr"):
            self.assertIn(symbol, exports)
            self.assertIn(f'pub unsafe extern "C" fn {symbol}', implementation)
        self.assertIn("feof_unlocked", exports)
        self.assertIn("ferror_unlocked", exports)
        for symbol in (
            "clearerr_unlocked",
            "fgetc_unlocked",
            "getc_unlocked",
            "getchar_unlocked",
            "fputc_unlocked",
            "putc_unlocked",
            "putchar_unlocked",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/{feof,ferror,clearerr}.c",
            "F_EOF",
            "F_ERR",
            "raw_syscall::SYS_READ",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("feof", "ferror", "clearerr", "FILE"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_STATUS_C11",
            "CRABC_STDIO_PERMANENT_STATUS_CXX17",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "mangled permanent-stream-status reference",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "redirect_empty_input",
            "fgetc_entry(stdin) != EOF",
            "feof_entry(stdin) == 0 || ferror_entry(stdin) != 0",
            "clearerr_entry(stdin)",
            "close_entry(STDIN_FILENO)",
            "feof_entry(stdin) != 0 || ferror_entry(stdin) == 0",
            "CRABC_STDIO_PERMANENT_STATUS_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_status_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_status_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong ${symbol}",
            "ferror_unlocked is separately selected",
            "--gc-sections",
            "-nostdlib -static",
            "dynamic TLS model",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-status"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-status"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-status-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-status", dispatcher)
        self.assertIn("run_stdio_permanent_status_header_abi.sh", dispatcher)
        self.assertIn("run_libc_stdio_permanent_status.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_freading_stdin_stays_bounded(
        self,
    ) -> None:
        """__freading observes fixed stdin F_NOWR only, not general input."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_freading_stdin_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_freading_stdin_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_freading_stdin_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_freading_stdin_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_freading_stdin_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_freading_stdin.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in (
            "__freading",
            "__fsetlocking",
            "__fseterr",
            "__freadable",
            "__fwritable",
            "__fbufsize",
            "__flbf",
        ):
            self.assertIn(symbol, exports)
        for symbol in (
            "__fwriting",
            "__fpending",
            "__fpurge",
            "_flushlbf",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/ext.c",
            "src/stdio/stdin.c",
            'pub unsafe extern "C" fn __freading',
            "(f->flags & F_NOWR) || f->rend",
            "stream != ptr::addr_of_mut!(STDIN_STREAM)",
            "StandardStream::new(0, F_PERM | F_NOWR)",
            "((*stream).flags & F_NOWR != 0) as c_int",
            "this leaf never observes rend",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("stdio_ext.h", "__freading", "FILE", "FREADING_STDIN"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_FREADING_STDIN_C11",
            "CRABC_STDIO_PERMANENT_FREADING_STDIN_CXX17",
            "stdio_ext.h stdio.h features.h bits/alltypes.h",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "freading_entry(stdin) != 1",
            "__freading(stdin) != 1",
            "CRABC_STDIO_PERMANENT_FREADING_STDIN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for forbidden in (
            "fputc",
            "fflush",
            "fgetc",
            "stdout",
            "stderr",
            "fopen",
            "tmpfile",
            "dup",
            "close",
            "setvbuf",
            "__freadable",
            "__fwriting",
        ):
            self.assertNotIn(forbidden, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_freading_stdin_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_freading_stdin_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong __freading",
            "__fwriting",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "__freading unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-freading-stdin"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-freading-stdin"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-freading-stdin-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-freading-stdin", dispatcher)
        self.assertIn(
            "stdio-permanent-freading-stdin-header-abi) ;;", dispatcher
        )
        self.assertIn(
            "|libc-stdio-permanent-freading-stdin|", dispatcher
        )
        self.assertIn(
            "run_stdio_permanent_freading_stdin_header_abi.sh", dispatcher
        )
        self.assertIn("run_libc_stdio_permanent_freading_stdin.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_fseterr_stdin_stays_bounded(
        self,
    ) -> None:
        """__fseterr selects one permanent F_ERR marker, not general status."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fseterr_stdin_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fseterr_stdin_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_fseterr_stdin_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fseterr_stdin_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fseterr_stdin_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_fseterr_stdin.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in (
            "__freading",
            "__fsetlocking",
            "__fseterr",
            "__freadable",
            "__fwritable",
            "__fbufsize",
            "__flbf",
        ):
            self.assertIn(symbol, exports)
        for symbol in (
            "__fwriting",
            "__fpending",
            "__fpurge",
            "_flushlbf",
            "__freadahead",
            "__freadptr",
            "__freadptrinc",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/ext2.c",
            'pub unsafe extern "C" fn __fseterr',
            "stream != ptr::addr_of_mut!(STDIN_STREAM)",
            "(*stream).flags |= F_ERR",
            "Set musl's fixed permanent-stdin error marker.",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("stdio_ext.h", "__fseterr", "FILE", "FSETERR_STDIN"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_FSETERR_STDIN_C11",
            "CRABC_STDIO_PERMANENT_FSETERR_STDIN_CXX17",
            "stdio_ext.h stdio.h features.h bits/alltypes.h",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "ferror(stdin) != 0",
            "__fseterr(stdin);",
            "fseterr_entry(stdin);",
            "clearerr(stdin);",
            "CRABC_STDIO_PERMANENT_FSETERR_STDIN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for forbidden in (
            "fputc",
            "fflush",
            "fgetc",
            "stdout",
            "stderr",
            "fopen",
            "tmpfile",
            "dup",
            "close",
            "setvbuf",
            "__freading",
            "__freadable",
            "__fwriting",
            "__fwritable",
        ):
            self.assertNotIn(forbidden, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_fseterr_stdin_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_fseterr_stdin_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong __fseterr",
            "ferror clearerr",
            "__fwriting",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "__fseterr unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-fseterr-stdin"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-fseterr-stdin"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-fseterr-stdin-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-fseterr-stdin", dispatcher)
        self.assertIn(
            "stdio-permanent-fseterr-stdin-header-abi) ;;", dispatcher
        )
        self.assertIn("|libc-stdio-permanent-fseterr-stdin|", dispatcher)
        self.assertIn("run_stdio_permanent_fseterr_stdin_header_abi.sh", dispatcher)
        self.assertIn("run_libc_stdio_permanent_fseterr_stdin.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_freadable_stdin_stays_bounded(
        self,
    ) -> None:
        """__freadable observes fixed stdin F_NORD only, not general input."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_freadable_stdin_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_freadable_stdin_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_freadable_stdin_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_freadable_stdin_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_freadable_stdin_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_freadable_stdin.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in ("__freading", "__fsetlocking", "__fseterr", "__freadable"):
            self.assertIn(symbol, exports)
        for symbol in (
            "__fwriting",
            "__fpending",
            "__fpurge",
            "_flushlbf",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/ext.c",
            'pub unsafe extern "C" fn __freadable',
            "!(f->flags & F_NORD)",
            "stream != ptr::addr_of_mut!(STDIN_STREAM)",
            "StandardStream::new(0, F_PERM | F_NOWR)",
            "((*stream).flags & F_NORD == 0) as c_int",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("stdio_ext.h", "__freadable", "FILE", "FREADABLE_STDIN"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_FREADABLE_STDIN_C11",
            "CRABC_STDIO_PERMANENT_FREADABLE_STDIN_CXX17",
            "stdio_ext.h stdio.h features.h bits/alltypes.h",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "freadable_entry(stdin) != 1",
            "__freadable(stdin) != 1",
            "CRABC_STDIO_PERMANENT_FREADABLE_STDIN_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for forbidden in (
            "fputc",
            "fflush",
            "fgetc",
            "stdout",
            "stderr",
            "fopen",
            "tmpfile",
            "dup",
            "close",
            "setvbuf",
            "__fwriting",
        ):
            self.assertNotIn(forbidden, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_freadable_stdin_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_freadable_stdin_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong __freadable",
            "__fwriting",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "__freadable unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-freadable-stdin"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-freadable-stdin"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-freadable-stdin-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-freadable-stdin", dispatcher)
        self.assertIn(
            "run_stdio_permanent_freadable_stdin_header_abi.sh", dispatcher
        )
        self.assertIn("run_libc_stdio_permanent_freadable_stdin.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_fbufsize_stderr_stays_bounded(
        self,
    ) -> None:
        """__fbufsize observes fixed stderr capacity only, not buffering."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fbufsize_stderr_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fbufsize_stderr_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_fbufsize_stderr_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fbufsize_stderr_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fbufsize_stderr_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_fbufsize_stderr.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in (
            "__freading",
            "__fsetlocking",
            "__fseterr",
            "__freadable",
            "__fwritable",
            "__fbufsize",
        ):
            self.assertIn(symbol, exports)
        for symbol in (
            "__fwriting",
            "__fpending",
            "__fpurge",
            "_flushlbf",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/ext.c",
            'pub unsafe extern "C" fn __fbufsize',
            "return f->buf_size",
            "stream != ptr::addr_of_mut!(STDERR_STREAM)",
            "StandardStream::new(2, F_PERM | F_NORD)",
            "STDERR_STREAM.capacity = 0",
            "unsafe { (*stream).capacity }",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("stdio_ext.h", "__fbufsize", "FILE", "FBUFSIZE_STDERR"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_FBUFSIZE_STDERR_C11",
            "CRABC_STDIO_PERMANENT_FBUFSIZE_STDERR_CXX17",
            "stdio_ext.h stdio.h features.h bits/alltypes.h",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "fbufsize_entry(stderr) != 0",
            "__fbufsize(stderr) != 0",
            "CRABC_STDIO_PERMANENT_FBUFSIZE_STDERR_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for forbidden in (
            "fputc",
            "fflush",
            "fgetc",
            "stdin",
            "stdout",
            "fopen",
            "tmpfile",
            "dup",
            "close",
            "setvbuf",
            "__freadable",
            "__fwritable",
            "__fwriting",
        ):
            self.assertNotIn(forbidden, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_fbufsize_stderr_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_fbufsize_stderr_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong __fbufsize",
            "__fwriting",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "__fbufsize unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-fbufsize-stderr"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-fbufsize-stderr"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-fbufsize-stderr-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-fbufsize-stderr", dispatcher)
        self.assertIn(
            "stdio-permanent-fbufsize-stderr-header-abi) ;;", dispatcher
        )
        self.assertIn(
            "|libc-stdio-permanent-fbufsize-stderr|", dispatcher
        )
        self.assertIn(
            "run_stdio_permanent_fbufsize_stderr_header_abi.sh", dispatcher
        )
        self.assertIn("run_libc_stdio_permanent_fbufsize_stderr.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_flbf_stderr_stays_bounded(
        self,
    ) -> None:
        """__flbf observes fixed stderr lbf only, not line buffering."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_flbf_stderr_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_flbf_stderr_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_flbf_stderr_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_flbf_stderr_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_flbf_stderr_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_flbf_stderr.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in (
            "__freading",
            "__fsetlocking",
            "__fseterr",
            "__freadable",
            "__fwritable",
            "__fbufsize",
            "__flbf",
        ):
            self.assertIn(symbol, exports)
        for symbol in (
            "__fwriting",
            "__fpending",
            "__fpurge",
            "_flushlbf",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/ext.c",
            "src/stdio/stderr.c",
            'pub unsafe extern "C" fn __flbf',
            "return f->lbf >= 0",
            "const STDERR_LBF: c_int = -1",
            "stream != ptr::addr_of_mut!(STDERR_STREAM)",
            "(STDERR_LBF >= 0) as c_int",
            "StandardStream::new(2, F_PERM | F_NORD)",
            "if !unsafe { is_path_stream(stream) }",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("stdio_ext.h", "__flbf", "FILE", "FLBF_STDERR"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_FLBF_STDERR_C11",
            "CRABC_STDIO_PERMANENT_FLBF_STDERR_CXX17",
            "stdio_ext.h stdio.h features.h bits/alltypes.h",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "flbf_entry(stderr) != 0",
            "__flbf(stderr) != 0",
            "CRABC_STDIO_PERMANENT_FLBF_STDERR_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for forbidden in (
            "fputc",
            "fflush",
            "fgetc",
            "stdin",
            "stdout",
            "fopen",
            "tmpfile",
            "dup",
            "close",
            "setvbuf",
            "__freadable",
            "__fbufsize",
            "__fwriting",
        ):
            self.assertNotIn(forbidden, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_flbf_stderr_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_flbf_stderr_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong __flbf",
            "__fwriting",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "__flbf unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-flbf-stderr"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-flbf-stderr"',
            ledger,
        )
        self.assertIn("does not select stdio.stream-io", ledger)
        self.assertIn("stdio-permanent-flbf-stderr-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-flbf-stderr", dispatcher)
        self.assertIn("stdio-permanent-flbf-stderr-header-abi) ;;", dispatcher)
        self.assertIn("|libc-stdio-permanent-flbf-stderr|", dispatcher)
        self.assertIn("run_stdio_permanent_flbf_stderr_header_abi.sh", dispatcher)
        self.assertIn("run_libc_stdio_permanent_flbf_stderr.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_fwritable_stderr_stays_bounded(
        self,
    ) -> None:
        """__fwritable observes fixed stderr F_NOWR only, not general output."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fwritable_stderr_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fwritable_stderr_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_fwritable_stderr_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fwritable_stderr_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fwritable_stderr_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_fwritable_stderr.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for symbol in ("__freading", "__fsetlocking", "__fseterr", "__fwritable"):
            self.assertIn(symbol, exports)
        for symbol in (
            "__fwriting",
            "__fpending",
            "__fpurge",
            "_flushlbf",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/ext.c",
            'pub unsafe extern "C" fn __fwritable',
            "!(f->flags & F_NOWR)",
            "stream != ptr::addr_of_mut!(STDERR_STREAM)",
            "StandardStream::new(2, F_PERM | F_NORD)",
            "((*stream).flags & F_NOWR == 0) as c_int",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("stdio_ext.h", "__fwritable", "FILE", "FWRITABLE_STDERR"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_FWRITABLE_STDERR_C11",
            "CRABC_STDIO_PERMANENT_FWRITABLE_STDERR_CXX17",
            "stdio_ext.h stdio.h features.h bits/alltypes.h",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "fwritable_entry(stderr) != 1",
            "__fwritable(stderr) != 1",
            "CRABC_STDIO_PERMANENT_FWRITABLE_STDERR_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for forbidden in (
            "fputc",
            "fflush",
            "fgetc",
            "stdin",
            "stdout",
            "fopen",
            "tmpfile",
            "dup",
            "close",
            "setvbuf",
            "__fwriting",
        ):
            self.assertNotIn(forbidden, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_fwritable_stderr_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_fwritable_stderr_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong __fwritable",
            "__fwriting",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "__fwritable unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-fwritable-stderr"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-fwritable-stderr"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-fwritable-stderr-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-fwritable-stderr", dispatcher)
        self.assertIn(
            "run_stdio_permanent_fwritable_stderr_header_abi.sh", dispatcher
        )
        self.assertIn("run_libc_stdio_permanent_fwritable_stderr.sh", dispatcher)

    def test_libc_static_c_abi_stdio_permanent_fileno_stays_bounded(self) -> None:
        """fileno observes only the three permanent descriptor adapters."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fileno_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fileno_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_fileno_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fileno_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fileno_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_fileno.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn("fileno", exports)
        self.assertIn("fileno_unlocked", exports)
        for required in (
            "src/stdio/fileno.c",
            'pub unsafe extern "C" fn fileno',
            "StandardStream::new(0, F_PERM | F_NOWR)",
            "StandardStream::new(1, F_PERM | F_NORD)",
            "StandardStream::new(2, F_PERM | F_NORD)",
            "(*stream).file_descriptor",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in ("fileno", "FILE", "_POSIX_C_SOURCE", "REQUIRE_HIDDEN"):
                self.assertIn(required, probe)
        for required in (
            "CRABC_STDIO_PERMANENT_FILENO_C11",
            "CRABC_STDIO_PERMANENT_FILENO_CXX17",
            "CRABC_STDIO_PERMANENT_FILENO_REQUIRE_HIDDEN",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "assert_strict_hidden",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "fileno_entry(stdin) != 0",
            "fileno_entry(stdout) != 1",
            "fileno_entry(stderr) != 2",
            "CRABC_STDIO_PERMANENT_FILENO_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for forbidden in ("fgetc", "fputc", "dup", "pipe", "fopen", "tmpfile"):
            self.assertNotIn(forbidden, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_fileno_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_fileno_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong fileno",
            "fileno_unlocked",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "fileno unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-fileno"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-fileno"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-fileno-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-fileno", dispatcher)
        self.assertIn("run_stdio_permanent_fileno_header_abi.sh", dispatcher)
        self.assertIn("run_libc_stdio_permanent_fileno.sh", dispatcher)

    def test_libc_static_c_abi_stdio_path_stream_stays_one_slot(self) -> None:
        """The pathname stream is a fixed static lifecycle, not general stdio."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_stdio_path_stream_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_stdio_path_stream_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_stdio_path_stream.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        symbols = (
            "fopen",
            "fclose",
            "setvbuf",
            "fseek",
            "fseeko",
            "ftell",
            "ftello",
            "rewind",
            "fgetpos",
            "fsetpos",
        )
        for symbol in symbols:
            if symbol in {"fseeko", "ftello"}:
                self.assertIn(f'pub(super) unsafe extern "C" fn __{symbol}', implementation)
                self.assertIn(f'".weak {symbol}"', implementation)
                self.assertIn(f'".set {symbol}, __{symbol}"', implementation)
                self.assertIn(f'".hidden __{symbol}"', implementation)
                self.assertIn(f"__{symbol}", exports)
            else:
                self.assertIn(f'pub unsafe extern "C" fn {symbol}', implementation)
            self.assertIn(symbol, exports)
        for required in (
            "static mut PATH_STREAM:",
            "static mut PATH_STREAM_STORAGE:",
            "enum PathOpenMode",
            "parse_path_open_mode",
            "match *mode as u8",
            "prepare_path_read",
            "prepare_path_write",
            "F_EXTERNAL_BUFFER",
            "F_IO_STARTED",
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_CLOSE",
            "raw_syscall::SYS_LSEEK",
        ):
            self.assertIn(required, implementation)
        for required in (
            'fopen_entry(path, "w+")',
            'fopen_entry(path, "a")',
            "errno != EMFILE",
            "_IONBF",
            "setvbuf_entry(stream, caller_buffer, _IOFBF",
            "fflush_entry(NULL)",
            "lseek_entry(fileno_entry(stream), 0, SEEK_CUR)",
            "fseeko_entry(stream, -1, SEEK_SET)",
            "ferror(stream) != 0",
            "saved_bytes[index] != 0xa5U",
            "read-ahead-adjusted",
            "fseeko_entry(stream, 1, SEEK_CUR)",
            "fgetpos_entry",
            "fsetpos_entry",
            "rewind_entry",
            'fopen_entry(path, "r")',
        ):
            self.assertIn(required, fixture)
        for required in (
            "untouched Linux entry stack",
            "__crabc_x86_static_tls_bootstrap",
            "exit_group",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_stdio_standard_header_abi.sh",
            "-nostdlib -static",
            "--no-undefined",
            "fdopen freopen",
            "fflush fileno lseek",
            "SYS_OPEN SYS_CLOSE SYS_LSEEK",
            "initial-TLS",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-path-stream"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-path-stream"', ledger
        )
        self.assertIn("libc-stdio-path-stream", dispatcher)
        self.assertIn("run_libc_stdio_path_stream.sh", dispatcher)

    def test_libc_static_c_abi_stdio_tmpfile_stays_bounded(self) -> None:
        """tmpfile remains one private slot route, not a temp-file framework."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        header = (ROOT / "include" / "stdio.h").read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "libc_stdio_tmpfile_header_probe.cpp"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_stdio_tmpfile_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_stdio_tmpfile_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_stdio_tmpfile.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn("tmpfile", exports)
        self.assertNotIn("tmpfile64", exports)
        self.assertIn("#define tmpfile64 tmpfile", header)
        for required in (
            "src/stdio/tmpfile.c",
            "src/temp/__randname.c",
            "const TMPFILE_RANDOM_BYTES: usize = 12;",
            "MAXTRIES = 100",
            "const TMPFILE_MAX_ATTEMPTS: usize = 100;",
            'pub unsafe extern "C" fn tmpfile',
            "raw_syscall::SYS_GETRANDOM",
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_UNLINK",
            "raw_syscall::SYS_CLOSE",
            "O_RDWR | O_CREAT | O_EXCL | O_LARGEFILE",
            "0o600",
            "last_open_error",
            "immediate unlinking fails",
        ):
            self.assertIn(required, implementation)
        for required in (
            "_LARGEFILE64_SOURCE",
            "tmpfile64",
            "crabc_tmpfile_signature",
            "decltype(&tmpfile64)",
            "crabc_tmpfile64_reference",
        ):
            self.assertIn(required, cxx_probe)
        for required in (
            "tmpfile_entry != tmpfile64_entry",
            "old_mask = umask_entry(0)",
            "(state.st_mode & S_IFMT) != S_IFREG",
            "(state.st_mode & 0777) != 0600",
            "state.st_nlink != 0",
            "umask_entry(0600)",
            "(state.st_mode & 0777) != 0",
            "F_GETFD",
            "fwrite_entry(payload",
            "fseek_entry(stream, 0, SEEK_SET)",
            "fread_entry(observed",
            "CRABC_STDIO_TMPFILE_FREESTANDING",
            "errno != EMFILE",
            "reused = tmpfile_entry()",
        ):
            self.assertIn(required, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_tmpfile_probe",
            "mov $231,%eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "STATIC_C_ABI_EXPORTS",
            "run_musl_oracle.sh",
            "libc_stdio_tmpfile_header_probe.cpp",
            "-std=c++17",
            "strong tmpfile",
            "header-only tmpfile64 alias",
            "-nostdlib -static",
            "SYS_GETRANDOM SYS_OPEN SYS_UNLINK SYS_CLOSE",
            "dynamic TLS model",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-tmpfile"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-tmpfile"', ledger
        )
        self.assertIn("tmpnam`/`tempnam`/`mkstemp`/`mkdtemp`/`mktemp", ledger)
        self.assertIn("libc-stdio-tmpfile", dispatcher)
        self.assertIn("run_libc_stdio_tmpfile.sh", dispatcher)

    def test_libc_static_c_abi_fopen64_alias_stays_source_only(self) -> None:
        """The LP64 `fopen64` spelling remains a source-only musl alias."""
        header = (ROOT / "include" / "stdio.h").read_text(encoding="utf-8")
        c_probe = (
            ROOT / "compat" / "x86_64" / "fopen64_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "fopen64_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_fopen64_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_fopen64_alias_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_fopen64_alias_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_fopen64_alias.sh"
        ).read_text(encoding="utf-8")
        exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertNotIn("fopen64", exports)
        self.assertIn("#if defined(_LARGEFILE64_SOURCE)", header)
        self.assertIn("#define fopen64 fopen", header)
        for probe in (c_probe, cxx_probe):
            for required in (
                "_LARGEFILE64_SOURCE",
                "fopen64",
                "fopen",
                "macro alias",
            ):
                self.assertIn(required, probe)
        for required in (
            "Pinned musl 1.2.6",
            "_LARGEFILE64_SOURCE",
            "fopen64",
            "cxx17",
            "c11-base",
            "_GNU_SOURCE",
            "_FILE_OFFSET_BITS",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "fopen_entry",
            "fopen64_macro_entry",
            "CRABC_FOPEN64_ALIAS_FREESTANDING",
            "ENOENT",
        ):
            self.assertIn(required, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_fopen64_alias_probe",
            "mov $231,%eax",
        ):
            self.assertIn(required, start)
        for required in (
            "selected static C ABI export surface",
            "emits no x86 ELF `fopen64` symbol",
            "fopen64",
            "run_fopen64_header_abi.sh",
            "-nostdlib -static",
            "--no-undefined",
            "fopen",
            "Pinned musl 1.2.6",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "stdio.fopen64-alias"', ledger)
        self.assertIn("source-only `fopen64` alias", ledger)
        for required in (
            "fopen64-header-abi",
            "libc-fopen64-alias",
            "run_fopen64_header_abi",
            "run_libc_fopen64_alias",
        ):
            self.assertIn(required, dispatcher)

    def test_libc_static_c_abi_text_math_locale_stdio_composition_stays_cross_surface(
        self,
    ) -> None:
        """The composition artifact stays an evidence join, not a new wrapper."""
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_text_math_locale_stdio_composition_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_text_math_locale_stdio_composition_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_text_math_locale_stdio_composition.sh"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "setlocale_entry",
            "localeconv_entry",
            "mbrtowc_entry",
            "strtod_entry",
            "fpclassify_entry",
            "fputc_entry",
            "fflush_entry",
            "errno != EILSEQ",
            "pipe_entry",
        ):
            self.assertIn(required, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "untouched Linux entry stack",
            "exit_group",
        ):
            self.assertIn(required, start)
        for required in (
            "run_math_complex_header_abi.sh",
            "run_float_parse_header_abi.sh",
            "run_locale_multibyte_header_abi.sh",
            "run_stdio_standard_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn(
            'id = "static-c-text-math-locale-stdio-composition"', parity_ledger,
        )
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-text-math-locale-stdio-composition"',
            parity_ledger,
        )
        self.assertIn("libc-text-math-locale-stdio-composition", dispatcher)

    def test_libc_static_c_abi_tree_search_slice_stays_independent(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "search_tree_intrusive.rs"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_search_tree_intrusive.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_search_tree_intrusive_probe.c"
        ).read_text(encoding="utf-8")
        header = (ROOT / "include" / "search.h").read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "search_tree_intrusive.rs"]', static_root)
        for symbol in (
            "__tsearch_balance",
            "tdelete",
            "tdestroy",
            "tfind",
            "tsearch",
            "twalk",
        ):
            self.assertIn(symbol, source)
            self.assertIn(symbol, static_exports)
        for required in (
            "src/search/tsearch.c",
            "MAX_HEIGHT",
            "size_of::<Node>() == 32",
            'global_asm!(".hidden __tsearch_balance")',
            "selected_mmap",
            "selected_munmap",
        ):
            self.assertIn(required, source)
        self.assertNotIn('#[linkage = "weak"]', source)
        for required in (
            "assert_selected_c_abi_surface",
            "assert_hidden_function",
            "assert_gnu_tree_hidden",
            "--wrap=malloc",
            "-nostdlib -static",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("run_libc_search_linear_intrusive.sh", runner)
        for required in (
            "check_null_duplicate_and_rotations",
            "check_balancing_find_and_walk",
            "check_delete_parent_identity_and_ownership",
            "check_allocation_failure_rollback_and_repeated_cycles",
            "raw_prlimit64",
            "mapping_is_live",
        ):
            self.assertIn(required, fixture)
        self.assertIn("#ifdef _GNU_SOURCE\nstruct qelem", header)
        self.assertNotIn(
            "#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)\nstruct qelem",
            header,
        )
        self.assertIn('id = "search.tree-intrusive"', parity)
        self.assertIn("libc-search-tree-intrusive)", dispatcher)
        self.assertIn("run_libc_search_tree_intrusive.sh", dispatcher)

    def test_libc_static_c_abi_hash_table_slice_stays_independent(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "search_hash_table.rs"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_search_hash_table.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_search_hash_table_probe.c"
        ).read_text(encoding="utf-8")
        header = (ROOT / "include" / "search.h").read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "search_hash_table.rs"]', static_root)
        for symbol in (
            "hcreate",
            "hcreate_r",
            "hdestroy",
            "hdestroy_r",
            "hsearch",
            "hsearch_r",
        ):
            self.assertIn(symbol, source)
            self.assertIn(symbol, static_exports)
        for required in (
            "src/search/hsearch.c",
            "MAXIMUM_SIZE",
            "wrapping_mul(31)",
            "selected_mmap",
            "selected_munmap",
            '#[linkage = "weak"]',
        ):
            self.assertIn(required, source)
        for required in (
            "assert_selected_c_abi_surface",
            "assert_weak_function",
            "assert_reentrant_hidden",
            "--wrap=calloc",
            "-nostdlib -static",
        ):
            self.assertIn(required, runner)
        for required in (
            "check_resize_failure_rollback",
            "check_unsigned_hash_bytes",
            "check_overflow_and_repeated_create",
            "raw_prlimit64",
            "mapping_is_live",
        ):
            self.assertIn(required, fixture)
        self.assertIn("#ifdef _GNU_SOURCE\nstruct hsearch_data", header)
        self.assertNotIn(
            "#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)\nstruct hsearch_data",
            header,
        )
        self.assertIn('id = "search.hash-table"', parity)
        self.assertIn("libc-search-hash-table)", dispatcher)
        self.assertIn("run_libc_search_hash_table.sh", dispatcher)

    def test_libc_static_c_abi_gettext_catalog_slice_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "gettext_catalog.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_gettext_catalog_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_gettext_catalog.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_gettext_catalog_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "gettext_catalog_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        nl_types = (ROOT / "include" / "nl_types.h").read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")
        symbols = (
            "bind_textdomain_codeset", "bindtextdomain", "catclose", "catgets",
            "catopen", "dcgettext", "dcngettext", "dgettext", "dngettext",
            "gettext", "ngettext", "textdomain",
        )

        self.assertIn('#[path = "gettext_catalog.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", source)
            self.assertIn(symbol, static_exports)
        for required in (
            "src/locale/dcngettext.c", "src/locale/textdomain.c",
            "src/locale/bind_textdomain_codeset.c",
            "src/locale/{catopen,catgets,catclose}.c",
            "BINDING_CAPACITY: usize = 4", "MAX_DIRECTORY_LENGTH",
            "catalog-file/NLSPATH/LANG lookup", "catopen` always reports `ENOENT`",
        ):
            self.assertIn(required, source)
        for forbidden in ("crabc_core", "crabc_mimalloc", "libmimalloc", "alloc::"):
            self.assertNotIn(forbidden, source)
        for required in (
            "assert_selected_c_abi_surface", "assert_strong_function",
            "run_gettext_catalog_header_abi.sh", "-nostdlib -static",
            "candidate selects allocator, catalog-file, environment, locale",
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "check_identity_fallback", "check_domain_and_binding_state",
            "check_codeset_and_missing_catalog", "check_fixed_binding_capacity",
            "CRABC_GETTEXT_CATALOG_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in ("-std=c++17", "nm --undefined-only", "libintl.h", "nl_types.h"):
            self.assertIn(required, header_runner)
        self.assertIn('extern "C" {', nl_types)
        self.assertIn("catgets_signature", header_cpp)
        self.assertIn('id = "catalog.gettext"', parity)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-gettext-catalog"', parity
        )
        self.assertIn("gettext-catalog-header-abi)", dispatcher)
        self.assertIn("libc-gettext-catalog)", dispatcher)

    def test_pathname_lifecycle_runner_releases_dedicated_mkdirat_export(
        self,
    ) -> None:
        """A dedicated selected leaf cannot remain a pathname-bundle exclusion."""

        source = (
            ROOT / "compat" / "x86_64" / "run_libc_pathname_lifecycle.sh"
        ).read_text(encoding="utf-8")
        unselected = re.search(r"for unselected in chroot(.*?); do", source, re.DOTALL)
        self.assertIsNotNone(unselected)
        assert unselected is not None
        self.assertNotIn("mkdirat", unselected.group(1).split())

    def test_libc_static_c_abi_sysv_semaphore_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        semaphore = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sysv_semaphore.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "sysv_semaphore_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "sysv_semaphore_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_sysv_semaphore_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_sysv_semaphore_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_sysv_semaphore_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_sysv_semaphore.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "sysv_semaphore.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 SysV semaphore C boundary",
            "musl 1.2.6 release commit",
            "src/ipc/semget.c",
            "src/ipc/semop.c",
            "src/ipc/semtimedop.c",
            "src/ipc/semctl.c",
            "global_asm!",
            "Semun",
            "_SEM_SEMUN_UNDEFINED",
            "IPC_64",
            "IPC_TIME64",
            "ipc_command",
            "semctl_no_argument",
            "semctl_word",
            "IPC_RMID",
            "GETPID",
            "GETVAL",
            "GETNCNT",
            "GETZCNT",
            "IPC_SET",
            "IPC_STAT",
            "IPC_INFO",
            "GETALL",
            "SETVAL",
            "SETALL",
            "SEM_STAT",
            "SEM_INFO",
            "SEM_STAT_ANY",
            "other command, including the five standard",
            "raw_syscall::SYS_SEMGET",
            "raw_syscall::SYS_SEMOP",
            "raw_syscall::SYS_SEMTIMEDOP",
            "raw_syscall::SYS_SEMCTL",
            "rcx",
            "r10",
        ):
            self.assertIn(required, semaphore)
        for forbidden in (
            "pub unsafe extern \"C\" fn semctl",
            "pub extern \"C\" fn msgget",
            "pub extern \"C\" fn sem_open",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, semaphore)
        for header_probe in (header_c_probe, header_cxx_probe):
            for required in (
                "sys/sem.h",
                "semctl",
                "semget",
                "semop",
                "semtimedop",
                "struct ipc_perm",
                "struct semid_ds",
                "struct sembuf",
                "_SEM_SEMUN_UNDEFINED",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "EXPECTED_PROFILE_COUNT=8",
            "EXPECTED_GNU_PROFILE_COUNT=2",
            "EXPECTED_GNU_HIDDEN_PROFILE_COUNT=6",
            "sys/sem.h",
            "sys/ipc.h",
            "GNU semtimedop",
            "C++ probe",
            "mangled SysV semaphore reference",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "#include <sys/sem.h>",
            "union semun",
            "semget(IPC_PRIVATE, 65536, 0600)",
            "semctl(semaphore_id, 0, SETVAL, argument)",
            "semctl(semaphore_id, 0, GETVAL)",
            "semtimedop(semaphore_id",
            "IPC_RMID",
            "#include <sys/prctl.h>",
            "CRABC_UNKNOWN_SEMCTL_COMMAND",
            "CRABC_SECCOMP_ARGUMENT_THREE_LOW",
            "CRABC_SECCOMP_ARGUMENT_THREE_HIGH",
            "CRABC_SECCOMP_BAD_ARGUMENT_ERRNO = EBADE",
            "SYS_seccomp",
            "crabc_x86_64_semctl_poisoned_default_call",
            "CRABC_SYSV_SEMAPHORE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sysv_semaphore_probe",
            "crabc_x86_64_semctl_poisoned_default_call",
            "movabs $0x13579bdf2468ace1, %rcx",
            "jmp semctl",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        self.assertNotIn("mov %rsi, %fs:0", start)
        for required in (
            "static_c_abi_exports.txt",
            "run_sysv_semaphore_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall semget 40",
            "assert_named_syscall semop 41",
            "assert_named_syscall semtimedop dc",
            "assert_semctl_dispatch_paths",
            "semctl_no_argument",
            "semctl_word",
            "0x10 0xd 0x11 0x1 0x3 0x13 0x2 0x12 0x14",
            "runtime seccomp regression",
            "unselected in sem_close",
            "SEM_UNDO",
            "unowned runtime dependency",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        expected_symbols = {"semget", "semop", "semtimedop", "semctl"}
        self.assertTrue(expected_symbols <= static_export_names)
        self.assertFalse(
            static_export_names
            & {
                "sem_close",
                "sem_open",
                "sem_timedwait",
                "sem_unlink",
            }
        )
        self.assertIn('id = "static-c-sysv-semaphore"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sysv-semaphore"',
            parity_ledger,
        )
        self.assertIn("run_sysv_semaphore_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_sysv_semaphore_header_abi.sh", runner
        )
        self.assertIn("run_libc_sysv_semaphore()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_sysv_semaphore.sh", runner
        )
        self.assertIn(
            '    sysv-semaphore-header-abi)\n        [ "$#" -eq 0 ] || fail "sysv-semaphore-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-sysv-semaphore)\n        [ "$#" -eq 0 ] || fail "libc-sysv-semaphore takes no arguments"',
            runner,
        )

    def test_filesystem_directory_traversal_dispatch_stays_explicit(self) -> None:
        """Keep ftw/nftw's opt-in gate and selected aggregate independently callable."""

        traversal_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_filesystem_traversal.sh"
        ).read_text(encoding="utf-8")
        aggregate_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_filesystem_directory.sh"
        ).read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "run_ftw_header_abi()",
            "/workspace/compat/x86_64/run_ftw_header_abi.sh",
            "run_libc_filesystem_traversal()",
            "/workspace/compat/x86_64/run_libc_filesystem_traversal.sh",
            "run_libc_filesystem_directory()",
            "/workspace/compat/x86_64/run_libc_filesystem_directory.sh",
            '    ftw-header-abi)\n        [ "$#" -eq 0 ] || fail "ftw-header-abi takes no arguments"',
            '    libc-filesystem-traversal)\n        [ "$#" -eq 0 ] || fail "libc-filesystem-traversal takes no arguments"',
            '    libc-filesystem-directory)\n        [ "$#" -eq 0 ] || fail "libc-filesystem-directory takes no arguments"',
        ):
            self.assertIn(required, runner)

        for component in (
            "run_libc_directory_streams.sh",
            "run_libc_scandir.sh",
            "run_libc_filesystem_traversal.sh",
        ):
            self.assertIn(component, aggregate_runner)
        self.assertIn("x86-filesystem-traversal", traversal_runner)
        self.assertIn("x86-scandir", aggregate_runner)

    def test_filesystem_extensions_dispatch_stays_explicit(self) -> None:
        """Keep the frozen five-symbol selected-private aggregate callable."""

        aggregate_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_filesystem_extensions.sh"
        ).read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "  temporary-names-header-abi  verify x86 C/C++ tmpnam/tempnam declarations",
            "  libc-temporary-names  run the opt-in static x86 tmpnam/tempnam slice",
            "  libc-filesystem-extensions  run the selected-private x86 filesystem-extensions capability aggregate",
            "run_libc_filesystem_extensions()",
            "/workspace/compat/x86_64/run_libc_filesystem_extensions.sh",
            '    libc-filesystem-extensions)\n        [ "$#" -eq 0 ] || fail "libc-filesystem-extensions takes no arguments"',
        ):
            self.assertIn(required, runner)

        for component in (
            "run_libc_mktemp.sh",
            "run_libc_file_handles.sh",
            "run_libc_temporary_names.sh",
        ):
            self.assertIn(component, aggregate_runner)

    def test_x86_fs_credentials_are_typed_and_child_contained(self) -> None:
        process = (ROOT / "crabc-rs" / "src" / "process_x86_64.rs").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "x86_fs_credentials_reference_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_x86_fs_credentials_reference.sh"
        ).read_text(encoding="utf-8")
        test = (ROOT / "crabc-rs" / "tests" / "x86_64_fs_credentials.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn("pub unsafe fn set_fs_uid", process)
        self.assertIn("pub unsafe fn set_fs_gid", process)
        self.assertIn("setfsuid_raw(uid).map(Uid::from_raw)", process)
        self.assertIn("setfsgid_raw(gid).map(Gid::from_raw)", process)
        self.assertGreaterEqual(process.count("== u32::MAX => return Err(crate::Errno::INVAL)"), 2)
        self.assertIn("previous value even when the requested change is denied", process)
        self.assertIn("calling-task operation, not musl's synchronized", process)

        self.assertIn("SYS_setfsuid == 122", probe)
        self.assertIn("SYS_setfsgid == 123", probe)
        self.assertIn("raw_fsuid_query", probe)
        self.assertIn("raw_fsgid_query", probe)
        self.assertIn("setfsuid(effective_uid)", probe)
        self.assertIn("setfsgid(effective_gid)", probe)
        self.assertIn("run_in_child", probe)
        self.assertIn("child-contained", probe)

        self.assertIn("run_musl_oracle.sh", runner)
        self.assertIn("/usr/local/bin/crabc-x86_64-musl-gcc", runner)
        self.assertNotIn("-p crabc-libc", runner)

        self.assertIn("#[ignore", test)
        self.assertIn('"--ignored"', test)
        self.assertIn("x86_64_fs_credentials_child_queries_and_requests_current_identity", test)
        self.assertIn("Err(Errno::INVAL)", test)

    def test_core_refuses_a_non_native_host_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'aarch64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment["PATH"] = f"{bin_directory}{os.pathsep}{environment['PATH']}"
            completed = subprocess.run(
                ["bash", str(RUNNER), "core"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("refuses emulation", completed.stderr)

    def test_core_uses_the_native_amd64_container_and_exact_cargo_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  printf '%s\\0' \"$@\" > \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "core"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            arguments = [
                argument.decode("utf-8")
                for argument in capture.read_bytes().split(bytes((0,)))
                if argument
            ]
            self.assertIn("--platform", arguments)
            platform_index = arguments.index("--platform")
            self.assertEqual(arguments[platform_index + 1], "linux/amd64")
            bash_index = arguments.index("bash")
            self.assertEqual(arguments[bash_index : bash_index + 2], ["bash", "-ceu"])
            core_test_command = arguments[bash_index + 2]
            self.assertIn(
                'CARGO_TARGET_DIR="$target_dir" cargo test --locked '
                '--target x86_64-unknown-linux-musl',
                core_test_command,
            )
            self.assertIn(
                '-p crabc-core --lib --no-default-features -- --test-threads=1',
                core_test_command,
            )
            self.assertIn('find "$target_dir/x86_64-unknown-linux-musl/debug/deps"', core_test_command)
            self.assertIn('objdump -d -- "$test_binary"', core_test_command)
            self.assertIn('fxrstor(64)?', core_test_command)

    def test_advanced_time_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "advanced-time-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 4)
            core_arguments, facade_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            core_cargo_index = core_arguments.index("cargo")
            self.assertEqual(
                core_arguments[core_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-core",
                    "--lib",
                    "--no-default-features",
                    "x86_64_posix_timer_writes_exact_id_and_old_setting_records",
                    "--",
                    "--test-threads=1",
                ],
            )

            facade_cargo_index = facade_arguments.index("cargo")
            self.assertEqual(
                facade_arguments[facade_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_advanced_time",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "time_dynamic_direct_probe",
                    "--example",
                    "process_clock_id_direct_probe",
                    "--example",
                    "time_settime_direct_probe",
                    "--example",
                    "time_timers_direct_probe",
                ],
            )
            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_advanced_time_reference.sh",
                ],
            )

    def test_mapping_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "mapping-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_memory_mapping",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "mapping_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_mapping_reference.sh",
                ],
            )

    def test_memory_vm_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "memory-vm-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                self.assertNotIn("--cap-add=SYS_ADMIN", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_memory_vm",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "memory_vm_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_memory_vm_reference.sh",
                ],
            )

    def test_pty_basic_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "pty-basic-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 4)
            test_arguments, alloc_test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                self.assertNotIn("--cap-add=SYS_ADMIN", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_pty_basic",
                    "--",
                    "--test-threads=1",
                ],
            )

            alloc_test_cargo_index = alloc_test_arguments.index("cargo")
            self.assertEqual(
                alloc_test_arguments[alloc_test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--test",
                    "x86_64_pty_basic",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "pty_basic_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_pty_basic_reference.sh",
                ],
            )

    def test_terminal_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "terminal-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 4)
            test_arguments, alloc_test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                self.assertNotIn("--cap-add=SYS_ADMIN", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
                    "-p", "crabc-rs", "--no-default-features", "--test", "x86_64_terminal",
                    "--", "--test-threads=1",
                ],
            )
            alloc_test_cargo_index = alloc_test_arguments.index("cargo")
            self.assertEqual(
                alloc_test_arguments[alloc_test_cargo_index:],
                [
                    "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
                    "-p", "crabc-rs", "--no-default-features", "--features", "alloc",
                    "--test", "x86_64_terminal", "--", "--test-threads=1",
                ],
            )
            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo", "build", "--locked", "--target", "x86_64-unknown-linux-musl",
                    "-p", "crabc-rs", "--no-default-features", "--example",
                    "x86_64_terminal_direct_probe",
                ],
            )
            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                ["bash", "/workspace/compat/x86_64/run_x86_terminal_reference.sh"],
            )

    def test_mount_reference_uses_the_native_amd64_container_and_unprivileged_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "mount-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                self.assertNotIn("--cap-add=SYS_ADMIN", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_mount",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "mount_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_mount_reference.sh",
                ],
            )

    def test_thread_kill_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "thread-kill-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_thread_kill",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "thread_kill_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_thread_kill_reference.sh",
                ],
            )

    def test_users_databases_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "users-databases-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--test",
                    "x86_64_users_databases",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--example",
                    "users_databases_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_users_databases_reference.sh",
                ],
            )

    def test_facade_uses_the_native_amd64_container_and_exact_cargo_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "facade"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 7)
            (
                arguments,
                fnmatch_build_arguments,
                fnmatch_verifier_arguments,
                chroot_arguments,
                allocation_arguments,
                glob_build_arguments,
                glob_verifier_arguments,
            ) = invocations
            self.assertIn("--platform", arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
            platform_index = arguments.index("--platform")
            self.assertEqual(arguments[platform_index + 1], "linux/amd64")
            cargo_index = arguments.index("cargo")
            self.assertEqual(
                arguments[cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--lib",
                    "--no-default-features",
                    "--test",
                    "fenv",
                    "--test",
                    "futex",
                    "--test",
                    "x86_64_foundation",
                    "--test",
                    "x86_64_fnmatch",
                    "--test",
                    "x86_64_memory_mapping",
                    "--test",
                    "x86_64_memory_vm",
                    "--test",
                    "x86_64_pty_basic",
                    "--test",
                    "x86_64_terminal",
                    "--test",
                    "x86_64_mount",
                    "--test",
                    "x86_64_epoll",
                    "--test",
                    "x86_64_eventfd",
                    "--test",
                    "x86_64_fcntl_getlk",
                    "--test",
                    "x86_64_fcntl_flags",
                    "--test",
                    "x86_64_flock",
                    "--test",
                    "x86_64_sendfile",
                    "--test",
                    "x86_64_copy_file_range",
                    "--test",
                    "x86_64_fs",
                    "--test",
                    "x86_64_fs_capacity",
                    "--test",
                    "x86_64_fs_advice",
                    "--test",
                    "x86_64_file_position",
                    "--test",
                    "x86_64_sync",
                    "--test",
                    "x86_64_syncfs",
                    "--test",
                    "x86_64_sync_file_range",
                    "--test",
                    "x86_64_ftruncate",
                    "--test",
                    "x86_64_futimens",
                    "--test",
                    "x86_64_timestamp_paths",
                    "--test",
                    "x86_64_path_lifecycle",
                    "--test",
                    "x86_64_namespace",
                    "--test",
                    "x86_64_xattr",
                    "--test",
                    "x86_64_raw_directory",
                    "--test",
                    "x86_64_directory",
                    "--test",
                    "x86_64_directory_position",
                    "--test",
                    "x86_64_temporary_objects",
                    "--test",
                    "x86_64_statx",
                    "--test",
                    "x86_64_canonicalize",
                    "--test",
                    "x86_64_cwd_mutation",
                    "--test",
                    "x86_64_ipc",
                    "--test",
                    "x86_64_shm",
                    "--test",
                    "x86_64_inotify",
                    "--test",
                    "x86_64_socket_transport",
                    "--test",
                    "x86_64_posix_fallocate",
                    "--test",
                    "x86_64_fallocate",
                    "--test",
                    "x86_64_fs_credentials",
                    "--test",
                    "x86_64_getgroups",
                    "--test",
                    "x86_64_getitimer",
                    "--test",
                    "x86_64_setitimer",
                    "--test",
                    "x86_64_io",
                    "--test",
                    "x86_64_memfd",
                    "--test",
                    "x86_64_mm",
                    "--test",
                    "x86_64_param",
                    "--test",
                    "x86_64_pipe",
                    "--test",
                    "x86_64_poll",
                    "--test",
                    "x86_64_pselect",
                    "--test",
                    "x86_64_priority",
                    "--test",
                    "x86_64_setpriority",
                    "--test",
                    "x86_64_process_identity",
                    "--test",
                    "x86_64_process_session",
                    "--test",
                    "x86_64_pidfd_open",
                    "--test",
                    "x86_64_rand",
                    "--test",
                    "x86_64_rlimit",
                    "--test",
                    "x86_64_rlimit_targeted",
                    "--test",
                    "x86_64_setrlimit",
                    "--test",
                    "x86_64_umask",
                    "--test",
                    "x86_64_rusage",
                    "--test",
                    "x86_64_scheduler_priority_bounds",
                    "--test",
                    "x86_64_sleep",
                    "--test",
                    "x86_64_clock_nanosleep",
                    "--test",
                    "x86_64_statat",
                    "--test",
                    "x86_64_access",
                    "--test",
                    "x86_64_getcwd",
                    "--test",
                    "x86_64_current_dir_name",
                    "--test",
                    "x86_64_readlink",
                    "--test",
                    "x86_64_sched_rr_interval",
                    "--test",
                    "x86_64_sched_affinity",
                    "--test",
                    "x86_64_sched_setaffinity",
                    "--test",
                    "x86_64_system",
                    "--test",
                    "x86_64_thread",
                    "--test",
                    "x86_64_thread_kill",
                    "--test",
                    "x86_64_thread_credentials",
                    "--test",
                    "x86_64_time",
                    "--test",
                    "time",
                    "--test",
                    "calendar_utc",
                    "--test",
                    "x86_64_calendar_time",
                    "--test",
                    "x86_64_advanced_time",
                    "--test",
                    "x86_64_timerfd",
                    "--test",
                    "x86_64_times",
                    "--",
                    "--test-threads=1",
                ],
            )
            self.assertIn("--platform", fnmatch_build_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", fnmatch_build_arguments)
            fnmatch_build_platform_index = fnmatch_build_arguments.index("--platform")
            self.assertEqual(
                fnmatch_build_arguments[fnmatch_build_platform_index + 1],
                "linux/amd64",
            )
            fnmatch_build_cargo_index = fnmatch_build_arguments.index("cargo")
            self.assertEqual(
                fnmatch_build_arguments[fnmatch_build_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--release",
                    "--example",
                    "fnmatch_direct_probe",
                ],
            )
            self.assertIn("--platform", fnmatch_verifier_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", fnmatch_verifier_arguments)
            fnmatch_verifier_platform_index = fnmatch_verifier_arguments.index("--platform")
            self.assertEqual(
                fnmatch_verifier_arguments[fnmatch_verifier_platform_index + 1],
                "linux/amd64",
            )
            fnmatch_verifier_bash_index = fnmatch_verifier_arguments.index("bash")
            self.assertEqual(
                fnmatch_verifier_arguments[fnmatch_verifier_bash_index:],
                ["bash", "/workspace/compat/x86_64/verify_fnmatch_direct.sh"],
            )
            self.assertIn('--cap-add=SYS_CHROOT', chroot_arguments)
            self.assertIn("--platform", chroot_arguments)
            chroot_platform_index = chroot_arguments.index("--platform")
            self.assertEqual(
                chroot_arguments[chroot_platform_index + 1],
                "linux/amd64",
            )
            chroot_cargo_index = chroot_arguments.index("cargo")
            self.assertEqual(
                chroot_arguments[chroot_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_chroot",
                    "--",
                    "--test-threads=1",
                ],
            )
            self.assertIn("--platform", allocation_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", allocation_arguments)
            allocation_platform_index = allocation_arguments.index("--platform")
            self.assertEqual(
                allocation_arguments[allocation_platform_index + 1],
                "linux/amd64",
            )
            allocation_cargo_index = allocation_arguments.index("cargo")
            self.assertEqual(
                allocation_arguments[allocation_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--test",
                    "timezone_rules",
                    "--test",
                    "calendar_local",
                    "--test",
                    "x86_64_glob",
                    "--test",
                    "x86_64_child_ownership",
                    "--test",
                    "x86_64_pty_basic",
                    "--test",
                    "x86_64_terminal",
                    "--test",
                    "x86_64_users_databases",
                    "--",
                    "--test-threads=1",
                ],
            )
            self.assertIn("--platform", glob_build_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", glob_build_arguments)
            glob_build_platform_index = glob_build_arguments.index("--platform")
            self.assertEqual(
                glob_build_arguments[glob_build_platform_index + 1], "linux/amd64"
            )
            glob_build_cargo_index = glob_build_arguments.index("cargo")
            self.assertEqual(
                glob_build_arguments[glob_build_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--release",
                    "--example",
                    "glob_direct_probe",
                ],
            )
            self.assertIn("--platform", glob_verifier_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", glob_verifier_arguments)
            glob_verifier_platform_index = glob_verifier_arguments.index("--platform")
            self.assertEqual(
                glob_verifier_arguments[glob_verifier_platform_index + 1], "linux/amd64"
            )
            glob_verifier_bash_index = glob_verifier_arguments.index("bash")
            self.assertEqual(
                glob_verifier_arguments[glob_verifier_bash_index:],
                ["bash", "/workspace/compat/x86_64/verify_glob_direct.sh"],
            )

    def test_ldso_relocation_uses_the_native_amd64_container_and_fixed_source_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  printf '%s\\0' \"$@\" > \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "ldso-relocation"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            arguments = [
                argument.decode("utf-8")
                for argument in capture.read_bytes().split(bytes((0,)))
                if argument
            ]
            self.assertIn("--platform", arguments)
            platform_index = arguments.index("--platform")
            self.assertEqual(arguments[platform_index + 1], "linux/amd64")
            bash_index = arguments.index("bash")
            self.assertEqual(arguments[bash_index : bash_index + 2], ["bash", "-ceu"])
            source_test_command = arguments[bash_index + 2]
            self.assertIn(
                'rustup run "$(python3 /workspace/scripts/rust_toolchain.py)" rustc --edition=2021 --test',
                source_test_command,
            )
            self.assertIn(
                "/workspace/ldso/src/x86_64_relocation.rs",
                source_test_command,
            )
            self.assertIn('"$test_binary" --test-threads=1', source_test_command)
            self.assertNotIn("cargo", source_test_command)

    def test_ldso_initial_exec_tls_stays_a_fixed_leaf_sibling(self) -> None:
        runner = (ROOT / "compat" / "x86_64" / "run_ldso_initial_tls.sh").read_text(
            encoding="utf-8"
        )
        launcher = (
            ROOT / "compat" / "x86_64" / "run_ldso_initial_exec_tls.sh"
        ).read_text(encoding="utf-8")
        graph = (ROOT / "ldso" / "src" / "x86_64_initial_graph.rs").read_text(
            encoding="utf-8"
        )
        leaf = (ROOT / "compat" / "x86_64" / "ldso_initial_tls_leaf.c").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "crabc_initial_exec_tls_graph",
            "R_X86_64_TPOFF64",
            "STATIC_TLS",
            "nonzero addend",
            "static-TLS flag on the GNU-Dynamic mid",
        ):
            self.assertIn(required, runner)
        self.assertIn("CRABC_LDSO_INITIAL_EXEC_TLS=1", launcher)
        for required in (
            "crabc_initial_exec_tls_graph",
            "R_X86_64_TPOFF64 =>",
            "leaf_initial_exec_tls",
            "object.static_tls",
        ):
            self.assertIn(required, graph)
        self.assertIn('tls_model("initial-exec")', leaf)
        self.assertIn("run_ldso_initial_exec_tls.sh", dispatcher)

    def test_process_globals_getopt_runner_keeps_the_private_native_boundary(self) -> None:
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_process_globals_getopt.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_process_globals_getopt_probe.c"
        ).read_text(encoding="utf-8")
        startup = (
            ROOT / "compat" / "x86_64" / "libc_process_globals_getopt_start.S"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_globals.rs"
        ).read_text(encoding="utf-8")
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "run_musl_oracle.sh",
            "assert_selected_c_abi_surface",
            "assert_process_global_aliases",
            "pinned-musl static reference",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
            "dynamic TLS",
            "public x86 support",
        ):
            self.assertIn(required, runner)
        for required in (
            "crabc_x86_64_process_globals_getopt_init",
            "&program_invocation_name != &__progname_full",
            "&optreset != &__optreset",
            "__posix_getopt != getopt",
            "program_invocation_short_name = replacement",
            "__optreset = 1",
            "optreset = 1",
            "C.UTF-8",
            "getopt_long_only",
        ):
            self.assertIn(required, fixture)
        self.assertIn("call __crabc_x86_static_tls_bootstrap", startup)
        self.assertIn("call __libc_start_main", startup)
        for required in (
            '".set optreset, __optreset"',
            '".set program_invocation_name, __progname_full"',
            '".set program_invocation_short_name, __progname"',
            '".set __posix_getopt, getopt"',
            'include!("../../getopt_exports.rs");',
        ):
            self.assertIn(required, leaf)
        for forbidden in (
            "__environ",
            "getenv(",
            "setenv(",
            "unsetenv(",
            "putenv(",
            "clearenv(",
        ):
            self.assertNotIn(forbidden, leaf)
        self.assertIn("libc-process-globals-getopt)", dispatcher)
        self.assertIn("run_libc_process_globals_getopt.sh", dispatcher)

    def test_fdim_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_fdim.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_fdim_probe.c").read_text(
            encoding="utf-8"
        )
        header = (ROOT / "compat" / "x86_64" / "fdim_header_abi_probe.cpp").read_text(
            encoding="utf-8"
        )
        for required in (
            "libc-fdim)",
            "run_libc_fdim_probe()",
            "/workspace/compat/x86_64/run_libc_fdim.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "fdim_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate retains TLS",
            "subsd",
            "subss",
            "ucomisd",
            "ucomiss",
        ):
            self.assertIn(required, runner)
        for required in (
            "check_binary64_values",
            "check_binary32_values",
            "signaling_nan_x",
            "FE_INVALID",
            "check_binary64_rounding",
            "check_binary32_rounding",
            "FE_OVERFLOW",
            "direct_fdim",
            "direct_fdimf",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_binary_signature",
            "float_binary_signature",
            "direct_fdim",
            "direct_fdimf",
        ):
            self.assertIn(required, header)
    def test_auxv_observation_runner_keeps_the_private_native_boundary(self) -> None:
        """The selected aux-vector lookup is one bounded static-startup leaf."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        startup = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_startup.rs"
        ).read_text(encoding="utf-8")
        leaf_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "auxv_observation.rs"
        fixture_path = ROOT / "compat" / "x86_64" / "libc_auxv_observation_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_auxv_observation_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_auxv_observation.sh"
        )
        for path in (leaf_path, fixture_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing auxv-observation artifact input: {path}")

        leaf = leaf_path.read_text(encoding="utf-8")
        fixture = fixture_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "auxv_observation.rs"]', static_root)
        for required in (
            "MAX_AUXV_ENTRIES",
            "AT_NULL",
            "ENOENT",
            "AtomicUsize",
            "pub(super) unsafe fn install_initial",
            'pub unsafe extern "C" fn __getauxval',
            '".weak getauxval"',
            '".set getauxval, __getauxval"',
        ):
            self.assertIn(required, leaf)
        self.assertNotIn("__auxv", leaf)
        for forbidden in ("raw_syscall", "getrandom", "fn secure_getenv"):
            self.assertNotIn(forbidden, leaf)

        install_call = "unsafe { auxv_observation::install_initial(vectors.auxv) };"
        init_call = "if let Some(init) = init {"
        self.assertIn(install_call, startup)
        self.assertIn("auxv: *const usize", startup)
        self.assertIn("MAX_AUXV_ENTRIES", startup)
        self.assertLess(startup.index(install_call), startup.index(init_call))
        self.assertLess(startup.index(install_call), startup.index("unsafe { process_globals::install"))

        self.assertTrue({"__getauxval", "getauxval"} <= static_export_names)
        self.assertNotIn("__auxv", static_export_names)
        for required in (
            "#include <elf.h>",
            "#include <errno.h>",
            "#include <sys/auxv.h>",
            "AT_PAGESZ",
            "AT_PHENT",
            "AT_PHNUM",
            "AT_SECURE",
            "AT_NULL",
            "ENOENT",
            "__getauxval",
            "crabc_x86_64_auxv_observation_init",
        ):
            self.assertIn(required, fixture)
        self.assertIn("call __crabc_x86_static_tls_bootstrap", start)
        self.assertIn("call __libc_start_main", start)
        self.assertIn("crabc_x86_64_auxv_observation_init", start)
        for required in (
            "run_machine_context_header_abi.sh",
            "pinned-musl static reference",
            "assert_weak_same_address_alias",
            "-nostdlib -static",
            "R_X86_64_TPOFF",
            "AT_SECURE",
            "AT_NULL",
            "ENOENT",
            "__getauxval",
            "getauxval",
            "dynamic TLS",
            "public x86 support",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn("libc-auxv-observation)", dispatcher)
        self.assertIn("run_libc_auxv_observation.sh", dispatcher)
        self.assertIn("separately selected archive member", artifact_runner)
        self.assertIn("<(secure_getenv|malloc|calloc|realloc|free)>", artifact_runner)

    def test_math_minmax_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_minmax.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_minmax_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_minmax_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_minmax.rs").read_text(
            encoding="utf-8"
        )
        for required in (
            "libc-math-minmax)",
            "run_libc_math_minmax_probe()",
            "/workspace/compat/x86_64/run_libc_math_minmax.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_minmax_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate retains TLS",
            "ucomisd",
            "ucomiss",
            "movq",
            "movd",
            "fmaxl fminl",
        ):
            self.assertIn(required, runner)
        for required in (
            "check_binary64_values",
            "check_binary32_values",
            "signaling_nan_x",
            "FE_INVALID",
            "check_fenv_preservation",
            "FE_DIVBYZERO",
            "direct_fmax",
            "direct_fmaxf",
            "direct_fmin",
            "direct_fminf",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_binary_signature",
            "float_binary_signature",
            "direct_fmax",
            "direct_fmaxf",
            "direct_fmin",
            "direct_fminf",
        ):
            self.assertIn(required, header)
        for required in (
            "src/math/fmax.c",
            "src/math/fmaxf.c",
            "src/math/fmin.c",
            "src/math/fminf.c",
            ".global fmax",
            ".global fmaxf",
            ".global fmin",
            ".global fminf",
            "ucomisd",
            "ucomiss",
            "FE_INVALID",
            "fmaxl`/`fminl",
        ):
            self.assertIn(required, leaf)

    def test_math_bit_sign_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_bit_sign.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_bit_sign_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_bit_sign_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_bit_sign.rs").read_text(
            encoding="utf-8"
        )

        for required in (
            "libc-math-bit-sign)",
            "run_libc_math_bit_sign_probe()",
            "/workspace/compat/x86_64/run_libc_math_bit_sign.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_bit_sign_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate retains TLS",
            "andpd andps orpd orps",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_fabs",
            "direct_fabsf",
            "direct_copysign",
            "direct_copysignf",
            "signaling_nan",
            "FE_INVALID",
            "check_fenv_preservation",
            "FE_DIVBYZERO",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_unary_signature",
            "float_unary_signature",
            "double_binary_signature",
            "float_binary_signature",
            "direct_fabs",
            "direct_copysignf",
        ):
            self.assertIn(required, header)
        for required in (
            ".global fabs",
            ".global fabsf",
            ".global copysign",
            ".global copysignf",
            "andpd xmm0",
            "andps xmm0",
            "orpd xmm0, xmm1",
            "orps xmm0, xmm1",
        ):
            self.assertIn(required, leaf)

    def test_math_trunc_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_trunc.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_trunc_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_trunc_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_trunc.rs").read_text(
            encoding="utf-8"
        )

        for required in (
            "libc-math-trunc)",
            "run_libc_math_trunc_probe()",
            "/workspace/compat/x86_64/run_libc_math_trunc.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_trunc_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate retains TLS",
            "addsd addss",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_trunc",
            "direct_truncf",
            "signaling_nan",
            "FE_INVALID",
            "FE_INEXACT",
            "check_fenv_boundary",
            "FE_DIVBYZERO",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_unary_signature",
            "float_unary_signature",
            "direct_trunc",
            "direct_truncf",
        ):
            self.assertIn(required, header)
        for required in (
            "src/math/trunc.c",
            "src/math/truncf.c",
            'pub extern "C" fn trunc',
            'pub extern "C" fn truncf',
            "FORCE_EVAL",
            "write_volatile",
            "u64::MAX",
            "u32::MAX",
        ):
            self.assertIn(required, leaf)

    def test_math_fmod_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_fmod.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_fmod_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_fmod_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_fmod.rs").read_text(
            encoding="utf-8"
        )

        for required in (
            "libc-math-fmod)",
            "run_libc_math_fmod_probe()",
            "/workspace/compat/x86_64/run_libc_math_fmod.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_fmod_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "divsd divss",
            "fmodl remainder",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_fmod",
            "direct_fmodf",
            "check_binary64_values",
            "check_binary32_values",
            "signaling_nan",
            "FE_INVALID",
            "check_fenv_boundary",
            "FE_DIVBYZERO",
            "check_invalid_domain",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_binary_signature",
            "float_binary_signature",
            "direct_fmod",
            "direct_fmodf",
        ):
            self.assertIn(required, header)
        for required in (
            "src/math/fmod.c",
            "src/math/fmodf.c",
            'pub extern "C" fn fmod',
            'pub extern "C" fn fmodf',
            "is_nan_f64",
            "is_nan_f32",
            "(x * y) / (x * y)",
            "u64::MAX",
            "u32::MAX",
            "fmodl",
        ):
            self.assertIn(required, leaf)

    def test_math_cbrt_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_cbrt.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_cbrt_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_cbrt_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_cbrt.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_cbrt_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_cbrt.py"
        ).read_text(encoding="utf-8")

        for required in (
            "libc-math-cbrt)",
            "run_libc_math_cbrt_probe()",
            "/workspace/compat/x86_64/run_libc_math_cbrt.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_cbrt_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "divsd mulsd cvtsd2ss",
            "cbrtl fmod",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_cbrt",
            "direct_cbrtf",
            "CBRT_RECORD_WORDS 4",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_unary_signature",
            "float_unary_signature",
            "direct_cbrt",
            "direct_cbrtf",
        ):
            self.assertIn(required, header)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/cbrt.c",
            "src/math/cbrtf.c",
            "-frounding-math",
            'include_str!("math_cbrt_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/cbrt.c"',
            '"src/math/cbrtf.c"',
            '"15.2.0"',
            '"-frounding-math"',
            "Sun Microsystems",
        ):
            self.assertIn(required, generator)
        for required in (
            "Sun Microsystems",
            "musl's MIT license",
            "\t.globl\tcbrt\n",
            "\t.globl\tcbrtf\n",
            "cvtsd2ss",
        ):
            self.assertIn(required, assembly)

    def test_math_exp2_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_exp2.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_exp2_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_exp2_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_math_exp2_header_abi.sh"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_exp2.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_exp2_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_exp2.py"
        ).read_text(encoding="utf-8")

        for required in (
            "math-exp2-header-abi)",
            "run_math_exp2_header_abi()",
            "libc-math-exp2)",
            "run_libc_math_exp2_probe()",
            "/workspace/compat/x86_64/run_libc_math_exp2.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "run_math_exp2_header_abi.sh",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd addss subsd mulsd mulss cvtsd2ss cvtss2sd",
            "exp2l exp expf",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_exp2",
            "direct_exp2f",
            "EXP2_RECORD_WORDS 4",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x7ff8000000000041",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in ("double_unary", "float_unary", "direct_exp2", "direct_exp2f"):
            self.assertIn(required, header)
        for required in ("math_exp2_header_abi_probe.cpp", "-mfpmath=387", "unmangled"):
            self.assertIn(required, header_runner)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/exp2.c",
            "src/math/exp2f.c",
            "exp2f_data",
            "WANT_ROUNDING",
            "-ffp-contract=off",
            'include_str!("math_exp2_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/exp2.c"',
            '"src/math/exp2f.c"',
            '"src/math/exp_data.c"',
            '"src/math/exp2f_data.c"',
            '"src/math/__math_xflowf.c"',
            '"15.2.0"',
            '"-frounding-math"',
            '"-ffp-contract=off"',
            "PRIVATE_RENAMES",
        ):
            self.assertIn(required, generator)
        for required in (
            "Copyright (c) 2018, Arm Limited.",
            "musl's MIT license",
            "\t.globl\texp2\n",
            "\t.globl\texp2f\n",
            ".local crabc_x86_math_exp2_data",
            ".local crabc_x86_math_exp2_provider_xflowf",
            "cvtsd2ss",
        ):
            self.assertIn(required, assembly)

    def test_math_expm1_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_expm1.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_expm1_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_expm1_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_math_expm1_header_abi.sh"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_expm1.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_expm1_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_expm1.py"
        ).read_text(encoding="utf-8")

        for required in (
            "math-expm1-header-abi)",
            "run_math_expm1_header_abi()",
            "libc-math-expm1)",
            "run_libc_math_expm1_probe()",
            "/workspace/compat/x86_64/run_libc_math_expm1.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "run_math_expm1_header_abi.sh",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd addss subsd subss mulsd mulss divsd divss cvtsd2ss",
            "expm1l exp expf",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_expm1",
            "direct_expm1f",
            "EXPM1_RECORD_WORDS 4",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x40862e42fefa39ef",
            "0x42b17217",
            "0x7ff0000000000042",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in ("double_unary", "float_unary", "direct_expm1", "direct_expm1f"):
            self.assertIn(required, header)
        for required in ("math_expm1_header_abi_probe.cpp", "-mfpmath=387", "unmangled"):
            self.assertIn(required, header_runner)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/expm1.c",
            "src/math/expm1f.c",
            "FORCE_EVAL",
            "-ffp-contract=off",
            'include_str!("math_expm1_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/expm1.c"',
            '"src/math/expm1f.c"',
            '"15.2.0"',
            '"-frounding-math"',
            '"-ffp-contract=off"',
            '"-mfpmath=sse"',
            "retained_notices",
        ):
            self.assertIn(required, generator)
        for required in (
            "Sun Microsystems",
            "musl's MIT license",
            "\t.globl\texpm1\n",
            "\t.globl\texpm1f\n",
            "cvtsd2ss",
        ):
            self.assertIn(required, assembly)

    def test_math_log10_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_log10.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_log10_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_log10_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_math_log10_header_abi.sh"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_log10.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_log10_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_log10.py"
        ).read_text(encoding="utf-8")

        for required in (
            "math-log10-header-abi)",
            "run_math_log10_header_abi()",
            "libc-math-log10)",
            "run_libc_math_log10_probe()",
            "/workspace/compat/x86_64/run_libc_math_log10.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "run_math_log10_header_abi.sh",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd addss subsd subss mulsd mulss divsd divss",
            "log10l log logf",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_log10",
            "direct_log10f",
            "LOG10_RECORD_WORDS 4",
            "LOG10_RECORD_COUNT",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x7ff0000000000042",
            "0x7f800042",
            "signed-zero divide-by-zero",
            "negative-domain invalid",
        ):
            self.assertIn(required, probe)
        for required in ("double_unary", "float_unary", "direct_log10", "direct_log10f"):
            self.assertIn(required, header)
        for required in ("math_log10_header_abi_probe.cpp", "-mfpmath=387", "unmangled"):
            self.assertIn(required, header_runner)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/log10.c",
            "src/math/log10f.c",
            "signed zero",
            "negative finite",
            "-ffp-contract=off",
            'include_str!("math_log10_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/log10.c"',
            '"src/math/log10f.c"',
            '"15.2.0"',
            '"-frounding-math"',
            '"-ffp-contract=off"',
            '"-mfpmath=sse"',
            "retained_notices",
        ):
            self.assertIn(required, generator)
        for required in (
            "Sun Microsystems",
            "musl's MIT license",
            "\t.globl\tlog10\n",
            "\t.globl\tlog10f\n",
        ):
            self.assertIn(required, assembly)

    def test_math_ceil_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_ceil.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_ceil_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_ceil_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_ceil.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_ceil_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_ceil.py"
        ).read_text(encoding="utf-8")

        for required in (
            "libc-math-ceil)",
            "run_libc_math_ceil_probe()",
            "/workspace/compat/x86_64/run_libc_math_ceil.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_ceil_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd subsd addss",
            "ceill floor",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_ceil",
            "direct_ceilf",
            "CEIL_RECORD_WORDS 4",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x7ff0000000000042",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_unary_signature",
            "float_unary_signature",
            "direct_ceil",
            "direct_ceilf",
        ):
            self.assertIn(required, header)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/ceil.c",
            "src/math/ceilf.c",
            "-frounding-math",
            "`toint` add/subtract sequence",
            "`FE_INEXACT`",
            'include_str!("math_ceil_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/ceil.c"',
            '"src/math/ceilf.c"',
            '"15.2.0"',
            '"-frounding-math"',
            "musl's MIT license",
        ):
            self.assertIn(required, generator)
        for required in (
            "musl's MIT license",
            "\t.globl\tceil\n",
            "\t.globl\tceilf\n",
            "addsd",
            "subsd",
            "addss",
        ):
            self.assertIn(required, assembly)

    def test_math_floor_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_floor.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_floor_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_floor_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_floor.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_floor_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_floor.py"
        ).read_text(encoding="utf-8")

        for required in (
            "libc-math-floor)",
            "run_libc_math_floor_probe()",
            "/workspace/compat/x86_64/run_libc_math_floor.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_floor_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd subsd addss",
            "floorl ceil",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_floor",
            "direct_floorf",
            "FLOOR_RECORD_WORDS 4",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x7ff0000000000042",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_unary_signature",
            "float_unary_signature",
            "direct_floor",
            "direct_floorf",
        ):
            self.assertIn(required, header)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/floor.c",
            "src/math/floorf.c",
            "-frounding-math",
            "`toint` add/subtract sequence",
            "`FE_INEXACT`",
            'include_str!("math_floor_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/floor.c"',
            '"src/math/floorf.c"',
            '"15.2.0"',
            '"-frounding-math"',
            "musl's MIT license",
        ):
            self.assertIn(required, generator)
        for required in (
            "musl's MIT license",
            "\t.globl\tfloor\n",
            "\t.globl\tfloorf\n",
            "addsd",
            "subsd",
            "addss",
        ):
            self.assertIn(required, assembly)

    def test_math_round_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_round.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_round_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_round_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_round.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_round_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_round.py"
        ).read_text(encoding="utf-8")

        for required in (
            "libc-math-round)",
            "run_libc_math_round_probe()",
            "/workspace/compat/x86_64/run_libc_math_round.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_round_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd subsd addss subss",
            "roundl ceil",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_round",
            "direct_roundf",
            "ROUND_RECORD_WORDS 4",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x7ff0000000000042",
            "0x7f800042",
            "0x3fe0000000000000",
            "0xbfe0000000000000",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_unary_signature",
            "float_unary_signature",
            "direct_round",
            "direct_roundf",
            "direct_round(-1.5)",
            "direct_roundf(-1.5f)",
        ):
            self.assertIn(required, header)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/round.c",
            "src/math/roundf.c",
            "-frounding-math",
            "`toint` add/subtract sequence",
            "half-away correction",
            "`FE_INEXACT`",
            'include_str!("math_round_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/round.c"',
            '"src/math/roundf.c"',
            '"15.2.0"',
            '"-frounding-math"',
            "musl's MIT license",
        ):
            self.assertIn(required, generator)
        for required in (
            "musl's MIT license",
            "\t.globl\tround\n",
            "\t.globl\troundf\n",
            "addsd",
            "subsd",
            "addss",
            "subss",
        ):
            self.assertIn(required, assembly)

    def test_math_log2_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        """Keep the private log-two archive leaf source-closed and non-promoting."""

        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_log2.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_log2_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_log2_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_log2.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_log2_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_log2.py"
        ).read_text(encoding="utf-8")

        for required in (
            "libc-math-log2)",
            "run_libc_math_log2_probe()",
            "/workspace/compat/x86_64/run_libc_math_log2.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "math_log2_header_abi_probe.cpp",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "__log2_data",
            "__math_divzero",
            "divsd mulsd addsd subsd divss mulss subss",
            "log2l log10",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_log2",
            "direct_log2f",
            "LOG2_RECORD_WORDS 4",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x3ff0000000000000",
            "0x0000000000000001",
            "0x7ff0000000000042",
            "0x3f800000",
            "0x00000001",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in (
            "double_unary_signature",
            "float_unary_signature",
            "direct_log2",
            "direct_log2f",
            "direct_log2(1.0)",
            "direct_log2f(1.0f)",
        ):
            self.assertIn(required, header)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/log2.c",
            "src/math/log2f.c",
            "src/math/log2_data.c",
            "src/math/log2f_data.c",
            "src/math/__math_divzero.c",
            "src/math/__math_invalidf.c",
            "-frounding-math",
            "localized",
            'include_str!("math_log2_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/log2.c"',
            '"src/math/log2f.c"',
            '"src/math/log2_data.c"',
            '"src/math/log2f_data.c"',
            '"15.2.0"',
            '"-frounding-math"',
            "PRIVATE_SYMBOLS",
            "musl's MIT license",
        ):
            self.assertIn(required, generator)
        for required in (
            "musl's MIT license",
            "\t.globl\tlog2\n",
            "\t.globl\tlog2f\n",
            "crabc_x86_math_log2___log2_data",
            "crabc_x86_math_log2___math_divzero",
            "divsd",
            "mulsd",
            "divss",
            "mulss",
        ):
            self.assertIn(required, assembly)

    def test_libc_static_c_abi_ns_put32_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ns_put32.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ns_put32_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_ns_put32_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ns_put32.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "ns_put32.rs"]', static_root)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/ns_parse.c",
            "core::ptr::write",
            "value >> 24",
            "bytes.add(3)",
            'pub unsafe extern "C" fn ns_put32',
            "at least four writable bytes",
            "truncates `value` to its low 32",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(
                r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                leaf,
            ),
            ["ns_put32"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall",
            "__errno_location",
            "__h_errno_location",
            "getaddrinfo",
            "gethostby",
            "socket(",
            "std::",
            "alloc::",
            "crabc_core",
            "crabc_mimalloc",
            "fn ns_get16",
            "fn ns_get32",
            "fn ns_put16",
        ):
            self.assertNotIn(forbidden, leaf)

        for required in (
            "#include <resolv.h>",
            "ns_put32_signature",
            "NS_CMPRSFLGS == 0xc0",
            "NS_MAXLABEL == 63",
            "NS_MAXCDNAME == 255",
            "NS_MAXDNAME == 1025",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cpp)
        for required in (
            "check_cxx_c_linkage",
            "nm --undefined-only",
            "_Z.*ns_put32",
            "STRICT_C_PROJECT_HEADERS",
            "DNS packet I/O",
            "netdb",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <resolv.h>",
            "ns_put32_signature",
            "NS_INT32SZ == 4",
            "unsigned char direct",
            "0x1122334455667788UL",
            "NS_PUT32(0xabcdffeeUL, cursor)",
            "CRABC_NS_PUT32_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_ns_put32_probe", start)
        self.assertIn("mov $60, %eax", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "ns_parse.lo",
            "ns_parse.c",
            "5",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "ns_put32 archive member also defines a nameserver sibling",
            "-nostdlib -static",
            '"$selected_member" -o "$candidate"',
            "candidate unexpectedly selects TLS",
            "__h_errno_location",
            "dn_expand dn_skipname ns_get16 ns_get32 ns_put16",
            "res_query res_querydomain res_search",
            "htonl htons ntohl ntohs",
            "getaddrinfo freeaddrinfo",
            "socket bind connect send recv",
            "call|syscall",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('"$archive" -o "$candidate"', artifact_runner)
        self.assertIn("ns_put32", static_exports.splitlines())
        self.assertFalse(
            set(static_exports.splitlines())
            & {"res_query", "res_querydomain", "res_search"}
        )
        self.assertIn('id = "static-c-ns-put32"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-ns-put32"',
            parity_ledger,
        )
        self.assertIn("nameser-header-abi)", dispatcher)
        self.assertIn("libc-ns-put32)", dispatcher)

    def test_libc_static_c_abi_ns_skiprr_artifact_stays_private(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ns_skiprr.rs"
        ).read_text(encoding="utf-8")
        dn_skipname = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dn_skipname.rs"
        ).read_text(encoding="utf-8")
        ns_get16 = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ns_get16.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "nameser_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ns_skiprr_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_ns_skiprr_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ns_skiprr.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "ns_skiprr.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 DNS resource-record span C ABI boundary",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/network/ns_parse.c::ns_skiprr",
            '#[link_name = "dn_skipname"]',
            '#[link_name = "ns_get16"]',
            "selected_dn_skipname",
            "selected_ns_get16",
            "QUESTION_FIXED_BYTES",
            "RESOURCE_FIXED_BYTES",
            "EMSGSIZE: c_int = 90",
            "super::errno::set_errno",
            "remaining_records.wrapping_sub(1)",
            'pub unsafe extern "C" fn ns_skiprr',
            "`count` must be nonnegative",
        ):
            self.assertIn(required, leaf)
        self.assertEqual(
            re.findall(
                r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(', leaf
            ),
            ["ns_skiprr"],
        )
        for forbidden in (
            "static mut",
            "raw_syscall::",
            "static_tls::",
            "crabc_core",
            "crabc_mimalloc",
            "fn ns_initparse",
            "fn ns_parserr",
            "fn ns_name_uncompress",
            "fn dn_expand",
            "socket(",
            "getaddrinfo",
        ):
            self.assertNotIn(forbidden, leaf)
        self.assertIn("#[inline(never)]", dn_skipname)
        self.assertIn("#[inline(never)]", ns_get16)

        for header in (header_c, header_cpp):
            self.assertIn("ns_skiprr_signature", header)
            self.assertIn("ns_skiprr_function", header)
        self.assertIn("ns_skiprr declaration", header_c)
        self.assertIn("ns_skiprr C++ declaration", header_cpp)
        for required in ("ns_skiprr", "_Z.*ns_skiprr", "check_cxx_c_linkage"):
            self.assertIn(required, header_runner)

        for required in (
            "#include <errno.h>",
            "#include <resolv.h>",
            "ns_skiprr_signature",
            "ns_s_qd == 0 && ns_s_an == 1",
            "questions",
            "answers",
            "expect_malformed",
            "EMSGSIZE",
            "CRABC_NS_SKIPRR_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_ns_skiprr_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "run_nameser_header_abi.sh",
            "AARCH64_STATIC_TSV",
            "ns_parse.lo",
            "ns_parse.c",
            "assert_selected_c_abi_surface",
            "extract_selected_member",
            "ns_skiprr archive member also defines a nameserver sibling",
            "-nostdlib -static",
            '"$selected_member" "$archive"',
            "candidate lacks the selected errno TLS segment",
            "candidate errno does not use direct fs initial TLS",
            "ns_skiprr does not call its selected dn_skipname dependency",
            "ns_skiprr does not call its selected ns_get16 dependency",
            "ns_skiprr implementation unexpectedly performs a syscall",
            "ns_initparse ns_parserr ns_name_uncompress",
            "res_query res_querydomain res_search",
            "getaddrinfo freeaddrinfo",
            "bind connect send recv",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("ns_skiprr", static_exports.splitlines())
        self.assertFalse(
            set(static_exports.splitlines())
            & {"res_query", "res_querydomain", "res_search"}
        )
        self.assertIn('id = "static-c-ns-skiprr"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-ns-skiprr"', parity_ledger
        )
        self.assertIn("nameser-header-abi)", dispatcher)
        self.assertIn("libc-ns-skiprr)", dispatcher)
        self.assertIn("run_libc_ns_skiprr.sh", dispatcher)

    def test_libc_static_c_abi_nameser_wire_aggregate_stays_private(self) -> None:
        probe = (
            ROOT / "compat" / "x86_64" / "libc_nameser_wire_aggregate_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_nameser_wire_aggregate_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_nameser_wire_aggregate.sh"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for required in (
            "owner_name",
            "ns_put16_function",
            "ns_put32_function",
            "ns_get16_function",
            "ns_get32_function",
            "dn_skipname_function",
            "dn_expand_function",
            "ns_skiprr_function",
            "ns_msg_getflag",
            "eom != message + 49",
            "expect_malformed(answer, eom - 1)",
            "CRABC_NAMESER_WIRE_AGGREGATE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_nameser_wire_aggregate_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "run_nameser_header_abi.sh",
            "ns_parse.lo",
            "dn_expand.lo",
            "assert_dn_expand_alias",
            "extract_selected_member",
            "ns_skiprr archive member also defines a nameserver sibling",
            '"$selected_member" "$archive"',
            "_ns_flagdata",
            "candidate lacks the selected errno TLS segment",
            "candidate errno does not use direct fs initial TLS",
            "ns_skiprr does not call its selected dn_skipname dependency",
            "ns_skiprr does not call its selected ns_get16 dependency",
            "ns_initparse ns_parserr ns_name_uncompress",
            "res_query res_querydomain res_search",
            "getaddrinfo",
            "socket bind",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-nameser-wire-aggregate"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-nameser-wire-aggregate"',
            parity_ledger,
        )
        self.assertIn("libc-nameser-wire-aggregate)", dispatcher)
        self.assertIn("run_libc_nameser_wire_aggregate.sh", dispatcher)

    def test_libc_static_c_abi_sched_getparam_artifact_stays_musl_enosys(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_getparam.rs"
        c_header_path = ROOT / "compat" / "x86_64" / "sched_getparam_header_abi_probe.c"
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sched_getparam_header_abi_probe.cpp"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_sched_getparam_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sched_getparam_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sched_getparam_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sched_getparam.sh"
        )
        process_resources_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_process_resources.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing sched_getparam input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        process_resources_runner = process_resources_runner_path.read_text(
            encoding="utf-8"
        )
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "sched_getparam.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static POSIX scheduler-parameter observation boundary",
            "src/sched/sched_getparam.c::sched_getparam",
            "__syscall_ret(-ENOSYS)",
            "raw syscall `sched_getparam=143`",
            "c_status(-ENOSYS)",
            'pub extern "C" fn sched_getparam(_pid: c_int, _param: *mut c_void) -> c_int',
        ):
            self.assertIn(required, source)
        for forbidden in ("raw_syscall::", "SYS_SCHED_GETPARAM", "sched_getscheduler"):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&sched_getparam)",
            "sched_getparam_signature)(pid_t, struct sched_param *)",
            "sizeof(struct sched_param) == 48",
            "offsetof(struct sched_param, __reserved3) == 40",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&sched_getparam)",
            "sched_getparam_signature",
            "sizeof(sched_param) == 48",
            'extern "C" void crabc_sched_getparam_linkage_witness',
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "strict posix xopen gnu",
            "sched_getparam_header_abi_probe.c",
            "sched_getparam_header_abi_probe.cpp",
            "unmangled sched_getparam",
            "project trace omitted",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "SYS_sched_getparam == 143",
            "raw_sched_getparam",
            "param_is_unchanged",
            "check_musl_process_api",
            "check_musl_null_parameter",
            "errno != ENOSYS",
            "CRABC_SCHED_GETPARAM_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sched_getparam_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_sched_getparam_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_musl_enosys_boundary",
            "sched_getparam forwarded raw Linux syscall 143",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sched_getparam", static_exports)
        self.assertNotIn("times sched_getparam", process_resources_runner)
        self.assertNotIn("sched_setscheduler", process_resources_runner)
        self.assertIn('id = "static-c-sched-getparam"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sched-getparam"', parity_ledger
        )
        self.assertIn("run_sched_getparam_header_abi()", dispatcher)
        self.assertIn("run_libc_sched_getparam_probe()", dispatcher)
        self.assertIn("sched-getparam-header-abi)", dispatcher)
        self.assertIn("libc-sched-getparam)", dispatcher)

    def test_libc_static_c_abi_sched_setparam_artifact_stays_musl_enosys(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_setparam.rs"
        c_header_path = ROOT / "compat" / "x86_64" / "sched_setparam_header_abi_probe.c"
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sched_setparam_header_abi_probe.cpp"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_sched_setparam_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sched_setparam_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sched_setparam_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sched_setparam.sh"
        )
        process_resources_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_process_resources.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing sched_setparam input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        process_resources_runner = process_resources_runner_path.read_text(
            encoding="utf-8"
        )
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "sched_setparam.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static POSIX scheduler-parameter compatibility-failure boundary",
            "src/sched/sched_setparam.c::sched_setparam",
            "__syscall_ret(-ENOSYS)",
            "raw syscall `sched_setparam=142`",
            "c_status(-ENOSYS)",
            'pub extern "C" fn sched_setparam(_pid: c_int, _param: *const c_void) -> c_int',
        ):
            self.assertIn(required, source)
        for forbidden in ("raw_syscall::", "SYS_SCHED_SETPARAM", "sched_getparam"):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&sched_setparam)",
            "sched_setparam_signature)(pid_t, const struct sched_param *)",
            "sizeof(struct sched_param) == 48",
            "offsetof(struct sched_param, __reserved3) == 40",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&sched_setparam)",
            "sched_setparam_signature",
            "sizeof(sched_param) == 48",
            'extern "C" void crabc_sched_setparam_linkage_witness',
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "strict posix xopen gnu",
            "sched_setparam_header_abi_probe.c",
            "sched_setparam_header_abi_probe.cpp",
            "unmangled sched_setparam",
            "project trace omitted",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "SYS_sched_setparam == 142",
            "raw_sched_setparam",
            "param_is_unchanged",
            "check_musl_process_api",
            "check_musl_null_parameter",
            "errno != ENOSYS",
            "CRABC_SCHED_SETPARAM_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sched_setparam_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_sched_setparam_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_musl_enosys_boundary",
            "sched_setparam forwarded raw Linux syscall 142",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sched_setparam", static_exports)
        self.assertNotIn("sched_setparam", process_resources_runner)
        self.assertIn('id = "static-c-sched-setparam"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sched-setparam"', parity_ledger
        )
        self.assertIn("run_sched_setparam_header_abi()", dispatcher)
        self.assertIn("run_libc_sched_setparam_probe()", dispatcher)
        self.assertIn("sched-setparam-header-abi)", dispatcher)
        self.assertIn("libc-sched-setparam)", dispatcher)

    def test_libc_static_c_abi_sched_setscheduler_artifact_stays_musl_enosys(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_setscheduler.rs"
        )
        c_header_path = (
            ROOT / "compat" / "x86_64" / "sched_setscheduler_header_abi_probe.c"
        )
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sched_setscheduler_header_abi_probe.cpp"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_sched_setscheduler_header_abi.sh"
        )
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_sched_setscheduler_probe.c"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_sched_setscheduler_start.S"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sched_setscheduler.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(
                path.is_file(), f"missing sched_setscheduler input: {path}"
            )
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "sched_setscheduler.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static POSIX scheduler-policy compatibility-failure boundary",
            "src/sched/sched_setscheduler.c::sched_setscheduler",
            "__syscall_ret(-ENOSYS)",
            "raw syscall `sched_setscheduler=144`",
            "c_status(-ENOSYS)",
            'pub extern "C" fn sched_setscheduler(',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "raw_syscall::",
            "SYS_SCHED_SETSCHEDULER",
            "sched_setparam",
            "run_libc_process_resources",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&sched_setscheduler)",
            "sched_setscheduler_signature)(",
            "pid_t, int, const struct sched_param *",
            "sizeof(struct sched_param) == 48",
            "offsetof(struct sched_param, __reserved3) == 40",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&sched_setscheduler)",
            "sched_setscheduler_signature",
            "sizeof(sched_param) == 48",
            'extern "C" void crabc_sched_setscheduler_linkage_witness',
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "strict posix xopen gnu",
            "sched_setscheduler_header_abi_probe.c",
            "sched_setscheduler_header_abi_probe.cpp",
            "unmangled sched_setscheduler",
            "project trace omitted",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "SYS_sched_setscheduler == 144",
            "raw_sched_setscheduler",
            "SCHED_OTHER",
            "param_is_unchanged",
            "check_musl_process_api",
            "check_musl_null_parameter",
            "errno != ENOSYS",
            "CRABC_SCHED_SETSCHEDULER_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sched_setscheduler_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_sched_setscheduler_header_abi.sh",
            "static_c_abi_exports.txt",
            "AARCH64_STATIC_ABI",
            "sched_setscheduler.lo",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_musl_enosys_boundary",
            "sched_setscheduler forwarded raw Linux syscall 144",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertNotIn("run_libc_process_resources", artifact_runner)
        self.assertIn("sched_setscheduler", static_exports)
        self.assertIn('id = "static-c-sched-setscheduler"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sched-setscheduler"',
            parity_ledger,
        )
        self.assertIn("run_sched_setscheduler_header_abi()", dispatcher)
        self.assertIn("run_libc_sched_setscheduler_probe()", dispatcher)
        self.assertIn("sched-setscheduler-header-abi)", dispatcher)
        self.assertIn("libc-sched-setscheduler)", dispatcher)

    def test_libc_static_c_abi_sched_getaffinity_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_getaffinity.rs"
        )
        c_header_path = (
            ROOT / "compat" / "x86_64" / "sched_getaffinity_header_abi_probe.c"
        )
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sched_getaffinity_header_abi_probe.cpp"
        )
        visibility_path = (
            ROOT / "compat" / "x86_64" / "sched_getaffinity_header_visibility_probe.c"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_sched_getaffinity_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sched_getaffinity_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sched_getaffinity_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sched_getaffinity.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            visibility_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing sched_getaffinity input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        visibility = visibility_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "sched_getaffinity.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static GNU scheduler-affinity observation boundary",
            "src/sched/affinity.c::do_getaffinity",
            "SYS_SCHED_GETAFFINITY",
            "c_status(result)",
            'pub unsafe extern "C" fn sched_getaffinity',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "SYS_SCHED_SETAFFINITY",
            'pub unsafe extern "C" fn sched_setaffinity',
            "pthread_",
            "static_tls",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&sched_getaffinity)",
            "sched_getaffinity_signature)(pid_t, size_t, cpu_set_t *)",
            "sizeof(cpu_set_t) == 128",
            "offsetof(cpu_set_t, __bits) == 0",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&sched_getaffinity)",
            "sched_getaffinity_signature",
            "sizeof(cpu_set_t) == 128",
            'extern "C" void crabc_sched_getaffinity_linkage_witness',
        ):
            self.assertIn(required, cxx_header)
        self.assertIn("sched_getaffinity", visibility)
        for required in (
            "strict posix xopen",
            "sched_getaffinity_header_visibility_probe.c",
            "unexpectedly exposes sched_getaffinity",
            "unmangled sched_getaffinity",
            "project trace omitted",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "SYS_sched_getaffinity == 204",
            "raw_sched_getaffinity",
            "raw_prefix_matches",
            "tail_is_zero",
            "check_invalid_capacity",
            "check_missing_task",
            "CRABC_SCHED_GETAFFINITY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sched_getaffinity_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_sched_getaffinity_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_affinity_boundary",
            "sched_getaffinity does not issue syscall 204",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sched_getaffinity", static_exports)
        self.assertIn('id = "static-c-sched-getaffinity"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sched-getaffinity"',
            parity_ledger,
        )
        self.assertIn("run_sched_getaffinity_header_abi()", dispatcher)
        self.assertIn("run_libc_sched_getaffinity_probe()", dispatcher)
        self.assertIn("sched-getaffinity-header-abi)", dispatcher)
        self.assertIn("libc-sched-getaffinity)", dispatcher)

    def test_libc_static_c_abi_sched_setaffinity_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_setaffinity.rs"
        )
        c_header_path = (
            ROOT / "compat" / "x86_64" / "sched_setaffinity_header_abi_probe.c"
        )
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "sched_setaffinity_header_abi_probe.cpp"
        )
        visibility_path = (
            ROOT
            / "compat"
            / "x86_64"
            / "sched_setaffinity_header_visibility_probe.c"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_sched_setaffinity_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_sched_setaffinity_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sched_setaffinity_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_sched_setaffinity.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            visibility_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing sched_setaffinity input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        visibility = visibility_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "sched_setaffinity.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static GNU scheduler-affinity mutation boundary",
            "src/sched/affinity.c::sched_setaffinity",
            "SYS_SCHED_SETAFFINITY",
            "c_status(result)",
            'pub unsafe extern "C" fn sched_setaffinity',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "SYS_SCHED_GETAFFINITY",
            'pub unsafe extern "C" fn sched_getaffinity',
            "pthread_",
            "static_tls",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&sched_setaffinity)",
            "sched_setaffinity_signature)(pid_t, size_t, const cpu_set_t *)",
            "sizeof(cpu_set_t) == 128",
            "offsetof(cpu_set_t, __bits) == 0",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&sched_setaffinity)",
            "sched_setaffinity_signature",
            "sizeof(cpu_set_t) == 128",
            'extern "C" void crabc_sched_setaffinity_linkage_witness',
        ):
            self.assertIn(required, cxx_header)
        self.assertIn("sched_setaffinity", visibility)
        for required in (
            "strict posix xopen",
            "sched_setaffinity_header_visibility_probe.c",
            "unexpectedly exposes sched_setaffinity",
            "unmangled sched_setaffinity",
            "project trace omitted",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "SYS_sched_setaffinity == 203",
            "raw_sched_getaffinity",
            "has_set_bit",
            "check_current_task",
            "check_empty_mask",
            "check_missing_task",
            "check_null_mask",
            "CRABC_SCHED_SETAFFINITY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sched_setaffinity_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_sched_setaffinity_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_affinity_boundary",
            "memcpy|memmove|memset|bzero|sched_getaffinity",
            "sched_setaffinity does not issue syscall 203",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sched_setaffinity", static_exports)
        self.assertIn('id = "static-c-sched-setaffinity"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sched-setaffinity"',
            parity_ledger,
        )
        self.assertIn("run_sched_setaffinity_header_abi()", dispatcher)
        self.assertIn("run_libc_sched_setaffinity_probe()", dispatcher)
        self.assertIn("sched-setaffinity-header-abi)", dispatcher)
        self.assertIn("libc-sched-setaffinity)", dispatcher)

    def test_libc_static_c_abi_setfsuid_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "setfsuid.rs"
        c_header_path = ROOT / "compat" / "x86_64" / "setfsuid_header_abi_probe.c"
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "setfsuid_header_abi_probe.cpp"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_setfsuid_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_setfsuid_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_setfsuid_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_setfsuid.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing setfsuid input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "setfsuid.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static filesystem-credential setfsuid boundary",
            "src/linux/setfsuid.c::setfsuid",
            "SYS_SETFSUID",
            "c_status(result)",
            'pub unsafe extern "C" fn setfsuid',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "SYS_SETFSGID",
            'pub unsafe extern "C" fn setfsgid',
            "pthread_",
            "static_tls",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&setfsuid)",
            "setfsuid_signature)(uid_t)",
            "sizeof(uid_t) == 4",
            "SYS_setfsuid == 122",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&setfsuid)",
            "setfsuid_signature",
            "sizeof(uid_t) == 4",
            'extern "C" void crabc_setfsuid_linkage_witness',
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "strict posix xopen gnu",
            "setfsuid_header_abi_probe.c",
            "unmangled setfsuid",
            "project trace omitted",
            "bits/alltypes.h",
            "leaked <sys/types.h>",
        ):
            self.assertIn(required, header_runner)
        self.assertNotIn("#include <sys/types.h>", c_header)
        self.assertNotIn("#include <sys/types.h>", cxx_header)

        for required in (
            "SYS_setfsuid == 122",
            "raw_setfsuid",
            "raw_geteuid",
            "setfsuid((uid_t)-1)",
            "CRABC_SETFSUID_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_setfsuid_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_setfsuid_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_setfsuid_boundary",
            "setfsuid does not issue syscall 122",
            "candidate unexpectedly pulls",
            "bits/alltypes.h",
            "leaked <sys/types.h>",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("#include <sys/types.h>", probe)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("setfsuid", static_exports)
        self.assertIn('id = "static-c-setfsuid"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-setfsuid"', parity_ledger
        )
        self.assertIn("run_setfsuid_header_abi()", dispatcher)
        self.assertIn("run_libc_setfsuid_probe()", dispatcher)
        self.assertIn("setfsuid-header-abi)", dispatcher)
        self.assertIn("libc-setfsuid)", dispatcher)

    def test_libc_static_c_abi_setfsgid_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "setfsgid.rs"
        c_header_path = ROOT / "compat" / "x86_64" / "setfsgid_header_abi_probe.c"
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "setfsgid_header_abi_probe.cpp"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_setfsgid_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_setfsgid_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_setfsgid_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_setfsgid.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing setfsgid input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "setfsgid.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static filesystem-credential setfsgid boundary",
            "src/linux/setfsgid.c::setfsgid",
            "SYS_SETFSGID",
            "c_status(result)",
            'pub unsafe extern "C" fn setfsgid',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "SYS_SETFSUID",
            'pub unsafe extern "C" fn setfsuid',
            "pthread_",
            "static_tls",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&setfsgid)",
            "setfsgid_signature)(gid_t)",
            "sizeof(gid_t) == 4",
            "SYS_setfsgid == 123",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&setfsgid)",
            "setfsgid_signature",
            "sizeof(gid_t) == 4",
            'extern "C" void crabc_setfsgid_linkage_witness',
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "strict posix xopen gnu",
            "setfsgid_header_abi_probe.c",
            "unmangled setfsgid",
            "project trace omitted",
            "bits/alltypes.h",
            "leaked <sys/types.h>",
        ):
            self.assertIn(required, header_runner)
        self.assertNotIn("#include <sys/types.h>", c_header)
        self.assertNotIn("#include <sys/types.h>", cxx_header)

        for required in (
            "SYS_setfsgid == 123",
            "raw_setfsgid",
            "raw_getegid",
            "setfsgid((gid_t)-1)",
            "CRABC_SETFSGID_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_setfsgid_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_setfsgid_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_setfsgid_boundary",
            "setfsgid does not issue syscall 123",
            "candidate unexpectedly pulls",
            "bits/alltypes.h",
            "leaked <sys/types.h>",
            "-C codegen-units=512",
            "isolated archive-member topology",
            "one-symbol direct-syscall closure",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("#include <sys/types.h>", probe)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertNotIn("-C link-dead-code=no", artifact_runner)
        self.assertIn(
            'rustflags = ["-C", "link-dead-code"]',
            (ROOT / ".cargo" / "config.toml").read_text(encoding="utf-8"),
        )
        self.assertIn("setfsgid", static_exports)
        self.assertIn('id = "static-c-setfsgid"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-setfsgid"', parity_ledger
        )
        self.assertIn("run_setfsgid_header_abi()", dispatcher)
        self.assertIn("run_libc_setfsgid_probe()", dispatcher)
        self.assertIn("setfsgid-header-abi)", dispatcher)
        self.assertIn("libc-setfsgid)", dispatcher)

    def test_libc_static_c_abi_personality_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "personality.rs"
        c_header_path = ROOT / "compat" / "x86_64" / "personality_header_abi_probe.c"
        cxx_header_path = (
            ROOT / "compat" / "x86_64" / "personality_header_abi_probe.cpp"
        )
        header_runner_path = (
            ROOT / "compat" / "x86_64" / "run_personality_header_abi.sh"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_personality_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_personality_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_personality.sh"
        )
        for path in (
            source_path,
            c_header_path,
            cxx_header_path,
            header_runner_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing personality input: {path}")
        self.assertTrue(header_runner_path.stat().st_mode & 0o111)
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

        source = source_path.read_text(encoding="utf-8")
        c_header = c_header_path.read_text(encoding="utf-8")
        cxx_header = cxx_header_path.read_text(encoding="utf-8")
        header_runner = header_runner_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "personality.rs"]', static_root)
        for required in (
            "Bounded Linux/x86-64 static process-personality boundary",
            "src/linux/personality.c::personality",
            "SYS_PERSONALITY",
            "c_status(result)",
            'pub unsafe extern "C" fn personality',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "SYS_PRCTL",
            "SYS_CAPGET",
            "SYS_CAPSET",
            "SYS_SETNS",
            "SYS_UNSHARE",
            "pthread_",
        ):
            self.assertNotIn(forbidden, source)

        for required in (
            "__typeof__(&personality)",
            "personality_signature)(unsigned long)",
            "sizeof(unsigned long) == 8",
            "SYS_personality == 135",
        ):
            self.assertIn(required, c_header)
        for required in (
            "decltype(&personality)",
            "personality_signature",
            "sizeof(unsigned long) == 8",
            'extern "C" void crabc_personality_linkage_witness',
        ):
            self.assertIn(required, cxx_header)
        for required in (
            "strict posix xopen gnu",
            "personality_header_abi_probe.c",
            "unmangled personality",
            "project trace omitted",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "SYS_personality == 135",
            "raw_personality",
            "0xffffffffUL",
            "CRABC_PERSONALITY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_personality_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_musl_oracle.sh",
            "run_personality_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_personality_boundary",
            "personality does not issue syscall 135",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("personality", static_exports)
        self.assertIn('id = "static-c-personality"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-personality"', parity_ledger
        )
        self.assertIn("run_personality_header_abi()", dispatcher)
        self.assertIn("run_libc_personality_probe()", dispatcher)
        self.assertIn("personality-header-abi)", dispatcher)
        self.assertIn("libc-personality)", dispatcher)

    def test_campaign_dispatch_surface_is_explicit_and_host_safe(self) -> None:
        """Phase 0 reporting must not need a Docker image just to explain blockers."""
        dispatcher = RUNNER.read_text(encoding="utf-8")

        for command in (
            "campaign-status",
            "campaign-family <family-id>",
            "campaign-static",
            "campaign-dynamic",
            "campaign-qualification",
            "campaign-promotion-check",
            "campaign-all",
        ):
            self.assertIn(command, dispatcher)
        for arm in (
            "campaign-status)",
            "campaign-family)",
            "campaign-static)",
            "campaign-dynamic)",
            "campaign-qualification)",
            "campaign-promotion-check)",
            "campaign-all)",
        ):
            self.assertIn(arm, dispatcher)

        self.assertIn("compat/x86_64/campaign_report.py", dispatcher)
        self.assertIn("compat/x86_64/campaign_runner.py", dispatcher)
        self.assertIn("compat/x86_64/generate_c_abi_evidence_matrix.py --run-family \"$1\"", dispatcher)
        campaign_status = dispatcher.index("campaign-status)")
        next_arm = dispatcher.index("campaign-family)", campaign_status)
        self.assertNotIn("ensure_image", dispatcher[campaign_status:next_arm])

    def test_routine_c_abi_matrix_dispatches_checked_registry_natively(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")

        self.assertIn("routine-c-abi-matrix <family-id>", dispatcher)
        self.assertIn("routine-c-abi-matrix)", dispatcher)
        self.assertIn(
            "compat/x86_64/generate_c_abi_evidence_matrix.py --run-family \"$1\"",
            dispatcher,
        )
        routine_matrix = dispatcher.index("routine-c-abi-matrix)")
        next_arm = dispatcher.index("getloadavg-header-abi)", routine_matrix)
        routine_matrix_arm = dispatcher[routine_matrix:next_arm]
        self.assertIn("ensure_image", routine_matrix_arm)
        self.assertIn("run_in_container", routine_matrix_arm)
        self.assertNotIn("getpagesize-noarg-scalar", routine_matrix_arm)
        self.assertNotIn("gethostid-noarg-scalar", routine_matrix_arm)


if __name__ == "__main__":
    unittest.main()
