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


class X86_64CoreRunnerTests(unittest.TestCase):
    def test_fcntl_header_posix_fallocate_declarations_stay_explicit(self) -> None:
        c_probe = (
            ROOT / "compat" / "x86_64" / "fcntl_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "fcntl_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        strict_c_probe = (
            ROOT / "compat" / "x86_64" / "fcntl_posix_fallocate_strict_probe.c"
        ).read_text(encoding="utf-8")
        strict_cxx_probe = (
            ROOT / "compat" / "x86_64" / "fcntl_posix_fallocate_strict_probe.cpp"
        ).read_text(encoding="utf-8")
        largefile_c_probe = (
            ROOT
            / "compat"
            / "x86_64"
            / "fcntl_posix_fallocate_largefile64_probe.c"
        ).read_text(encoding="utf-8")
        largefile_cxx_probe = (
            ROOT
            / "compat"
            / "x86_64"
            / "fcntl_posix_fallocate_largefile64_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_fcntl_header_abi.sh"
        ).read_text(encoding="utf-8")

        for required in (
            "static int (*posix_fallocate_signature)(int, off_t, off_t) = posix_fallocate;",
            "static int (*posix_fallocate64_signature)(int, off64_t, off64_t) = posix_fallocate64;",
            "(void)posix_fallocate_signature;",
            "(void)posix_fallocate64_signature;",
        ):
            self.assertIn(required, c_probe)
        for required in (
            "using posix_fallocate_function = int (*)(int, off_t, off_t);",
            "using posix_fallocate64_function = int (*)(int, off64_t, off64_t);",
            "decltype(&posix_fallocate)",
            "decltype(&posix_fallocate64)",
        ):
            self.assertIn(required, cxx_probe)
        for probe in (strict_c_probe, strict_cxx_probe):
            self.assertIn("#ifdef _GNU_SOURCE", probe)
            self.assertIn("#ifdef _LARGEFILE64_SOURCE", probe)
            self.assertIn("#ifdef posix_fallocate64", probe)
            self.assertIn("posix_fallocate", probe)
        for probe in (largefile_c_probe, largefile_cxx_probe):
            self.assertIn("#define _LARGEFILE64_SOURCE 1", probe)
            self.assertIn("#ifdef _GNU_SOURCE", probe)
            self.assertIn("#ifndef posix_fallocate64", probe)
            self.assertIn("posix_fallocate64", probe)
        for probe in (strict_c_probe, largefile_c_probe):
            self.assertIn("static int (*posix_fallocate", probe)
        for probe in (strict_cxx_probe, largefile_cxx_probe):
            self.assertIn("decltype(&posix_fallocate", probe)
        for probe in (
            strict_c_probe,
            strict_cxx_probe,
            largefile_c_probe,
            largefile_cxx_probe,
        ):
            self.assertIn("sizeof(off_t) == 8", probe)
            self.assertIn("signed 64-bit off_t", probe)
        for probe in (largefile_c_probe, largefile_cxx_probe):
            self.assertIn("sizeof(off64_t) == 8", probe)
        self.assertIn("return posix_fallocate(-1, 0, 0);", strict_cxx_probe)
        self.assertIn(
            "return posix_fallocate64(-1, (off64_t)0, (off64_t)0);",
            largefile_cxx_probe,
        )
        for required in (
            "fcntl_posix_fallocate_strict_probe.c",
            "fcntl_posix_fallocate_strict_probe.cpp",
            "fcntl_posix_fallocate_largefile64_probe.c",
            "fcntl_posix_fallocate_largefile64_probe.cpp",
            '-std=c11 -U_GNU_SOURCE -fsyntax-only "$strict_c_probe"',
            '-std=c11 -U_GNU_SOURCE -fsyntax-only "$largefile_c_probe"',
            "assert_cxx_posix_fallocate_linkage",
            "strict_cxx_oracle_object",
            "largefile_cxx_project_object",
            "does not retain C linkage for posix_fallocate",
            "retains a mangled posix_fallocate reference",
            '"$ROOT_DIR/include/features.h"',
        ):
            self.assertIn(required, header_runner)

    def test_descriptor_advice_header_profiles_stay_explicit(self) -> None:
        c_probe = (
            ROOT / "compat" / "x86_64" / "descriptor_advice_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "descriptor_advice_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_descriptor_advice_header_abi.sh"
        ).read_text(encoding="utf-8")

        for probe in (c_probe, cxx_probe):
            for required in (
                "CRABC_DESCRIPTOR_ADVICE_STRICT",
                "CRABC_DESCRIPTOR_ADVICE_GNU",
                "CRABC_DESCRIPTOR_ADVICE_LARGEFILE64",
                "CRABC_DESCRIPTOR_ADVICE_REQUIRE_READAHEAD_HIDDEN",
                "POSIX_FADV_NORMAL == 0",
                "POSIX_FADV_RANDOM == 1",
                "POSIX_FADV_SEQUENTIAL == 2",
                "POSIX_FADV_WILLNEED == 3",
                "POSIX_FADV_DONTNEED == 4",
                "POSIX_FADV_NOREUSE == 5",
                "sizeof(off_t) == 8",
                "posix_fadvise64",
                "readahead",
            ):
                self.assertIn(required, probe)
        self.assertIn("__builtin_types_compatible_p", c_probe)
        self.assertIn("readahead_signature", c_probe)
        self.assertIn("__is_same", cxx_probe)
        self.assertIn("readahead_signature", cxx_probe)
        self.assertIn("descriptor_advice_cxx_posix_fadvise64", cxx_probe)
        self.assertIn("descriptor_advice_cxx_readahead", cxx_probe)
        for required in (
            "c11-strict",
            "cxx17-strict",
            "c11-gnu",
            "cxx17-gnu",
            "c11-largefile64",
            "cxx17-largefile64",
            "-nostdinc",
            "-nostdinc++",
            "expect_readahead_hidden",
            "hidden readahead diagnostic does not name readahead",
            "does not retain C linkage for",
            "retained a mangled descriptor-advice reference",
            "posix_fadvise64",
            "features.h",
        ):
            self.assertIn(required, runner)

    def test_stdlib_header_profile_matrix_stays_a_private_audit(self) -> None:
        """The broad stdlib matrix records drift; it does not select runtime ABI."""
        c_probe = (
            ROOT / "compat" / "x86_64" / "stdlib_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "stdlib_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        matrix = (
            ROOT / "compat" / "x86_64" / "run_stdlib_header_abi.sh"
        ).read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        for probe in (c_probe, cxx_probe):
            for required in (
                "CRABC_STDLIB_STRICT",
                "CRABC_STDLIB_POSIX_2008",
                "CRABC_STDLIB_XOPEN_700",
                "CRABC_STDLIB_GNU",
                "CRABC_STDLIB_BSD",
                "CRABC_STDLIB_LFS",
                "CRABC_STDLIB_REQUIRE_POSIX_HIDDEN",
                "CRABC_STDLIB_REQUIRE_XOPEN_HIDDEN",
                "CRABC_STDLIB_REQUIRE_GNU_BSD_HIDDEN",
                "CRABC_STDLIB_REQUIRE_GNU_ONLY_HIDDEN",
                "rand_r",
                "mkstemps",
                "mkostemps",
                "memalign",
                "WIFCONTINUED",
                "WCOREDUMP",
                "WIFSTOPPED",
                "WIFSIGNALED",
                "0x007f",
                "0x137f",
                "strtof_l",
                "strtod_l",
                "strtold_l",
                "mkstemp64",
                "mkostemp64",
            ):
                self.assertIn(required, probe)
        self.assertIn("__builtin_types_compatible_p", c_probe)
        self.assertIn("__is_same", cxx_probe)
        for required in (
            "CRABC_STDLIB_REQUIRE_CPP_NULLPTR",
            "CRABC_STDLIB_NULL_WITNESS_ONLY",
            "decltype(NULL)",
            "decltype(nullptr)",
            "CRABC_STDLIB_INCLUDE_STDIO_FIRST",
            "CRABC_STDLIB_INCLUDE_STRING_FIRST",
            "#include <stdio.h>",
            "#include <string.h>",
        ):
            self.assertIn(required, cxx_probe)
        stdio_include = cxx_probe.index("#include <stdio.h>")
        stdio_null_assertion = cxx_probe.index(
            "musl C++17 stdio.h NULL is nullptr before stdlib.h",
            stdio_include,
        )
        stdio_stdlib_include = cxx_probe.index("#include <stdlib.h>", stdio_include)
        self.assertLess(stdio_include, stdio_null_assertion)
        self.assertLess(stdio_null_assertion, stdio_stdlib_include)
        string_include = cxx_probe.index("#include <string.h>")
        string_null_assertion = cxx_probe.index(
            "musl C++17 string.h NULL is nullptr before stdlib.h",
            string_include,
        )
        string_stdlib_include = cxx_probe.index(
            "#include <stdlib.h>", string_include
        )
        self.assertLess(string_include, string_null_assertion)
        self.assertLess(string_null_assertion, string_stdlib_include)

        for required in (
            "MUSL_ROOT=/opt/musl-1.2.6",
            "CANDIDATE_CC=/usr/bin/gcc",
            "-nostdinc",
            "-nostdinc++",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-gnu",
            "c11-bsd",
            "c11-lfs",
            "cxx17-strict",
            "cxx17-posix-2008",
            "cxx17-xopen-700",
            "cxx17-gnu",
            "cxx17-bsd",
            "cxx17-lfs",
            "check_cxx_c_linkage",
            "nm --undefined-only",
            "cxx-null-stdio-first",
            "cxx-null-string-first",
            "MISMATCH:",
            "x86 remains unpromoted",
            "candidate mismatches",
        ):
            self.assertIn(required, matrix)
        self.assertIn("run_stdlib_header_abi()", runner)
        self.assertIn(
            "compat/x86_64/run_stdlib_header_abi.sh",
            runner,
        )
        self.assertIn("stdlib-header-abi", runner)

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
            "[(false, &C_NAME[..]), (true, &UTF8_NAME[..])]",
            "LC_CTYPE_UTF8_MASK",
            "category != LC_CTYPE as usize && utf8",
            "(state == LC_CTYPE_UTF8_MASK).then_some(state)",
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

    def test_filesystem_capacity_header_and_static_c_abi_stay_explicit(
        self,
    ) -> None:
        """Filesystem capacity remains one private header/archive vertical slice."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "filesystem_capacity.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "filesystem_capacity_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "filesystem_capacity_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_filesystem_capacity_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_filesystem_capacity_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_filesystem_capacity_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_filesystem_capacity.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "filesystem_capacity.rs"]', static_root)
        self.assertIn("SYS_STATFS: i64 = 137", syscall)
        self.assertIn("SYS_FSTATFS: i64 = 138", syscall)
        for required in (
            "musl 1.2.6 release commit",
            "src/stat/statvfs.c",
            'extern "C" fn statfs',
            'extern "C" fn fstatfs',
            'extern "C" fn statvfs',
            'extern "C" fn fstatvfs',
            "raw_syscall::SYS_STATFS",
            "raw_syscall::SYS_FSTATFS",
            "statvfs_from_statfs",
            "c_status(result)",
        ):
            self.assertIn(required, implementation)
        self.assertNotIn("crabc_core", implementation)

        for probe in (header_c, header_cpp):
            for required in (
                "sys/statfs.h",
                "sys/statvfs.h",
                "struct statfs",
                "struct statvfs",
                "statfs64",
                "fstatfs64",
                "statvfs64",
                "fstatvfs64",
                "fsblkcnt64_t",
                "fsfilcnt64_t",
            ):
                self.assertIn(required, probe)
        for required in (
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "c11-gnu",
            "cxx17-strict",
            "cxx17-gnu",
            "c11-largefile64",
            "cxx17-largefile64",
            "retained a mangled filesystem-capacity reference",
            "features.h",
            "bits/statfs.h",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "SYS_statfs == 137",
            "SYS_fstatfs == 138",
            "statfs(path, &path_statfs)",
            "fstatfs(descriptor, &fd_statfs)",
            "statvfs(path, &path_statvfs)",
            "fstatvfs(descriptor, &fd_statvfs)",
            "CRABC_FILESYSTEM_CAPACITY_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_filesystem_capacity_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_filesystem_capacity_header_abi.sh",
            "run_x86_statfs_reference.sh",
            "-nostdlib -static",
            "assert_capacity_syscall_paths",
            "statfs lacks Linux syscall 137",
            "fstatfs lacks Linux syscall 138",
            "assert_fixture_tls_capacity",
        ):
            self.assertIn(required, artifact_runner)
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        for symbol in ("statfs", "fstatfs", "statvfs", "fstatvfs"):
            self.assertIn(symbol, static_export_names)
        self.assertNotIn("statfs64", static_export_names)
        self.assertNotIn("statvfs64", static_export_names)
        for command in (
            "./scripts/dev-x86_64.sh filesystem-capacity-header-abi",
            "./scripts/dev-x86_64.sh libc-filesystem-capacity",
        ):
            self.assertIn(command, parity_ledger)
        for required in (
            "run_filesystem_capacity_header_abi()",
            "run_libc_filesystem_capacity_probe()",
            "/workspace/compat/x86_64/run_filesystem_capacity_header_abi.sh",
            "/workspace/compat/x86_64/run_libc_filesystem_capacity.sh",
            '    filesystem-capacity-header-abi)\n        [ "$#" -eq 0 ] || fail "filesystem-capacity-header-abi takes no arguments"',
            '    libc-filesystem-capacity)\n        [ "$#" -eq 0 ] || fail "libc-filesystem-capacity takes no arguments"',
        ):
            self.assertIn(required, runner)

    def test_vector_io_header_and_static_c_abi_stay_explicit(self) -> None:
        """Vector I/O remains one private header/archive vertical slice."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "vector_io.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "vector_io_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "vector_io_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_vector_io_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_vector_io_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_vector_io_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_vector_io.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "vector_io.rs"]', static_root)
        for required in (
            "SYS_READV: i64 = 19",
            "SYS_WRITEV: i64 = 20",
            "SYS_PREADV: i64 = 295",
            "SYS_PWRITEV: i64 = 296",
        ):
            self.assertIn(required, syscall)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/readv.c",
            "src/unistd/pwritev.c",
            'extern "C" fn readv',
            'extern "C" fn writev',
            'extern "C" fn preadv',
            'extern "C" fn pwritev',
            "raw_syscall::SYS_READV",
            "raw_syscall::SYS_PWRITEV2",
            "offset == -1",
            "RWF_NOAPPEND",
            "EOPNOTSUPP",
            "F_GETFL",
            "O_APPEND",
        ):
            self.assertIn(required, implementation)
        self.assertNotIn("crabc_core", implementation)

        for probe in (header_c, header_cpp):
            for required in (
                "sys/uio.h",
                "struct iovec",
                "UIO_MAXIOV == 1024",
                "preadv64",
                "pwritev64",
                "off64_t",
                "preadv2",
                "pwritev2",
                "RWF_NOAPPEND",
            ):
                self.assertIn(required, probe)
        for required in (
            "EXPECTED_PROFILE_COUNT=14",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-bsd",
            "c11-gnu",
            "cxx17-gnu",
            "c11-largefile64",
            "cxx17-largefile64",
            "c11-bsd-largefile64",
            "cxx17-bsd-largefile64",
            "c11-gnu-largefile64",
            "cxx17-gnu-largefile64",
            "positioned-hidden",
            "gnu-v2-hidden",
            "gnu-process-vm-hidden",
            "gnu-rwf-hidden",
            "retained a mangled vector-I/O reference",
            "features.h",
            "bits/alltypes.h",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "SYS_readv == 19",
            "SYS_writev == 20",
            "SYS_preadv == 295",
            "SYS_pwritev == 296",
            "writev(descriptor, write_parts, 2)",
            "pwritev(descriptor, positioned_parts, 2, 1)",
            "preadv(descriptor, read_parts, 2, 0)",
            "readv(descriptor, read_second_parts, 2)",
            "((off_t)1 << 32) + 17",
            "SEEK_END) != high_offset + 1",
            "CRABC_VECTOR_IO_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_vector_io_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_vector_io_header_abi.sh",
            "-nostdlib -static",
            "assert_named_syscall readv 13",
            "assert_named_syscall writev 14",
            "assert_named_syscall preadv 127",
            "for syscall_word in 148 48 128; do",
            "pwritev lacks Linux syscall ${syscall_word}",
        ):
            self.assertIn(required, artifact_runner)
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        for symbol in ("readv", "writev", "preadv", "pwritev"):
            self.assertIn(symbol, static_export_names)
        self.assertNotIn("preadv64", static_export_names)
        self.assertNotIn("pwritev64", static_export_names)
        for command in (
            "./scripts/dev-x86_64.sh vector-io-header-abi",
            "./scripts/dev-x86_64.sh libc-vector-io",
        ):
            self.assertIn(command, parity_ledger)
        for required in (
            "run_vector_io_header_abi()",
            "run_libc_vector_io_probe()",
            "/workspace/compat/x86_64/run_vector_io_header_abi.sh",
            "/workspace/compat/x86_64/run_libc_vector_io.sh",
            '    vector-io-header-abi)\n        [ "$#" -eq 0 ] || fail "vector-io-header-abi takes no arguments"',
            '    libc-vector-io)\n        [ "$#" -eq 0 ] || fail "libc-vector-io takes no arguments"',
        ):
            self.assertIn(required, runner)

    def test_socket_messages_header_and_static_c_abi_stay_explicit(self) -> None:
        """Socket messages/options remain one private header/archive vertical slice."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "socket_messages.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "socket_messages_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "socket_messages_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        visibility = (
            ROOT / "compat" / "x86_64" / "socket_messages_header_visibility_probe.c"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_socket_messages_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_socket_messages_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_socket_messages_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_socket_messages.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "socket_messages.rs"]', static_root)
        for required in (
            "SYS_IOCTL: i64 = 16",
            "SYS_SENDMSG: i64 = 46",
            "SYS_RECVMSG: i64 = 47",
            "SYS_SETSOCKOPT: i64 = 54",
            "SYS_GETSOCKOPT: i64 = 55",
            "SYS_RECVMMSG: i64 = 299",
            "SYS_SENDMMSG: i64 = 307",
        ):
            self.assertIn(required, syscall)
        for required in (
            "musl 1.2.6 release commit",
            "src/network/setsockopt.c",
            "src/network/sendmmsg.c",
            "src/network/sockatmark.c",
            "MUSL_SEND_CONTROL_BYTES",
            "1_056",
            "zero_cmsg_padding",
            "SYS_SENDMSG",
            "SYS_RECVMMSG",
            "SIOCATMARK",
            'extern "C" fn setsockopt',
            'extern "C" fn getsockopt',
            'extern "C" fn sendmsg',
            'extern "C" fn recvmsg',
            'extern "C" fn sendmmsg',
            'extern "C" fn recvmmsg',
            'extern "C" fn sockatmark',
        ):
            self.assertIn(required, implementation)
        self.assertNotIn("crabc_core", implementation)
        self.assertNotIn("crabc_mimalloc", implementation)

        for probe in (header_c, header_cpp):
            for required in (
                "sys/socket.h",
                "msghdr",
                "cmsghdr",
                "CMSG_ALIGN",
                "setsockopt",
                "getsockopt",
                "sendmsg",
                "recvmsg",
                "sockatmark",
            ):
                self.assertIn(required, probe)
        for required in ("mmsghdr", "sendmmsg", "recvmmsg"):
            self.assertIn(required, visibility)
        for required in (
            "compile_profile posix",
            "compile_profile gnu",
            "compile_profile bsd",
            "POSIX profile",
            "unmangled",
            "CMSG_ALIGN remains available",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "SCM_RIGHTS",
            "too_large.msg_controllen = 1057",
            "failed_receive.__pad1 != 0",
            "sendmmsg(pair[0], send_messages, 2, 0)",
            "recvmmsg(pair[1], receive_messages, 2, 0, 0)",
            "sockatmark(-1)",
            "CRABC_SOCKET_MESSAGES_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_socket_messages_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_socket_messages_header_abi.sh",
            "-nostdlib -static",
            "assert_named_syscall setsockopt 36",
            "assert_named_syscall getsockopt 37",
            "assert_named_syscall sendmsg 2e",
            "assert_named_syscall recvmsg 2f",
            "assert_named_syscall recvmmsg 12b",
            "assert_named_syscall sockatmark 10",
            "sendmmsg lacks its musl-shaped sendmsg syscall path",
            "sendmmsg incorrectly uses raw Linux SYS_sendmmsg",
        ):
            self.assertIn(required, artifact_runner)
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        for symbol in (
            "setsockopt",
            "getsockopt",
            "sendmsg",
            "recvmsg",
            "sendmmsg",
            "recvmmsg",
            "sockatmark",
        ):
            self.assertIn(symbol, static_export_names)
        for command in (
            "./scripts/dev-x86_64.sh socket-messages-header-abi",
            "./scripts/dev-x86_64.sh libc-socket-messages",
        ):
            self.assertIn(command, parity_ledger)
        for required in (
            "run_socket_messages_header_abi()",
            "/workspace/compat/x86_64/run_socket_messages_header_abi.sh",
            "/workspace/compat/x86_64/run_libc_socket_messages.sh",
            '    socket-messages-header-abi)\n        [ "$#" -eq 0 ] || fail "socket-messages-header-abi takes no arguments"',
            '    libc-socket-messages)\n        [ "$#" -eq 0 ] || fail "libc-socket-messages takes no arguments"',
        ):
            self.assertIn(required, runner)

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
            "[[:space:]]TLS[[:space:]]", "__newlocale", "strxfrm",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn('id = "static-c-locale-ctype-locators"', parity)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-locale-ctype-locators"',
            parity,
        )
        self.assertIn("libc-locale-ctype-locators)", dispatcher)

    def test_bounded_dlopen_elf_checks_are_pipefail_safe(self) -> None:
        runner = (
            ROOT / "compat" / "x86_64" / "run_ldso_bounded_dlopen.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("set -euo pipefail", runner)
        self.assertNotIn(" | grep -q ", runner)
        self.assertNotIn(" | grep -Eq ", runner)
        self.assertIn("grep -F ' TLS ' >/dev/null", runner)
        self.assertIn("grep -E '\\(NEEDED\\)|\\(INTERP\\)|\\(RELR\\)' >/dev/null", runner)
        self.assertIn("-Wl,-init,bounded_plugin_legacy_initialize", runner)
        self.assertIn("-Wl,-init,mid_value", runner)
        self.assertIn("candidate accepted DT_INIT in an initial DSO", runner)
        self.assertIn("rewrite_init_array_as_preinit", runner)
        self.assertIn("DT_PREINIT_ARRAY", runner)
        self.assertIn("main-musl-bounded-preinit", runner)

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
            "    ctype-header-abi|locale-profile-header-abi|locale-multibyte-header-abi|iconv-header-abi|wide-character-header-abi|locale-object-wide-header-abi|locale-narrow-header-abi) ;;",
            source,
        )
        self.assertIn("    ffs-header-abi) ;;", source)
        self.assertIn("    byte-strings-header-abi) ;;", source)
        self.assertIn("    memory-search-header-abi) ;;", source)
        self.assertIn("    string-copy-header-abi) ;;", source)
        self.assertIn("    string-duplication-header-abi) ;;", source)
        self.assertIn("    linux-5-10-uapi) ;;", source)
        self.assertIn("    candidate-header-closure) ;;", source)
        self.assertIn("    installed-header-tree-closure) ;;", source)
        self.assertIn("    dirent-header-abi) ;;", source)
        self.assertIn("    inet-address-header-abi) ;;", source)
        self.assertIn("    libc-network-byte-order) ;;", source)
        self.assertIn("    libc-in6addr-any)", source)
        self.assertIn("    libc-in6addr-loopback)", source)
        self.assertIn("    libc-inet-ntoa)", source)
        self.assertIn("    libc-inet-classful)", source)
        self.assertIn("    libc-hstrerror)", source)
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
        preflight = source.split('case "$command" in\n', 1)[1].split(
            '\nesac\n\nrequire_native_linux_x86_64_host\n\ncase "$command" in\n', 1
        )[0]
        actual_groups = tuple(
            line.strip()[:-4]
            for line in preflight.splitlines()
            if line.strip().endswith(") ;;")
        )
        expected_groups = (
            "timerfd-header-abi|signalfd-header-abi",
            "libc-timerfd|libc-signalfd|libc-sigpause|libc-sigisemptyset|libc-sigandset-sigorset|libc-sigpending|libc-sigrtmax|libc-sigrtmin|libc-sigaddset-sigdelset-sigfillset",
            "ctermid-header-abi|gethostid-header-abi|isatty-header-abi|tcgetpgrp-header-abi|tcsetpgrp-header-abi|getpass-header-abi|libc-ctermid|libc-gethostid|libc-isatty|libc-tcgetpgrp|libc-tcsetpgrp|libc-getpass|mkfifo-header-abi|mkfifoat-header-abi|libc-mkfifo|libc-mkfifoat|mktemp-header-abi|libc-mktemp",
            "stdio-permanent-line-io-header-abi|stdio-octal-hex-scan-header-abi",
            "math-complex-complete-header-abi|libc-math-complex-complete",
            "stdio-permanent-byte-io-header-abi",
            "stdio-permanent-status-header-abi",
            "stdio-permanent-fileno-header-abi",
            "stdio-permanent-fileno-unlocked-header-abi",
            "stdio-permanent-feof-unlocked-header-abi",
            "image|musl-oracle|header-abi-reference|public-header-surface|header-abi-project|math-complex-header-abi|sys-reg-header-abi|types-header-abi|stat-header-abi|utime-header-abi|pthread-c11-header-abi|pthread-cancellation-header-abi|stdlib-header-abi|stdio-standard-header-abi|time-header-abi|poll-header-abi|select-header-abi|fcntl-header-abi|descriptor-advice-header-abi|filesystem-capacity-header-abi|flock-header-abi|sendfile-header-abi|ioctl-header-abi|unistd-header-abi|system-header-abi|syscall-header-abi|signal-header-abi|termios-header-abi|mman-header-abi|resource-header-abi|socket-header-abi|socket-messages-header-abi|random-entropy-header-abi|mm-abi-reference|mapping-reference|memory-vm-reference|pty-basic-reference|terminal-reference|mlock-reference|msync-reference|mincore-reference|fs-advice-reference|memfd-reference|ftruncate-reference|statfs-reference|timestamp-reference|path-lifecycle-reference|namespace-reference|path-core-reference|xattr-reference|directory-reference|temporary-object-reference|statx-reference|cwd-canonicalize-reference|root-change-reference|mount-reference|thread-kill-reference|ipc-reference|shm-reference|inotify-reference|socket-transport-reference|interface-device-reference|resolver-transport-reference|resolver-facade-reference|netdb-reference|users-databases-reference|posix-fallocate-reference|fallocate-reference|file-position-reference|sync-reference|syncfs-reference|sync-file-range-reference|rand-reference|time-abi-reference|time-observation-reference|calendar-time-reference|advanced-time-reference|relative-sleep-reference|clock-nanosleep-reference|getitimer-reference|setitimer-reference|timerfd-reference|pselect-reference|poll-reference|ppoll-reference|epoll-reference|process-identity-reference|child-ownership-reference|getgroups-reference|process-session-reference|pidfd-open-reference|fcntl-getlk-reference|fcntl-status-reference|flock-reference|sendfile-reference|copy-file-range-reference|scheduler-priority-bounds-reference|rr-interval-reference|sched-affinity-reference|sched-affinity-set-reference|priority-reference|setpriority-reference|rlimit-reference|rlimit-targeted-reference|setrlimit-reference|umask-reference|rusage-reference|times-reference|fstat-reference|statat-reference|getcwd-reference|readlinkat-reference|access-reference|system-reference|thread-reference|thread-credentials-reference|fs-credentials-reference|core|facade|facade-record-owning|libc-syscall|libc-errno-tls|libc-stat-compat|libc-credentials|libc-bootstrap-primitives|libc-signal-control|libc-signal-execution|libc-static-tls-v1|libc-crt-static-tls|libc-pthread-create-join-tls|libc-c11-lifecycle|libc-c11-plain-sync|libc-pthread-c11-once|libc-pthread-c11-tsd|libc-pthread-tls-aggregate|libc-pthread-cancel-deferred|libc-pthread-atfork|libc-thrd-sleep|libc-pthread-mutex-normal|libc-pthread-rwlock|libc-pthread-cond-private|libc-termios-control|libc-process-context|libc-environment|libc-descriptor-io|libc-descriptor-lifecycle|libc-timestamp-updates|libc-process-resources|libc-socket-transport|libc-socket-messages|libc-thread-pointer|libc-foundation|libc-fenv|libc-math-complex|libc-elementary-sqrt-fenv|libc-math-x87-extended|libc-memory|libc-setjmp|libc-atomic|libc-clone-raw|libc-signal-altstack|libc-signal-foundation|ldso-relocation|ldso-image|ldso-initial-graph|ldso-initial-tls|ldso-initial-exec-tls|ldso-owned-crt-handoff|ldso-fixed-graph-introspection|ldso-dynamic-admission",
            "math-elementary-long-double-header-abi|libc-math-elementary-long-double",
            "ldso-fixed-graph-dlfcn",
            "ldso-public-dlfcn|ldso-dladdr-symbol-bounds",
            "ldso-bounded-dlopen",
            "math-special-header-abi|libc-math-special",
            "inet-address-header-abi",
            "libc-network-byte-order",
            "ldso-target-root",
            "libc-fenv-rounding",
            "libc-math-minmax",
            "libc-math-bit-sign",
            "libc-math-trunc",
            "libc-math-fmod",
            "libc-math-cbrt",
            "libc-math-ceil",
            "libc-math-floor",
            "libc-math-round",
            "libc-fdim",
            "machine-context-header-abi",
            "memory-sync-header-abi",
            "memory-locking-header-abi",
            "memfd-create-header-abi",
            "vector-io-header-abi",
            "libc-crt1-static-tls",
            "owned-static-sysroot",
            "crt-object-bundle",
            "crt-dynamic-startup|crt-dynamic-link-contract|consumer-static-pie-lto|consumer-native-facade-lto",
            "linux-5-10-uapi",
            "candidate-header-closure",
            "installed-header-tree-closure",
            "uapi-wrapper-matrix",
            "epoll-header-abi",
            "event-descriptors-header-abi",
            "dirent-header-abi",
            "pathname-lifecycle-header-abi",
            "timeval-transitive-header-abi",
            "sys-time-direct-header-abi",
            "access-header-abi",
            "xattr-header-abi",
            "madvise-reference",
            "ctype-header-abi|locale-profile-header-abi|locale-multibyte-header-abi|iconv-header-abi|wide-character-header-abi|locale-object-wide-header-abi|locale-narrow-header-abi",
            "integer-arithmetic-header-abi|integer-parse-header-abi|float-parse-header-abi|getsubopt-header-abi|intmax-arithmetic-header-abi|credential-observation-header-abi|login-name-header-abi|child-reaping-header-abi|immediate-termination-header-abi|bsearch-header-abi|linear-search-header-abi|qsort-header-abi|callback-algorithms-header-abi",
            "posix-exit-header-abi",
            "ffs-header-abi",
            "byte-strings-header-abi",
            "memory-search-header-abi",
            "memccpy-header-abi",
            "mempcpy-header-abi",
            "strsep-header-abi",
            "string-copy-header-abi",
            "error-strings-header-abi|strsignal-header-abi|gettext-catalog-header-abi",
            "string-duplication-header-abi",
            "random-entropy-header-abi",
            "sysv-semaphore-header-abi|posix-semaphore-header-abi",
            "sysv-message-shared-memory-header-abi",
            "libc-event-descriptors",
            "libc-extended-attributes",
            "libc-pathname-lifecycle",
            "libc-directory-streams",
            "libc-lchmod-unsupported",
            "libc-stdio-standard|libc-stdio-format-scan|libc-stdio-integer-scan|libc-stdio-octal-hex-scan|libc-stdio-float-hex-output|libc-stdio-errno-output|libc-stdio-permanent-line-io|libc-stdio-permanent-byte-io|libc-stdio-permanent-status|libc-stdio-permanent-fileno|libc-stdio-permanent-fileno-unlocked|libc-stdio-permanent-feof-unlocked|libc-stdio-path-stream|libc-stdio-tmpfile|libc-text-math-locale-stdio-composition",
            "libc-pthread-identity",
            "libc-pthread-affinity",
            "libc-pthread-cpuclock",
            "libc-pthread-name",
            "libc-pthread-detach",
            "libc-thrd-yield",
            "libc-memory-sync",
            "libc-memory-locking",
            "libc-memfd-create",
            "libc-legacy-memory",
            "libc-memccpy",
            "libc-mempcpy",
            "libc-strsep",
            "libc-allocator-runtime",
            "libc-allocator-string-duplication",
            "libc-allocator-observability",
            "libc-alloca",
            "libc-static-c-abi-differential",
            "libc-static-c-abi-same-object-differential|qualification-posix-abi-admission",
            "libc-interface-discovery",
            "libc-posix-exit",
            "libc-readiness-waits|libc-system-observation|libc-system-information|libc-fcntl-record-locks|libc-flock|libc-sendfile|libc-posix-fallocate|libc-descriptor-advice|libc-filesystem-capacity|libc-uts-identity|libc-ctype|libc-locale-profile|libc-locale-multibyte|libc-locale-wide-iconv|libc-wide-character|libc-locale-object-wide|libc-locale-narrow|libc-locale-ctype-locators|libc-locale-error-strings|libc-regex|libc-integer-arithmetic|libc-integer-parse|libc-float-parse|libc-getsubopt|libc-intmax-arithmetic|libc-credential-observation|libc-secure-environment|libc-login-name|libc-child-reaping|libc-immediate-termination|libc-bsearch|libc-linear-search|libc-qsort|libc-callback-algorithms|libc-search-tree-intrusive|libc-search-hash-table|libc-gettext-catalog|libc-access|libc-clock-gettime|libc-time-observation|libc-difftime|libc-timegm|libc-gmtime-r|libc-system-configuration|libc-mapping-core|libc-header-layouts-baseline|libc-nanosleep|libc-clock-nanosleep|libc-descriptor-entry|libc-fcntl-status-control|libc-ioctl|libc-ffs|libc-byte-strings|libc-in6addr-any|libc-in6addr-loopback|libc-process-globals-getopt|libc-auxv-observation|libc-inet-address|libc-inet-ntoa|libc-inet-classful|libc-hstrerror|libc-numeric-netdb|libc-random-entropy|libc-memory-search|libc-string-copy|libc-error-strings|libc-strsignal|libc-descriptor-pipeline",
            "libc-vector-io|libc-uio-cxx-linkage",
            "libc-sysv-semaphore|libc-posix-semaphore",
            "libc-sysv-message-shared-memory",
        )
        self.assertEqual(actual_groups, expected_groups)

        expected_commands = {
            command
            for group in expected_groups
            for command in group.split("|")
        }
        handlers = source.split(
            'require_native_linux_x86_64_host\n\ncase "$command" in\n', 1
        )[1]
        handler_groups = re.findall(
            r"^    ([a-z0-9-]+(?:\|[a-z0-9-]+)*)\)$", handlers, re.MULTILINE
        )
        handled_commands = {
            command
            for group in handler_groups
            for command in group.split("|")
        }
        self.assertSetEqual(handled_commands, expected_commands)
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
        self.assertIn("libc-termios-control", source)
        self.assertIn("ctermid-header-abi", source)
        self.assertIn("libc-ctermid", source)
        self.assertIn("tcsetpgrp-header-abi", source)
        self.assertIn("libc-tcsetpgrp", source)
        self.assertIn("getpass-header-abi", source)
        self.assertIn("libc-getpass", source)
        self.assertIn("mkfifo-header-abi", source)
        self.assertIn("libc-mkfifo", source)
        self.assertIn("mkfifoat-header-abi", source)
        self.assertIn("libc-mkfifoat", source)
        self.assertIn("mktemp-header-abi", source)
        self.assertIn("libc-mktemp", source)
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
        self.assertIn("libc-lchmod-unsupported", source)
        self.assertIn("libc-process-resources", source)
        self.assertIn("libc-readiness-waits", source)
        self.assertIn("libc-socket-transport", source)
        self.assertIn("libc-system-observation", source)
        self.assertIn("libc-system-information", source)
        self.assertIn("libc-fcntl-record-locks", source)
        self.assertIn("libc-uts-identity", source)
        self.assertIn('run_musl_oracle()', source)
        self.assertIn('compat/x86_64/run_musl_oracle.sh', source)
        self.assertIn('run_linux_5_10_uapi()', source)
        self.assertIn('compat/x86_64/run_linux_5_10_uapi.sh', source)
        self.assertIn('run_header_abi_reference()', source)
        self.assertIn('compat/x86_64/run_header_abi_reference.sh', source)
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
        self.assertIn('run_descriptor_advice_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_descriptor_advice_header_abi.sh', source
        )
        self.assertIn('run_ioctl_header_abi()', source)
        self.assertIn('compat/x86_64/run_ioctl_header_abi.sh', source)
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
        self.assertIn('rustup run nightly-2026-07-24 rustc --edition=2021 --test', source)
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

    def test_pinned_musl_oracle_and_reference_header_baseline_stay_closed(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        dockerfile = (ROOT / "docker" / "Dockerfile.x86_64").read_text(encoding="utf-8")
        wrapper = (ROOT / "docker" / "x86_64-musl-oracle-gcc").read_text(encoding="utf-8")
        oracle = (ROOT / "compat" / "x86_64" / "run_musl_oracle.sh").read_text(
            encoding="utf-8"
        )
        reference = (ROOT / "compat" / "x86_64" / "run_header_abi_reference.sh").read_text(
            encoding="utf-8"
        )
        project = (ROOT / "compat" / "x86_64" / "run_project_header_abi.sh").read_text(
            encoding="utf-8"
        )
        sys_reg = (ROOT / "compat" / "x86_64" / "run_sys_reg_header_abi.sh").read_text(
            encoding="utf-8"
        )
        types = (ROOT / "compat" / "x86_64" / "run_types_header_abi.sh").read_text(
            encoding="utf-8"
        )
        syscall = (ROOT / "compat" / "x86_64" / "run_x86_syscall_header.sh").read_text(
            encoding="utf-8"
        )
        mapping = (ROOT / "compat" / "x86_64" / "run_x86_mm_reference.sh").read_text(
            encoding="utf-8"
        )
        mlock = (ROOT / "compat" / "x86_64" / "run_x86_mlock_reference.sh").read_text(
            encoding="utf-8"
        )
        msync = (ROOT / "compat" / "x86_64" / "run_x86_msync_reference.sh").read_text(
            encoding="utf-8"
        )
        madvise = (ROOT / "compat" / "x86_64" / "run_x86_madvise_reference.sh").read_text(
            encoding="utf-8"
        )
        mincore = (ROOT / "compat" / "x86_64" / "run_x86_mincore_reference.sh").read_text(
            encoding="utf-8"
        )
        fs_advice = (
            ROOT / "compat" / "x86_64" / "run_x86_fs_advice_reference.sh"
        ).read_text(encoding="utf-8")
        memfd = (ROOT / "compat" / "x86_64" / "run_x86_memfd_reference.sh").read_text(
            encoding="utf-8"
        )
        ftruncate = (
            ROOT / "compat" / "x86_64" / "run_x86_ftruncate_reference.sh"
        ).read_text(encoding="utf-8")
        timestamp = (
            ROOT / "compat" / "x86_64" / "run_x86_timestamp_reference.sh"
        ).read_text(encoding="utf-8")
        posix_fallocate = (
            ROOT / "compat" / "x86_64" / "run_x86_posix_fallocate_reference.sh"
        ).read_text(encoding="utf-8")
        fallocate = (
            ROOT / "compat" / "x86_64" / "run_x86_fallocate_reference.sh"
        ).read_text(encoding="utf-8")
        file_position = (
            ROOT / "compat" / "x86_64" / "run_x86_file_position_reference.sh"
        ).read_text(encoding="utf-8")
        sync = (ROOT / "compat" / "x86_64" / "run_x86_sync_reference.sh").read_text(
            encoding="utf-8"
        )
        syncfs = (
            ROOT / "compat" / "x86_64" / "run_x86_syncfs_reference.sh"
        ).read_text(encoding="utf-8")
        sync_file_range = (
            ROOT / "compat" / "x86_64" / "run_x86_sync_file_range_reference.sh"
        ).read_text(encoding="utf-8")
        signal = (ROOT / "compat" / "x86_64" / "run_signal_header_abi.sh").read_text(
            encoding="utf-8"
        )
        termios_header = (
            ROOT / "compat" / "x86_64" / "run_termios_header_abi.sh"
        ).read_text(encoding="utf-8")
        mman = (ROOT / "compat" / "x86_64" / "run_mman_header_abi.sh").read_text(
            encoding="utf-8"
        )
        resource_header = (
            ROOT / "compat" / "x86_64" / "run_resource_header_abi.sh"
        ).read_text(encoding="utf-8")
        random = (ROOT / "compat" / "x86_64" / "run_x86_rand_reference.sh").read_text(
            encoding="utf-8"
        )
        stat_header = (ROOT / "compat" / "x86_64" / "run_stat_header_abi.sh").read_text(
            encoding="utf-8"
        )
        time_header = (ROOT / "compat" / "x86_64" / "run_time_header_abi.sh").read_text(
            encoding="utf-8"
        )
        poll_header = (ROOT / "compat" / "x86_64" / "run_poll_header_abi.sh").read_text(
            encoding="utf-8"
        )
        select_header = (
            ROOT / "compat" / "x86_64" / "run_select_header_abi.sh"
        ).read_text(encoding="utf-8")
        fcntl_header = (ROOT / "compat" / "x86_64" / "run_fcntl_header_abi.sh").read_text(
            encoding="utf-8"
        )
        unistd_header = (ROOT / "compat" / "x86_64" / "run_unistd_header_abi.sh").read_text(
            encoding="utf-8"
        )
        system_header = (ROOT / "compat" / "x86_64" / "run_system_header_abi.sh").read_text(
            encoding="utf-8"
        )
        time_reference = (ROOT / "compat" / "x86_64" / "run_x86_time_reference.sh").read_text(
            encoding="utf-8"
        )
        time_observation_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_time_observation_reference.sh"
        ).read_text(encoding="utf-8")
        relative_sleep_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_relative_sleep_reference.sh"
        ).read_text(encoding="utf-8")
        clock_nanosleep_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_clock_nanosleep_reference.sh"
        ).read_text(encoding="utf-8")
        clock_nanosleep_probe = (
            ROOT / "compat" / "x86_64" / "x86_clock_nanosleep_reference_probe.c"
        ).read_text(encoding="utf-8")
        getitimer_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_getitimer_reference.sh"
        ).read_text(encoding="utf-8")
        setitimer_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_setitimer_reference.sh"
        ).read_text(encoding="utf-8")
        setitimer_probe = (
            ROOT / "compat" / "x86_64" / "x86_setitimer_reference_probe.c"
        ).read_text(encoding="utf-8")
        setitimer_test = (
            ROOT / "crabc-rs" / "tests" / "x86_64_setitimer.rs"
        ).read_text(encoding="utf-8")
        timerfd_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_timerfd_reference.sh"
        ).read_text(encoding="utf-8")
        pselect_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_pselect_reference.sh"
        ).read_text(encoding="utf-8")
        poll_reference = (ROOT / "compat" / "x86_64" / "run_x86_poll_reference.sh").read_text(
            encoding="utf-8"
        )
        ppoll_reference = (ROOT / "compat" / "x86_64" / "run_x86_ppoll_reference.sh").read_text(
            encoding="utf-8"
        )
        epoll_reference = (ROOT / "compat" / "x86_64" / "run_x86_epoll_reference.sh").read_text(
            encoding="utf-8"
        )
        process_identity_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_process_identity_reference.sh"
        ).read_text(encoding="utf-8")
        getgroups_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_getgroups_reference.sh"
        ).read_text(encoding="utf-8")
        process_session_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_process_session_reference.sh"
        ).read_text(encoding="utf-8")
        pidfd_open_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_pidfd_open_reference.sh"
        ).read_text(encoding="utf-8")
        fcntl_getlk_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_fcntl_getlk_reference.sh"
        ).read_text(encoding="utf-8")
        fcntl_status_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_fcntl_status_reference.sh"
        ).read_text(encoding="utf-8")
        flock_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_flock_reference.sh"
        ).read_text(encoding="utf-8")
        sendfile_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_sendfile_reference.sh"
        ).read_text(encoding="utf-8")
        copy_file_range_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_copy_file_range_reference.sh"
        ).read_text(encoding="utf-8")
        scheduler_priority_bounds_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_scheduler_priority_bounds_reference.sh"
        ).read_text(encoding="utf-8")
        priority_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_priority_reference.sh"
        ).read_text(encoding="utf-8")
        setpriority_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_setpriority_reference.sh"
        ).read_text(encoding="utf-8")
        rlimit_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_rlimit_reference.sh"
        ).read_text(encoding="utf-8")
        rusage_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_rusage_reference.sh"
        ).read_text(encoding="utf-8")
        times_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_times_reference.sh"
        ).read_text(encoding="utf-8")
        fstat_reference = (ROOT / "compat" / "x86_64" / "run_x86_fstat_reference.sh").read_text(
            encoding="utf-8"
        )
        statfs_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_statfs_reference.sh"
        ).read_text(encoding="utf-8")
        statat_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_statat_reference.sh"
        ).read_text(encoding="utf-8")
        getcwd_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_getcwd_reference.sh"
        ).read_text(encoding="utf-8")
        readlinkat_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_readlinkat_reference.sh"
        ).read_text(encoding="utf-8")
        access_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_access_reference.sh"
        ).read_text(encoding="utf-8")
        rr_interval_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_sched_rr_interval_reference.sh"
        ).read_text(encoding="utf-8")
        sched_affinity_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_sched_affinity_reference.sh"
        ).read_text(encoding="utf-8")
        sched_affinity_set_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_sched_setaffinity_reference.sh"
        ).read_text(encoding="utf-8")
        system_reference = (ROOT / "compat" / "x86_64" / "run_x86_system_reference.sh").read_text(
            encoding="utf-8"
        )
        thread_reference = (ROOT / "compat" / "x86_64" / "run_x86_thread_reference.sh").read_text(
            encoding="utf-8"
        )
        thread_credentials_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_thread_credentials_reference.sh"
        ).read_text(encoding="utf-8")
        image = (ROOT / "ldso" / "run-x86_64-image.sh").read_text(encoding="utf-8")
        sys_types = (ROOT / "include" / "sys" / "types.h").read_text(encoding="utf-8")
        unistd_include = (ROOT / "include" / "unistd.h").read_text(encoding="utf-8")

        self.assertIn('ARG MUSL_VERSION=1.2.6', dockerfile)
        self.assertIn('ARG MUSL_SHA256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a', dockerfile)
        self.assertIn('ld-musl-x86_64.so.1', dockerfile)
        self.assertIn('/opt/musl-1.2.6/lib/musl-gcc.specs', wrapper)
        self.assertIn('CRABC_MUSL_ORACLE_LIBC_PATH', oracle)
        self.assertIn('libc\\.so\\.6', oracle)
        self.assertIn('run_musl_oracle.sh', reference)
        self.assertIn('header_abi_probe.c', reference)
        self.assertIn('fldt|fstpt', reference)
        self.assertNotIn('-p crabc-libc', reference)
        self.assertIn('run_musl_oracle.sh', project)
        self.assertIn('project_header_abi_probe.c', project)
        self.assertIn('-mfpmath=387', project)
        self.assertIn('-fsyntax-only', project)
        self.assertNotIn('-p crabc-libc', project)
        self.assertIn('run_musl_oracle.sh', sys_reg)
        self.assertIn('sys_reg_header_abi_probe.c', sys_reg)
        self.assertIn('-fsyntax-only', sys_reg)
        self.assertNotIn('-p crabc-libc', sys_reg)
        self.assertIn('types_header_abi_probe.c', types)
        self.assertIn('types_header_abi_probe.cpp', types)
        self.assertIn('-fsyntax-only', types)
        self.assertNotIn('-p crabc-libc', types)
        self.assertIn('x86_syscall_header_probe.c', syscall)
        self.assertIn('384 __NR_* plus 384 SYS_*', syscall)
        self.assertIn('-fsyntax-only', syscall)
        self.assertNotIn('-p crabc-libc', syscall)
        self.assertIn('x86_mm_reference_probe.c', mapping)
        self.assertIn('-fsyntax-only', mapping)
        self.assertNotIn('-p crabc-libc', mapping)
        self.assertIn('x86_mlock_reference_probe.c', mlock)
        self.assertIn('memory-locking ABI/behavior reference', mlock)
        self.assertNotIn('-p crabc-libc', mlock)
        self.assertIn('x86_msync_reference_probe.c', msync)
        self.assertIn('msync ABI/behavior reference', msync)
        self.assertNotIn('-p crabc-libc', msync)
        self.assertIn('x86_madvise_reference_probe.c', madvise)
        self.assertIn('madvise ABI/behavior reference', madvise)
        self.assertNotIn('-p crabc-libc', madvise)
        self.assertIn('x86_mincore_reference_probe.c', mincore)
        self.assertIn('mincore ABI/behavior reference', mincore)
        self.assertNotIn('-p crabc-libc', mincore)
        self.assertIn('x86_fs_advice_reference_probe.c', fs_advice)
        self.assertIn('filesystem-advice ABI/behavior reference', fs_advice)
        self.assertNotIn('-p crabc-libc', fs_advice)
        self.assertIn('x86_memfd_reference_probe.c', memfd)
        self.assertIn('memfd/sealing ABI/behavior reference', memfd)
        self.assertIn(
            'syscalls=319,72 commands=1033,1034 mfd=1,2,4 seals=1,2,4,8,16 name=249-ok:250-einval:proc-label fd=cloexec-owned lifecycle=allow-empty:write-live-map-ebusy:grow-shrink-enforced:write-enforced:future-write-existing-map-preserved:direct-write-rejected:new-writable-map-rejected:final-seal plain=seal-seal errors=EINVAL,EPERM,EBUSY,EBADF',
            memfd,
        )
        self.assertIn('run_musl_oracle.sh', memfd)
        self.assertNotIn('-p crabc-libc', memfd)
        self.assertIn('x86_ftruncate_reference_probe.c', ftruncate)
        self.assertIn('ftruncate ABI/behavior reference', ftruncate)
        self.assertIn('ftruncate=77 loff_t=signed64', ftruncate)
        self.assertIn('run_musl_oracle.sh', ftruncate)
        self.assertNotIn('-p crabc-libc', ftruncate)
        self.assertIn('x86_timestamp_reference_probe.c', timestamp)
        self.assertIn('run_musl_oracle.sh', timestamp)
        self.assertNotIn('-p crabc-libc', timestamp)
        self.assertIn('x86_posix_fallocate_reference_probe.c', posix_fallocate)
        self.assertIn('posix_fallocate reference', posix_fallocate)
        self.assertIn('syscall=285', posix_fallocate)
        self.assertIn('mode=zero', posix_fallocate)
        self.assertIn('bytes=retained-prefix:zero-filled', posix_fallocate)
        self.assertIn('run_musl_oracle.sh', posix_fallocate)
        self.assertNotIn('-p crabc-libc', posix_fallocate)
        self.assertIn('x86_fallocate_reference_probe.c', fallocate)
        self.assertIn('general fallocate(2) reference', fallocate)
        self.assertIn('syscall=285 off_t=signed64', fallocate)
        self.assertIn('modes=zero:keep-size:punch-hole|keep-size:zero-range:zero-range', fallocate)
        self.assertIn('fixture=unlinked-regular-file', fallocate)
        self.assertIn('success:retained-edges:zeroed-range:size-extends-or-kept|EOPNOTSUPP', fallocate)
        self.assertIn('env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH', fallocate)
        self.assertIn('run_musl_oracle.sh', fallocate)
        self.assertNotIn('-p crabc-libc', fallocate)
        self.assertIn('x86_file_position_reference_probe.c', file_position)
        self.assertIn('lseek/fsync/fdatasync ABI/behavior reference', file_position)
        self.assertIn('syscalls=lseek:8,fsync:74,fdatasync:75', file_position)
        self.assertIn('sparse=data4096:hole0', file_position)
        self.assertIn('SEEK_DATA/HOLE:ENXIO', file_position)
        self.assertIn('run_musl_oracle.sh', file_position)
        self.assertNotIn('-p crabc-libc', file_position)
        self.assertIn('x86_sync_reference_probe.c', sync)
        self.assertIn('global sync ABI reference', sync)
        self.assertIn('run_musl_oracle.sh', sync)
        self.assertIn('does not measure writeback timing', sync)
        self.assertNotIn('-p crabc-libc', sync)
        self.assertIn('x86_syncfs_reference_probe.c', syncfs)
        self.assertIn('syncfs ABI/descriptor reference', syncfs)
        self.assertIn('closed-fd=EBADF', syncfs)
        self.assertIn('run_musl_oracle.sh', syncfs)
        self.assertIn('does not claim data survives a crash', syncfs)
        self.assertNotIn('-p crabc-libc', syncfs)
        self.assertIn('x86_sync_file_range_reference_probe.c', sync_file_range)
        self.assertIn('sync_file_range ABI/behavior reference', sync_file_range)
        self.assertIn('run_musl_oracle.sh', sync_file_range)
        self.assertIn('does not claim writeback durability', sync_file_range)
        self.assertNotIn('-p crabc-libc', sync_file_range)
        self.assertIn('signal_header_abi_probe.c', signal)
        self.assertIn('signal_header_posix_abi_probe.c', signal)
        self.assertIn('-fsyntax-only', signal)
        self.assertNotIn('-p crabc-libc', signal)
        self.assertIn('termios_header_abi_probe.c', termios_header)
        self.assertIn('termios_header_abi_probe.cpp', termios_header)
        self.assertIn('include/termios.h', termios_header)
        self.assertIn('include/bits/alltypes.h', termios_header)
        self.assertIn('-fsyntax-only', termios_header)
        self.assertNotIn('-p crabc-libc', termios_header)
        self.assertIn('mman_header_abi_probe.c', mman)
        self.assertIn('mman_header_abi_probe.cpp', mman)
        self.assertIn('include/sys/mman.h', mman)
        self.assertIn('include/bits/mman.h', mman)
        self.assertIn('-fsyntax-only', mman)
        self.assertNotIn('-p crabc-libc', mman)
        self.assertIn('resource_header_abi_probe.c', resource_header)
        self.assertIn('resource_header_abi_probe.cpp', resource_header)
        self.assertIn('sys/resource.h', resource_header)
        self.assertIn('sys/time.h', resource_header)
        self.assertIn('-D_GNU_SOURCE', resource_header)
        self.assertIn('-D_LARGEFILE64_SOURCE', resource_header)
        self.assertIn('-fsyntax-only', resource_header)
        self.assertNotIn('-p crabc-libc', resource_header)
        self.assertIn('x86_rand_reference_probe.c', random)
        self.assertIn('getrandom ABI/behavior reference', random)
        self.assertNotIn('-p crabc-libc', random)
        self.assertIn('stat_header_abi_probe.c', stat_header)
        self.assertIn('stat_header_abi_probe.cpp', stat_header)
        self.assertIn('include/sys/stat.h', stat_header)
        self.assertIn('include/bits/stat.h', stat_header)
        self.assertIn('-fsyntax-only', stat_header)
        self.assertNotIn('-p crabc-libc', stat_header)
        self.assertIn('time_header_abi_probe.c', time_header)
        self.assertIn('time_header_abi_probe.cpp', time_header)
        self.assertIn('include/time.h', time_header)
        self.assertIn('-fsyntax-only', time_header)
        self.assertNotIn('-p crabc-libc', time_header)
        self.assertIn('poll_header_abi_probe.c', poll_header)
        self.assertIn('poll_header_abi_probe.cpp', poll_header)
        self.assertIn('include/poll.h', poll_header)
        self.assertIn('-fsyntax-only', poll_header)
        self.assertNotIn('-p crabc-libc', poll_header)
        self.assertIn('select_header_abi_probe.c', select_header)
        self.assertIn('select_header_abi_probe.cpp', select_header)
        self.assertIn('for header in sys/select.h time.h bits/alltypes.h', select_header)
        self.assertIn('-fsyntax-only', select_header)
        self.assertNotIn('-p crabc-libc', select_header)
        self.assertIn('fcntl_header_abi_probe.c', fcntl_header)
        self.assertIn('fcntl_header_abi_probe.cpp', fcntl_header)
        self.assertIn('include/fcntl.h', fcntl_header)
        self.assertIn('include/bits/fcntl.h', fcntl_header)
        self.assertIn('-fsyntax-only', fcntl_header)
        self.assertNotIn('-p crabc-libc', fcntl_header)
        self.assertIn('unistd_header_abi_probe.c', unistd_header)
        self.assertIn('unistd_header_abi_probe.cpp', unistd_header)
        self.assertIn('include/unistd.h', unistd_header)
        self.assertIn('-fsyntax-only', unistd_header)
        self.assertNotIn('-p crabc-libc', unistd_header)
        self.assertIn('system_header_abi_probe.c', system_header)
        self.assertIn('system_header_abi_probe.cpp', system_header)
        self.assertIn('include tree first', system_header)
        self.assertIn('-fsyntax-only', system_header)
        self.assertNotIn('-p crabc-libc', system_header)
        self.assertIn('x86_time_reference_probe.c', time_reference)
        self.assertIn('timespec ABI reference', time_reference)
        self.assertNotIn('-p crabc-libc', time_reference)
        self.assertIn('x86_time_observation_reference_probe.c', time_observation_reference)
        self.assertIn('realtime observation reference', time_observation_reference)
        self.assertIn('c-time=whole-second', time_observation_reference)
        self.assertNotIn('-p crabc-libc', time_observation_reference)
        self.assertIn('x86_relative_sleep_reference_probe.c', relative_sleep_reference)
        self.assertIn('relative-sleep reference', relative_sleep_reference)
        self.assertNotIn('-p crabc-libc', relative_sleep_reference)
        self.assertIn('x86_clock_nanosleep_reference_probe.c', clock_nanosleep_reference)
        self.assertIn('clock_nanosleep ABI and behavior reference', clock_nanosleep_reference)
        self.assertIn('run_musl_oracle.sh', clock_nanosleep_reference)
        self.assertIn('musl-convention=positive-error/raw-errno', clock_nanosleep_reference)
        self.assertNotIn('-p crabc-libc', clock_nanosleep_reference)
        self.assertIn('(void)ualarm(20000, 0);', clock_nanosleep_probe)
        self.assertNotIn('ualarm(20000, 0) != 0', clock_nanosleep_probe)
        self.assertIn('x86_getitimer_reference_probe.c', getitimer_reference)
        self.assertIn('getitimer ABI and read-only behavior reference', getitimer_reference)
        self.assertIn('run_musl_oracle.sh', getitimer_reference)
        self.assertNotIn('-p crabc-libc', getitimer_reference)
        self.assertIn('x86_setitimer_reference_probe.c', setitimer_reference)
        self.assertIn('setitimer ABI and contained behavior reference', setitimer_reference)
        self.assertIn('run_musl_oracle.sh', setitimer_reference)
        self.assertNotIn('-p crabc-libc', setitimer_reference)
        self.assertIn(
            '-p crabc-rs --no-default-features --test x86_64_setitimer \\\n        -- --test-threads=1',
            source,
        )
        self.assertIn('SYS_setitimer == 38', setitimer_probe)
        self.assertIn('run_in_child', setitimer_probe)
        self.assertIn('invalid=EINVAL', setitimer_probe)
        self.assertIn('ualarm(', setitimer_probe)
        self.assertIn('alarm(', setitimer_probe)
        self.assertIn('aliases=alarm-ceil,ualarm-subsecond', setitimer_probe)
        self.assertIn('ualarm-invalid=EINVAL', setitimer_probe)
        self.assertIn('SigHandler::Ignore', setitimer_test)
        self.assertIn('Signal::ALARM', setitimer_test)
        self.assertIn('restore SIGALRM', setitimer_test)
        self.assertIn('x86_timerfd_reference_probe.c', timerfd_reference)
        self.assertIn('timerfd ABI/lifecycle reference', timerfd_reference)
        self.assertIn('run_musl_oracle.sh', timerfd_reference)
        self.assertNotIn('-p crabc-libc', timerfd_reference)
        self.assertIn('x86_pselect_reference_probe.c', pselect_reference)
        self.assertIn('pselect ABI/behavior reference', pselect_reference)
        self.assertIn('run_musl_oracle.sh', pselect_reference)
        self.assertNotIn('-p crabc-libc', pselect_reference)
        self.assertIn('x86_poll_reference_probe.c', poll_reference)
        self.assertIn('poll ABI/behavior reference', poll_reference)
        self.assertNotIn('-p crabc-libc', poll_reference)
        self.assertIn('x86_ppoll_reference_probe.c', ppoll_reference)
        self.assertIn('ppoll/pause signal-mask reference', ppoll_reference)
        self.assertNotIn('-p crabc-libc', ppoll_reference)
        self.assertIn('x86_epoll_reference_probe.c', epoll_reference)
        self.assertIn('epoll ABI/behavior reference', epoll_reference)
        self.assertIn('run_musl_oracle.sh', epoll_reference)
        self.assertNotIn('-p crabc-libc', epoll_reference)
        self.assertIn('x86_process_identity_reference_probe.c', process_identity_reference)
        self.assertIn('process-identity reference', process_identity_reference)
        self.assertNotIn('-p crabc-libc', process_identity_reference)
        self.assertIn(
            'x86_thread_credentials_reference_probe.c',
            thread_credentials_reference,
        )
        self.assertIn(
            'calling-thread credential ABI reference',
            thread_credentials_reference,
        )
        self.assertIn(
            'syscalls=setresuid:117,setresgid:119',
            thread_credentials_reference,
        )
        self.assertIn('run_musl_oracle.sh', thread_credentials_reference)
        self.assertNotIn('-p crabc-libc', thread_credentials_reference)
        self.assertIn('x86_getgroups_reference_probe.c', getgroups_reference)
        self.assertIn('getgroups ABI and supplementary-group behavior reference', getgroups_reference)
        self.assertIn('run_musl_oracle.sh', getgroups_reference)
        self.assertNotIn('-p crabc-libc', getgroups_reference)
        self.assertIn('x86_process_session_reference_probe.c', process_session_reference)
        self.assertIn('process-session reference', process_session_reference)
        self.assertNotIn('-p crabc-libc', process_session_reference)
        self.assertIn('x86_pidfd_open_reference_probe.c', pidfd_open_reference)
        self.assertIn('pidfd_open reference', pidfd_open_reference)
        self.assertNotIn('-p crabc-libc', pidfd_open_reference)
        self.assertIn('x86_fcntl_getlk_reference_probe.c', fcntl_getlk_reference)
        self.assertIn('fcntl_getlk reference', fcntl_getlk_reference)
        self.assertNotIn('-p crabc-libc', fcntl_getlk_reference)
        self.assertIn('x86_fcntl_status_reference_probe.c', fcntl_status_reference)
        self.assertIn('fcntl status reference', fcntl_status_reference)
        self.assertIn('run_musl_oracle.sh', fcntl_status_reference)
        self.assertNotIn('-p crabc-libc', fcntl_status_reference)
        self.assertIn('x86_flock_reference_probe.c', flock_reference)
        self.assertIn('flock(2) reference', flock_reference)
        self.assertIn('syscall=73 bits=SH1,EX2,NB4,UN8', flock_reference)
        self.assertIn('run_musl_oracle.sh', flock_reference)
        self.assertIn('fcntl record locks', flock_reference)
        self.assertNotIn('-p crabc-libc', flock_reference)
        self.assertIn('x86_sendfile_reference_probe.c', sendfile_reference)
        self.assertIn('sendfile(2) reference', sendfile_reference)
        self.assertIn('syscall=40 off_t=signed64', sendfile_reference)
        self.assertIn('run_musl_oracle.sh', sendfile_reference)
        self.assertIn('socket', sendfile_reference)
        self.assertNotIn('-p crabc-libc', sendfile_reference)
        self.assertIn('x86_copy_file_range_reference_probe.c', copy_file_range_reference)
        self.assertIn('copy_file_range(2) reference', copy_file_range_reference)
        self.assertIn('syscall=326 off_t=signed64', copy_file_range_reference)
        self.assertIn('run_musl_oracle.sh', copy_file_range_reference)
        self.assertIn('flags=zero-only', copy_file_range_reference)
        self.assertIn('sendfile-splice-fallback=excluded', copy_file_range_reference)
        self.assertNotIn('-p crabc-libc', copy_file_range_reference)
        self.assertIn('x86_scheduler_priority_bounds_reference_probe.c', scheduler_priority_bounds_reference)
        self.assertIn('scheduler-priority bounds reference', scheduler_priority_bounds_reference)
        self.assertNotIn('-p crabc-libc', scheduler_priority_bounds_reference)
        self.assertIn('x86_priority_reference_probe.c', priority_reference)
        self.assertIn('getpriority reference', priority_reference)
        self.assertNotIn('-p crabc-libc', priority_reference)
        self.assertIn('x86_setpriority_reference_probe.c', setpriority_reference)
        self.assertIn('setpriority ABI and behavior reference', setpriority_reference)
        self.assertIn('run_musl_oracle.sh', setpriority_reference)
        self.assertNotIn('-p crabc-libc', setpriority_reference)
        self.assertIn('x86_rlimit_reference_probe.c', rlimit_reference)
        self.assertIn('getrlimit/prlimit64 reference', rlimit_reference)
        self.assertIn('run_musl_oracle.sh', rlimit_reference)
        self.assertNotIn('-p crabc-libc', rlimit_reference)
        self.assertIn('x86_rusage_reference_probe.c', rusage_reference)
        self.assertIn('getrusage ABI/behavior reference', rusage_reference)
        self.assertIn('run_musl_oracle.sh', rusage_reference)
        self.assertNotIn('-p crabc-libc', rusage_reference)
        self.assertIn('x86_times_reference_probe.c', times_reference)
        self.assertIn('times ABI and process-accounting behavior reference', times_reference)
        self.assertIn('run_musl_oracle.sh', times_reference)
        self.assertNotIn('-p crabc-libc', times_reference)
        self.assertIn('x86_fstat_reference_probe.c', fstat_reference)
        self.assertIn('fstat reference', fstat_reference)
        self.assertNotIn('-p crabc-libc', fstat_reference)
        self.assertIn('x86_statfs_reference_probe.c', statfs_reference)
        self.assertIn('statfs reference', statfs_reference)
        self.assertNotIn('-p crabc-libc', statfs_reference)
        self.assertIn('x86_statat_reference_probe.c', statat_reference)
        self.assertIn('statat reference', statat_reference)
        self.assertIn('run_musl_oracle.sh', statat_reference)
        self.assertNotIn('-p crabc-libc', statat_reference)
        self.assertIn('x86_getcwd_reference_probe.c', getcwd_reference)
        self.assertIn('getcwd reference', getcwd_reference)
        self.assertIn('run_musl_oracle.sh', getcwd_reference)
        self.assertNotIn('-p crabc-libc', getcwd_reference)
        self.assertIn('x86_readlinkat_reference_probe.c', readlinkat_reference)
        self.assertIn('readlinkat reference', readlinkat_reference)
        self.assertIn('run_musl_oracle.sh', readlinkat_reference)
        self.assertNotIn('-p crabc-libc', readlinkat_reference)
        self.assertIn('x86_access_reference_probe.c', access_reference)
        self.assertIn('access/faccessat/faccessat2 reference', access_reference)
        self.assertIn('run_musl_oracle.sh', access_reference)
        self.assertNotIn('-p crabc-libc', access_reference)
        self.assertIn('sched_getaffinity ABI and behavior reference', sched_affinity_reference)
        self.assertIn('run_musl_oracle.sh', sched_affinity_reference)
        self.assertNotIn('-p crabc-libc', sched_affinity_reference)
        self.assertIn('sched_setaffinity ABI and behavior reference', sched_affinity_set_reference)
        self.assertIn('run_musl_oracle.sh', sched_affinity_set_reference)
        self.assertIn('child-singleton', sched_affinity_set_reference)
        self.assertNotIn('-p crabc-libc', sched_affinity_set_reference)
        self.assertIn('x86_sched_rr_interval_reference_probe.c', rr_interval_reference)
        self.assertIn('sched_rr_get_interval ABI and behavior reference', rr_interval_reference)
        self.assertIn('run_musl_oracle.sh', rr_interval_reference)
        self.assertNotIn('-p crabc-libc', rr_interval_reference)
        self.assertIn('x86_system_reference_probe.c', system_reference)
        self.assertIn('uname/sysinfo ABI and behavior reference', system_reference)
        self.assertNotIn('-p crabc-libc', system_reference)
        self.assertIn('x86_thread_reference_probe.c', thread_reference)
        self.assertIn('thread observation/yield reference', thread_reference)
        self.assertNotIn('-p crabc-libc', thread_reference)
        self.assertIn('x86_64_image.rs', image)
        self.assertIn('--test', image)
        self.assertNotIn('-p crabc-ldso', image)
        self.assertIn('#if defined(__x86_64__) && !defined(__cplusplus)', sys_types)
        self.assertIn('defined(__x86_64__) && defined(__LP64__)', unistd_include)
        self.assertNotIn('#if defined(__x86_64__)\n', unistd_include)

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

    def test_libc_syscall_probe_stays_outside_the_libc_artifact_boundary(self) -> None:
        source = (ROOT / "compat" / "x86_64" / "libc_syscall_probe.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/syscall.rs', source)
        self.assertIn('syscall::syscall4(', source)
        self.assertIn('syscall::syscall5(', source)
        self.assertIn('syscall::syscall6(', source)
        self.assertNotIn('crabc_libc', source)

    def test_libc_errno_tls_probe_is_a_fixed_source_only_static_tls_boundary(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_errno_tls_probe.rs").read_text(
            encoding="utf-8"
        )
        errno_source = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "errno.rs").read_text(
            encoding="utf-8"
        )
        c_probe = (ROOT / "compat" / "x86_64" / "libc_errno_tls_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_errno_tls.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/errno.rs', rust_probe)
        self.assertIn('#[thread_local]', errno_source)
        self.assertIn('__errno_location', errno_source)
        self.assertIn('#include <errno.h>', c_probe)
        self.assertIn('pthread_create', c_probe)
        self.assertIn('R_X86_64_TPOFF', script)
        self.assertIn('__tls_get_addr', script)
        self.assertIn('-no-pie -pthread', script)
        self.assertNotIn('--allow-multiple-definition', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_libc_static_c_abi_artifact_boundaries(self) -> None:
        libc_root = (ROOT / "libc" / "src" / "lib.rs").read_text(encoding="utf-8")
        static_c_abi = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        stat_compat = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stat_compat.rs"
        ).read_text(encoding="utf-8")
        credentials = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "credentials.rs"
        ).read_text(encoding="utf-8")
        errno = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "errno.rs").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_stat_compat_probe.c").read_text(
            encoding="utf-8"
        )
        start = (ROOT / "compat" / "x86_64" / "libc_stat_compat_start.S").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_stat_compat.sh").read_text(
            encoding="utf-8"
        )
        credential_probe = (
            ROOT / "compat" / "x86_64" / "libc_credentials_probe.c"
        ).read_text(encoding="utf-8")
        credential_start = (
            ROOT / "compat" / "x86_64" / "libc_credentials_start.S"
        ).read_text(encoding="utf-8")
        credential_script = (
            ROOT / "compat" / "x86_64" / "run_libc_credentials.sh"
        ).read_text(encoding="utf-8")
        bootstrap_script = (
            ROOT / "compat" / "x86_64" / "run_libc_bootstrap_primitives.sh"
        ).read_text(encoding="utf-8")
        bootstrap_probe = (
            ROOT / "compat" / "x86_64" / "libc_bootstrap_primitives_probe.c"
        ).read_text(encoding="utf-8")
        process_context = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_context.rs"
        ).read_text(encoding="utf-8")
        process_context_probe = (
            ROOT / "compat" / "x86_64" / "libc_process_context_probe.c"
        ).read_text(encoding="utf-8")
        process_context_start = (
            ROOT / "compat" / "x86_64" / "libc_process_context_start.S"
        ).read_text(encoding="utf-8")
        process_context_script = (
            ROOT / "compat" / "x86_64" / "run_libc_process_context.sh"
        ).read_text(encoding="utf-8")
        descriptor_io = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_io.rs"
        ).read_text(encoding="utf-8")
        descriptor_io_script = (
            ROOT / "compat" / "x86_64" / "run_libc_descriptor_io.sh"
        ).read_text(encoding="utf-8")
        process_resources = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_resources.rs"
        ).read_text(encoding="utf-8")
        process_resources_script = (
            ROOT / "compat" / "x86_64" / "run_libc_process_resources.sh"
        ).read_text(encoding="utf-8")
        readiness_waits = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "readiness_waits.rs"
        ).read_text(encoding="utf-8")
        readiness_waits_probe = (
            ROOT / "compat" / "x86_64" / "libc_readiness_waits_probe.c"
        ).read_text(encoding="utf-8")
        readiness_waits_start = (
            ROOT / "compat" / "x86_64" / "libc_readiness_waits_start.S"
        ).read_text(encoding="utf-8")
        readiness_waits_script = (
            ROOT / "compat" / "x86_64" / "run_libc_readiness_waits.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]

        self.assertIn('target_arch = "x86_64"', libc_root)
        self.assertIn('#[path = "c_abi/x86_64/static_c_abi.rs"]', libc_root)
        self.assertNotIn('mod c_abi_x86_64', libc_root)
        for composition_member in (
            '#[path = "errno.rs"]',
            '#[path = "syscall.rs"]',
            '#[path = "stat_compat.rs"]',
            '#[path = "credentials.rs"]',
            '#[path = "process_context.rs"]',
            '#[path = "clock_nanosleep.rs"]',
            '#[path = "descriptor_io.rs"]',
            '#[path = "process_resources.rs"]',
            '#[path = "readiness_waits.rs"]',
            'fn c_status',
            'fn c_ssize_status',
            'fn c_off_status',
            'fn rust_eh_personality',
        ):
            self.assertIn(composition_member, static_c_abi)
        self.assertIn('#[thread_local]', errno)
        self.assertIn('struct Stat', stat_compat)
        self.assertIn('size_of::<Stat>() == 144', stat_compat)
        self.assertIn('raw_syscall::SYS_FSTAT', stat_compat)
        self.assertIn('raw_syscall::SYS_NEWFSTATAT', stat_compat)
        for symbol in (
            'fn stat(',
            'fn lstat(',
            'fn fstat(',
            'fn fstatat(',
            'fn __xstat(',
            'fn __lxstat(',
            'fn __fxstat(',
            'fn __fxstatat(',
        ):
            self.assertIn(symbol, stat_compat)
        for symbol in (
            'fn setgroups(',
            'fn setuid(',
            'fn setgid(',
            'fn setresuid(',
            'fn setresgid(',
            'fn seteuid(',
            'fn setegid(',
            'fn setreuid(',
            'fn setregid(',
        ):
            self.assertIn(symbol, credentials)
        for syscall in (
            'raw_syscall::SYS_SETGROUPS',
            'raw_syscall::SYS_SETUID',
            'raw_syscall::SYS_SETGID',
            'raw_syscall::SYS_SETRESUID',
            'raw_syscall::SYS_SETRESGID',
        ):
            self.assertIn(syscall, credentials)
        self.assertIn('EOPNOTSUPP', credentials)
        for static_source in (
            static_c_abi,
            stat_compat,
            credentials,
            process_context,
            descriptor_io,
            process_resources,
            readiness_waits,
            errno,
        ):
            self.assertNotIn('crabc_core', static_source)
            self.assertNotIn('crabc_mimalloc', static_source)
        self.assertIn('_Static_assert(sizeof(struct stat) == 144', probe)
        self.assertIn('SYS_newfstatat == 262', probe)
        self.assertIn('errno != ENOENT', probe)
        self.assertIn('errno != EBADF', probe)
        self.assertIn('errno != EINVAL', probe)
        self.assertIn('ARCH_SET_FS', start)
        self.assertIn('mov %rsi, %fs:0', start)
        self.assertIn('crabc_x86_64_stat_compat_probe', start)
        self.assertIn('cargo rustc --locked -p crabc-libc --lib', script)
        self.assertIn('-nostdlib -static', script)
        self.assertIn('-Wl,-e,_start', script)
        self.assertIn('R_X86_64_TPOFF', script)
        self.assertIn('Requesting program interpreter', script)
        self.assertIn('__tls_get_addr', script)
        self.assertNotIn('-p crabc-core', script)
        self.assertNotIn('--whole-archive', script)
        self.assertIn('#include <grp.h>', credential_probe)
        self.assertIn('_Static_assert(SYS_setgroups == 116', credential_probe)
        self.assertIn('UINT32_MAX', credential_probe)
        self.assertIn('raw_syscall3', credential_probe)
        self.assertIn('same_state', credential_probe)
        self.assertIn('CRABC_CREDENTIAL_PROFILE', credential_probe)
        self.assertIn('EOPNOTSUPP', credential_probe)
        self.assertIn('ARCH_SET_FS', credential_start)
        self.assertIn('mov %rsi, %fs:0', credential_start)
        self.assertIn('crabc_x86_64_credentials_probe', credential_start)
        self.assertIn('cargo rustc --locked -p crabc-libc --lib', credential_script)
        self.assertIn('-DCRABC_CREDENTIAL_PROFILE', credential_script)
        self.assertIn('-nostdlib -static', credential_script)
        self.assertIn('-Wl,-e,_start', credential_script)
        self.assertIn('R_X86_64_TPOFF', credential_script)
        self.assertIn('Requesting program interpreter', credential_script)
        self.assertIn('__tls_get_addr', credential_script)
        self.assertNotIn('-p crabc-core', credential_script)
        self.assertNotIn('--whole-archive', credential_script)
        self.assertEqual(static_export_names, sorted(static_export_names))
        self.assertEqual(len(static_export_names), len(set(static_export_names)))
        for symbol in (
            "__errno_location",
            "stat",
            "setgroups",
            "getpid",
            "clock_nanosleep",
            "read",
            "getrlimit",
            "memcpy",
            "feclearexcept",
            "setjmp",
            "rust_eh_personality",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("raw_syscall::SYS_GETPID", process_context)
        self.assertIn("raw_syscall::SYS_SETPGID", process_context)
        self.assertIn("raw_syscall::SYS_UMASK", process_context)
        self.assertIn("raw_syscall0", process_context_probe)
        self.assertIn("raw_syscall4", process_context_probe)
        self.assertIn("child_setpgrp_case", process_context_probe)
        self.assertIn("child_setsid_case", process_context_probe)
        self.assertIn("ARCH_SET_FS", process_context_start)
        self.assertIn("mov %rsi, %fs:0", process_context_start)
        self.assertIn("crabc_x86_64_process_context_probe", process_context_start)
        self.assertIn("check_poll_and_ppoll", readiness_waits_probe)
        self.assertIn("check_atomic_signal_waits", readiness_waits_probe)
        self.assertIn("ARCH_SET_FS", readiness_waits_start)
        self.assertIn("mov %rsi, %fs:0", readiness_waits_start)
        self.assertIn("crabc_x86_64_readiness_waits_probe", readiness_waits_start)
        for artifact_script in (
            script,
            credential_script,
            bootstrap_script,
            process_context_script,
            descriptor_io_script,
            process_resources_script,
            readiness_waits_script,
        ):
            self.assertIn('TLSLD', artifact_script)
            self.assertIn('DTPMOD', artifact_script)
            self.assertIn('DTPOFF', artifact_script)
            self.assertIn(
                'candidate_relocations="$work_dir/candidate-relocations"',
                artifact_script,
            )
            self.assertIn('readelf --relocs --wide "$candidate"', artifact_script)
            self.assertIn(
                'candidate relocations retain a dynamic TLS model', artifact_script
            )
            self.assertIn('ar t "$archive_path"', artifact_script)
            self.assertIn('^c\\..+\\.rcgu\\.o$', artifact_script)
            self.assertIn("static_c_abi_exports.txt", artifact_script)
            self.assertIn('selected static C ABI export surface drifted', artifact_script)
        self.assertIn('memmove(destination_end, source_end, length)', bootstrap_probe)
        self.assertIn('memmove(overlap_source + 1, overlap_source, length)', bootstrap_probe)
        self.assertIn('memcmp(source_end, destination_end, length)', bootstrap_probe)
        self.assertIn('bcmp(source_end, destination_end, length)', bootstrap_probe)

    def test_libc_static_c_abi_signal_control_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        signal_foundation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_foundation.rs"
        ).read_text(encoding="utf-8")
        signal_control = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_control.rs"
        ).read_text(encoding="utf-8")
        signal_pending = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_pending.rs"
        ).read_text(encoding="utf-8")
        signal_realtime_max = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "signal_realtime_max.rs"
        ).read_text(encoding="utf-8")
        signal_set_mutation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_set_mutation.rs"
        ).read_text(encoding="utf-8")
        foundation_probe = (
            ROOT / "compat" / "x86_64" / "libc_signal_foundation_probe.rs"
        ).read_text(encoding="utf-8")
        control_probe = (
            ROOT / "compat" / "x86_64" / "libc_signal_control_probe.c"
        ).read_text(encoding="utf-8")
        control_start = (
            ROOT / "compat" / "x86_64" / "libc_signal_control_start.S"
        ).read_text(encoding="utf-8")
        control_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_signal_control.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_foundation.rs"]', static_root)
        self.assertIn('#[path = "signal_control.rs"]', static_root)
        self.assertIn('#[path = "signal_realtime_max.rs"]', static_root)
        self.assertIn('#[path = "signal_pending.rs"]', static_root)
        self.assertIn('#[path = "signal_set_mutation.rs"]', static_root)
        for symbol in (
            "fn sigaction(",
            "fn signal(",
            "fn sigemptyset(",
            "fn sigismember(",
            "fn sigprocmask(",
        ):
            self.assertIn(symbol, signal_control)
        self.assertNotIn("fn __libc_current_sigrtmax(", signal_control)
        self.assertIn("fn __libc_current_sigrtmax(", signal_realtime_max)
        self.assertIn(
            "const APPLICATION_SIGNAL_MAX: c_int = 64;", signal_control
        )
        self.assertIn(
            "if signal <= 0 || signal > APPLICATION_SIGNAL_MAX {", signal_control
        )
        self.assertNotIn("fn sigpending(", signal_control)
        self.assertIn("fn sigpending(", signal_pending)
        for symbol in ("fn sigfillset(", "fn sigaddset(", "fn sigdelset("):
            self.assertNotIn(symbol, signal_control)
            self.assertIn(symbol, signal_set_mutation)
        for required in (
            "raw_syscall::SYS_RT_SIGACTION",
            "raw_syscall::SYS_RT_SIGPROCMASK",
            "raw_syscall::syscall4(",
            "SA_RESTORER",
            "pack_public_action",
            "unpack_kernel_action",
        ):
            self.assertIn(required, signal_control)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn raise(",
            "fn kill(",
            "fn tgkill(",
            "fn sigsuspend(",
            "fn sigtimedwait(",
            "fn sigwaitinfo(",
            "fn sigwait(",
            "fn sigaltstack(",
            "fn pthread_sigmask(",
        ):
            self.assertNotIn(forbidden, signal_control)
        self.assertNotIn("#[no_mangle]", signal_foundation)
        self.assertIn("fn pack_public_action", signal_foundation)
        self.assertIn("fn unpack_kernel_action", signal_foundation)
        self.assertIn("crabc_x86_64_signal_restorer", signal_foundation)
        self.assertIn("crabc_x86_64_signal_action_pack", foundation_probe)
        self.assertIn("raw_tgkill_self", control_probe)
        self.assertIn("sigpending", control_probe)
        self.assertIn("SA_RESTART", control_probe)
        self.assertIn("ARCH_SET_FS", control_start)
        self.assertIn("mov %rsi, %fs:0", control_start)
        self.assertIn("crabc_x86_64_signal_control_probe", control_start)
        # The archive is shared with the separately selected process-signal
        # and readiness/waits artifacts. Their named exports must not be
        # treated as accidental signal-control exports by this older gate.
        self.assertIn(
            "The selected process-signal, alternate-stack, and readiness artifacts",
            control_runner,
        )
        self.assertIn("tgkill", control_runner)
        self.assertIn("pthread_sigmask", control_runner)
        self.assertIn("signalfd", control_runner)
        for required in (
            "static_c_abi_exports.txt",
            'ar t "$archive_path"',
            "selected static C ABI export surface drifted",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "crabc_x86_64_signal_restorer",
            "GLOBAL +HIDDEN",
            "mov rax, 15",
            "syscall",
        ):
            self.assertIn(required, control_runner)
        self.assertNotIn("--whole-archive", control_runner)
        self.assertNotIn("crabc_x86_64_signal_action_pack", static_export_names)
        for symbol in (
            "__libc_current_sigrtmax",
            "sigaction",
            "signal",
            "sigemptyset",
            "sigfillset",
            "sigaddset",
            "sigdelset",
            "sigismember",
            "sigprocmask",
            "sigpending",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-signal-control", runner)

    def test_libc_static_c_abi_signal_execution_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        signal_execution = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_execution.rs"
        ).read_text(encoding="utf-8")
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_signal_execution_probe.c"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_signal_execution_start.S"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_signal_execution.sh"
        )
        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing signal-execution input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
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
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_execution.rs"]', static_root)
        for source in (
            "src/signal/kill.c",
            "src/signal/killpg.c",
            "src/signal/raise.c",
            "src/signal/sigqueue.c",
            "src/signal/sigtimedwait.c",
            "src/signal/sigwaitinfo.c",
            "src/signal/sigwait.c",
        ):
            self.assertIn(source, signal_execution)
        for symbol in (
            "fn kill(",
            "fn killpg(",
            "fn raise(",
            "fn sigqueue(",
            "fn sigtimedwait(",
            "fn sigwaitinfo(",
            "fn sigwait(",
        ):
            self.assertIn(symbol, signal_execution)
        for required in (
            "APPLICATION_SIGNAL_MASK",
            "0xffff_fffc_7fff_ffff",
            "block_application_signals",
            "restore_signals",
            "SYS_TKILL",
            "SYS_RT_SIGQUEUEINFO",
            "SYS_RT_SIGTIMEDWAIT",
            "process_context::getuid()",
            "process_context::getpid()",
            "result != -EINTR",
            "return -1;",
            "positive errno value",
        ):
            self.assertIn(required, signal_execution)
        for forbidden in (
            "pub extern \"C\" fn tgkill(",
            "pub extern \"C\" fn sigaltstack(",
            "pub extern \"C\" fn signalfd(",
            "pub extern \"C\" fn pthread_kill(",
            "pub extern \"C\" fn clone(",
        ):
            self.assertNotIn(forbidden, signal_execution)

        for required in (
            "sizeof(siginfo_t) == 128",
            "offsetof(siginfo_t, si_value) == 24",
            "raw_clone_sigchld",
            "raw_wait4_cleanup",
            "check_retry_after_eintr",
            "killpg(-1, 0)",
            "sigtimedwait(0, &info, &zero_timeout)",
            "sigwait(0, &waited_signal)",
            "sigsuspend(&empty_set)",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_signal_execution_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "TLSGD",
            "__gxx_personality_v0",
            "pthread_create",
            "pthread_kill",
            "getauxval sysconf",
            "assert_named_syscall kill 3e",
            "assert_named_syscall killpg 3e",
            "assert_named_syscall raise e",
            "assert_named_syscall raise c8",
            "assert_named_syscall sigqueue e",
            "assert_named_syscall sigqueue 81",
            "assert_named_syscall sigtimedwait 80",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "kill",
            "killpg",
            "raise",
            "sigqueue",
            "sigtimedwait",
            "sigwaitinfo",
            "sigwait",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-process-signal-execution"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-signal-execution"',
            parity_ledger,
        )
        self.assertIn("run_libc_signal_execution_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_signal_execution.sh", runner
        )
        self.assertIn(
            '    libc-signal-execution)\n        [ "$#" -eq 0 ] || fail "libc-signal-execution takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_signal_altstack_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        signal_altstack = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_altstack.rs"
        ).read_text(encoding="utf-8")
        probe_path = ROOT / "compat" / "x86_64" / "libc_signal_altstack_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_signal_altstack_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_signal_altstack.sh"
        )
        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing signal-altstack input: {path}")
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
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_altstack.rs"]', static_root)
        for required in (
            "src/signal/sigaltstack.c",
            "struct PublicSignalStack",
            "size_of::<PublicSignalStack>() == 24",
            "offset_of!(PublicSignalStack, flags) == 8",
            "offset_of!(PublicSignalStack, size) == 16",
            "raw_syscall::SYS_SIGALTSTACK",
            "MINSIGSTKSZ: usize = 2_048",
            "requested.size < MINSIGSTKSZ",
            "requested.flags & SS_ONSTACK",
            "_SC_MINSIGSTKSZ",
            "AT_MINSIGSTKSZ",
        ):
            self.assertIn(required, signal_altstack)
        self.assertLess(
            signal_altstack.index("requested.size < MINSIGSTKSZ"),
            signal_altstack.index("requested.flags & SS_ONSTACK"),
        )
        self.assertNotIn("padding: c_int", signal_altstack)
        for forbidden in ("fn signalfd(", "fn sigqueue(", "fn sigtimedwait(", "fn pthread_"):
            self.assertNotIn(forbidden, signal_altstack)

        for required in (
            "sizeof(stack_t) == 24",
            "MINSIGSTKSZ == 2048",
            "SYS_sigaltstack == 131",
            "too_small_onstack",
            "errno != ENOMEM",
            "SA_ONSTACK",
            "handler_disable_rejected",
            "disabled_previous",
            "observed.ss_flags != SS_DISABLE",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_signal_altstack_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_named_syscall sigaltstack 83",
            "sysconf getauxval",
            "crabc_x86_64_signal_restorer",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sigaltstack", static_exports)
        self.assertIn('id = "static-c-signal-altstack"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-signal-altstack"',
            parity_ledger,
        )
        self.assertIn("run_libc_signal_altstack_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_signal_altstack.sh", runner
        )
        self.assertIn(
            '    libc-signal-altstack)\n        [ "$#" -eq 0 ] || fail "libc-signal-altstack takes no arguments"',
            runner,
        )

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

    def test_libc_static_c_abi_sigpause_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        sigpause = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_pause.rs"
        ).read_text(encoding="utf-8")
        probe_path = ROOT / "compat" / "x86_64" / "libc_sigpause_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_sigpause_start.S"
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_sigpause.sh"
        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing sigpause input: {path}")
        self.assertTrue(artifact_runner_path.stat().st_mode & 0o111)

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

        self.assertIn('#[path = "signal_pause.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 sigpause C boundary",
            "src/signal/sigpause.c",
            "KERNEL_SIGSET_SIZE",
            "raw_syscall::SYS_RT_SIGPROCMASK",
            "raw_syscall::SYS_RT_SIGSUSPEND",
            "raw_syscall::syscall4(",
            "raw_syscall::syscall2(",
            'pub extern "C" fn sigpause',
            "errno::set_errno",
            "c_status",
        ):
            self.assertIn(required, sigpause)
        for forbidden in (
            "sigprocmask(",
            "sigdelset(",
            "sigsuspend(",
            "sigtimedwait(",
            "signalfd",
            "timerfd",
            "pthread_",
            "process_context",
        ):
            self.assertNotIn(forbidden, sigpause)

        for required in (
            "sigpause(0)",
            "sigpause(32)",
            "sigpause(SIGUSR1)",
            "SIGUSR1",
            "SIGUSR2",
            "SYS_rt_sigaction == 13",
            "SYS_rt_sigprocmask == 14",
            "SYS_rt_sigsuspend == 130",
            "CRABC_SIGPAUSE_FREESTANDING",
            "raw_syscall4",
            "raw_read",
            "raw_write",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sigpause_probe",
            "crabc_x86_64_sigpause_restorer",
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
            "R_X86_64_TPOFF",
            "assert_named_syscall sigpause e",
            "assert_named_syscall sigpause 82",
            "run_interrupted_wait",
            "candidate unexpectedly pulls",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sigpause", static_exports)
        self.assertIn('id = "static-c-sigpause"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sigpause"', parity_ledger
        )
        self.assertIn("run_libc_sigpause_probe()", dispatcher)
        self.assertIn("libc-sigpause)", dispatcher)

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

    def test_libc_static_c_abi_pthread_create_exit_join_tls_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_pthread_create_join_tls_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_pthread_create_join_tls_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_create_join_tls.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_create_join.rs"]', static_root)
        for required in (
            "src/thread/pthread_create.c::__pthread_create",
            "src/thread/pthread_create.c::__pthread_exit",
            "src/thread/x86_64/clone.s::__clone",
            "src/thread/pthread_join.c",
            "src/thread/pthread_detach.c",
            "struct ThreadControl",
            "PTHREAD_CLONE_FLAGS",
            "CLONE_SETTLS",
            "CLONE_PARENT_SETTID",
            "CLONE_CHILD_CLEARTID",
            "FUTEX_WAIT",
            "raw_syscall::SYS_MMAP",
            "raw_syscall::SYS_MUNMAP",
            "raw_syscall::SYS_FUTEX",
            "static_tls::is_ready()",
            "static_tls::allocate_thread()",
            "static_tls::release_thread(tls_block)",
            "static_tls::StaticInitialTlsBlock",
            "start_ready",
            "tls_released",
            "tls_block.thread_pointer()",
            "SELECTED_WORKER_REGISTRY_SIZE",
            "SELECTED_WORKER_REGISTRY",
            "SELECTED_WORKER_REGISTRY_LOCK",
            "reserve_selected_worker",
            "claim_selected_worker_by_thread_pointer",
            "publish_selected_worker_result",
            "release_selected_worker",
            "release_selected_worker_locked",
            "reclaim_withdrawn_selected_worker",
            "reap_finished_detached_selected_workers",
            "SelectedWorkerLifecycleState",
            "pthread_identity::current_thread_pointer",
            "current_linux_thread_id",
            "raw_syscall::SYS_GETTID",
            "registry_retired",
            "finished",
            ".hidden __crabc_x86_pthread_clone",
            "fn pthread_create(",
            "fn pthread_exit(",
            "fn pthread_join(",
            "fn pthread_detach(",
            "tls_block.thread_pointer().cast()",
        ):
            self.assertIn(required, pthread_create_join)
        for forbidden in (
            "fn pthread_self(",
            "fn pthread_cancel(",
            "fn pthread_key_create(",
            "fn pthread_mutex_",
            "WORKER_CONTROL_TPOFF",
            "INITIAL_TLS_REGION_SIZE",
            "initial_errno_offset",
            "child_errno",
            "child_thread_pointer",
            "SYS_ARCH_PRCTL",
            "ARCH_SET_FS",
            "__tls_get_addr",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, pthread_create_join)
        public_create_body = pthread_create_join.split(
            'pub unsafe extern "C" fn pthread_create', 1
        )[1].split(
            "/// Create one selected default-attribute worker for the pthread or C11 leaf.",
            1,
        )[0]
        self.assertLess(
            public_create_body.index("if thread.is_null() || start.is_none()"),
            public_create_body.index("if !attributes.is_null()"),
        )
        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "run_worker_round",
            "observe_explicit_exit_worker",
            "observe_held_explicit_exit_worker",
            "run_explicit_exit_round",
            "run_null_result_join",
            "run_concurrent_worker_round",
            "run_concurrent_explicit_exit_round",
            "run_registry_capacity_round",
            "pthread_exit",
            "__atomic_fetch_add",
            "first.errno_location == second.errno_location",
            "CRABC_PTHREAD_CREATE_JOIN_TLS_FREESTANDING",
            "CRABC_PTHREAD_CREATE_JOIN_TLS_SELECTED_WORKER_LIMIT",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_create_join_tls_probe",
        ):
            self.assertIn(required, start)
        for forbidden in (
            "arch_prctl",
            "mov %rsi, %fs:0",
            "crabc_x86_64_pthread_create_join_tls_initial_tls",
            "crabc_x86_64_pthread_create_join_tls_thread_pointer",
        ):
            self.assertNotIn(forbidden, start.lower())
        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "-pthread",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_CREATE_JOIN_TLS_SELECTED_WORKER_LIMIT=64",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "__crabc_x86_pthread_clone",
            "__crabc_x86_static_tls_bootstrap",
            "GLOBAL +HIDDEN",
            "GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "pthread clone boundary lacks clone syscall number 56",
            "seventh-argument child-tid shuffle",
            "child exit syscall number 60",
            "pthread_exit lacks an x86 thread-exit syscall instruction",
            "candidate lacks gettid syscall number 186 identity validation",
            "pthread_exit lacks thread exit syscall number 60",
            "pthread_join lacks futex syscall number 202",
            "pthread_join lacks munmap syscall number 11",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        selected_join_body = pthread_create_join.split(
            "pub(super) unsafe fn join_selected_worker", 1
        )[1].split("/// Join one normal-returning", 1)[0]
        self.assertIn("claim_selected_worker_by_thread_pointer(", selected_join_body)
        self.assertIn("SelectedWorkerLifecycleState::JoinClaimed", selected_join_body)
        self.assertLess(
            selected_join_body.index("claim_selected_worker_by_thread_pointer("),
            selected_join_body.index("(*control)"),
        )
        self.assertLess(
            selected_join_body.index("release_selected_worker"),
            selected_join_body.index("reclaim_withdrawn_selected_worker(control)"),
        )
        tls_reclamation = pthread_create_join.split(
            "unsafe fn reclaim_withdrawn_selected_worker", 1
        )[1].split("/// Reap every detached selected worker", 1)[0]
        self.assertIn("tls_released.load(Ordering::Acquire)", tls_reclamation)
        self.assertLess(
            tls_reclamation.index("static_tls::release_thread(tls_block)"),
            tls_reclamation.index("tls_released.store(1, Ordering::Release)"),
        )
        current_worker_resolution = pthread_create_join.split(
            "fn current_selected_worker_control", 1
        )[1].split("/// Return the current selected worker's bounded TSD table", 1)[0]
        self.assertIn("worker_tid.load", current_worker_resolution)
        self.assertIn("child_tid.load", current_worker_resolution)
        self.assertLess(
            current_worker_resolution.index("lock_selected_worker_registry"),
            current_worker_resolution.index("unlock_selected_worker_registry"),
        )
        selected_publish = pthread_create_join.split(
            "unsafe fn publish_selected_worker_result", 1
        )[1].split("/// Map one control/stack backing range", 1)[0]
        self.assertIn("publish_worker_result", selected_publish)
        worker_entry = pthread_create_join.split(
            'unsafe extern "C" fn worker_entry', 1
        )[1].split("/// Create one default-attribute", 1)[0]
        self.assertIn("start_ready.load(Ordering::Acquire)", worker_entry)
        self.assertLess(
            worker_entry.index("start_ready.load(Ordering::Acquire)"),
            worker_entry.index("current_linux_thread_id()"),
        )
        selected_create_body = pthread_create_join.split(
            "pub(super) unsafe fn create_selected_worker", 1
        )[1].split("/// Exit a selected worker", 1)[0]
        self.assertLess(
            selected_create_body.index("static_tls::is_ready()"),
            selected_create_body.index("reap_finished_detached_selected_workers()"),
        )
        self.assertLess(
            selected_create_body.index("reap_finished_detached_selected_workers()"),
            selected_create_body.index("static_tls::allocate_thread()"),
        )
        self.assertLess(
            selected_create_body.index("start_ready.store(1, Ordering::Release)"),
            selected_create_body.index("__crabc_x86_pthread_clone("),
        )
        self.assertIn(
            "core::ptr::write(thread, tls_block.thread_pointer().cast())",
            selected_create_body,
        )
        clone_failure = selected_create_body.split("if is_linux_error(clone_result)", 1)[
            1
        ].split("// SAFETY: clone succeeded", 1)[0]
        self.assertIn("if !release_selected_worker", clone_failure)
        self.assertIn("return EAGAIN", clone_failure)
        self.assertLess(
            clone_failure.index("if !release_selected_worker"),
            clone_failure.index("unmap_worker"),
        )
        for symbol in ("pthread_create", "pthread_exit", "pthread_join", "pthread_detach"):
            self.assertIn(symbol, static_export_names)
        # Deferred cancellation is a separately bounded sibling.  Keep this
        # create/join artifact focused on its established lifecycle seam;
        # the cancellation-specific contract below owns its selected exports.
        self.assertIn("libc-pthread-create-join-tls", runner)

    def test_libc_static_c_abi_pthread_cancel_deferred_artifact_stays_bounded(
        self,
    ) -> None:
        """One explicit deferred testcancel route must not select a runtime."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        cancellation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_cancel.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_pthread_cancel_deferred_probe.c"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_pthread_cancel_deferred_start.S"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_cancel_deferred.sh"
        )
        c_header_probe = (
            ROOT
            / "compat"
            / "x86_64"
            / "pthread_cancellation_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT
            / "compat"
            / "x86_64"
            / "pthread_cancellation_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT
            / "compat"
            / "x86_64"
            / "run_pthread_cancellation_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing deferred-cancellation input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_cancel.rs"]', static_root)
        for required in (
            "src/thread/pthread_cancel.c::{pthread_cancel,__testcancel,__cancel}",
            "src/thread/pthread_setcancelstate.c::__pthread_setcancelstate",
            "src/thread/pthread_setcanceltype.c::pthread_setcanceltype",
            "SelectedCancellationSlot",
            "PTHREAD_CANCEL_ENABLE",
            "PTHREAD_CANCEL_DISABLE",
            "PTHREAD_CANCEL_MASKED",
            "PTHREAD_CANCEL_DEFERRED",
            "PTHREAD_CANCEL_ASYNCHRONOUS",
            "PTHREAD_CANCELED",
            "pub unsafe extern \"C\" fn pthread_cancel",
            "pub unsafe extern \"C\" fn pthread_setcancelstate",
            "pub unsafe extern \"C\" fn pthread_setcanceltype",
            "pub unsafe extern \"C\" fn pthread_testcancel",
            "pub unsafe extern \"C\" fn _pthread_cleanup_push",
            "pub unsafe extern \"C\" fn _pthread_cleanup_pop",
            "request_selected_pthread_cancellation",
            "run_current_selected_pthread_cleanup_handlers",
            "2 => PTHREAD_CANCEL_MASKED",
            "ENOTSUP",
            "no signal handler",
            "interrupt blocking syscalls",
            "no implicit cancellation points",
            "C11 workers, foreign threads, stale handles",
            "public x86 pthread-runtime claim",
        ):
            self.assertIn(required, cancellation)
        for forbidden in (
            "SYS_TGKILL",
            "SYS_RT_TGSIGQUEUEINFO",
            "__tls_get_addr",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, cancellation)

        for required in (
            "request_selected_pthread_cancellation",
            "pthread_cancel::mark_selected_worker_pending",
            "pthread_cancel::initialize_selected_worker_slot",
            "pthread_cancel::release_selected_worker_slot",
            "pthread_cancel::run_current_selected_pthread_cleanup_handlers",
        ):
            self.assertIn(required, pthread_create_join)
        selected_exit = pthread_create_join.split(
            "unsafe fn exit_selected_worker", 1
        )[1].split("/// End one selected pthread-mode worker", 1)[0]
        self.assertLess(
            selected_exit.index("run_current_selected_pthread_cleanup_handlers"),
            selected_exit.index("run_selected_worker_tsd_destructors"),
        )
        self.assertLess(
            selected_exit.index("run_selected_worker_tsd_destructors"),
            selected_exit.index("publish_selected_worker_result"),
        )

        for required in (
            "pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED",
            "pthread_setcancelstate(PTHREAD_CANCEL_DISABLE",
            "pthread_setcancelstate(PTHREAD_CANCEL_MASKED",
            "CANCELLATION_PHASE_DISABLED",
            "pthread_cancel(worker)",
            "A queued request must remain harmless at this disabled explicit",
            "pthread_setcancelstate(PTHREAD_CANCEL_ENABLE",
            "CANCELLATION_PHASE_MASKED_TESTCANCEL_RETURNED",
            "pthread_testcancel();",
            "pthread_cleanup_push",
            "pthread_cleanup_pop",
            "CANCELLATION_ORDER_TSD",
            "PTHREAD_CANCELED",
            "errno != EACCES || __errno_location() != main_errno_location",
            "CRABC_PTHREAD_CANCEL_DEFERRED_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_cancel_deferred_probe",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "PTHREAD_CANCEL_ENABLE == 0",
                "PTHREAD_CANCEL_DISABLE == 1",
                "PTHREAD_CANCEL_MASKED == 2",
                "PTHREAD_CANCEL_DEFERRED == 0",
                "PTHREAD_CANCEL_ASYNCHRONOUS == 1",
                "PTHREAD_CANCELED",
                "pthread_cancel",
                "pthread_setcancelstate",
                "pthread_setcanceltype",
                "pthread_testcancel",
                "struct __ptcb",
                "sizeof(struct __ptcb) == 24",
                "__ptcb alignment",
                "__ptcb callback offset",
                "__ptcb argument offset",
                "__ptcb link offset",
                "_pthread_cleanup_push",
                "_pthread_cleanup_pop",
                "pthread_cleanup_push",
                "pthread_cleanup_pop",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "EXPECTED_PROFILE_COUNT=8",
            "-nostdinc",
            "-nostdinc++",
            "c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "check_cxx_c_linkage",
            "does not retain C linkage for",
            "retained a mangled pthread-cancellation reference",
            "pthread_cancel pthread_setcancelstate pthread_setcanceltype pthread_testcancel",
            "_pthread_cleanup_push _pthread_cleanup_pop",
            "compile-only",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "-pthread",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_CANCEL_DEFERRED_FREESTANDING",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate does not define ${symbol}",
            "candidate relocations retain a dynamic TLS model",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        for symbol in (
            "pthread_cancel",
            "pthread_setcancelstate",
            "pthread_setcanceltype",
            "pthread_testcancel",
            "_pthread_cleanup_push",
            "_pthread_cleanup_pop",
        ):
            self.assertIn(symbol, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {
                "pthread_cancel",
                "pthread_setcancelstate",
                "pthread_setcanceltype",
                "pthread_testcancel",
                "_pthread_cleanup_push",
                "_pthread_cleanup_pop",
            }
            <= static_exports
        )
        self.assertIn("run_pthread_cancellation_header_abi()", runner)
        self.assertIn("run_libc_pthread_cancel_deferred_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_pthread_cancellation_header_abi.sh",
            runner,
        )
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_cancel_deferred.sh",
            runner,
        )
        self.assertIn(
            '    pthread-cancellation-header-abi)\n        [ "$#" -eq 0 ] || fail "pthread-cancellation-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-pthread-cancel-deferred)\n        [ "$#" -eq 0 ] || fail "libc-pthread-cancel-deferred takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_atfork_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        atfork = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_atfork.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        static_startup = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_startup.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_pthread_atfork_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_pthread_atfork_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_atfork.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_atfork.rs"]', static_root)
        for required in (
            "pinned musl 1.2.6 release commit",
            "src/thread/pthread_atfork.c",
            "src/process/fork.c",
            "const ATFORK_CAPACITY: usize = 32",
            "fn __fork_handler",
            "fn pthread_atfork",
            "fn fork",
            "ENOMEM",
            "EAGAIN",
            "callbacks must not create, join, or detach",
            "Concurrent selected-worker lifecycle calls",
        ):
            self.assertIn(required, atfork)
        fork_body = atfork.split('pub unsafe extern "C" fn fork()', 1)[1]
        self.assertLess(
            fork_body.index("has_live_selected_workers"),
            fork_body.index("__fork_handler(-1)"),
        )
        self.assertLess(
            fork_body.index("__fork_handler(-1)"),
            fork_body.index("syscall0(LINUX_X86_64_SYS_FORK)"),
        )
        self.assertLess(
            fork_body.index("syscall0(LINUX_X86_64_SYS_FORK)"),
            fork_body.index("__fork_handler(if result == 0"),
        )
        self.assertLess(
            fork_body.index("__fork_handler(if result == 0"),
            fork_body.index("c_status(result)"),
        )
        for required in (
            "SELECTED_WORKER_REGISTRY_RESERVING",
            "has_live_selected_workers",
            "slot.control.load(Ordering::Acquire) != 0",
        ):
            self.assertIn(required, pthread_create_join)
        for required in ("fn atexit", "fn __funcs_on_exit", "fn exit"):
            self.assertIn(required, static_startup)

        for required in (
            "check_parent_child_and_exit_order",
            "check_live_selected_worker_rejection",
            "check_fixed_capacity_rejection",
            "check_raw_fork_error_parent_order",
            "install_fork_error_filter",
            "SYS_clone",
            "SYS_fork",
            "SYS_seccomp",
            "CRABC_SECCOMP_RET_ERRNO | EPERM",
            "pthread_join(worker, &result)",
            "recovery = check_parent_child_and_exit_order()",
            "atexit(child_exit_callback)",
        ):
            self.assertIn(required, probe)
        self.assertLess(
            probe.index("result = check_live_selected_worker_rejection();"),
            probe.index("result = check_raw_fork_error_parent_order();"),
        )
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_atfork_probe",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start.lower())

        for required in (
            "run_musl_oracle.sh",
            "sys/prctl.h",
            "-pthread",
            "-nostdlib -static",
            "-DCRABC_ATFORK_FREESTANDING",
            "candidate does not define ${symbol}",
            "fork does not route through the private atfork dispatcher",
            "exit does not route through the bounded ordinary-exit dispatcher",
            "candidate selected dynamic interpreter",
            "candidate selected dynamic dependency",
            "candidate retains unresolved symbol",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {"pthread_atfork", "fork", "__fork_handler", "atexit", "exit", "__funcs_on_exit"}
            <= static_exports
        )
        self.assertIn("run_libc_pthread_atfork_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_atfork.sh", runner
        )
        self.assertIn(
            '    libc-pthread-atfork)\n        [ "$#" -eq 0 ] || fail "libc-pthread-atfork takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_affinity_stays_bounded(self) -> None:
        affinity = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "pthread_affinity.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        sched_header = (ROOT / "include" / "sched.h").read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_pthread_affinity_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_pthread_affinity_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_affinity.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "src/sched/affinity.c",
            "pthread_getaffinity_np",
            "pthread_setaffinity_np",
            "SYS_SCHED_SETAFFINITY",
            "SYS_SCHED_GETAFFINITY",
            "is_initial_thread_pointer",
            "CPU_*` mask helper",
        ):
            self.assertIn(required, affinity)
        self.assertIn("selected_worker_linux_thread_id", pthread_create_join)
        self.assertIn("SYS_SCHED_SETAFFINITY: i64 = 203", syscall)
        for required in (
            "typedef struct cpu_set_t",
            "unsigned long __bits[128 / sizeof(long)]",
            "CPU_*\n * construction/allocation helper macro family remains unselected",
        ):
            self.assertIn(required, sched_header)
        for required in (
            "sizeof(cpu_set_t) == 128",
            "pthread_getaffinity_np declaration",
            "pthread_setaffinity_np declaration",
            "check_getaffinity",
            "holding_worker",
            "pthread_setaffinity_np(worker_thread",
            "CRABC_PTHREAD_AFFINITY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_affinity_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_pthread_c11_header_abi.sh",
            "-pthread",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_AFFINITY_FREESTANDING",
            "pthread_getaffinity_np",
            "pthread_setaffinity_np",
            "selected static C ABI export surface drifted",
            "candidate selected a dynamic runtime",
            "candidate retains an unresolved symbol",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {"pthread_getaffinity_np", "pthread_setaffinity_np"}
            <= static_exports
        )
        self.assertIn("run_libc_pthread_affinity_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_affinity.sh", runner
        )
        self.assertIn(
            '    libc-pthread-affinity)\n        [ "$#" -eq 0 ] || fail "libc-pthread-affinity takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_identity_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_identity = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_identity.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        pthread_header = (ROOT / "include" / "pthread.h").read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_pthread_identity_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_pthread_identity_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_identity.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_identity.rs"]', static_root)
        self.assertIn("weak `pthread_self`/", static_root)
        for required in (
            "musl 1.2.6 release commit",
            "arch/x86_64/pthread_arch.h::__get_tp()",
            "src/internal/pthread_impl.h::__pthread_self()",
            "src/thread/pthread_self.c",
            "src/thread/pthread_equal.c",
            "pub(super) fn current_thread_pointer()",
            "mov {thread_pointer}, fs:[0]",
            "options(readonly, nostack, preserves_flags)",
            ".weak pthread_self",
            ".set thrd_current, pthread_self",
            ".weak pthread_equal",
            ".set thrd_equal, pthread_equal",
            "mov rax, qword ptr fs:[0]",
            "cmp rdi, rsi",
            "sete al",
        ):
            self.assertIn(required, pthread_identity)
        self.assertNotIn("#[no_mangle]", pthread_identity)
        for forbidden in (
            "pthread_detach",
            "pthread_cancel",
            "pthread_key_create",
            "pthread_mutex",
            "thrd_create",
            "thrd_join",
            "__tls_get_addr",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, pthread_identity)

        self.assertIn("pthread_identity::current_thread_pointer()", pthread_create_join)
        self.assertIn("fn claim_selected_worker_by_thread_pointer", pthread_create_join)
        self.assertIn(
            "core::ptr::write(thread, tls_block.thread_pointer().cast())",
            pthread_create_join,
        )
        selected_join_body = pthread_create_join.split(
            "pub(super) unsafe fn join_selected_worker", 1
        )[1].split("/// Join one normal-returning", 1)[0]
        self.assertLess(
            selected_join_body.index("claim_selected_worker_by_thread_pointer("),
            selected_join_body.index("(*control)"),
        )

        self.assertIn(
            "#ifdef __GNUC__\n__attribute__((const))\n#endif\npthread_t pthread_self(void);",
            pthread_header,
        )
        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "#include <threads.h>",
            "pthread_equal_macro",
            "thrd_equal_macro",
            "#undef pthread_equal",
            "#undef thrd_equal",
            "run_two_live_workers",
            "run_explicit_exit_worker",
            "pthread_exit",
            "thrd_current",
            "thrd_equal",
            "errno = E2BIG",
            "pthread_equal_macro(handle, observation->pthread_identity) != 1",
            "pthread_equal_macro(handle, main_identity) != 0",
            "thrd_equal((thrd_t)handle, (thrd_t)main_identity) != 0",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertIn("crabc_x86_64_pthread_identity_probe", start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "MUSL_LIBC=/opt/musl-1.2.6/lib/libc.a",
            "readelf --symbols --wide \"$MUSL_LIBC\"",
            "assert_weak_same_address_pair",
            "pthread_self thrd_current",
            "pthread_equal thrd_equal",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate pthread_self does not read the Variant-II fs self word",
            "candidate pthread_equal does not return canonical pointer equality",
            "candidate relocations retain a dynamic TLS model",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {"pthread_self", "pthread_equal", "thrd_current", "thrd_equal"}
            <= static_export_names
        )
        self.assertIn("libc-pthread-identity", runner)

    def test_libc_static_c_abi_c11_lifecycle_artifact_stays_typed_and_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        c11_lifecycle = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "c11_thread_lifecycle.rs"
        ).read_text(encoding="utf-8")
        c_probe = (
            ROOT / "compat" / "x86_64" / "libc_c11_lifecycle_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_c11_lifecycle_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_c11_lifecycle.sh"
        ).read_text(encoding="utf-8")
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
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "c11_thread_lifecycle.rs"]', static_root)
        for required in (
            "src/thread/thrd_create.c",
            "src/thread/pthread_create.c::start_c11",
            "src/thread/thrd_join.c",
            "src/thread/thrd_exit.c",
            "src/thread/thrd_detach.c",
            "src/thread/thrd_sleep.c",
            "C11StartRoutine",
            "SelectedWorkerStart::C11",
            "THRD_NOMEM",
            "fn thrd_create(",
            "fn thrd_join(",
            "fn thrd_exit(",
            "fn thrd_detach(",
            "fn thrd_sleep(",
            "detach_selected_worker",
            "super::clock_nanosleep::clock_nanosleep",
            "super::clock_nanosleep::CLOCK_REALTIME",
            "exit_selected_c11_worker",
            "SelectedWorkerResultKind::C11",
            "INT_MIN",
            "INT_MAX",
            "dynamic/loader TLS",
            "public x86 support",
        ):
            self.assertIn(required, c11_lifecycle)
        for forbidden in (
            "fn thrd_yield(",
            "fn call_once(",
            "fn mtx_",
            "fn cnd_",
            "fn tss_",
            "pthread_mutex",
            "__tls_get_addr",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, c11_lifecycle)

        for required in (
            "enum SelectedWorkerStart",
            "C11(C11StartRoutine)",
            "SelectedWorkerResult::C11",
            "SelectedWorkerResultKind::Invalid",
            "exit_selected_pthread_worker",
            "exit_selected_c11_worker",
            "join_selected_worker",
            "detach_selected_worker",
            "result_kind: AtomicU8",
            "pthread_exit(void *)",
            "decode_c11_result",
        ):
            self.assertIn(required, pthread_create_join)
        self.assertNotRegex(
            pthread_create_join,
            r"C11StartRoutine[^\n]*as[^\n]*(?:PthreadStartRoutine|StartRoutine)",
        )

        for required in (
            "#include <errno.h>",
            "#include <limits.h>",
            "#include <pthread.h>",
            "#include <threads.h>",
            "normal_worker",
            "explicit_exit_worker",
            "run_normal_round(INT_MIN)",
            "run_normal_round(INT_MAX)",
            "run_explicit_exit_round(INT_MIN)",
            "run_explicit_exit_round(INT_MAX)",
            "run_null_result_round",
            "run_two_live_workers",
            "run_null_start_rejection_round",
            "run_cross_mode_pthread_exit_rejection_round",
            "run_cross_mode_thrd_exit_rejection_round",
            "run_registry_capacity_round",
            "thrd_create(&handle, 0, 0) != thrd_error",
            "pthread_exit(&observation->result)",
            "thrd_exit(observation->result)",
            "thrd_join(handle, &joined_result) != thrd_error",
            "pthread_join(handle, &joined_result) != EINVAL",
            "volatile int observed;",
            "__atomic_store_n(&observation->observed, 1, __ATOMIC_RELEASE)",
            "thrd_nomem",
            "CRABC_C11_LIFECYCLE_FREESTANDING",
            "CRABC_C11_LIFECYCLE_SELECTED_WORKER_LIMIT",
            "errno = E2BIG",
            "(void *)thrd_current() != inline_thread_pointer()",
        ):
            self.assertIn(required, c_probe)
        # A successful join releases the selected worker's TLS/control mapping,
        # so handle identity must be checked while the handle is still valid.
        for round_name, join_call in (
            ("run_normal_round", "thrd_join(handle, &joined_result)"),
            ("run_explicit_exit_round", "thrd_join(handle, &joined_result)"),
            ("run_null_result_round", "thrd_join(handle, 0)"),
            (
                "run_cross_mode_pthread_exit_rejection_round",
                "thrd_join(handle, &joined_result)",
            ),
        ):
            section = c_probe[c_probe.index(f"static int {round_name}") :]
            self.assertLess(
                section.index("check = check_observation"),
                section.index(join_call),
            )
        symmetric_cross_mode = c_probe[
            c_probe.index("static int run_cross_mode_thrd_exit_rejection_round") :
        ]
        self.assertLess(
            symmetric_cross_mode.index("observation.identity"),
            symmetric_cross_mode.index("pthread_join(handle, &joined_result)"),
        )
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertIn("crabc_x86_64_c11_lifecycle_probe", start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "crabc_thrd_exit_signature",
            "thrd_exit noreturn signature",
            "crabc_thrd_detach_signature",
            "thrd_detach signature",
            "crabc_thrd_sleep_signature",
            "thrd_sleep signature",
        ):
            self.assertIn(required, c_header_probe)
            self.assertIn(required, cxx_header_probe)
        for required in (
            "thrd_create thrd_detach thrd_join thrd_exit thrd_sleep thrd_yield thrd_current thrd_equal",
            "thrd_create|thrd_detach|thrd_join|thrd_exit|thrd_sleep|thrd_yield|thrd_current|thrd_equal",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "run_pthread_c11_header_abi.sh",
            "-nostdlib -static",
            "-DCRABC_C11_LIFECYCLE_SELECTED_WORKER_LIMIT=64",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "thrd_create thrd_exit thrd_join",
            "thrd_exit lacks an x86 thread-exit syscall instruction",
            "thrd_join lacks futex syscall number 202",
            "thrd_join lacks munmap syscall number 11",
            "C11 callback is cast to the pthread callback type",
            "SelectedWorkerResultKind::Invalid",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {"thrd_create", "thrd_detach", "thrd_join", "thrd_exit", "thrd_sleep"}
            <= static_exports
        )
        self.assertIn("thrd_yield", static_exports)
        self.assertIn("run_libc_c11_lifecycle_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_c11_lifecycle.sh", runner
        )
        self.assertIn(
            '    libc-c11-lifecycle)\n        [ "$#" -eq 0 ] || fail "libc-c11-lifecycle takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_thrd_sleep_artifact_stays_narrow(self) -> None:
        """Keep C11 sleep as a direct static errno-neutral adapter only."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        c11_lifecycle = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "c11_thread_lifecycle.rs"
        ).read_text(encoding="utf-8")
        clock_nanosleep = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clock_nanosleep.rs"
        ).read_text(encoding="utf-8")
        probe_path = ROOT / "compat" / "x86_64" / "libc_thrd_sleep_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_thrd_sleep_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_thrd_sleep.sh"
        )
        c_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.cpp"
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

        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing thrd_sleep artifact input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "c11_thread_lifecycle.rs"]', static_root)
        for required in (
            "src/thread/thrd_sleep.c",
            "const THRD_SLEEP_INTR: c_int = -1;",
            "const THRD_SLEEP_ERROR: c_int = -2;",
            "pub unsafe extern \"C\" fn thrd_sleep(",
            "super::clock_nanosleep::clock_nanosleep(",
            "super::clock_nanosleep::CLOCK_REALTIME",
            "EINTR => THRD_SLEEP_INTR",
            "_ => THRD_SLEEP_ERROR",
            "not a cancellation",
            "thrd_yield",
            "public x86 support",
        ):
            self.assertIn(required, c11_lifecycle)
        thrd_sleep_body = c11_lifecycle.split(
            'pub unsafe extern "C" fn thrd_sleep', 1
        )[1].split("/// End the current selected C11 worker", 1)[0]
        for forbidden in (
            "c_status",
            "set_errno",
            "super::nanosleep",
            "pthread_",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, thrd_sleep_body)
        for required in (
            "pub(super) const CLOCK_REALTIME: c_int = 0;",
            "raw_syscall::SYS_CLOCK_NANOSLEEP",
            "raw_syscall::syscall4(",
            "positive errno",
        ):
            self.assertIn(required, clock_nanosleep)

        for required in (
            "#include <errno.h>",
            "#include <signal.h>",
            "#include <threads.h>",
            "thrd_sleep(&zero, 0) != thrd_success",
            "thrd_sleep(&invalid, 0) != thrd_sleep_error",
            "thrd_sleep(0, 0) != thrd_sleep_error",
            "thrd_sleep(&requested, &remaining)",
            "thrd_sleep_interrupted",
            "positive_remainder",
            "errno != preserved_errno",
            "CRABC_THRD_SLEEP_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_thrd_sleep_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_pthread_c11_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "assert_thrd_sleep_path",
            "clock_nanosleep syscall 230",
            "fourth-argument r10 path",
            "thrd_sleep must not mutate errno TLS",
            "thrd_yield",
            "malloc free calloc realloc",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("thrd_sleep", static_exports)
        for header_probe in (c_header_probe, cxx_header_probe):
            self.assertIn("crabc_thrd_sleep_signature", header_probe)
            self.assertIn("thrd_sleep signature", header_probe)
        self.assertIn('id = "static-c-thrd-sleep"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-thrd-sleep"',
            parity_ledger,
        )
        self.assertIn("run_libc_thrd_sleep_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_thrd_sleep.sh", runner
        )
        self.assertIn(
            '    libc-thrd-sleep)\n        [ "$#" -eq 0 ] || fail "libc-thrd-sleep takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_thrd_yield_artifact_stays_direct_and_errno_neutral(
        self,
    ) -> None:
        """Keep C11 thrd_yield as one raw, statusless scheduler boundary."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        thrd_yield = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "thrd_yield.rs"
        ).read_text(encoding="utf-8")
        probe_path = ROOT / "compat" / "x86_64" / "libc_thrd_yield_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_thrd_yield_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_thrd_yield.sh"
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

        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing thrd_yield artifact input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "thrd_yield.rs"]', static_root)
        for required in (
            "src/thread/thrd_yield.c::thrd_yield",
            "SYS_sched_yield",
            "sched_yield=24",
            "pub extern \"C\" fn thrd_yield()",
            "raw_syscall::syscall0(raw_syscall::SYS_SCHED_YIELD)",
            "does not publish a raw failure through errno",
            "POSIX `sched_yield` C API",
            "scheduler policy or parameter APIs",
            "affinity",
            "lifecycle/synchronization/TSS/cancellation",
            "public x86 support",
        ):
            self.assertIn(required, thrd_yield)
        for forbidden in (
            "set_errno",
            "c_status",
            "crabc_core",
            "crabc_mimalloc",
            "pub extern \"C\" fn sched_yield",
        ):
            self.assertNotIn(forbidden, thrd_yield)

        for required in (
            "#include <errno.h>",
            "#include <sys/prctl.h>",
            "#include <sys/syscall.h>",
            "#include <threads.h>",
            "SYS_sched_yield == 24",
            "CRABC_SECCOMP_RET_ERRNO | EPERM",
            "install_yield_error_filter",
            "check_normal_yield_preserves_errno",
            "check_forced_error_preserves_errno",
            "errno == preserved_errno",
            "CRABC_THRD_YIELD_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_thrd_yield_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_pthread_c11_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "assert_thrd_yield_syscall",
            "sched_yield syscall 24",
            "must not publish a raw failure through errno TLS",
            "archive accidentally exposes the unselected sched_yield C API",
            "src/thread/thrd_yield.c",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("thrd_yield", static_exports)
        self.assertNotIn("sched_yield", static_exports)
        for header_probe in (c_header_probe, cxx_header_probe):
            self.assertIn("crabc_thrd_yield_signature", header_probe)
            self.assertIn("thrd_yield signature", header_probe)
        self.assertIn(
            "thrd_create thrd_detach thrd_join thrd_exit thrd_sleep thrd_yield thrd_current thrd_equal",
            header_runner,
        )
        self.assertIn(
            "thrd_create|thrd_detach|thrd_join|thrd_exit|thrd_sleep|thrd_yield|thrd_current|thrd_equal",
            header_runner,
        )
        self.assertIn('id = "static-c-thrd-yield"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-thrd-yield"',
            parity_ledger,
        )
        self.assertIn("run_libc_thrd_yield_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_thrd_yield.sh", runner
        )
        self.assertIn(
            '    libc-thrd-yield)\n        [ "$#" -eq 0 ] || fail "libc-thrd-yield takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_cpuclock_artifact_stays_self_only(
        self,
    ) -> None:
        """Keep the selected CPU clock apart from general pthread/clock behavior."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_cpuclock = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_cpuclock.rs"
        ).read_text(encoding="utf-8")
        probe_path = ROOT / "compat" / "x86_64" / "libc_pthread_cpuclock_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_pthread_cpuclock_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_cpuclock.sh"
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

        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing pthread CPU-clock input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_cpuclock.rs"]', static_root)
        for required in (
            "src/thread/pthread_getcpuclockid.c::pthread_getcpuclockid",
            "pthread_getcpuclockid",
            "SYS_GETTID",
            "gettid=186",
            "current_thread_pointer",
            "is_initial_thread_pointer",
            "thread_cpu_clock_id",
            "does not write C `errno`",
            "clock_getcpuclockid",
            "worker CPU clocks",
            "affinity or scheduling attributes",
            "public x86 support",
        ):
            self.assertIn(required, pthread_cpuclock)
        for forbidden in (
            "pthread_create_join",
            "selected_worker_linux_thread_id",
            "set_errno",
            "c_status",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, pthread_cpuclock)

        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "#include <sys/syscall.h>",
            "#include <time.h>",
            "SYS_gettid == 186",
            "expected_thread_cpu_clock",
            "pthread_getcpuclockid",
            "clock_gettime",
            "CRABC_PTHREAD_CPUCLOCK_FREESTANDING",
            "check_candidate_null_handle_rejection",
            "ESRCH",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_cpuclock_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_pthread_c11_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "assert_pthread_cpuclock_path",
            "gettid syscall 186",
            "must not publish pthread status through errno",
            "src/thread/pthread_getcpuclockid.c",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("pthread_getcpuclockid", static_exports)
        for header_probe in (c_header_probe, cxx_header_probe):
            self.assertIn("crabc_pthread_getcpuclockid_signature", header_probe)
            self.assertIn("pthread_getcpuclockid signature", header_probe)
        self.assertIn("crabc_force_pthread_getcpuclockid", cxx_header_probe)
        self.assertIn(
            "pthread_create pthread_detach pthread_self pthread_equal pthread_getcpuclockid",
            header_runner,
        )
        self.assertIn(
            "pthread_create|pthread_detach|pthread_self|pthread_equal|pthread_getcpuclockid",
            header_runner,
        )
        self.assertIn('id = "static-c-pthread-cpuclock"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-pthread-cpuclock"',
            parity_ledger,
        )
        self.assertIn("run_libc_pthread_cpuclock_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_cpuclock.sh", runner
        )
        self.assertIn("    libc-pthread-cpuclock) ;;", runner)
        self.assertIn(
            '    libc-pthread-cpuclock)\n        [ "$#" -eq 0 ] || fail "libc-pthread-cpuclock takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_name_artifact_stays_self_only(
        self,
    ) -> None:
        """Keep GNU task names apart from general pthread task naming."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_name = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_name.rs"
        ).read_text(encoding="utf-8")
        probe_path = ROOT / "compat" / "x86_64" / "libc_pthread_name_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_pthread_name_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_name.sh"
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

        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing pthread task-name input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_name.rs"]', static_root)
        for required in (
            "src/thread/pthread_setname_np.c::pthread_setname_np",
            "src/thread/pthread_getname_np.c::pthread_getname_np",
            "pthread_setname_np",
            "pthread_getname_np",
            "SYS_PRCTL",
            "PR_SET_NAME",
            "PR_GET_NAME",
            "is_initial_thread_pointer",
            "before the name input or output is",
            "observed. It does not select worker names",
            "neither entry writes C",
            "or public x86",
            "support. Pthread errors",
        ):
            self.assertIn(required, pthread_name)
        for forbidden in (
            "pthread_create_join",
            "selected_worker_linux_thread_id",
            "set_errno",
            "c_status",
            "SYS_OPEN",
            "SYS_WRITE",
            "pthread_setcancel",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, pthread_name)

        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "#include <sys/prctl.h>",
            "#include <sys/syscall.h>",
            "SYS_prctl == 157",
            "PR_SET_NAME == 15 && PR_GET_NAME == 16",
            "pthread_setname_np",
            "pthread_getname_np",
            "raw_get_name",
            "CRABC_PTHREAD_NAME_FREESTANDING",
            "check_candidate_nonself_rejection",
            "ESRCH",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_name_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_pthread_c11_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "assert_pthread_name_path",
            "fixed prctl syscall 157",
            "must not publish pthread status through errno",
            "src/thread/pthread_setname_np.c",
            "src/thread/pthread_getname_np.c",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {"pthread_setname_np", "pthread_getname_np"} <= static_exports
        )
        for header_probe in (c_header_probe, cxx_header_probe):
            self.assertIn("crabc_pthread_setname_np_signature", header_probe)
            self.assertIn("crabc_pthread_getname_np_signature", header_probe)
            self.assertIn("pthread_setname_np signature", header_probe)
            self.assertIn("pthread_getname_np signature", header_probe)
        self.assertIn("crabc_force_pthread_setname_np", cxx_header_probe)
        self.assertIn("crabc_force_pthread_getname_np", cxx_header_probe)
        self.assertIn("pthread_sigmask pthread_setname_np pthread_getname_np", header_runner)
        self.assertIn("pthread_getcpuclockid|pthread_setname_np|pthread_getname_np", header_runner)
        self.assertIn('id = "static-c-pthread-name"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-pthread-name"',
            parity_ledger,
        )
        self.assertIn("run_libc_pthread_name_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_name.sh", runner
        )
        self.assertIn("    libc-pthread-name) ;;", runner)
        self.assertIn(
            '    libc-pthread-name)\n        [ "$#" -eq 0 ] || fail "libc-pthread-name takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_normal_mutex_artifact_stays_private(
        self,
    ) -> None:
        """Keep the selected normal mutex apart from pthread/C11 promotion."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        atomic = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "atomic.rs"
        ).read_text(encoding="utf-8")
        pthread_mutex = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_mutex.rs"
        ).read_text(encoding="utf-8")
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_pthread_mutex_normal_probe.c"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_pthread_mutex_normal_start.S"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_mutex_normal.sh"
        )
        c_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.cpp"
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

        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing normal mutex artifact input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "atomic.rs"]', static_root)
        self.assertIn('#[path = "pthread_mutex.rs"]', static_root)
        for required in (
            "AtomicI32::from_ptr",
            "x86_64_load_acquire_i32",
            "x86_64_load_relaxed_i32",
            "x86_64_compare_exchange_acqrel_i32",
            "x86_64_swap_acqrel_i32",
            "x86_64_fetch_add_acqrel_i32",
            "x86_64_fetch_sub_acqrel_i32",
            "private normal-mutex and its private condition-variable handoff artifacts",
        ):
            self.assertIn(required, atomic)
        self.assertNotIn("#[no_mangle]", atomic)

        for required in (
            "1.2.6 release commit",
            "src/thread/pthread_mutex_init.c",
            "src/thread/pthread_mutex_trylock.c::__pthread_mutex_trylock",
            "src/thread/pthread_mutex_lock.c::__pthread_mutex_lock",
            "src/thread/pthread_mutex_timedlock.c::__pthread_mutex_timedlock",
            "src/thread/pthread_mutex_unlock.c::__pthread_mutex_unlock",
            "src/thread/pthread_mutex_destroy.c",
            "process-private `PTHREAD_MUTEX_NORMAL`",
            "struct PublicPthreadMutex",
            "#[repr(C, align(8))]",
            "MUTEX_TYPE_WORD: usize = 0",
            "MUTEX_LOCK_WORD: usize = 1",
            "MUTEX_WAITERS_WORD: usize = 2",
            "MUTEX_WORD_COUNT: usize = 10",
            "MUTEX_WAITER_BIT: c_int = c_int::MIN",
            "size_of::<PublicPthreadMutex>() == 40",
            "align_of::<PublicPthreadMutex>() == 8",
            "FUTEX_WAIT_PRIVATE",
            "FUTEX_WAKE_PRIVATE",
            "raw_syscall::SYS_FUTEX",
            "raw_syscall::syscall4(",
            "x86_64_compare_exchange_acqrel_i32",
            "x86_64_swap_acqrel_i32",
            "x86_64_fetch_add_acqrel_i32",
            "x86_64_fetch_sub_acqrel_i32",
            "pub unsafe extern \"C\" fn pthread_mutex_init",
            "pub unsafe extern \"C\" fn pthread_mutex_destroy",
            "pub unsafe extern \"C\" fn pthread_mutex_trylock",
            "pub unsafe extern \"C\" fn pthread_mutex_lock",
            "pub unsafe extern \"C\" fn pthread_mutex_unlock",
            "return ENOTSUP;",
            "public pthread boundary never writes C `errno`",
            "public x86 support",
        ):
            self.assertIn(required, pthread_mutex)
        mutex_exports = set(
            re.findall(
                r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                pthread_mutex,
            )
        )
        self.assertSetEqual(
            mutex_exports,
            {
                "pthread_mutex_init",
                "pthread_mutex_destroy",
                "pthread_mutex_trylock",
                "pthread_mutex_lock",
                "pthread_mutex_unlock",
            },
        )
        for forbidden in (
            "pub unsafe extern \"C\" fn pthread_mutexattr_",
            "pub unsafe extern \"C\" fn pthread_mutex_timedlock",
            "pub unsafe extern \"C\" fn pthread_cond_",
            "pub unsafe extern \"C\" fn pthread_rwlock_",
            "pub unsafe extern \"C\" fn pthread_once",
            "pub unsafe extern \"C\" fn mtx_",
            "pthread_self",
            "SYS_GETTID",
            "__tls_get_addr",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, pthread_mutex)

        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "WORKER_COUNT = 2",
            "CONTENTION_ROUNDS = 6",
            "static pthread_mutex_t static_normal_mutex = PTHREAD_MUTEX_INITIALIZER;",
            "run_static_initializer_probe",
            "pthread_mutex_init(&round.mutex, 0)",
            "pthread_mutex_trylock(&round.mutex) != EBUSY",
            "critical_overlap",
            "errno = E2BIG",
            "errno != E2BIG",
            "CRABC_PTHREAD_MUTEX_NORMAL_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("#include <threads.h>", probe)

        for required in (
            ".globl _start",
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_mutex_normal_probe",
            "mov $60, %eax",
            "syscall",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "run_pthread_c11_header_abi.sh",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_MUTEX_NORMAL_FREESTANDING",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "timeout \"$EXECUTION_TIMEOUT\"",
            "lock[[:space:]]+cmpxchg",
            "futex syscall number 202",
            "FUTEX_WAIT_PRIVATE",
            "FUTEX_WAKE_PRIVATE",
            "atomic exchange release",
            "pthread_mutexattr_init",
            "pthread_cond_timedwait",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {
                "pthread_mutex_init",
                "pthread_mutex_destroy",
                "pthread_mutex_trylock",
                "pthread_mutex_lock",
                "pthread_mutex_unlock",
            }
            <= static_exports
        )
        self.assertTrue(
            {
                "pthread_mutexattr_init",
                "pthread_mutex_timedlock",
                "pthread_condattr_init",
                "pthread_cond_timedwait",
            }.isdisjoint(static_exports)
        )
        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "crabc_pthread_mutex_init_signature",
                "crabc_pthread_mutex_destroy_signature",
                "crabc_pthread_mutex_lock_signature",
                "crabc_pthread_mutex_trylock_signature",
                "crabc_pthread_mutex_unlock_signature",
                "pthread_mutex_init signature",
                "pthread_mutex_destroy signature",
                "pthread_mutex_lock signature",
                "pthread_mutex_trylock signature",
                "pthread_mutex_unlock signature",
            ):
                self.assertIn(required, header_probe)
        self.assertIn('id = "static-c-pthread-normal-mutex"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-pthread-mutex-normal"',
            parity_ledger,
        )
        self.assertIn("run_libc_pthread_mutex_normal_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_mutex_normal.sh", runner
        )
        self.assertIn(
            '    libc-pthread-mutex-normal)\n        [ "$#" -eq 0 ] || fail "libc-pthread-mutex-normal takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_rwlock_artifact_stays_private_and_exact(
        self,
    ) -> None:
        """Keep the full rwlock family as a verified pthread/TLS sub-artifact."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_rwlock = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_rwlock.rs"
        ).read_text(encoding="utf-8")
        probe_path = ROOT / "compat" / "x86_64" / "libc_pthread_rwlock_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_pthread_rwlock_start.S"
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_pthread_rwlock.sh"
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

        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing rwlock artifact input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_rwlock.rs"]', static_root)
        for required in (
            "1.2.6 release commit",
            "src/thread/pthread_rwlock_init.c",
            "src/thread/pthread_rwlock_destroy.c",
            "src/thread/pthread_rwlock_{tryrdlock,timedrdlock,rdlock}.c",
            "src/thread/pthread_rwlock_{trywrlock,timedwrlock,wrlock}.c",
            "src/thread/pthread_rwlock_unlock.c",
            "src/thread/pthread_rwlockattr_{init,destroy,setpshared}.c",
            "pthread_rwlockattr_getpshared",
            "src/thread/__timedwait.c",
            "struct PublicPthreadRwlock",
            "struct PublicPthreadRwlockAttr",
            "RWLOCK_LOCK_WORD: usize = 0",
            "RWLOCK_WAITERS_WORD: usize = 1",
            "RWLOCK_SHARED_WORD: usize = 2",
            "RWLOCK_WORD_COUNT: usize = 14",
            "RWLOCK_WRITER: c_int = 0x7fff_ffff",
            "RWLOCK_READER_MAX: c_int = 0x7fff_fffe",
            "RWLOCK_WAITER_BIT: c_int = c_int::MIN",
            "size_of::<PublicPthreadRwlock>() == 56",
            "align_of::<PublicPthreadRwlock>() == 8",
            "size_of::<PublicPthreadRwlockAttr>() == 8",
            "align_of::<PublicPthreadRwlockAttr>() == 4",
            "CLOCK_REALTIME",
            "timed_futex_wait",
            "futex_private_flag",
            "FUTEX_PRIVATE_FLAG",
            "raw_syscall::SYS_CLOCK_GETTIME",
            "raw_syscall::SYS_FUTEX",
            "raw_syscall::syscall2(",
            "raw_syscall::syscall4(",
            "x86_64_compare_exchange_acqrel_i32",
            "x86_64_fetch_add_acqrel_i32",
            "x86_64_fetch_sub_acqrel_i32",
            "__pthread_rwlock_rdlock",
            "__pthread_rwlock_tryrdlock",
            "__pthread_rwlock_timedrdlock",
            "__pthread_rwlock_wrlock",
            "__pthread_rwlock_trywrlock",
            "__pthread_rwlock_timedwrlock",
            "__pthread_rwlock_unlock",
            ".hidden __pthread_rwlock_rdlock",
            ".weak pthread_rwlock_rdlock",
            ".set pthread_rwlock_rdlock, __pthread_rwlock_rdlock",
            "public x86 support",
        ):
            self.assertIn(required, pthread_rwlock)
        rwlock_exports = set(
            re.findall(
                r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                pthread_rwlock,
            )
        )
        self.assertSetEqual(
            rwlock_exports,
            {
                "pthread_rwlockattr_init",
                "pthread_rwlockattr_destroy",
                "pthread_rwlockattr_setpshared",
                "pthread_rwlockattr_getpshared",
                "pthread_rwlock_init",
                "pthread_rwlock_destroy",
                "__pthread_rwlock_rdlock",
                "__pthread_rwlock_tryrdlock",
                "__pthread_rwlock_timedrdlock",
                "__pthread_rwlock_wrlock",
                "__pthread_rwlock_trywrlock",
                "__pthread_rwlock_timedwrlock",
                "__pthread_rwlock_unlock",
            },
        )
        for forbidden in (
            "errno::",
            "c_status(",
            "pthread_mutex::",
            "pthread_cond::",
            "crabc_core",
            "crabc_mimalloc",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, pthread_rwlock)

        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "#include <sys/mman.h>",
            "#include <sys/syscall.h>",
            "sizeof(pthread_rwlock_t) == 56",
            "PTHREAD_RWLOCK_INITIALIZER",
            "PTHREAD_PROCESS_SHARED",
            "SYS_fork == 57",
            "SYS_wait4 == 61",
            "run_static_initializer_probe",
            "run_attribute_and_private_probe",
            "run_timed_status_probe",
            "run_timed_futex_timeout_case",
            "run_timed_release_probe",
            "TIMED_FUTEX_TIMEOUT_SECONDS",
            "run_reader_concurrency_round",
            "run_writer_exclusion_round",
            "run_process_shared_case",
            "wait_for_waiter_mark",
            "MAP_SHARED | MAP_ANONYMOUS",
            "pthread_rwlock_timedrdlock",
            "pthread_rwlock_timedwrlock",
            "ETIMEDOUT",
            "CRABC_PTHREAD_RWLOCK_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("#include <threads.h>", probe)

        for required in (
            ".globl _start",
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_rwlock_probe",
            "mov $60, %eax",
            "syscall",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "run_pthread_c11_header_abi.sh",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_RWLOCK_FREESTANDING",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "timeout \"$EXECUTION_TIMEOUT\"",
            "assert_weak_hidden_alias_pair",
            "GLOBAL +HIDDEN",
            "WEAK +DEFAULT",
            "same-address alias",
            "pthread_rwlockattr_getpshared",
            "__pthread_rwlock_timedwrlock",
            "futex syscall number 202",
            "clock_gettime syscall number 228",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)

        rwlock_static_exports = {
            "pthread_rwlockattr_init",
            "pthread_rwlockattr_destroy",
            "pthread_rwlockattr_setpshared",
            "pthread_rwlockattr_getpshared",
            "pthread_rwlock_init",
            "pthread_rwlock_destroy",
            "pthread_rwlock_rdlock",
            "pthread_rwlock_tryrdlock",
            "pthread_rwlock_timedrdlock",
            "pthread_rwlock_wrlock",
            "pthread_rwlock_trywrlock",
            "pthread_rwlock_timedwrlock",
            "pthread_rwlock_unlock",
            "__pthread_rwlock_rdlock",
            "__pthread_rwlock_tryrdlock",
            "__pthread_rwlock_timedrdlock",
            "__pthread_rwlock_wrlock",
            "__pthread_rwlock_trywrlock",
            "__pthread_rwlock_timedwrlock",
            "__pthread_rwlock_unlock",
        }
        self.assertTrue(rwlock_static_exports <= static_exports)

        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "crabc_pthread_rwlock_init_signature",
                "crabc_pthread_rwlock_destroy_signature",
                "crabc_pthread_rwlock_rdlock_signature",
                "crabc_pthread_rwlock_tryrdlock_signature",
                "crabc_pthread_rwlock_timedrdlock_signature",
                "crabc_pthread_rwlock_wrlock_signature",
                "crabc_pthread_rwlock_trywrlock_signature",
                "crabc_pthread_rwlock_timedwrlock_signature",
                "crabc_pthread_rwlock_unlock_signature",
                "crabc_pthread_rwlockattr_init_signature",
                "crabc_pthread_rwlockattr_destroy_signature",
                "crabc_pthread_rwlockattr_setpshared_signature",
                "crabc_pthread_rwlockattr_getpshared_signature",
                "pthread_rwlock_init signature",
                "pthread_rwlockattr_getpshared signature",
            ):
                self.assertIn(required, header_probe)
        self.assertIn("pthread_rwlock_timedwrlock", header_runner)
        self.assertIn("pthread_rwlockattr_getpshared", header_runner)
        self.assertIn('id = "static-c-pthread-rwlock"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-pthread-rwlock"',
            parity_ledger,
        )
        self.assertIn("run_libc_pthread_rwlock_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_rwlock.sh", runner
        )
        self.assertIn(
            '    libc-pthread-rwlock)\n        [ "$#" -eq 0 ] || fail "libc-pthread-rwlock takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_private_condition_artifact_stays_bounded(
        self,
    ) -> None:
        """Keep the selected waiter/barrier/requeue handoff private and exact."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        raw_syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        pthread_mutex = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_mutex.rs"
        ).read_text(encoding="utf-8")
        pthread_cond = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_cond.rs"
        ).read_text(encoding="utf-8")
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_pthread_cond_private_probe.c"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_pthread_cond_private_start.S"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_cond_private.sh"
        )
        c_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" / "pthread_c11_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing private condition artifact input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_mutex.rs"]', static_root)
        self.assertIn('#[path = "pthread_cond.rs"]', static_root)
        for required in (
            "1.2.6 release commit",
            "src/thread/pthread_cond_init.c::pthread_cond_init",
            "src/thread/pthread_cond_destroy.c::pthread_cond_destroy",
            "src/thread/pthread_cond_wait.c::pthread_cond_wait",
            "src/thread/pthread_cond_timedwait.c::__pthread_cond_timedwait",
            "src/thread/pthread_cond_signal.c::pthread_cond_signal",
            "src/thread/pthread_cond_broadcast.c::pthread_cond_broadcast",
            "src/thread/pthread_cond_timedwait.c::__private_cond_signal",
            "src/thread/__wait.c::__wait",
            "src/thread/pthread_cond_timedwait.c::{lock,unlock,unlock_requeue}",
            "process-private condition-variable handoff",
            "struct PublicPthreadCond",
            "#[repr(C, align(8))]",
            "COND_WORD_COUNT: usize = 12",
            "COND_LOCK_WORD: usize = 8",
            "size_of::<PublicPthreadCond>() == 48",
            "align_of::<PublicPthreadCond>() == 8",
            "cond_head_slot",
            "cond_tail_slot",
            "struct Waiter",
            "barrier: c_int",
            "notify: *mut c_int",
            "let mut node = Waiter {",
            "WAITER_LEAVING: c_int = 2",
            "private_cond_signal",
            "private_unlock_requeue",
            "const FUTEX_WAIT: i64 = 0;",
            "const FUTEX_WAKE: i64 = 1;",
            "const FUTEX_REQUEUE: i64 = 3;",
            "const FUTEX_PRIVATE_FLAG: i64 = 128;",
            "const FUTEX_WAIT_PRIVATE: i64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;",
            "const FUTEX_WAKE_PRIVATE: i64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;",
            "const FUTEX_REQUEUE_PRIVATE: i64 = FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG;",
            "raw_syscall::SYS_FUTEX",
            "raw_syscall::syscall4(",
            "raw_syscall::syscall5(",
            "val2=1` in r10",
            "mutex_lock` in r8",
            "pthread_mutex::selected_normal_mutex_words",
            "pthread_mutex::unlock_selected_normal_mutex",
            "pthread_mutex::lock_selected_normal_mutex",
            "never writes C errno",
            "public x86 support",
        ):
            self.assertIn(required, pthread_cond)
        condition_exports = set(
            re.findall(
                r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                pthread_cond,
            )
        )
        self.assertSetEqual(
            condition_exports,
            {
                "pthread_cond_init",
                "pthread_cond_destroy",
                "pthread_cond_wait",
                "pthread_cond_signal",
                "pthread_cond_broadcast",
            },
        )
        for forbidden in (
            'pub unsafe extern "C" fn pthread_cond_timedwait',
            'pub unsafe extern "C" fn pthread_condattr_',
            'pub unsafe extern "C" fn cnd_',
            'pub unsafe extern "C" fn mtx_',
            'pub unsafe extern "C" fn pthread_mutexattr_',
            'pub unsafe extern "C" fn pthread_rwlock_',
            'pub unsafe extern "C" fn pthread_once',
            "__tls_get_addr",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, pthread_cond)

        for required in (
            "pub(super) unsafe fn selected_normal_mutex_words",
            "pub(super) unsafe fn lock_selected_normal_mutex",
            "pub(super) unsafe fn unlock_selected_normal_mutex",
        ):
            self.assertIn(required, pthread_mutex)
        syscall5 = raw_syscall.split("pub(crate) unsafe fn syscall5(", 1)[1].split(
            "/// Issue a six-argument raw Linux/x86-64 syscall.", 1
        )[0]
        self.assertIn('in("r10") a4', syscall5)
        self.assertIn('in("r8") a5', syscall5)

        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "sizeof(pthread_cond_t) == 48",
            "PTHREAD_COND_INITIALIZER",
            "PTHREAD_MUTEX_INITIALIZER",
            "BROADCAST_WAITER_COUNT = 2",
            "PING_PONG_HANDOFFS = 64",
            "PING_PONG_ROUNDS = 4",
            "run_static_initializer_round",
            "run_initialized_waiter_round",
            "run_no_waiter_signal_round",
            "run_candidate_only_attribute_rejection",
            "run_ping_pong_round",
            "pthread_cond_wait",
            "pthread_cond_signal",
            "pthread_cond_broadcast",
            "errno != E2BIG",
            "CRABC_PTHREAD_COND_PRIVATE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("#include <threads.h>", probe)

        for required in (
            ".globl _start",
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pthread_cond_private_probe",
            "mov $60, %eax",
            "syscall",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "run_pthread_c11_header_abi.sh",
            "assert_private_futex_path",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_COND_PRIVATE_FREESTANDING",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "timeout \"$EXECUTION_TIMEOUT\"",
            "FUTEX_WAIT_PRIVATE",
            "FUTEX_WAKE_PRIVATE",
            "FUTEX_REQUEUE_PRIVATE",
            "requeue val2=1 in x86 r10",
            "uaddr2 handoff through x86 r8",
            "assert_private_futex_path pthread_cond_wait wait",
            "assert_private_futex_path pthread_cond_wait requeue",
            "assert_private_futex_path pthread_cond_signal wake",
            "assert_private_futex_path pthread_cond_broadcast wake",
            "pthread_condattr_init",
            "pthread_cond_timedwait",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)

        self.assertTrue(
            {
                "pthread_cond_init",
                "pthread_cond_destroy",
                "pthread_cond_wait",
                "pthread_cond_signal",
                "pthread_cond_broadcast",
            }
            <= static_exports
        )
        self.assertTrue(
            {
                "pthread_condattr_init",
                "pthread_condattr_destroy",
                "pthread_cond_timedwait",
            }.isdisjoint(static_exports)
        )
        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "crabc_pthread_cond_init_signature",
                "crabc_pthread_cond_destroy_signature",
                "crabc_pthread_cond_wait_signature",
                "crabc_pthread_cond_signal_signature",
                "crabc_pthread_cond_broadcast_signature",
                "pthread_cond_init signature",
                "pthread_cond_destroy signature",
                "pthread_cond_wait signature",
                "pthread_cond_signal signature",
                "pthread_cond_broadcast signature",
            ):
                self.assertIn(required, header_probe)
        self.assertIn("run_libc_pthread_cond_private_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_cond_private.sh", runner
        )
        self.assertIn(
            '    libc-pthread-cond-private)\n        [ "$#" -eq 0 ] || fail "libc-pthread-cond-private takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_c11_plain_sync_artifact_stays_private_and_bounded(
        self,
    ) -> None:
        """Keep C11 plain synchronization distinct from family promotion."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_mutex = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_mutex.rs"
        ).read_text(encoding="utf-8")
        pthread_cond = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_cond.rs"
        ).read_text(encoding="utf-8")
        c11_sync_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "c11_sync.rs"
        probe_path = ROOT / "compat" / "x86_64" / "libc_c11_plain_sync_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_c11_plain_sync_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_c11_plain_sync.sh"
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

        for path in (c11_sync_path, probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing C11 plain-sync input: {path}")
        c11_sync = c11_sync_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")

        self.assertIn('#[path = "c11_sync.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "src/thread/mtx_init.c",
            "mtx_destroy.c",
            "mtx_lock.c",
            "mtx_trylock.c",
            "mtx_unlock.c",
            "src/thread/cnd_init.c",
            "cnd_destroy.c",
            "cnd_wait.c",
            "cnd_signal.c",
            "cnd_broadcast.c",
            "struct PublicC11Mutex",
            "struct PublicC11Condition",
            "size_of::<PublicC11Mutex>() == 40",
            "size_of::<PublicC11Condition>() == 48",
            "MTX_PLAIN: c_int = 0",
            "THRD_SUCCESS: c_int = 0",
            "THRD_BUSY: c_int = 1",
            "THRD_ERROR: c_int = 2",
            "pthread_mutex::init_selected_normal_mutex",
            "pthread_mutex::destroy_selected_normal_mutex",
            "pthread_mutex::lock_selected_normal_mutex",
            "pthread_mutex::try_lock_selected_normal_mutex",
            "pthread_mutex::unlock_selected_normal_mutex",
            "pthread_cond::init_selected_private_cond",
            "pthread_cond::destroy_selected_private_cond",
            "pthread_cond::wait_selected_private_cond",
            "pthread_cond::signal_selected_private_cond",
            "pthread_cond::broadcast_selected_private_cond",
            "general C11",
            "pthread parity",
            "public x86 support",
        ):
            self.assertIn(required, c11_sync)
        c11_sync_exports = set(
            re.findall(
                r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                c11_sync,
            )
        )
        self.assertSetEqual(
            c11_sync_exports,
            {
                "mtx_init",
                "mtx_destroy",
                "mtx_lock",
                "mtx_trylock",
                "mtx_unlock",
                "cnd_init",
                "cnd_destroy",
                "cnd_wait",
                "cnd_signal",
                "cnd_broadcast",
            },
        )
        for forbidden in (
            'pub unsafe extern "C" fn mtx_timedlock',
            'pub unsafe extern "C" fn cnd_timedwait',
            'pub unsafe extern "C" fn call_once',
            'pub unsafe extern "C" fn tss_',
            "__tls_get_addr",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, c11_sync)
        self.assertNotRegex(
            c11_sync,
            r"pthread_(?:mutex|cond)_(?:init|destroy|lock|trylock|unlock|wait|signal|broadcast)\(",
        )
        for required in (
            "pub(super) unsafe fn init_selected_normal_mutex",
            "pub(super) unsafe fn destroy_selected_normal_mutex",
            "pub(super) unsafe fn try_lock_selected_normal_mutex",
        ):
            self.assertIn(required, pthread_mutex)
        for required in (
            "pub(super) unsafe fn init_selected_private_cond",
            "pub(super) unsafe fn destroy_selected_private_cond",
            "pub(super) unsafe fn wait_selected_private_cond",
            "pub(super) unsafe fn signal_selected_private_cond",
            "pub(super) unsafe fn broadcast_selected_private_cond",
        ):
            self.assertIn(required, pthread_cond)

        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "#include <threads.h>",
            "C11 mtx_t remains distinct from pthread_mutex_t",
            "C11 cnd_t remains distinct from pthread_cond_t",
            "run_trylock_round",
            "mtx_trylock(&mutex) != thrd_busy",
            "run_waiter_round(1, 0)",
            "run_waiter_round(BROADCAST_WAITER_COUNT, 1)",
            "PING_PONG_HANDOFFS = 64",
            "PING_PONG_ROUNDS = 4",
            "run_ping_pong_round",
            "run_candidate_only_kind_rejection",
            "mtx_init(&recursive, mtx_recursive) != thrd_error",
            "mtx_init(&timed, mtx_timed) != thrd_error",
            "CRABC_C11_PLAIN_SYNC_FREESTANDING",
            "errno != E2BIG",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("pthread_cond_wait", probe)
        self.assertNotIn("pthread_mutex_lock", probe)
        for required in (
            ".global _start",
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_c11_plain_sync_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "run_pthread_c11_header_abi.sh",
            "-nostdlib -static",
            "-DCRABC_C11_PLAIN_SYNC_FREESTANDING",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "assert_private_futex_path cnd_wait wait",
            "assert_private_futex_path cnd_wait requeue",
            "assert_private_futex_path cnd_signal wake",
            "assert_private_futex_path cnd_broadcast wake",
            "mtx_lock lacks its x86 atomic compare-exchange",
            "mtx_unlock lacks its atomic exchange release",
            "C11 plain-sync wrapper crosses an interposable pthread C ABI",
            "mtx_timedlock cnd_timedwait",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {
                "mtx_init",
                "mtx_destroy",
                "mtx_lock",
                "mtx_trylock",
                "mtx_unlock",
                "cnd_init",
                "cnd_destroy",
                "cnd_wait",
                "cnd_signal",
                "cnd_broadcast",
            }
            <= static_exports
        )
        self.assertTrue(
            {"mtx_timedlock", "cnd_timedwait"}.isdisjoint(static_exports)
        )
        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "crabc_mtx_init_signature",
                "crabc_mtx_destroy_signature",
                "crabc_mtx_lock_signature",
                "crabc_mtx_trylock_signature",
                "crabc_mtx_unlock_signature",
                "crabc_cnd_init_signature",
                "crabc_cnd_destroy_signature",
                "crabc_cnd_wait_signature",
                "crabc_cnd_signal_signature",
                "crabc_cnd_broadcast_signature",
                "mtx_init signature",
                "mtx_destroy signature",
                "mtx_lock signature",
                "mtx_trylock signature",
                "mtx_unlock signature",
                "cnd_init signature",
                "cnd_destroy signature",
                "cnd_wait signature",
                "cnd_signal signature",
                "cnd_broadcast signature",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "mtx_init mtx_destroy mtx_lock mtx_trylock mtx_unlock",
            "cnd_init cnd_destroy cnd_wait cnd_signal cnd_broadcast",
            "|mtx_init|mtx_destroy|mtx_lock|mtx_trylock|mtx_unlock",
            "|cnd_init|cnd_destroy|cnd_wait|cnd_signal|cnd_broadcast",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('id = "static-c-c11-plain-sync"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-c11-plain-sync"',
            parity_ledger,
        )
        self.assertIn("run_libc_c11_plain_sync_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_c11_plain_sync.sh", runner
        )
        self.assertIn(
            '    libc-c11-plain-sync)\n        [ "$#" -eq 0 ] || fail "libc-c11-plain-sync takes no arguments"',
            runner,
        )

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
            "non-cancellation",
            "recursive same-control",
            "dynamic/loader TLS",
            "weak `pthread_once` ELF-alias binding",
            "public x86 support",
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
            "pthread_rwlockattr_getpshared|pthread_once",
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
                "tss_get",
                "tss_set",
            },
        )
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
            ("tss_get", "pthread_getspecific(key)"),
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
            "pthread_equal|pthread_key_create|pthread_key_delete|pthread_getspecific|pthread_setspecific",
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

    def test_libc_static_c_abi_pthread_detach_artifact_stays_private_and_prompt(
        self,
    ) -> None:
        """Keep selected detach ownership distinct from pthread/C11 promotion."""

        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        c11_lifecycle = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "c11_thread_lifecycle.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_pthread_detach_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_pthread_detach_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_detach.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn("create/explicit-exit/join/detach worker", static_root)
        for required in (
            "src/thread/pthread_detach.c",
            "enum SelectedWorkerLifecycleState",
            "Joinable",
            "JoinClaimed",
            "Detached",
            "DetachedReclaiming",
            "fn claim_finished_detached_selected_worker",
            "unsafe fn reclaim_withdrawn_selected_worker",
            "fn reap_finished_detached_selected_workers",
            "pub(super) unsafe fn detach_selected_worker",
            "pub unsafe extern \"C\" fn pthread_detach",
            "CLONE_CHILD_CLEARTID",
        ):
            self.assertIn(required, pthread_create_join)
        detach_body = pthread_create_join.split(
            "pub(super) unsafe fn detach_selected_worker", 1
        )[1].split("/// Detach one selected static pthread/C11 worker", 1)[0]
        self.assertIn("SelectedWorkerLifecycleState::Detached", detach_body)
        self.assertIn("claim_selected_worker_by_thread_pointer", detach_body)
        for forbidden in (
            "reap_finished_detached_selected_workers",
            "reclaim_withdrawn_selected_worker",
            "raw_syscall",
            "unmap_worker",
            "static_tls::",
        ):
            self.assertNotIn(forbidden, detach_body)
        self.assertEqual(
            pthread_create_join.count("reap_finished_detached_selected_workers();"),
            2,
        )
        detached_claim = pthread_create_join.split(
            "fn claim_finished_detached_selected_worker", 1
        )[1].split("/// Release mappings for a registry-withdrawn", 1)[0]
        for earlier, later in (
            (
                "SelectedWorkerLifecycleState::Detached.encode()",
                "child_tid.load(Ordering::Acquire)",
            ),
            (
                "child_tid.load(Ordering::Acquire)",
                "SelectedWorkerLifecycleState::DetachedReclaiming.encode()",
            ),
            (
                "SelectedWorkerLifecycleState::DetachedReclaiming.encode()",
                "release_selected_worker_locked",
            ),
        ):
            self.assertLess(detached_claim.index(earlier), detached_claim.index(later))

        self.assertIn("src/thread/thrd_detach.c", c11_lifecycle)
        c11_detach = c11_lifecycle.split("pub unsafe extern \"C\" fn thrd_detach", 1)[1].split(
            "/// End the current selected C11 worker", 1
        )[0]
        self.assertIn("detach_selected_worker", c11_detach)
        self.assertIn("THRD_SUCCESS", c11_detach)
        self.assertIn("THRD_ERROR", c11_detach)

        for required in (
            "run_pthread_round",
            "run_thrd_round",
            "run_double_detach_round",
            "run_thrd_double_detach_round",
            "run_candidate_self_detach_completion_round",
            "run_candidate_null_detach_rejection_round",
            "run_candidate_detach_race_round",
            "run_candidate_join_detach_race_round",
            "run_candidate_join_after_detach_diagnostic",
            "run_detached_completion_reuse_round",
            "pthread_detach(pthread_self())",
            "pthread_join(pthread_thread, 0) == 0",
            "thrd_join(thrd_thread, 0) == thrd_success",
            "CRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertIn("crabc_x86_64_pthread_detach_probe", start)
        self.assertNotIn("arch_prctl", start.lower())
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "run_musl_oracle.sh",
            "run_pthread_c11_header_abi.sh",
            "-pthread",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "pthread_create pthread_exit pthread_join pthread_detach",
            "thrd_create thrd_exit thrd_join thrd_detach",
            "detach must be a prompt state transition, not a wait or reaper",
            "selected detach source must remain state-only without a wait or reaper",
            "selected detached reaping must occur only at later create/join boundaries",
            "CLONE_CHILD_CLEARTID",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertTrue(
            {"pthread_detach", "thrd_detach", "pthread_create", "thrd_create"}
            <= static_exports
        )
        self.assertIn("thrd_yield", static_exports)
        self.assertIn("run_libc_pthread_detach_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pthread_detach.sh", runner
        )
        self.assertIn(
            '    libc-pthread-detach)\n        [ "$#" -eq 0 ] || fail "libc-pthread-detach takes no arguments"',
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

        self.assertIn('#[path = "static_tls.rs"]', static_root)
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
            "__tls_get_addr",
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

    def test_libc_crt_static_tls_handoff_artifact_stays_private_and_composed(self) -> None:
        """Ratchet archive-owned static startup without promoting it to general CRT."""

        rcrt1 = (ROOT / "crt" / "src" / "x86_64_rcrt1.rs").read_text(
            encoding="utf-8"
        )
        startup = (ROOT / "crt" / "src" / "x86_64_startup.rs").read_text(
            encoding="utf-8"
        )
        static_tls = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_tls.rs"
        ).read_text(encoding="utf-8")
        static_startup = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_startup.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_crt_static_tls_probe.c"
        ).read_text(encoding="utf-8")
        peer = (
            ROOT / "compat" / "x86_64" / "libc_crt_static_tls_peer.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_crt_static_tls.sh"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("mod x86_64_static_tls", rcrt1)
        self.assertIn("__crabc_x86_static_tls_bootstrap", startup)
        self.assertIn(
            'core::arch::global_asm!(".hidden __crabc_x86_static_tls_bootstrap");',
            startup,
        )
        bootstrap_call = "if unsafe { __crabc_x86_static_tls_bootstrap(initial_stack) } != 0"
        lifecycle_call = "unsafe {\n        __libc_start_main("
        self.assertIn(bootstrap_call, startup)
        self.assertIn(lifecycle_call, startup)
        self.assertLess(startup.index(bootstrap_call), startup.index(lifecycle_call))
        self.assertIn("rcrt1.o", static_tls)
        self.assertIn("Static Initial TLS v1", static_tls)
        self.assertFalse(
            (ROOT / "compat" / "x86_64" / "libc_crt_static_tls_startup_seam.c").exists()
        )
        for required in (
            "__libc_start_main",
            "static_tls::is_ready()",
            "rtld_fini.is_some()",
            "ATEXIT_CAPACITY: usize = 32",
            "__cxa_atexit",
            "__cxa_finalize",
            "__funcs_on_exit",
            "pub unsafe extern \"C\" fn exit",
            "immediate_termination::_Exit(127)",
        ):
            self.assertIn(required, static_startup)

        for required in (
            "__thread",
            "tls_alignment = 4096",
            "aligned(tls_alignment)",
            "preinit",
            "init",
            "fini",
            "pthread_create",
            "pthread_join",
            "CRABC_CRT_STATIC_TLS_MUSL_REFERENCE",
            "CRABC_CRT_STATIC_TLS_CANDIDATE",
            "atexit",
            "__cxa_atexit",
            "__cxa_finalize",
            "quiet_exit_handler",
        ):
            self.assertIn(required, probe)
        for required in ("__thread", "crabc_crt_peer_initial", "crabc_crt_peer_tbss"):
            self.assertIn(required, peer)
        for required in (
            "rustup run nightly-2026-07-24 rustc",
            "rcrt1.o",
            "crti.o",
            "crtn.o",
            "-C relocation-model=pic",
            "-Ztls-model=initial-exec",
            "GOTTPOFF",
            "candidate_without_archive",
            "__crabc_x86_static_tls_bootstrap",
            "__libc_start_main",
            "PT_PHDR",
            "tls_filesz_offset",
            "PIMBCAF",
            "candidate_startup_disassembly",
            "RELATIVE TLS-bootstrap slot",
            "expect_bootstrap_rejection",
            "CRABC_CRT_STATIC_TLS_CANDIDATE",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertNotIn("startup_seam", artifact_runner)

        self.assertIn('id = "static-c-crt-initial-tls-handoff"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-crt-static-tls"',
            parity_ledger,
        )
        self.assertIn('id = "static-c-crt1-initial-tls-handoff"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-crt1-static-tls"',
            parity_ledger,
        )
        pthread_tls_family = parity_ledger.split(
            '[[family]]\nid = "libc.pthread-tls"', 1
        )[1].split("\n[[family]]", 1)[0]
        self.assertIn('status = "planned"', pthread_tls_family)
        self.assertIn("public x86 support", pthread_tls_family)

    def test_libc_crt1_static_tls_artifact_is_an_owned_et_exec_composition(self) -> None:
        """Ratchet the conventional static start object before sysroot work."""

        crt1 = (ROOT / "crt" / "src" / "x86_64_crt1.rs").read_text(
            encoding="utf-8"
        )
        startup = (ROOT / "crt" / "src" / "x86_64_startup.rs").read_text(
            encoding="utf-8"
        )
        builder = (ROOT / "crt" / "build_x86_64.py").read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_crt1_static_tls.sh"
        ).read_text(encoding="utf-8")
        dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(
            encoding="utf-8"
        )

        for required in (
            ".section .text._start",
            "mov r15, rsp",
            "and rsp, -16",
            "__crabc_x86_64_static_pie_start",
            ".note.GNU-stack",
        ):
            self.assertIn(required, crt1)
        self.assertNotIn("arch_prctl", crt1.lower())
        self.assertNotIn("__crabc_x86_static_tls_bootstrap", crt1)

        self.assertIn("__crabc_x86_static_tls_bootstrap", startup)
        self.assertLess(
            startup.index("if unsafe { __crabc_x86_static_tls_bootstrap(initial_stack) }"),
            startup.index("unsafe {\n        __libc_start_main("),
        )
        for required in (
            '"crt1.o"',
            '"x86_64_crt1.rs"',
            "relocation-model=static",
            "R_X86_64_PLT32",
            "ordinary-static-entry",
        ):
            self.assertIn(required, builder)

        for required in (
            "-static",
            "--no-dynamic-linker",
            "--no-undefined",
            '"$crt_dir/crt1.o"',
            '"$crt_dir/crti.o"',
            '"$crt_dir/crtn.o"',
            "ET_EXEC",
            "PT_TLS",
            "__crabc_x86_static_tls_bootstrap",
            "__libc_start_main",
            "PIMBCAF",
            "expect_bootstrap_rejection",
            "PT_TLS p_filesz",
        ):
            self.assertIn(required, runner)
        self.assertNotIn('"$link_editor" -pie', runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn("libc-crt1-static-tls", dispatcher)

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
            "nightly-2026-07-24",
            "c.*.rcgu.o",
            "stock_compiler_builtins_members_installed",
            "ambient_target_crt_or_library_installed",
            "private-static-pthread-tls-consumer-slice",
            "sysroot.static-tls family completion",
            "sysroot.owned-artifact family completion",
            "staged_output.replace(output)",
        ):
            self.assertIn(required, builder)
        for required in (
            "-nostdinc",
            "audit_header_dependencies",
            "audit_link_trace",
            "without-builtins",
            "/usr/lib/crt1.o",
            "/opt/musl-x86_64/lib/libc.a",
            "libgcc.a",
            "/lib/ld-musl-x86_64.so.1",
            "GNU_RELRO",
            "GNU_STACK",
            "PIMBCAF",
            "expect_bootstrap_rejection",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn("__udivti3", fixture)
        self.assertIn("owned-static-sysroot", dispatcher)
        self.assertIn("still-planned `sysroot.static-tls`", normalized_evidence)
        self.assertIn("still-planned `sysroot.owned-artifact`", normalized_evidence)
        self.assertIn("not public x86-64 support", normalized_evidence)

    def test_libc_static_c_abi_termios_control_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        termios_control = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "termios_control.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "termios_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "termios_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_termios_control_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_termios_control_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_termios_control.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "termios_control.rs"]', static_root)
        for symbol in (
            "fn cfgetispeed(",
            "fn cfgetospeed(",
            "fn cfsetispeed(",
            "fn cfsetospeed(",
            "fn cfsetspeed(",
            "fn cfmakeraw(",
            "fn tcgetattr(",
            "fn tcsetattr(",
            "fn tcflush(",
            "fn tcflow(",
            "fn tcsendbreak(",
            "fn tcgetwinsize(",
            "fn tcsetwinsize(",
        ):
            self.assertIn(symbol, termios_control)
        for required in (
            "struct PublicTermios",
            "struct KernelTermios",
            "struct Winsize",
            "size_of::<PublicTermios>()",
            "size_of::<KernelTermios>()",
            "raw_syscall::SYS_IOCTL",
            "raw_syscall::syscall3(",
            "CBAUD",
            "CIBAUD",
            "TCGETS",
            "TCSETS",
            "TIOCGWINSZ",
            "TIOCSWINSZ",
            "TCSBRK, 0",
        ):
            self.assertIn(required, termios_control)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn ioctl(",
            "fn tcdrain(",
            "fn tcgetsid(",
            "fn tcgetpgrp(",
            "fn tcsetpgrp(",
            "fn openpty(",
            "fn forkpty(",
            "fn login_tty(",
        ):
            self.assertNotIn(forbidden, termios_control)
        self.assertIn('extern "C" {', header_cxx)
        self.assertIn("CBAUD == 0x100f", header_c)
        self.assertIn("B4000000", header_c)
        self.assertIn("PUBLIC_TERMIOS_TAIL_BYTES", probe)
        self.assertIn("public_tail_has_value", probe)
        self.assertIn("tcsetattr(-1, -1, 0)", probe)
        self.assertIn("tcsendbreak(master, 1)", probe)
        self.assertIn("FIXTURE_TIOCGPTPEER", probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_termios_control_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "tcgetattr lacks the fixed TCGETS request",
            "tcsetattr does not map actions onto TCSETS through TCSETSF",
            "tcflush lacks the fixed TCFLSH request",
            "tcflow lacks the fixed TCXONC request",
            "tcsendbreak does not discard duration",
            "tcgetwinsize lacks the fixed TIOCGWINSZ request",
            "tcsetwinsize lacks the fixed TIOCSWINSZ request",
        ):
            self.assertIn(required, artifact_runner)
        # qsort/bsearch are globally selected archive exports from the later
        # callback-algorithms vertical, so this older focused runner may not
        # classify either as an unselected symbol.
        for globally_selected in ("bsearch", "qsort"):
            self.assertIn(globally_selected, static_export_names)
        self.assertNotIn("qsort bsearch", artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "cfgetispeed",
            "cfgetospeed",
            "cfsetispeed",
            "cfsetospeed",
            "cfsetspeed",
            "cfmakeraw",
            "tcgetattr",
            "tcsetattr",
            "tcflush",
            "tcflow",
            "tcsendbreak",
            "tcgetwinsize",
            "tcsetwinsize",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("termios-header-abi", runner)
        self.assertIn("libc-termios-control", runner)

    def test_libc_static_c_abi_ctermid_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ctermid.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ctermid_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_ctermid_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ctermid.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_ctermid_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "ctermid_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "ctermid_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        stdio_header = (ROOT / "include" / "stdio.h").read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "ctermid.rs"]', static_root)
        self.assertIn("ctermid", static_export_names)
        self.assertEqual(
            set(
                re.findall(
                    r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                    source,
                )
            ),
            {"ctermid"},
        )
        for required in (
            "pinned musl 1.2.6 release commit",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/unistd/ctermid.c",
            "CTERMID_PATH: [u8; 9]",
            "does not open",
            "# Safety",
            "destination.add(index).write(CTERMID_PATH[index])",
            "immutable literal pointer",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "termios_control::",
            "getpass::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "L_ctermid == 20",
            "expected_ctermid",
            "ctermid((char *)0)",
            "result != buffer",
            "sizeof(expected_ctermid)",
            "0x5aU",
        ):
            self.assertIn(required, probe)
        for required in ("crabc_x86_64_ctermid_probe", "mov $60, %eax"):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_ctermid_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "archive does not define ctermid",
            "--disassemble=ctermid",
            "ctermid candidate unexpectedly retains TLS",
            "ctermid unexpectedly performs a syscall",
            "candidate selects terminal, filesystem, or string helper behavior",
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "ctermid_header_abi_probe.c",
            "ctermid_header_abi_probe.cpp",
            "Pinned musl 1.2.6",
            "strict ${language}",
            "retained a mangled ctermid reference",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "ctermid declaration",
            "ctermid_must_be_hidden",
            "CRABC_REQUIRE_L_CTERMID_HIDDEN",
            "L_ctermid",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cxx)
        self.assertIn(
            "#define L_ctermid 20\nchar *ctermid(char *);",
            stdio_header,
        )
        self.assertNotIn("#define L_ctermid 20\n\n/* File access */", stdio_header)
        self.assertIn("ctermid-header-abi", runner)
        self.assertIn("libc-ctermid", runner)

    def test_libc_static_c_abi_isatty_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "isatty.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_isatty_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_isatty_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_isatty.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_isatty_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "isatty_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "isatty_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "isatty.rs"]', static_root)
        self.assertIn("isatty", static_export_names)
        self.assertEqual(
            set(
                re.findall(
                    r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                    source,
                )
            ),
            {"isatty"},
        )
        for required in (
            "pinned musl 1.2.6 release commit",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/unistd/isatty.c::isatty",
            "TIOCGWINSZ: i64 = 0x5413",
            "struct KernelWinsize",
            "MaybeUninit::<KernelWinsize>::uninit()",
            "raw_syscall::SYS_IOCTL",
            "c_status(result) + 1",
            "terminal-path or",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "termios_control::",
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_OPENAT",
            "TCGETS",
            "TIOCSPTLCK",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "FIXTURE_EBADF",
            "FIXTURE_ENOTTY",
            "FIXTURE_TIOCGWINSZ",
            "FIXTURE_TIOCSPTLCK",
            "FIXTURE_TIOCGPTPEER",
            "open_pty_pair",
            "isatty(pair.slave) != 1 || errno != 313",
            "isatty(-1) != 0 || errno != FIXTURE_EBADF",
            "isatty(null_fd) != 0 || errno != FIXTURE_ENOTTY",
        ):
            self.assertIn(required, probe)
        for forbidden in ("tcgetattr(", "tcsetattr(", "ttyname(", "getpass("):
            self.assertNotIn(forbidden, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_isatty_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_isatty_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "for symbol in __errno_location isatty",
            "--disassemble=isatty",
            "project-header isatty fixture contract drifted",
            "fixture did not use the project",
            "fixed TIOCGWINSZ request",
            "termios-control request",
            "candidate selects an excluded terminal helper",
            'timeout "$EXECUTION_TIMEOUT"',
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "isatty_header_abi_probe.c",
            "isatty_header_abi_probe.cpp",
            "Pinned musl 1.2.6",
            "unconditional <unistd.h> declaration",
            "retained a mangled isatty reference",
        ):
            self.assertIn(required, header_runner)
        for required in ("isatty declaration", "isatty_function = isatty"):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cxx)
        self.assertIn("isatty-header-abi", runner)
        self.assertIn("libc-isatty", runner)

    def test_libc_static_c_abi_tcgetpgrp_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "tcgetpgrp.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_tcgetpgrp_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_tcgetpgrp_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_tcgetpgrp.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_tcgetpgrp_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "tcgetpgrp_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "tcgetpgrp_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "tcgetpgrp.rs"]', static_root)
        self.assertIn("tcgetpgrp", static_export_names)
        self.assertEqual(
            set(
                re.findall(
                    r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                    source,
                )
            ),
            {"tcgetpgrp"},
        )
        for required in (
            "pinned musl 1.2.6 release commit",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/unistd/tcgetpgrp.c::tcgetpgrp",
            "TIOCGPGRP: i64 = 0x540f",
            "MaybeUninit::<c_int>::uninit()",
            "raw_syscall::SYS_IOCTL",
            "if c_status(result) < 0",
            "neither creates a session",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "termios_control::",
            "raw_syscall::SYS_SETSID",
            "raw_syscall::SYS_FORK",
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_OPENAT",
            "TIOCSCTTY",
            "TIOCSPGRP",
            "TIOCGSID",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "FIXTURE_EBADF",
            "FIXTURE_ENOTTY",
            "FIXTURE_TIOCSCTTY",
            "FIXTURE_TIOCGPGRP",
            "FIXTURE_TIOCSPTLCK",
            "FIXTURE_TIOCGPTPEER",
            "__builtin_types_compatible_p(pid_t, int)",
            "open_pty_pair",
            "child_reads_foreground_group",
            "check_foreground_group",
            "tcgetpgrp(slave) != (pid_t)pid || errno != 313",
            "tcgetpgrp(-1) != -1 || errno != FIXTURE_EBADF",
            "tcgetpgrp(null_fd) != -1 || errno != FIXTURE_ENOTTY",
        ):
            self.assertIn(required, probe)
        for forbidden in (
            "tcsetpgrp(",
            "tcgetsid(",
            "tcgetattr(",
            "tcsetattr(",
            "ttyname(",
            "getpass(",
        ):
            self.assertNotIn(forbidden, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_tcgetpgrp_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_tcgetpgrp_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "for symbol in __errno_location tcgetpgrp",
            "--disassemble=tcgetpgrp",
            "project-header tcgetpgrp fixture contract drifted",
            "fixture did not use the project",
            "fixed TIOCGPGRP request",
            "terminal-control request",
            "candidate selects an excluded session or terminal helper",
            'timeout "$EXECUTION_TIMEOUT"',
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "tcgetpgrp_header_abi_probe.c",
            "tcgetpgrp_header_abi_probe.cpp",
            "Pinned musl 1.2.6",
            "unconditional <unistd.h> declaration",
            "retained a mangled tcgetpgrp reference",
        ):
            self.assertIn(required, header_runner)
        for required in ("tcgetpgrp declaration", "tcgetpgrp_function = tcgetpgrp"):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cxx)
        self.assertIn("tcgetpgrp-header-abi", runner)
        self.assertIn("libc-tcgetpgrp", runner)

    def test_libc_static_c_abi_tcsetpgrp_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "tcsetpgrp.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_tcsetpgrp_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_tcsetpgrp_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_tcsetpgrp.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_tcsetpgrp_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "tcsetpgrp_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "tcsetpgrp_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "tcsetpgrp.rs"]', static_root)
        self.assertIn("tcsetpgrp", static_export_names)
        self.assertEqual(
            set(
                re.findall(
                    r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                    source,
                )
            ),
            {"tcsetpgrp"},
        )
        for required in (
            "pinned musl 1.2.6 release commit",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/unistd/tcsetpgrp.c::tcsetpgrp",
            "TIOCSPGRP: i64 = 0x5410",
            "let mut pgrp_int = pgrp;",
            "raw_syscall::SYS_IOCTL",
            "c_status(result)",
            "neither creates a session",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "termios_control::",
            "raw_syscall::SYS_SETSID",
            "raw_syscall::SYS_FORK",
            "raw_syscall::SYS_SETPGID",
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_OPENAT",
            "TIOCSCTTY",
            "TIOCGPGRP",
            "TIOCGSID",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "FIXTURE_EBADF",
            "FIXTURE_ENOTTY",
            "FIXTURE_TIOCSCTTY",
            "FIXTURE_TIOCGPGRP",
            "FIXTURE_TIOCSPGRP",
            "FIXTURE_TIOCSPTLCK",
            "FIXTURE_TIOCGPTPEER",
            "__builtin_types_compatible_p(pid_t, int)",
            "open_pty_pair",
            "child_assigns_foreground_group",
            "check_foreground_group_assignment",
            "raw_syscall2(SYS_setpgid, member, member)",
            "tcsetpgrp(slave, (pid_t)member) != 0 || errno != 313",
            "foreground_group != (int)member",
            "tcsetpgrp(-1, 0) != -1 || errno != FIXTURE_EBADF",
            "tcsetpgrp(null_fd, 0) != -1 || errno != FIXTURE_ENOTTY",
        ):
            self.assertIn(required, probe)
        for forbidden in (
            "tcgetpgrp(",
            "tcgetsid(",
            "tcgetattr(",
            "tcsetattr(",
            "ttyname(",
            "getpass(",
        ):
            self.assertNotIn(forbidden, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_tcsetpgrp_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_tcsetpgrp_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "for symbol in __errno_location tcsetpgrp",
            "--disassemble=tcsetpgrp",
            "project-header tcsetpgrp fixture contract drifted",
            "fixture did not use the project",
            "fixed TIOCSPGRP request",
            "terminal-control request",
            "candidate selects an excluded session or terminal helper",
            'timeout "$EXECUTION_TIMEOUT"',
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "tcsetpgrp_header_abi_probe.c",
            "tcsetpgrp_header_abi_probe.cpp",
            "Pinned musl 1.2.6",
            "unconditional <unistd.h> declaration",
            "retained a mangled tcsetpgrp reference",
        ):
            self.assertIn(required, header_runner)
        for required in ("tcsetpgrp declaration", "tcsetpgrp_function = tcsetpgrp"):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cxx)
        self.assertIn("tcsetpgrp-header-abi", runner)
        self.assertIn("libc-tcsetpgrp", runner)

    def test_libc_static_c_abi_getpass_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "getpass.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_getpass_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_getpass_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_getpass.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_getpass_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "getpass_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "getpass_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "getpass.rs"]', static_root)
        self.assertIn("getpass", static_export_names)
        self.assertEqual(
            set(
                re.findall(
                    r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                    source,
                )
            ),
            {"getpass"},
        )
        for required in (
            "pinned musl 1.2.6 release commit",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/legacy/getpass.c",
            "Source-function mapping: musl `getpass` -> `getpass.rs::getpass`",
            "struct PublicTermios",
            "PASSWORD_CAPACITY: usize = 128",
            "O_RDWR",
            "O_NOCTTY",
            "O_CLOEXEC",
            "TCSAFLUSH",
            "TCSBRK",
            "drain_terminal_output",
            "termios_control::tcgetattr",
            "termios_control::tcsetattr",
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_READ",
            "raw_syscall::SYS_WRITE",
            "raw_syscall::SYS_CLOSE",
            "create a Rust secret type",
            "secret-memory ownership",
            "initial `tcgetattr` failure returns null",
            "a null prompt writes no bytes",
            "cleanup preserves a raw read error",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "fn ioctl(",
            'pub unsafe extern "C" fn tcdrain',
            "forkpty(",
            "openpty(",
            "login_tty(",
            "vhangup(",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "check_no_controlling_tty",
            "FIXTURE_ENXIO",
            "check_interactive_tty",
            "FIXTURE_TIOCSCTTY",
            "FIXTURE_TIOCGPTPEER",
            "c_string_equals",
            "FIXTURE_PASSWORD_BYTES",
            "bytes_contain",
            "raw_syscall4(SYS_openat",
            "getpass(NULL) != NULL || errno != FIXTURE_ENXIO",
            "second != first",
            "FIXTURE_PASSWORD_BYTES - 1",
            "!bytes_equal(&before, &after, sizeof(before))",
        ):
            self.assertIn(required, probe)
        for forbidden in ("openpty(", "forkpty(", "login_tty(", "vhangup("):
            self.assertNotIn(forbidden, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_getpass_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_getpass_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "for symbol in __errno_location getpass",
            "for unselected in cuserid getusershell",
            "--disassemble=getpass",
            "Linux x86-64 open syscall 2",
            "fixed private TCSBRK drain request",
            "candidate selects an account or login helper",
            "forkpty|openpty|login_tty|vhangup|TIOCGPTPEER",
            'timeout "$EXECUTION_TIMEOUT"',
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "getpass_header_abi_probe.c",
            "getpass_header_abi_probe.cpp",
            "Pinned musl 1.2.6",
            "getpass outside GNU/BSD selection",
            "retained a mangled getpass reference",
        ):
            self.assertIn(required, header_runner)
        for required in ("getpass declaration", "getpass_must_be_hidden"):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cxx)
        self.assertIn("getpass-header-abi", runner)
        self.assertIn("libc-getpass", runner)

    def test_libc_static_c_abi_mktemp_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        source = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "mktemp.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_mktemp_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_mktemp_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_mktemp.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_mktemp_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "mktemp_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "mktemp_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "mktemp.rs"]', static_root)
        self.assertIn("mktemp", static_export_names)
        self.assertEqual(
            set(
                re.findall(
                    r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
                    source,
                )
            ),
            {"mktemp"},
        )
        for required in (
            "pinned musl 1.2.6 release commit",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/temp/mktemp.c::mktemp",
            "src/temp/__randname.c::__randname",
            "TEMPLATE_SUFFIX_BYTES: usize = 6",
            "MAX_ATTEMPTS: usize = 100",
            "CLOCK_REALTIME",
            "struct Timespec",
            "struct KernelStatScratch",
            "size_of::<KernelStatScratch>() == 144",
            "raw_syscall::SYS_CLOCK_GETTIME",
            "raw_syscall::SYS_GETTID",
            "raw_syscall::SYS_NEWFSTATAT",
            "wrapping_mul(65_537)",
            "random >>= 5",
            "if error != ENOENT",
            "errno::set_errno(EEXIST)",
            "inherently racy",
            "does not create, open, reserve, unlink",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_OPENAT",
            "raw_syscall::SYS_GETRANDOM",
            "raw_syscall::SYS_UNLINK",
            "raw_syscall::SYS_UNLINKAT",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "FIXTURE_ENOENT",
            "FIXTURE_EINVAL",
            "FIXTURE_ELOOP",
            "FIXTURE_STAT_BYTES = 144",
            "has_musl_randname_alphabet",
            "path_is_absent",
            "mktemp(invalid) != invalid || invalid[0] != '\\0' || errno != EINVAL",
            "mktemp(valid) != valid || errno != ENOENT",
            "SYS_symlinkat",
            "mktemp(loop_template) != loop_template || loop_template[0] != '\\0'",
            "errno != ELOOP",
            "crabc_x86_64_mktemp_probe",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_mktemp_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_mktemp_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "for symbol in __errno_location mktemp",
            "--disassemble=mktemp",
            "for word in 0xe4 0xba 0x106",
            "excluded temporary or handle API",
            "excluded entropy or authority API",
            'timeout "$EXECUTION_TIMEOUT"',
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "mktemp_header_abi_probe.c",
            "mktemp_header_abi_probe.cpp",
            "Pinned musl 1.2.6",
            "mktemp outside GNU/BSD selection",
            "retained a mangled mktemp reference",
        ):
            self.assertIn(required, header_runner)
        for required in ("mktemp declaration", "mktemp_must_be_hidden"):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cxx)
        self.assertIn("mktemp-header-abi", runner)
        self.assertIn("libc-mktemp", runner)

    def test_libc_static_c_abi_process_context_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        process_context = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_context.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_process_context_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_process_context_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_process_context.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "process_context.rs"]', static_root)
        for symbol in (
            "fn getpid(",
            "fn getppid(",
            "fn getuid(",
            "fn getgid(",
            "fn geteuid(",
            "fn getegid(",
            "fn umask(",
            "fn setsid(",
            "fn setpgid(",
            "fn getpgid(",
            "fn getsid(",
            "fn getpgrp(",
            "fn setpgrp(",
        ):
            self.assertIn(symbol, process_context)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/getpid.c",
            "src/unistd/setpgid.c",
            "src/stat/umask.c",
            "raw_syscall::SYS_GETPID",
            "raw_syscall::SYS_UMASK",
            "raw_syscall::SYS_SETSID",
            "raw_syscall::SYS_SETPGID",
            "raw_syscall::SYS_GETPGID",
            "raw_syscall::SYS_GETSID",
            "c_status(result)",
        ):
            self.assertIn(required, process_context)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn fork(",
            "fn wait(",
            "fn waitpid(",
            "fn waitid(",
            "fn execve(",
            "fn kill(",
            "fn raise(",
            "fn gettid(",
        ):
            self.assertNotIn(forbidden, process_context)
        self.assertIn("SYS_fork == 57", probe)
        self.assertIn("SYS_wait4 == 61", probe)
        self.assertIn("SYS_exit == 60", probe)
        self.assertIn("check_failure_translation", probe)
        self.assertIn("check_umask_exchange", probe)
        self.assertIn("child_setpgrp_case", probe)
        self.assertIn("child_setpgid_case", probe)
        self.assertIn("child_setsid_case", probe)
        self.assertIn("raw_syscall4", probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_process_context_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall getpid 27",
            "assert_named_syscall getppid 6e",
            "assert_named_syscall getuid 66",
            "assert_named_syscall getgid 68",
            "assert_named_syscall geteuid 6b",
            "assert_named_syscall getegid 6c",
            "assert_named_syscall umask 5f",
            "assert_named_syscall setsid 70",
            "assert_named_syscall setpgid 6d",
            "assert_named_syscall getpgid 79",
            "assert_named_syscall getsid 7c",
            "assert_named_syscall getpgrp 79",
            "setpgrp does not derive its legacy alias from setpgid(0, 0)",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "getpid",
            "getppid",
            "getuid",
            "getgid",
            "geteuid",
            "getegid",
            "umask",
            "setsid",
            "setpgid",
            "getpgid",
            "getsid",
            "getpgrp",
            "setpgrp",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-process-context", runner)

    def test_libc_static_c_abi_environment_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        startup = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_startup.rs"
        ).read_text(encoding="utf-8")
        environment = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "environment.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_environment_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_environment_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_environment.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        structure = (ROOT / "scripts" / "check_structure.py").read_text(
            encoding="utf-8"
        )
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "environment.rs"]', static_root)
        self.assertIn(
            'Path("libc/src/c_abi/x86_64/environment.rs")', structure
        )
        self.assertIn("environment::install_initial(vectors.envp)", startup)
        for required in (
            "ENVIRONMENT_ENTRY_CAPACITY: usize = 128",
            "ENVIRONMENT_STORAGE_BYTES: usize = 16 * 1024",
            ".set environ, __environ",
            ".set _environ, __environ",
            ".set ___environ, __environ",
            "pub unsafe extern \"C\" fn getenv",
            "pub unsafe extern \"C\" fn setenv",
            "pub unsafe extern \"C\" fn putenv",
            "pub unsafe extern \"C\" fn unsetenv",
            "pub unsafe extern \"C\" fn clearenv",
            "putenv(\"NAME\")",
            "ENVIRONMENT_LOOKUP_LIMIT",
            "1,048,576",
            "secure_getenv",
            "16 KiB private byte arena",
            "caller-owned `putenv` strings",
            "fork recovery",
        ):
            self.assertIn(required, environment)
        self.assertNotIn("alloc::", environment)
        self.assertNotIn("crabc_core", environment)
        self.assertNotIn("secure_getenv(", environment)
        for required in (
            "aliases_match",
            "check_startup_environment",
            "check_initial_and_mutation",
            "check_clear_and_direct_assignment",
            "check_fixed_capacity",
            "check_fixed_storage",
            "check_lookup_limit",
            "check_nonreclaiming_storage",
            "CRABC_ENVIRONMENT_FREESTANDING",
            "ENVIRONMENT_ENTRY_CAPACITY = 128",
            "ENVIRONMENT_STORAGE_BYTES = 16 * 1024",
            "ENVIRONMENT_LOOKUP_LIMIT = 1 << 20",
            "overfull_environment",
            "lookup_limit_environment",
            'getenv("CRABC_X86_INITIAL")',
            "putenv(remove_duplicate)",
            "borrowed[7] = 'B'",
            "setenv(\"EXTRA\", \"value\", 1)",
            "setenv(\"E127\", \"replacement\", 1)",
            "unsetenv(\"E127\")",
            "aliases_match(overfull_environment)",
            "setenv(\"TOO_LARGE\", too_large, 1)",
            "setenv(\"X\", \"\", 1)",
            "setenv(\"Y\", \"\", 1)",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertIn("__libc_start_main", start)
        self.assertIn("main", start)
        self.assertNotIn("ARCH_SET_FS", start)
        self.assertNotIn("%fs:0", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "symbol_value",
            "is not an ELF alias of __environ",
            "environment object does not have x86 LP64 size/type/binding",
            "environment alias is not a weak x86 LP64 object",
            "__secure_getenv __putenv __env_rm_add",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "env -i CRABC_X86_INITIAL=entry",
            "bootstrap_call_line",
            "startup_call_line",
            "TLS bootstrap does not precede libc startup",
            "non-reclaiming arena unexpectedly accepted a new value",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "__environ",
            "environ",
            "_environ",
            "___environ",
            "getenv",
            "setenv",
            "putenv",
            "unsetenv",
            "clearenv",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-environment", runner)

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

    def test_libc_static_c_abi_descriptor_io_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        descriptor_io = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_io.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_io_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_io_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_descriptor_io.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "descriptor_io.rs"]', static_root)
        for symbol in (
            "fn close(",
            "fn read(",
            "fn write(",
            "fn pread(",
            "fn pwrite(",
            "fn lseek(",
            "fn ftruncate(",
            "fn fsync(",
            "fn fdatasync(",
            "fn dup(",
            "fn dup2(",
            "fn dup3(",
            "fn pipe(",
            "fn pipe2(",
        ):
            self.assertIn(symbol, descriptor_io)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/pwrite.c",
            "struct IoVec",
            "raw_syscall::SYS_PWRITEV2",
            "raw_syscall::SYS_PWRITE64",
            "raw_syscall::SYS_FCNTL",
            "RWF_NOAPPEND",
            "if offset == -1 { -2 } else { offset }",
            "raw_syscall::SYS_DUP2",
            "raw_syscall::SYS_DUP3",
            "if result != -EBUSY",
            "if result == -EINTR",
            "raw_syscall::SYS_PIPE",
            "raw_syscall::SYS_PIPE2",
            "c_ssize_status(result)",
            "c_off_status(result)",
        ):
            self.assertIn(required, descriptor_io)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn open(",
            "fn openat(",
            "fn fcntl(",
            "fn readv(",
            "fn writev(",
            "fn preadv(",
            "fn pwritev(",
            "fn socket(",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, descriptor_io)
        for required in (
            "raw_memfd_create",
            "raw_fcntl",
            "check_transfer_position_truncate_and_sync",
            "check_pwrite_append_boundary",
            "check_dup_and_close",
            "check_dup2_and_dup3",
            "check_pipe_and_pipe2",
            "O_APPEND",
            "#include <sys/mman.h>",
            "MFD_CLOEXEC",
            'raw_memfd_create("crabc-dup-close", MFD_CLOEXEC)',
            "raw_fcntl(file_descriptor, F_GETFD, 0) != FD_CLOEXEC",
            "raw_fcntl(duplicate, F_GETFD, 0) != 0",
            "O_CLOEXEC | O_NONBLOCK",
            "pwrite(file_descriptor, \"X\", 1, -1)",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_descriptor_io_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall close 3",
            "assert_named_syscall pread 11",
            "assert_named_syscall dup3 124",
            "assert_named_syscall pipe2 125",
            "for syscall_word in 148 12 48; do",
            "sys/mman.h",
            "assert_ebusy_retry dup2",
            "assert_ebusy_retry dup3",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "close",
            "read",
            "write",
            "pread",
            "pwrite",
            "lseek",
            "ftruncate",
            "fsync",
            "fdatasync",
            "dup",
            "dup2",
            "dup3",
            "pipe",
            "pipe2",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-descriptor-io", runner)

    def test_libc_static_c_abi_descriptor_lifecycle_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        stat_compat = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stat_compat.rs"
        ).read_text(encoding="utf-8")
        descriptor_entry = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_entry.rs"
        ).read_text(encoding="utf-8")
        descriptor_control = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_control.rs"
        ).read_text(encoding="utf-8")
        descriptor_io = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_io.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_lifecycle_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_lifecycle_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_descriptor_lifecycle.sh"
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

        for module in (
            '#[path = "stat_compat.rs"]',
            '#[path = "descriptor_entry.rs"]',
            '#[path = "descriptor_control.rs"]',
            '#[path = "descriptor_io.rs"]',
        ):
            self.assertIn(module, static_root)
        for symbol in ("fn fstat(", "fn fstatat("):
            self.assertIn(symbol, stat_compat)
        for symbol in ("fn open(", "fn openat(", "fn creat("):
            self.assertIn(symbol, descriptor_entry)
        self.assertIn("fcntl_no_argument", descriptor_control)
        for symbol in ("fn read(", "fn pread(", "fn dup3("):
            self.assertIn(symbol, descriptor_io)
        for required in (
            "#include <errno.h>",
            "#include <fcntl.h>",
            "#include <stddef.h>",
            "#include <sys/stat.h>",
            "#include <unistd.h>",
            "fstat declaration",
            "fstatat declaration",
            "O_CLOEXEC",
            "O_LARGEFILE",
            "ftruncate(primary, 6)",
            "fstatat(directory_fd, \"primary\"",
            "dup3(duplicate, duplicate, O_CLOEXEC)",
            "close(-1)",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_descriptor_lifecycle_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_fcntl_header_abi.sh",
            "run_stat_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_fcntl_no_argument_path",
            "assert_fcntl_scalar_path",
            "assert_named_syscall fstat 5",
            "assert_named_syscall fstatat 106",
            "assert_named_syscall dup3 124",
            "assert_named_syscall fsync 4a",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "open",
            "openat",
            "creat",
            "fcntl",
            "read",
            "write",
            "pread",
            "pwrite",
            "lseek",
            "fstat",
            "fstatat",
            "dup",
            "dup2",
            "dup3",
            "ftruncate",
            "fsync",
            "fdatasync",
            "close",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-descriptor-lifecycle"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-descriptor-lifecycle"',
            parity_ledger,
        )
        self.assertIn("run_libc_descriptor_lifecycle_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_descriptor_lifecycle.sh", runner
        )
        self.assertIn(
            '    libc-descriptor-lifecycle)\n        [ "$#" -eq 0 ] || fail "libc-descriptor-lifecycle takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_process_resources_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        process_resources = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_resources.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_process_resources_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_process_resources_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_process_resources.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "process_resources.rs"]', static_root)
        for symbol in (
            "fn getrlimit(",
            "fn setrlimit(",
            "fn prlimit(",
            "fn getrusage(",
            "fn getpriority(",
            "fn setpriority(",
            "fn nice(",
        ):
            self.assertIn(symbol, process_resources)
        for required in (
            "musl 1.2.6 release commit",
            "src/misc/getrlimit.c",
            "src/misc/getrusage.c",
            "src/linux/prlimit.c",
            "src/unistd/nice.c",
            "struct Rlimit",
            "struct Rusage",
            "size_of::<Rusage>() == 272",
            "offset_of!(Rusage, reserved) == 144",
            "raw_syscall::SYS_PRLIMIT64",
            "raw_syscall::SYS_GETRUSAGE",
            "raw_syscall::SYS_GETPRIORITY",
            "raw_syscall::SYS_SETPRIORITY",
            "errno::get_errno()",
            "EACCES",
            "EPERM",
        ):
            self.assertIn(required, process_resources)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn times(",
            "fn sched_",
            "fn fork(",
            "fn wait",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, process_resources)
        for required in (
            "check_limit_queries",
            "child_limit_transaction",
            "check_live_child_prlimit",
            "check_rusage",
            "check_priority_queries",
            "child_priority_and_nice",
            "raw_prlimit",
            "RUSAGE_CHILDREN",
            "reserved_tail_is_unchanged",
            "raw_result == -EACCES",
            "nice(-1) != -1 || errno != EPERM",
            "nice(0) != 19 || errno != EINVAL",
            "#include <sys/resource.h>",
            "#include <sys/time.h>",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_process_resources_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall getrlimit 12e",
            "assert_named_syscall getrusage 62",
            "assert_named_syscall getpriority 8c",
            "assert_named_syscall setpriority 8d",
            "prlimit lacks the x86 r10 fourth-argument path",
            "nice lacks the EACCES compatibility branch",
            "sys/resource.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "getrlimit",
            "setrlimit",
            "prlimit",
            "getrusage",
            "getpriority",
            "setpriority",
            "nice",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertNotIn("prlimit64", static_export_names)
        self.assertIn("libc-process-resources", runner)

    def test_libc_static_c_abi_readiness_signal_waits_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        readiness_waits = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "readiness_waits.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_readiness_waits_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_readiness_waits_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_readiness_waits.sh"
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

        self.assertIn('#[path = "readiness_waits.rs"]', static_root)
        for symbol in (
            "fn poll(",
            "fn ppoll(",
            "fn select(",
            "fn pselect(",
            "fn pause()",
            "fn sigsuspend(",
        ):
            self.assertIn(symbol, readiness_waits)
        for required in (
            "musl 1.2.6 release commit",
            "src/select/poll.c",
            "src/select/ppoll.c",
            "src/select/select.c",
            "src/select/pselect.c",
            "src/unistd/pause.c",
            "src/signal/sigsuspend.c",
            "struct PollFd",
            "struct FdSet",
            "struct Timeval",
            "struct Timespec",
            "struct PublicSigSet",
            "struct PselectMaskArgument",
            "size_of::<PollFd>() == 8",
            "size_of::<FdSet>() == 128",
            "size_of::<PublicSigSet>() == 128",
            "raw_syscall::SYS_POLL",
            "raw_syscall::SYS_PPOLL",
            "raw_syscall::SYS_SELECT",
            "raw_syscall::SYS_PSELECT6",
            "raw_syscall::SYS_PAUSE",
            "raw_syscall::SYS_RT_SIGSUSPEND",
            "raw_syscall::syscall3(",
            "raw_syscall::syscall5(",
            "raw_syscall::syscall6(",
            "raw_syscall::syscall0(",
            "raw_syscall::syscall2(",
            "KERNEL_SIGSET_SIZE",
        ):
            self.assertIn(required, readiness_waits)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn epoll",
            "fn eventfd",
            "fn open(",
            "fn fcntl(",
            "fn readv(",
            "fn writev(",
            "fn sigtimedwait(",
            "fn sigwaitinfo(",
            "fn sigwait(",
            "fn sigaltstack(",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, readiness_waits)
        for required in (
            "#include <poll.h>",
            "#include <sys/select.h>",
            "sizeof(struct pollfd) == 8",
            "FD_SETSIZE == 1024",
            "sizeof(sigset_t) == 128",
            "check_poll_and_ppoll",
            "check_select_and_pselect",
            "check_atomic_signal_waits",
            "raw_tgkill_self",
            "retain_pause_without_a_racy_runtime_wait",
            "CRABC_READINESS_WAITS_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_readiness_waits_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall poll 7",
            "assert_named_syscall ppoll 10f",
            "assert_named_syscall select 17",
            "assert_named_syscall pselect 10e",
            "assert_named_syscall pause 22",
            "assert_named_syscall sigsuspend 82",
            "pselect lacks the x86 ${register} argument path",
            "sigsuspend lacks Linux's eight-byte kernel signal-set size",
            "does not exercise epoll/eventfd",
            "separate static artifact owns those archive exports",
            "pthread_sigmask",
            "sys/select.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertNotIn("epoll_create", artifact_runner)
        for symbol in ("poll", "ppoll", "select", "pselect", "pause", "sigsuspend"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-readiness-signal-waits"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-readiness-waits"',
            parity_ledger,
        )
        self.assertIn("libc-readiness-waits", runner)

    def test_socket_header_ipv6_macro_regression_stays_native(self) -> None:
        header = (ROOT / "include" / "netinet" / "in.h").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "socket_header_ipv6_macro_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_socket_header_abi.sh"
        ).read_text(encoding="utf-8")

        for macro in (
            "IN6_IS_ADDR_UNSPECIFIED",
            "IN6_IS_ADDR_LOOPBACK",
            "IN6_IS_ADDR_MULTICAST",
            "IN6_IS_ADDR_LINKLOCAL",
            "IN6_IS_ADDR_SITELOCAL",
            "IN6_IS_ADDR_V4MAPPED",
            "IN6_IS_ADDR_V4COMPAT",
            "IN6_IS_ADDR_MC_NODELOCAL",
            "IN6_IS_ADDR_MC_LINKLOCAL",
            "IN6_IS_ADDR_MC_SITELOCAL",
            "IN6_IS_ADDR_MC_ORGLOCAL",
            "IN6_IS_ADDR_MC_GLOBAL",
        ):
            self.assertIn(macro, header)
            self.assertIn(macro, probe)
        self.assertIn("__IN6_ADDR_BYTE", header)
        self.assertNotIn("#define IN6_IS_ADDR_UNSPECIFIED(a) 0", header)
        for required in (
            'extern "C" {',
            "uint8_t __s6_addr[16]",
            "uint16_t __s6_addr16[8]",
            "uint32_t __s6_addr32[4]",
            "__in6_union",
            "extern const struct in6_addr in6addr_any",
            "extern const struct in6_addr in6addr_loopback",
        ):
            self.assertIn(required, header)
        for required in (
            "socket_header_ipv6_macro_probe.c",
            '"$ORACLE_CC" -std=c11 "$ipv6_macro_probe"',
            '"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" "$ipv6_macro_probe"',
            '"$musl_ipv6_macro"',
            '"$project_ipv6_macro"',
            "check_cxx_in6addr_any_linkage",
            "check_cxx_in6addr_loopback_linkage",
            "in6addr_any",
            "in6addr_loopback",
        ):
            self.assertIn(required, runner)

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

    def test_libc_static_c_abi_socket_transport_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        socket_transport = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "socket_transport.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_socket_transport_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_socket_transport_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_socket_transport.sh"
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

        self.assertIn('#[path = "socket_transport.rs"]', static_root)
        for symbol in (
            "fn socket(",
            "fn socketpair(",
            "fn bind(",
            "fn listen(",
            "fn accept(",
            "fn accept4(",
            "fn connect(",
            "fn send(",
            "fn recv(",
            "fn sendto(",
            "fn recvfrom(",
            "fn shutdown(",
            "fn getsockname(",
            "fn getpeername(",
        ):
            self.assertIn(symbol, socket_transport)
        for required in (
            "musl 1.2.6 release commit",
            "src/network/socket.c",
            "src/network/socketpair.c",
            "src/network/bind.c",
            "src/network/listen.c",
            "src/network/accept.c",
            "src/network/accept4.c",
            "src/network/connect.c",
            "src/network/send.c",
            "src/network/recv.c",
            "src/network/sendto.c",
            "src/network/recvfrom.c",
            "src/network/shutdown.c",
            "src/network/getsockname.c",
            "src/network/getpeername.c",
            "raw_syscall::SYS_SOCKET",
            "raw_syscall::SYS_SOCKETPAIR",
            "raw_syscall::SYS_BIND",
            "raw_syscall::SYS_LISTEN",
            "raw_syscall::SYS_ACCEPT",
            "raw_syscall::SYS_ACCEPT4",
            "raw_syscall::SYS_CONNECT",
            "raw_syscall::SYS_SENDTO",
            "raw_syscall::SYS_RECVFROM",
            "raw_syscall::SYS_SHUTDOWN",
            "raw_syscall::SYS_GETSOCKNAME",
            "raw_syscall::SYS_GETPEERNAME",
            "c_status(result)",
            "c_ssize_status(result)",
        ):
            self.assertIn(required, socket_transport)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn setsockopt(",
            "fn getsockopt(",
            "fn sendmsg(",
            "fn recvmsg(",
            "fn sendmmsg(",
            "fn recvmmsg(",
            "fn poll(",
            "fn pthread_",
            "pthread_cancel",
        ):
            self.assertNotIn(forbidden, socket_transport)
        for required in (
            "#include <sys/socket.h>",
            "check_unix_pair",
            "check_loopback_datagram",
            "check_loopback_stream",
            "check_error_translation",
            "accept4",
            "sendto",
            "recvfrom",
            "CRABC_SOCKET_TRANSPORT_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_socket_transport_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall socket 29",
            "assert_named_syscall socketpair 35",
            "assert_named_syscall bind 31",
            "assert_named_syscall listen 32",
            "assert_named_syscall accept 2b",
            "assert_named_syscall accept4 120",
            "assert_named_syscall connect 2a",
            "assert_named_syscall sendto 2c",
            "assert_named_syscall recvfrom 2d",
            "assert_named_syscall shutdown 30",
            "assert_named_syscall getsockname 33",
            "assert_named_syscall getpeername 34",
            "sys/socket.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn(
            "for unselected in if_nametoindex if_indextoname",
            artifact_runner,
        )
        for required in (
            "socket-transport candidate unexpectedly pulls interface discovery",
            "if_nametoindex|if_indextoname|if_nameindex|if_freenameindex|getifaddrs|freeifaddrs",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "socket",
            "socketpair",
            "bind",
            "listen",
            "accept",
            "accept4",
            "connect",
            "send",
            "recv",
            "sendto",
            "recvfrom",
            "shutdown",
            "getsockname",
            "getpeername",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-socket-transport"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-socket-transport"',
            parity_ledger,
        )
        self.assertIn("libc-socket-transport", runner)

    def test_libc_static_c_abi_interface_discovery_stays_resolver_free(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "interface_discovery.rs"
        ).read_text(encoding="utf-8")
        shared = (ROOT / "libc" / "src" / "network_interface_exports.rs").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "libc_interface_discovery_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_interface_discovery_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_interface_discovery.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "interface_discovery.rs"]', static_root)
        for required in (
            "outside\n//! the x86 numeric-netdb boundary",
            "private result-storage seams",
            "SYS_IOCTL: i64 = 16",
            "SYS_SENDTO: i64 = 44",
            "SYS_RECVFROM: i64 = 45",
            "InterfaceAllocationHeader",
            "include!(\"../../network_interface_exports.rs\")",
        ):
            self.assertIn(required, implementation)
        for required in (
            "fn if_nametoindex",
            "fn if_indextoname",
            "fn if_nameindex",
            "fn if_freenameindex",
            "fn getifaddrs",
            "fn freeifaddrs",
            "CABI_SIOCGIFINDEX",
            "CABI_RTM_GETLINK",
            "CABI_RTM_GETADDR",
            "cabi_interface_set_errno",
            "cabi_interface_errno",
        ):
            self.assertIn(required, shared)
        for forbidden in (
            "res_query",
            "getaddrinfo",
            "gethostbyname",
            "getnetbyname",
            "ERRNO =",
        ):
            self.assertNotIn(forbidden, shared)
        for required in (
            "#include <ifaddrs.h>",
            "#include <net/if.h>",
            "#include <netpacket/packet.h>",
            "name_index_cases",
            "list_is_valid",
            "ifaddrs_cases",
            "AF_PACKET",
            "CRABC_INTERFACE_DISCOVERY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_interface_discovery_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "resolver configuration, DNS, or network-database behavior",
            "candidate exposes a general C allocator",
            "0x29 0x2c 0x2d 0x10",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        for symbol in (
            "if_nametoindex",
            "if_indextoname",
            "if_nameindex",
            "if_freenameindex",
            "getifaddrs",
            "freeifaddrs",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-interface-discovery"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-interface-discovery"',
            parity_ledger,
        )
        self.assertIn("run_in_network_none_container", runner)
        self.assertIn("libc-interface-discovery", runner)

    def test_libc_static_c_abi_system_observation_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        system_observation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_observation.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_system_observation_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_system_observation_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_system_observation.sh"
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

        self.assertIn('#[path = "system_observation.rs"]', static_root)
        for symbol in ("fn uname(", "fn sysinfo("):
            self.assertIn(symbol, system_observation)
        for required in (
            "musl 1.2.6 release commit",
            "src/misc/uname.c",
            "src/linux/sysinfo.c",
            "struct UtsName",
            "struct SysInfo",
            "KERNEL_SYSINFO_BYTES",
            "size_of::<UtsName>() == 390",
            "size_of::<SysInfo>() == 368",
            "offset_of!(SysInfo, compatibility_tail) == 108",
            "raw_syscall::SYS_UNAME",
            "raw_syscall::SYS_SYSINFO",
            "raw_syscall::syscall1(",
            "c_status(result)",
        ):
            self.assertIn(required, system_observation)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn sysconf(",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, system_observation)
        for required in (
            "#include <sys/sysinfo.h>",
            "#include <sys/utsname.h>",
            "sizeof(struct utsname) == 390",
            "sizeof(struct sysinfo) == 368",
            "SYS_uname == 63 && SYS_sysinfo == 99",
            "check_null_pointer_errors",
            "check_uname_record",
            "check_sysinfo_record_and_tail",
            "SYSINFO_RESERVED_KERNEL_BYTES",
            "CRABC_SYSTEM_OBSERVATION_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_system_observation_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall uname 3f",
            "assert_named_syscall sysinfo 63",
            "sys/utsname.h",
            "sys/sysinfo.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("uname", "sysinfo"):
            self.assertIn(symbol, static_export_names)
        # These belong to the separately selected UTS-identity artifact. The
        # system-observation leaf remains narrow through its own exact source
        # export set, rather than by treating shared-archive exports as if
        # they all belonged to this older artifact.
        for separately_selected_uts_symbol in (
            "gethostname",
            "sethostname",
            "getdomainname",
            "setdomainname",
        ):
            self.assertIn(separately_selected_uts_symbol, static_export_names)
        self.assertIn('id = "static-c-system-observation"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-system-observation"',
            parity_ledger,
        )
        self.assertIn("libc-system-observation", runner)

    def test_libc_static_c_abi_system_information_artifact_stays_narrow(
        self,
    ) -> None:
        """The selected CPU/page helpers retain musl's bounded raw semantics."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        system_information = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_information.rs"
        ).read_text(encoding="utf-8")
        system_observation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_observation.rs"
        ).read_text(encoding="utf-8")
        system_configuration = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_configuration.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_system_information_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_system_information_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_system_information.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "system_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "system_header_abi_probe.cpp"
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

        self.assertIn('#[path = "system_information.rs"]', static_root)
        for symbol in (
            "fn get_nprocs_conf()",
            "fn get_nprocs()",
            "fn get_phys_pages()",
            "fn get_avphys_pages()",
        ):
            self.assertIn(symbol, system_information)
        for required in (
            "musl 1.2.6 release commit",
            "src/conf/legacy.c",
            "src/conf/sysconf.c",
            "CPUSET_BYTES: usize = 128",
            "mask[0] = 1",
            "raw_syscall::SYS_SCHED_GETAFFINITY",
            "raw_syscall::syscall3(",
            "count_ones()",
            "system_observation::sysinfo_raw",
            "system_configuration::X86_64_LINUX_PAGE_SIZE",
            "wrapping_add",
            "wrapping_mul",
            "c_long::MAX",
        ):
            self.assertIn(required, system_information)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn getloadavg(",
            "fn sysconf(",
            "alloc::",
        ):
            self.assertNotIn(forbidden, system_information)
        for required in (
            "pub(super) unsafe fn sysinfo_raw",
            "pub(super) total_ram",
            "pub(super) free_ram",
            "pub(super) buffer_ram",
            "pub(super) memory_unit",
        ):
            self.assertIn(required, system_observation)
        self.assertIn("pub(super) const X86_64_LINUX_PAGE_SIZE", system_configuration)

        for header_probe in (header_c, header_cxx):
            for signature in (
                "get_nprocs_conf_signature",
                "get_nprocs_signature",
                "get_phys_pages_signature",
                "get_avphys_pages_signature",
            ):
                self.assertIn(signature, header_probe)
        for required in (
            "#include <errno.h>",
            "#include <sys/prctl.h>",
            "SYS_sched_getaffinity == 204",
            "SYS_sysinfo == 99",
            "check_stale_errno_and_live_values",
            "check_affinity_error_fallback_in_child",
            "CRABC_SECCOMP_RET_ERRNO",
            "PR_SET_NO_NEW_PRIVS",
            "CRABC_SYSTEM_INFORMATION_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("crabc_x86_64_system_information_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall get_nprocs cc",
            "assert_named_syscall get_phys_pages 63",
            "sched_getaffinity",
            "sys/sysinfo.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "get_nprocs_conf",
            "get_nprocs",
            "get_phys_pages",
            "get_avphys_pages",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-system-information"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-system-information"',
            parity_ledger,
        )
        self.assertIn("run_libc_system_information_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_system_information.sh", runner
        )
        self.assertIn(
            '    libc-system-information)\n        [ "$#" -eq 0 ] || fail "libc-system-information takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_uts_identity_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        system_observation = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "system_observation.rs"
        ).read_text(encoding="utf-8")
        uts_identity = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "uts_identity.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_uts_identity_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_uts_identity_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_uts_identity.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "system_observation.rs"]', static_root)
        self.assertIn('#[path = "uts_identity.rs"]', static_root)
        for required in (
            "pub(super) struct UtsName",
            "pub(super) const UTS_FIELD_BYTES: usize = 65",
            "pub(super) unsafe fn uname_raw",
        ):
            self.assertIn(required, system_observation)
        for symbol in (
            "fn gethostname(",
            "fn sethostname(",
            "fn getdomainname(",
            "fn setdomainname(",
        ):
            self.assertIn(symbol, uts_identity)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/gethostname.c",
            "src/linux/sethostname.c",
            "src/misc/getdomainname.c",
            "src/misc/setdomainname.c",
            "system_observation::UtsName",
            "system_observation::UTS_FIELD_BYTES",
            "system_observation::uname_raw",
            "MaybeUninit",
            "raw_syscall::SYS_SETHOSTNAME",
            "raw_syscall::SYS_SETDOMAINNAME",
            "raw_syscall::syscall2(",
            "errno::set_errno(EINVAL)",
            "c_status(result)",
        ):
            self.assertIn(required, uts_identity)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn gethostid(",
            "fn sysconf(",
            "fn fork(",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, uts_identity)
        for required in (
            "#define _GNU_SOURCE 1",
            "#include <sys/utsname.h>",
            "#include <unistd.h>",
            "SYS_uname == 63 && SYS_sethostname == 170",
            "SYS_setdomainname == 171",
            "check_selected_identity_setup",
            "check_hostname_copy_contract",
            "check_domain_copy_contract",
            "check_setter_error_contract_and_stability",
            "gethostname(NULL, 0)",
            "getdomainname(NULL, 0)",
            "sethostname(NULL, 1)",
            "setdomainname(NULL, 1)",
            "CRABC_UTS_IDENTITY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_uts_identity_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "run_in_fresh_uts_namespace",
            "unshare --uts --fork",
            "assert_named_syscall gethostname 3f",
            "assert_named_syscall getdomainname 3f",
            "assert_named_syscall sethostname aa",
            "assert_named_syscall setdomainname ab",
            "sys/utsname.h",
            "unistd.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "gethostname",
            "sethostname",
            "getdomainname",
            "setdomainname",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-uts-identity", runner)

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
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("getrandom", "getentropy"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-random-entropy"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-random-entropy"',
            parity_ledger,
        )
        self.assertIn("libc-random-entropy", runner)

    def test_libc_static_c_abi_legacy_memory_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "legacy_memory.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_legacy_memory_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_legacy_memory_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_legacy_memory.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_byte_strings_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "legacy_memory.rs"]', static_root)
        for required in (
            "musl 1.2.6",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/string/bcopy.c",
            "src/string/bzero.c",
            ".global bcopy",
            ".global bzero",
            "xchg rdi, rsi",
            "mov rdx, rsi",
            "xor esi, esi",
            "jmp memmove",
            "jmp memset",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
            "memccpy",
            "mempcpy",
            "explicit_bzero",
        ):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "bcopy_signature",
            "bzero_signature",
            "_Static_assert",
            "check_bcopy_overlap",
            "source += 5",
            "destination += 3",
            "check_bzero_ranges",
            "CRABC_LEGACY_MEMORY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in ("crabc_x86_64_legacy_memory_probe", "mov $60, %eax"):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_byte_strings_header_abi.sh",
            "bcopy.lo",
            "bzero.lo",
            "archive_member_for_symbol",
            "legacy adapter object export surface drifted",
            "legacy adapter unexpectedly performs a syscall",
            "legacy adapter must tail-transfer into the bulk-memory owner",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "candidate retains a PLT",
            "unowned allocator or memory utility",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_REQUIRE_BCOPY",
            "CRABC_REQUIRE_BZERO",
            "bsd_definitions=(-D_BSD_SOURCE -DCRABC_EXPECT_ALIASES)",
            "BSD bcopy/bzero",
        ):
            self.assertIn(required, header_runner)
        for symbol in ("bcopy", "bzero"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-legacy-memory"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-legacy-memory"',
            parity_ledger,
        )
        self.assertIn("libc-legacy-memory", runner)

    def test_libc_static_c_abi_memccpy_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memccpy.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_memccpy_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_memccpy_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_memccpy.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "memccpy_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "memccpy_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_memccpy_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "memccpy.rs"]', static_root)
        for required in (
            "musl 1.2.6",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/string/memccpy.c",
            "const WORD_SIZE",
            "const ALIGN",
            "const ONES",
            "const HIGHS",
            "const fn has_zero_byte",
            "wrapping_mul",
            "pub unsafe extern \"C\" fn memccpy",
            "restrict contract",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
            "use super::memory",
            "memory::",
        ):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "memccpy_signature",
            "_Static_assert",
            "requested_targets",
            "source_offset <= CRABC_MEMCCPY_MAX_OFFSET",
            "destination_offset <= CRABC_MEMCCPY_MAX_OFFSET",
            "0x100",
            "0x1ff",
            "CRABC_MEMCCPY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in ("crabc_x86_64_memccpy_probe", "mov $60, %eax"):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_memccpy_header_abi.sh",
            "memccpy.lo",
            "archive_member_for_symbol",
            "memccpy object export surface drifted",
            "memccpy object unexpectedly depends on another symbol",
            "memccpy object unexpectedly performs a syscall",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "candidate retains a PLT",
            "unowned allocator, runtime, or memory utility",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "memccpy_signature",
            "CRABC_EXPECT_MEMCCPY",
            "CRABC_REQUIRE_MEMCCPY_HIDDEN",
        ):
            self.assertIn(required, header_c)
        for required in ("memccpy_signature", "CRABC_EXPECT_MEMCCPY"):
            self.assertIn(required, header_cxx)
        for required in (
            "xopen_definitions=(-D_XOPEN_SOURCE=700 -DCRABC_EXPECT_MEMCCPY)",
            "gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_MEMCCPY)",
            "bsd_definitions=(-D_BSD_SOURCE -DCRABC_EXPECT_MEMCCPY)",
            "strict/POSIX C",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("memccpy", static_export_names)
        self.assertIn('id = "static-c-memccpy"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-memccpy"',
            parity_ledger,
        )
        self.assertIn("memccpy-header-abi", runner)
        self.assertIn("libc-memccpy", runner)

    def test_libc_static_c_abi_mempcpy_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "mempcpy.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_mempcpy_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_mempcpy_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_mempcpy.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "mempcpy_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "mempcpy_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_mempcpy_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "mempcpy.rs"]', static_root)
        for required in (
            "musl 1.2.6",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/string/mempcpy.c",
            ".global mempcpy",
            "push rbx",
            "lea rbx, [rdi + rdx]",
            "call memcpy",
            "mov rax, rbx",
            "pop rbx",
            "restrict",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
            "memccpy",
            "explicit_bzero",
        ):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "mempcpy_signature",
            "_Static_assert",
            "source_offset <= CRABC_MEMPCPY_MAX_OFFSET",
            "destination_offset <= CRABC_MEMPCPY_MAX_OFFSET",
            "lengths[]",
            "CRABC_MEMPCPY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in ("crabc_x86_64_mempcpy_probe", "mov $60, %eax"):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_mempcpy_header_abi.sh",
            "mempcpy.lo",
            "archive_member_for_symbol",
            "mempcpy adapter object export surface drifted",
            "mempcpy adapter dependency closure drifted",
            "mempcpy adapter lacks direct memcpy relocation",
            "SysV return preservation",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "candidate retains a PLT",
            "unowned allocator, runtime, or memory utility",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "mempcpy_signature",
            "CRABC_EXPECT_MEMPCPY",
            "CRABC_REQUIRE_MEMPCPY_HIDDEN",
        ):
            self.assertIn(required, header_c)
        for required in ("mempcpy_signature", "CRABC_EXPECT_MEMPCPY"):
            self.assertIn(required, header_cxx)
        for required in (
            "default_definitions=()",
            "xopen_definitions=(-D_XOPEN_SOURCE=700)",
            "bsd_definitions=(-D_BSD_SOURCE)",
            "gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_MEMPCPY)",
            "default/strict/POSIX/XOPEN/BSD C",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("mempcpy", static_export_names)
        self.assertIn('id = "static-c-mempcpy"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-mempcpy"',
            parity_ledger,
        )
        self.assertIn("mempcpy-header-abi", runner)
        self.assertIn("libc-mempcpy", runner)

    def test_libc_static_c_abi_strsep_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "strsep.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_strsep_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_strsep_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_strsep.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "strsep_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "strsep_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_strsep_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "strsep.rs"]', static_root)
        for required in (
            "musl 1.2.6",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "src/string/strsep.c",
            "pub unsafe extern \"C\" fn strsep",
            "caller-owned `char **` state slot",
            "stringp.write(null_mut())",
            "current.write(0)",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
            "malloc",
            "strcspn",
            "strtok",
            "strtok_r",
            "use super::",
        ):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "strsep_signature",
            "_Static_assert",
            "check_basic_sequence",
            "check_delimiter_set_sequence",
            "check_no_separator_cases",
            "check_unsigned_delimiter_byte",
            "check_null_state_value",
            "CRABC_STRSEP_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in ("crabc_x86_64_strsep_probe", "mov $60, %eax"):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_strsep_header_abi.sh",
            "strsep.lo",
            "archive_member_for_symbol",
            "strsep object export surface drifted",
            "strsep object unexpectedly depends on another symbol",
            "strsep object unexpectedly performs a syscall",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "candidate retains a PLT",
            "unowned allocator, runtime, or string utility",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "strsep_signature",
            "CRABC_EXPECT_STRSEP",
            "CRABC_REQUIRE_STRSEP_HIDDEN",
        ):
            self.assertIn(required, header_c)
        for required in ("strsep_signature", "CRABC_EXPECT_STRSEP"):
            self.assertIn(required, header_cxx)
        for required in (
            "default_definitions=()",
            "xopen_definitions=(-D_XOPEN_SOURCE=700)",
            "gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_STRSEP)",
            "bsd_definitions=(-D_BSD_SOURCE -DCRABC_EXPECT_STRSEP)",
            "default/strict/POSIX/XOPEN C",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("strsep", static_export_names)
        self.assertIn('id = "static-c-strsep"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-strsep"', parity_ledger
        )
        self.assertIn("strsep-header-abi", runner)
        self.assertIn("libc-strsep", runner)

    def test_libc_static_c_abi_memory_search_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        memory_search = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_search.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_memory_search_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_memory_search.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "memory_search.rs"]', static_root)
        for symbol in ("fn memchr(", "fn memmem(", "fn memrchr("):
            self.assertIn(symbol, memory_search)
        for required in (
            "musl 1.2.6 release commit",
            "src/string/memchr.c",
            "src/string/memmem.c",
            "src/string/memrchr.c",
            "__memrchr",
            "stateless",
            "allocation-free",
        ):
            self.assertIn(required, memory_search)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn free(",
            "fn __memrchr(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, memory_search)
        for required in (
            "#include <string.h>",
            "memchr",
            "memmem",
            "memrchr",
            "CRABC_MEMORY_SEARCH_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate unexpectedly selects TLS",
            "candidate retains a dynamic TLS model",
            "string.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("memchr", "memmem", "memrchr"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-memory-search"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-memory-search"',
            parity_ledger,
        )
        self.assertIn("libc-memory-search", runner)

    def test_libc_static_c_abi_string_copy_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        string_copy = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "string_copy.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_string_copy_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_string_copy.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_string_copy_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "string_copy.rs"]', static_root)
        for symbol in (
            "fn stpcpy(",
            "fn stpncpy(",
            "fn strcpy(",
            "fn strncpy(",
            "fn strcat(",
            "fn strncat(",
            "fn strlcpy(",
            "fn strlcat(",
        ):
            self.assertIn(symbol, string_copy)
        for required in (
            "musl 1.2.6 release commit",
            "src/string/stpcpy.c",
            "src/string/stpncpy.c",
            "src/string/strcpy.c",
            "src/string/strncpy.c",
            "src/string/strcat.c",
            "src/string/strncat.c",
            "src/string/strlcpy.c",
            "src/string/strlcat.c",
            "__stpcpy",
            "__stpncpy",
            "stateless",
            "allocation-free",
            "scalar fallback",
        ):
            self.assertIn(required, string_copy)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn free(",
            "fn __stpcpy(",
            "fn __stpncpy(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, string_copy)
        for required in (
            "#include <string.h>",
            "stpcpy",
            "stpncpy",
            "strcpy",
            "strncpy",
            "strcat",
            "strncat",
            "strlcpy",
            "strlcat",
            "CRABC_STRING_COPY_FREESTANDING",
            "check_page_edges",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate unexpectedly selects TLS",
            "candidate retains a dynamic TLS model",
            "__stpcpy",
            "__stpncpy",
            "string.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_POSIX_COPY",
            "CRABC_EXPECT_GNU_COPY",
            "CRABC_REQUIRE_POSIX_COPY_HIDDEN",
            "CRABC_REQUIRE_GNU_COPY_HIDDEN",
            "-std=c++17",
            "string.h",
        ):
            self.assertIn(required, header_runner)
        for symbol in (
            "stpcpy",
            "stpncpy",
            "strcpy",
            "strncpy",
            "strcat",
            "strncat",
            "strlcpy",
            "strlcat",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-string-copy"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-string-copy"',
            parity_ledger,
        )
        self.assertIn("libc-string-copy", runner)

    def test_libc_static_c_abi_error_strings_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "error_strings.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_error_strings_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_error_strings.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_error_strings_header_abi.sh"
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
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "error_strings.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "src/errno/__strerror.h",
            "src/errno/strerror.c",
            "src/string/strerror_r.c",
            "No error information",
            "weak_alias(strerror_r, __xpg_strerror_r)",
            ".weak __xpg_strerror_r",
            ".set __xpg_strerror_r, strerror_r",
            'fn strerror(',
            'fn strerror_r(',
            "capacity.wrapping_sub(1)",
            "immutable",
            "allocation-free",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "static mut",
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn free(",
            "fn abort(",
            "fn syscall(",
            "fn strerror_l(",
            "fn __strerror_l(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "#include <string.h>",
            "__xpg_strerror_r",
            "strerror-domain-fnv1a64",
            "error <= 134",
            "strerror_r(ENOENT, (char *)0, 0)",
            "strerror_r != __xpg_strerror_r",
            "CRABC_ERROR_STRINGS_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "run_error_strings_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib",
            "-Wl,--no-undefined",
            "candidate unexpectedly selects TLS",
            "same-address strerror_r alias",
            "candidate output differs from pinned musl",
            "strerror-domain-fnv1a64",
            "malloc|free|syscall",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_STRERROR_R",
            "CRABC_REQUIRE_STRERROR_R_HIDDEN",
            "-std=c++17",
            "C++ probe does not retain C linkage",
            "string.h",
        ):
            self.assertIn(required, header_runner)
        for symbol in ("strerror", "strerror_r", "__xpg_strerror_r"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-error-strings"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-error-strings"',
            parity_ledger,
        )
        self.assertIn("error-strings-header-abi", runner)
        self.assertIn("libc-error-strings", runner)

    def test_libc_static_c_abi_strsignal_slice_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "strsignal.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_strsignal_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_strsignal.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_strsignal_header_abi.sh"
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
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "strsignal.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "src/string/strsignal.c",
            "SIGHUP..SIGSYS == 1..31",
            "MAX_SIGNAL_NUMBER: c_int = 64",
            "RT32",
            "RT64",
            "LCTRANS_CUR",
            'fn strsignal(',
            "immutable",
            "general diagnostics",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "static mut",
            "crabc_core",
            "crabc_mimalloc",
            "alloc::",
            "fn strerror(",
            "fn strerror_l(",
            "fn psignal(",
            "fn abort(",
            "fn syscall(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "#include <string.h>",
            "strsignal-domain-fnv1a64",
            "signal_number = -4",
            "RT32",
            "RT64",
            "strsignal(-1) != strsignal(0)",
            "CRABC_STRSIGNAL_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "run_strsignal_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,--no-undefined",
            "candidate unexpectedly selects TLS",
            "candidate retains a dynamic TLS model",
            "candidate output differs from pinned musl",
            "strerror(_r|_l)?",
            "strsignal-domain-fnv1a64",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_STRSIGNAL",
            "CRABC_REQUIRE_STRSIGNAL_HIDDEN",
            "-std=c++17",
            "C++ probe does not retain C linkage",
            "string.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("strsignal", static_export_names)
        self.assertIn('id = "error.strsignal"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-strsignal"', parity_ledger
        )
        self.assertIn("strsignal-header-abi", runner)
        self.assertIn("libc-strsignal", runner)

    def test_libc_static_c_abi_ctype_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        ctype = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ctype.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ctype_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ctype.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_ctype_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = (
            "isalnum",
            "isalpha",
            "isblank",
            "iscntrl",
            "isdigit",
            "isgraph",
            "islower",
            "isprint",
            "ispunct",
            "isspace",
            "isupper",
            "isxdigit",
            "tolower",
            "toupper",
            "isascii",
            "toascii",
        )
        self.assertIn('#[path = "ctype.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", ctype)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/ctype/isalnum.c",
            "src/ctype/isalpha.c",
            "src/ctype/isblank.c",
            "src/ctype/iscntrl.c",
            "src/ctype/isdigit.c",
            "src/ctype/isgraph.c",
            "src/ctype/islower.c",
            "src/ctype/isprint.c",
            "src/ctype/ispunct.c",
            "src/ctype/isspace.c",
            "src/ctype/isupper.c",
            "src/ctype/isxdigit.c",
            "src/ctype/tolower.c",
            "src/ctype/toupper.c",
            "src/ctype/isascii.c",
            "src/ctype/toascii.c",
            "fixed C locale",
            "stateless",
            "allocation-free",
            "EOF",
        ):
            self.assertIn(required, ctype)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn free(",
            "_l(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, ctype)
        for required in (
            "#include <ctype.h>",
            "ctype_fn",
            "value = -1",
            "value <= 255",
            "isascii",
            "toascii",
            "CRABC_CTYPE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains TLS",
            "ctype.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_EXTENDED_CTYPE",
            "CRABC_REQUIRE_EXTENDED_CTYPE_HIDDEN",
            "-std=c++17",
            "ctype.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('id = "static-c-ctype"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-ctype"',
            parity_ledger,
        )
        self.assertIn("libc-ctype", runner)

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
            "#define REG_NEWLINE 4",
            "#define REG_NOSUB 8",
            "#define REG_ENOSYS -1",
        ):
            self.assertIn(required, header)
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

    def test_libc_static_c_abi_integer_arithmetic_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        integer_arithmetic = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "integer_arithmetic.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_integer_arithmetic_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_integer_arithmetic.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_integer_arithmetic_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("abs", "labs", "llabs", "div", "ldiv", "lldiv")
        self.assertIn('#[path = "integer_arithmetic.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", integer_arithmetic)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/abs.c",
            "src/stdlib/labs.c",
            "src/stdlib/llabs.c",
            "src/stdlib/div.c",
            "src/stdlib/ldiv.c",
            "src/stdlib/lldiv.c",
            "stateless",
            "allocation-free",
            "wrapping_neg",
            "native signed `idiv`",
            "undefined",
            "core::arch::asm!",
        ):
            self.assertIn(required, integer_arithmetic)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn rand(",
            "wrapping_div",
            "wrapping_rem",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, integer_arithmetic)
        for required in (
            "#include <stdlib.h>",
            "abs_fn",
            "div_fn",
            "defined domain",
            "-2147483647",
            "CRABC_INTEGER_ARITHMETIC_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains TLS",
            "strtoimax",
            "stdlib.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "stdlib.h",
            "features.h",
            "bits/alltypes.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('id = "static-c-integer-arithmetic"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-integer-arithmetic"',
            parity_ledger,
        )
        self.assertIn("libc-integer-arithmetic", runner)

    def test_libc_static_c_abi_integer_parse_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        integer_parse = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "integer_parse.rs"
        ).read_text(encoding="utf-8")
        inttypes_header = (ROOT / "include" / "inttypes.h").read_text(
            encoding="utf-8"
        )
        stdlib_header = (ROOT / "include" / "stdlib.h").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "libc_integer_parse_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_integer_parse.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_integer_parse_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "integer_parse_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "integer_parse_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = (
            "atoi",
            "atol",
            "atoll",
            "strtol",
            "strtoul",
            "strtoll",
            "strtoull",
            "strtoimax",
            "strtoumax",
        )
        self.assertIn('#[path = "integer_parse.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", integer_parse)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/strtol.c",
            "src/internal/intscan.c",
            "src/internal/intscan.h",
            "src/internal/shgetc.c",
            "src/internal/shgetc.h",
            "src/stdlib/atoi.c",
            "src/stdlib/atol.c",
            "src/stdlib/atoll.c",
            "base validation",
            "end-pointer",
            "EINVAL",
            "ERANGE",
            "defined-input",
            "allocation-free",
            "LP64",
        ):
            self.assertIn(required, integer_parse)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn strtod(",
            "fn wcstol(",
            "fn malloc(",
            "raw_syscall::",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, integer_parse)
        for required in (
            "#include <errno.h>",
            "#include <inttypes.h>",
            "#include <limits.h>",
            "#include <stdlib.h>",
            "expect_long",
            "expect_ulong",
            "expect_intmax",
            '"0x"',
            "CRABC_INTEGER_PARSE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate lacks the selected errno TLS segment",
            "__strtol_internal",
            "strtoimax",
            "stdlib.h",
            "run_integer_parse_header_abi.sh",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "inttypes.h",
            "stdlib.h",
            "bits/alltypes.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("strtoimax_signature", header_c_probe)
        self.assertIn("decltype(&strtol)", header_cxx_probe)
        self.assertIn('extern "C" {', inttypes_header)
        self.assertIn('extern "C" {', stdlib_header)
        self.assertIn('id = "static-c-integer-parse"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-integer-parse"',
            parity_ledger,
        )
        self.assertIn("integer-parse-header-abi", runner)
        self.assertIn("libc-integer-parse", runner)

    def test_libc_static_c_abi_float_parse_locale_capability_is_closed(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "float_parse.rs"
        ).read_text(encoding="utf-8")
        locale_implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "float_parse_locale.rs"
        ).read_text(encoding="utf-8")
        getsubopt_implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "getsubopt.rs"
        ).read_text(encoding="utf-8")
        locale_aliases = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64"
            / "float_parse_locale_aliases_x86_64.S"
        ).read_text(encoding="utf-8")
        wide_assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64"
            / "float_parse_locale_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        entry_assembly = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "float_parse_musl_entry_x86_64.S"
        ).read_text(encoding="utf-8")
        scanner_assembly = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "float_parse_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        support_assembly = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "float_parse_musl_support_x86_64.S"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_float_parse_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_float_parse.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_float_parse_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "float_parse_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "float_parse_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("strtof", "strtod", "strtold", "atof")
        self.assertIn('#[path = "float_parse.rs"]', static_root)
        self.assertIn('#[path = "float_parse_locale.rs"]', static_root)
        self.assertIn('#[path = "getsubopt.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(symbol, static_export_names)
            self.assertIn(f".globl {symbol}", entry_assembly)
        capability_symbols = (
            "atof", "ecvt", "fcvt", "gcvt", "getsubopt", "strtod",
            "strtod_l", "strtof", "strtof_l", "strtold", "strtold_l",
            "wcstod", "wcstof", "wcstoimax", "wcstol", "wcstold",
            "wcstoll", "wcstoul", "wcstoull", "wcstoumax", "__strtod_l",
            "__strtof_l", "__strtold_l",
        )
        for symbol in capability_symbols:
            self.assertIn(symbol, static_export_names)
            self.assertIn(symbol, probe)
            self.assertIn(symbol, artifact_runner)
        for symbol in ("strtof_l", "strtod_l", "strtold_l"):
            self.assertIn(f".globl {symbol}", locale_aliases)
            self.assertIn(f".weak __{symbol}", locale_aliases)
        for symbol in ("wcstof", "wcstod", "wcstold"):
            self.assertIn(f".globl {symbol}", wide_assembly)
        for required in (
            "src/stdlib/wcstod.c",
            "src/stdlib/wcstol.c",
            "src/stdlib/{ecvt,fcvt,gcvt}.c",
            "src/locale/strtod_l.c",
            "exact binary64-to-decimal",
            "C/POSIX/C.UTF-8",
        ):
            self.assertIn(required, locale_implementation)
        for required in (
            "src/misc/getsubopt.c",
            "State-free Linux/x86-64 C `getsubopt` parser",
            "core::hint::black_box",
            'pub unsafe extern "C" fn getsubopt',
        ):
            self.assertIn(required, getsubopt_implementation)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/strtod.c",
            "src/stdlib/atof.c",
            "src/internal/floatscan.c",
            "src/internal/shgetc.c",
            "scalbnl",
            "fmodl",
            "x87 binary80",
            "pseudo-`FILE`",
            "initial-TLS",
            "rational packer",
        ):
            self.assertIn(required, implementation)
        for required in ("fldt", "fstpt"):
            self.assertIn(required, scanner_assembly)
        self.assertIn("fprem", support_assembly)
        for required in (
            "strtold_fn",
            "long_double_mantissa",
            "long_double_sign_exponent",
            "long_double_underflow_cases",
            "long_double_rounding_cases",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "CRABC_FLOAT_PARSE_FREESTANDING",
            "check_locale_argument_aliases",
            "check_wide_floating_conversions",
            "check_wide_integer_conversions",
            "check_legacy_decimal_conversions",
            "check_getsubopt",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "run_float_parse_header_abi.sh",
            "__strtold_internal",
            "fldt",
            "fstpt",
            "fprem",
            "sprintf",
            "__intscan",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17", "strtof", "strtod", "strtold", "atof", "ecvt",
            "fcvt", "gcvt", "getsubopt", "strtof_l", "wcstod", "wcstoimax",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("crabc_strtold_signature", header_c_probe)
        self.assertIn("crabc_strtold_signature", header_cxx_probe)
        self.assertIn('id = "static-c-float-parse"', parity_ledger)
        self.assertIn('id = "numeric.parse-float-locale"', parity_ledger)
        self.assertIn('capabilities = ["numeric.parse-float-locale"]', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-float-parse"',
            parity_ledger,
        )
        self.assertIn("float-parse-header-abi", runner)
        self.assertIn("libc-float-parse", runner)

    def test_libc_static_c_abi_getsubopt_artifact_stays_state_free(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "getsubopt.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "getsubopt_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "getsubopt_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_getsubopt_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_getsubopt_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_getsubopt.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "getsubopt.rs"]\nmod getsubopt;', static_root)
        for required in (
            "src/misc/getsubopt.c",
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "core::hint::black_box",
            'pub unsafe extern "C" fn getsubopt',
            "NUL-terminated key vector",
            "no storage and reads or writes no errno, TLS",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "static mut",
            "errno::",
            "raw_syscall",
            "getenv",
            "setenv",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, implementation)

        for header_probe in (header_c_probe, header_cxx_probe):
            for required in (
                "getsubopt",
                "char *const *",
                "CRABC_EXPECT_GETSUBOPT",
                "CRABC_REQUIRE_GETSUBOPT_HIDDEN",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "CANDIDATE_CC=/usr/bin/gcc",
            "-nostdinc",
            "-nostdinc++",
            "-D_POSIX_C_SOURCE=200809L",
            "-D_XOPEN_SOURCE=700",
            "-D_GNU_SOURCE",
            "-D_BSD_SOURCE",
            "retain C linkage",
            "escaped its declared roots",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "CRABC_GETSUBOPT_FREESTANDING",
            "check_primary_sequence",
            "check_exact_key_matching",
            "check_interleaved_cursors",
            "check_empty_key",
            "errno = E2BIG",
        ):
            self.assertIn(required, probe)
        for required in (
            "getsubopt.lo",
            "run_getsubopt_header_abi.sh",
            "-nostdlib -static",
            "--no-undefined",
            "candidate unexpectedly selects TLS",
            "call|syscall",
            "strchr strlen strncmp",
            "getenv setenv unsetenv clearenv",
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn("getsubopt", static_exports.splitlines())
        self.assertIn('id = "static-c-getsubopt"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-getsubopt"', parity_ledger
        )
        self.assertIn("getsubopt-header-abi", runner)
        self.assertIn("libc-getsubopt", runner)

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
        self.assertIn('#[path = "stdio_standard.rs"]', static_root)
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

    def test_libc_static_c_abi_stdio_format_scan_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "stdio_format_scan.rs"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_stdio_format_scan_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_stdio_format_scan_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_stdio_format_scan.sh"
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

        symbols = (
            "snprintf", "vsnprintf", "sprintf", "vsprintf", "sscanf", "vsscanf"
        )
        self.assertIn('#[path = "stdio_format_scan.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f'pub unsafe extern "C" fn {symbol}', implementation)
            self.assertIn(symbol, static_export_names)
            self.assertIn(symbol, fixture)
        self.assertEqual(implementation.count("# Safety"), len(symbols))
        for required in (
            "musl 1.2.6 release commit",
            "src/stdio/vfprintf.c",
            "src/internal/intscan.c",
            "The active Linux/AArch64 implementation remains the broader",
            "args.next_arg",
            "zero-capacity",
            "pointer-valued `%p`",
        ):
            self.assertIn(required, implementation)
        self.assertNotIn("src/stdio/printf_core.c", implementation)
        for required in (
            "CRABC_TYPE_IS(__typeof__(&snprintf)",
            "call_vsnprintf",
            "call_vsprintf",
            "call_vsscanf",
            '"%#x|%#.3o|%#.0o|%08.3d"',
            '"ab%hhncd%ln"',
            '"%2147483648d%n"',
            '"0xg"',
            '"0x1", "%2x"',
            '" %Q", "%%%c"',
            '"a", "%2c"',
            "CRABC_STDIO_FORMAT_SCAN_FREESTANDING",
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
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "--no-undefined",
            "R_X86_64_TPOFF",
            "__errno_location",
            "CRABC_STDIO_FORMAT_SCAN_FREESTANDING",
            "timeout --foreground",
            "printf fprintf vprintf vfprintf",
            "args.next_arg",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-stdio-format-scan"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-format-scan"',
            parity_ledger,
        )
        self.assertIn("libc-stdio-format-scan", dispatcher)
        self.assertIn("run_libc_stdio_format_scan.sh", dispatcher)

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
            "b'a' | b'A' if matches!(length, Length::None | Length::L)",
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
            "b'm' if length == Length::None",
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
            "b'm' if length == Length::None",
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
        for symbol in (
            "ferror_unlocked",
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
            "ferror_unlocked clearerr_unlocked",
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

    def test_libc_static_c_abi_stdio_permanent_feof_unlocked_stays_bounded(
        self,
    ) -> None:
        """One GNU/BSD EOF alias remains permanent-stdin observation only."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_feof_unlocked_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_feof_unlocked_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_feof_unlocked_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_feof_unlocked_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_feof_unlocked_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_feof_unlocked.sh"
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

        self.assertIn("feof", exports)
        self.assertIn("feof_unlocked", exports)
        for symbol in (
            "ferror_unlocked",
            "clearerr_unlocked",
            "_IO_feof_unlocked",
        ):
            self.assertNotIn(symbol, exports)
        for required in (
            "src/stdio/feof.c",
            "weak_alias(feof, feof_unlocked)",
            'pub unsafe extern "C" fn feof',
            ".weak feof_unlocked",
            ".set feof_unlocked, feof",
            "F_EOF",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in (
                "feof_unlocked",
                "FILE",
                "_GNU_SOURCE",
                "_BSD_SOURCE",
                "REQUIRE_HIDDEN",
            ):
                self.assertIn(required, probe)
        for required in (
            "c11-gnu",
            "c11-bsd",
            "cxx17-gnu",
            "cxx17-bsd",
            "c11-posix-2008",
            "cxx17-posix-2008",
            "CRABC_STDIO_PERMANENT_FEOF_UNLOCKED_C11_GNU",
            "CRABC_STDIO_PERMANENT_FEOF_UNLOCKED_CXX17_GNU",
            "CRABC_STDIO_PERMANENT_FEOF_UNLOCKED_REQUIRE_HIDDEN",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "assert_hidden",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "feof_unlocked_entry != feof_entry",
            "redirect_empty_input",
            "feof_entry(stdin) != 0 || feof_unlocked_entry(stdin) != 0",
            "fgetc_entry(stdin) != EOF",
            "feof_entry(stdin) == 0 || feof_unlocked_entry(stdin) == 0",
            "CRABC_STDIO_PERMANENT_FEOF_UNLOCKED_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_feof_unlocked_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_feof_unlocked_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong feof",
            "weak feof_unlocked",
            "assert_weak_same_address_alias",
            "weak_alias(feof, feof_unlocked)",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "feof unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-feof-unlocked"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-feof-unlocked"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-feof-unlocked-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-feof-unlocked", dispatcher)
        self.assertIn("run_stdio_permanent_feof_unlocked_header_abi.sh", dispatcher)
        self.assertIn("run_libc_stdio_permanent_feof_unlocked.sh", dispatcher)

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

    def test_libc_static_c_abi_stdio_permanent_fileno_unlocked_stays_bounded(
        self,
    ) -> None:
        """The GNU/BSD weak alias remains permanent-stream-only evidence."""
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stdio_standard.rs"
        ).read_text(encoding="utf-8")
        c_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fileno_unlocked_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        cxx_header_probe = (
            ROOT / "compat" / "x86_64" /
            "stdio_permanent_fileno_unlocked_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_stdio_permanent_fileno_unlocked_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fileno_unlocked_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" /
            "libc_stdio_permanent_fileno_unlocked_start.S"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_stdio_permanent_fileno_unlocked.sh"
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
            "weak_alias(fileno, fileno_unlocked)",
            'pub unsafe extern "C" fn fileno',
            ".weak fileno_unlocked",
            ".set fileno_unlocked, fileno",
        ):
            self.assertIn(required, implementation)
        for probe in (c_header_probe, cxx_header_probe):
            for required in (
                "fileno_unlocked",
                "FILE",
                "_GNU_SOURCE",
                "_BSD_SOURCE",
                "REQUIRE_HIDDEN",
            ):
                self.assertIn(required, probe)
        for required in (
            "c11-gnu",
            "c11-bsd",
            "cxx17-gnu",
            "cxx17-bsd",
            "c11-posix-2008",
            "cxx17-posix-2008",
            "CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_C11_GNU",
            "CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_CXX17_GNU",
            "CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_REQUIRE_HIDDEN",
            "-nostdinc",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "assert_hidden",
            "run_musl_oracle.sh",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "fileno_unlocked_entry != fileno_entry",
            "fileno_entry(stdin) != 0 || fileno_unlocked_entry(stdin) != 0",
            "fileno_entry(stdout) != 1 || fileno_unlocked_entry(stdout) != 1",
            "fileno_entry(stderr) != 2 || fileno_unlocked_entry(stderr) != 2",
            "CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for forbidden in ("fgetc", "fputc", "dup", "pipe", "fopen", "tmpfile"):
            self.assertNotIn(forbidden, fixture)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_stdio_permanent_fileno_unlocked_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        for required in (
            "ORACLE_ARCHIVE",
            "run_stdio_permanent_fileno_unlocked_header_abi.sh",
            "STATIC_C_ABI_EXPORTS",
            "strong fileno",
            "weak fileno_unlocked",
            "assert_weak_same_address_alias",
            "weak_alias(fileno, fileno_unlocked)",
            "-nostdlib -static",
            "dynamic TLS model",
            "unowned runtime dependency",
            "fileno unexpectedly contains a syscall path",
            "__crabc_x86_static_tls_bootstrap",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertIn('id = "static-c-stdio-permanent-fileno-unlocked"', ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-stdio-permanent-fileno-unlocked"',
            ledger,
        )
        self.assertIn("does not select `stdio.stream-io`", ledger)
        self.assertIn("stdio-permanent-fileno-unlocked-header-abi", dispatcher)
        self.assertIn("libc-stdio-permanent-fileno-unlocked", dispatcher)
        self.assertIn("run_stdio_permanent_fileno_unlocked_header_abi.sh", dispatcher)
        self.assertIn("run_libc_stdio_permanent_fileno_unlocked.sh", dispatcher)

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

    def test_libc_static_c_abi_intmax_arithmetic_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        intmax_arithmetic = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "intmax_arithmetic.rs"
        ).read_text(encoding="utf-8")
        inttypes_header = (ROOT / "include" / "inttypes.h").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "libc_intmax_arithmetic_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_intmax_arithmetic.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_intmax_arithmetic_header_abi.sh"
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

        symbols = ("imaxabs", "imaxdiv")
        self.assertIn('#[path = "intmax_arithmetic.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", intmax_arithmetic)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/imaxabs.c",
            "src/stdlib/imaxdiv.c",
            "intmax_t",
            "imaxdiv_t",
            "stateless",
            "allocation-free",
            "wrapping_neg",
            "native signed `idiv`",
            "undefined",
            "core::arch::asm!",
        ):
            self.assertIn(required, intmax_arithmetic)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn strtoimax(",
            "wrapping_div",
            "wrapping_rem",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, intmax_arithmetic)
        for required in (
            "#include <inttypes.h>",
            "imaxabs_fn",
            "imaxdiv_fn",
            "defined domain",
            "INTMAX_MIN + INTMAX_C(1)",
            "CRABC_INTMAX_ARITHMETIC_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains TLS",
            "strtoimax",
            "inttypes.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "inttypes.h",
            "bits/alltypes.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('extern "C" {', inttypes_header)
        self.assertIn('id = "static-c-intmax-arithmetic"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-intmax-arithmetic"',
            parity_ledger,
        )
        self.assertIn("libc-intmax-arithmetic", runner)

    def test_libc_static_c_abi_credential_observation_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        credential_observation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "credential_observation.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_credential_observation_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_credential_observation.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_credential_observation_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" /
            "credential_observation_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" /
            "credential_observation_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("getgroups", "getresuid", "getresgid")
        self.assertIn('#[path = "credential_observation.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", credential_observation)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/getgroups.c",
            "src/misc/getresuid.c",
            "src/misc/getresgid.c",
            "SYS_GETGROUPS",
            "SYS_GETRESUID",
            "SYS_GETRESGID",
            "query-then-fill race",
            "c_status",
            "EFAULT",
        ):
            self.assertIn(required, credential_observation)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn setgroups(",
            "fn setresuid(",
            "fn setresgid(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, credential_observation)
        for required in (
            "GROUP_CAPTURE_ATTEMPTS",
            "GROUP_STORAGE_CAPACITY",
            "getgroups(-1",
            "count-to-fill window",
            "SYS_getresuid",
            "SYS_getresgid",
            "EFAULT",
            "CRABC_CREDENTIAL_OBSERVATION_FREESTANDING",
            "check_user_partial_fault_order",
            "check_group_partial_fault_order",
            "for (valid_mask = 0; valid_mask < 8; ++valid_mask)",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains a dynamic TLS model",
            "getgroups getresuid getresgid",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_GNU_CREDENTIAL_OBSERVATION",
            "CRABC_REQUIRE_GETRES_HIDDEN",
            "-U_GNU_SOURCE",
            "-std=c++17",
            "nm --undefined-only",
            "unistd.h",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("getresuid_must_be_hidden", header_probe)
            self.assertIn("getresgid_must_be_hidden", header_probe)
        self.assertIn('id = "static-c-credential-observation"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-credential-observation"',
            parity_ledger,
        )
        self.assertIn("libc-credential-observation", runner)

    def test_libc_static_c_abi_login_name_stays_environment_borrowed(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        login_name = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "login_name.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_login_name_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_login_name.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_login_name_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (
            ROOT / "compat" / "x86_64" / "parity.toml"
        ).read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "login_name.rs"]', static_root)
        for symbol in ("getlogin", "getlogin_r"):
            self.assertIn(f"fn {symbol}(", login_name)
            self.assertIn(symbol, static_exports)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/getlogin.c",
            "src/unistd/getlogin_r.c",
            "LOGNAME\\0",
            "environment::getenv",
            "ENXIO",
            "ERANGE",
            "copy_nonoverlapping",
            "borrowed pointer",
            "Caller-coordinated environment writers",
            "does not set `errno`",
        ):
            self.assertIn(required, login_name)
        for forbidden in (
            "alloc::", "crabc_core", "crabc_mimalloc", "getpwnam",
            "getpwuid", "getutent", "getutxent", "ttyname", "fn fork(", "fn execve(",
        ):
            self.assertNotIn(forbidden, login_name)
        for required in (
            "check_absent_logname",
            "check_borrowed_putenv_value",
            "check_first_match_and_copy",
            "check_empty_logname",
            "getlogin() != borrowed + 8",
            "getlogin_r(buffer, 5) != ERANGE",
            "getlogin_r(buffer, 6) != 0",
            "getlogin_r(0, 0) != ERANGE",
            "CRABC_LOGIN_NAME_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "-nostdlib -static",
            "static_c_abi_exports.txt",
            "getlogin getlogin_r",
            "exact crate-owned login-name exports",
            "candidate retains a dynamic TLS model",
            "unowned runtime dependency",
            "passwd/utmp/terminal dependency",
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "strict", "posix", "gnu", "bsd", "-std=c++17",
            "nm --undefined-only", "unistd.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('id = "static-c-login-name"', parity_ledger)
        self.assertIn("login-name-header-abi", runner)
        self.assertIn("libc-login-name", runner)

    def test_libc_static_c_abi_child_reaping_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        child_reaping = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "child_reaping.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_child_reaping_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_child_reaping.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_child_reaping_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" /
            "child_reaping_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" /
            "child_reaping_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("wait", "waitpid", "waitid")
        self.assertIn('#[path = "child_reaping.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", child_reaping)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/process/wait.c",
            "src/process/waitpid.c",
            "src/process/waitid.c",
            "SYS_WAIT4",
            "SYS_WAITID",
            "cancellation",
            "WNOWAIT",
            "initial-TLS",
        ):
            self.assertIn(required, child_reaping)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn fork(",
            "fn execve(",
            "fn wait4(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, child_reaping)
        for required in (
            "raw_clone_sigchld",
            "returns_twice",
            "WNOHANG",
            "WNOWAIT",
            "CLD_EXITED",
            "CRABC_CHILD_REAPING_FREESTANDING",
            "raw_wait4_cleanup",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains a dynamic TLS model",
            "wait waitpid waitid",
            "wait4",
            "waitid f7",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "sys/wait.h",
            "siginfo_t",
            "CRABC_CHILD_REAPING_POSIX",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("waitid_signature", header_probe)
            self.assertIn("siginfo_t", header_probe)
            self.assertIn("WIFSTOPPED", header_probe)
            self.assertIn("WIFSIGNALED", header_probe)
            self.assertIn("0x007f", header_probe)
            self.assertIn("0x137f", header_probe)
        self.assertIn('id = "static-c-child-reaping"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-child-reaping"',
            parity_ledger,
        )
        self.assertIn("child-reaping-header-abi", runner)
        self.assertIn("libc-child-reaping", runner)

    def test_libc_static_c_abi_immediate_termination_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        immediate_termination = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "immediate_termination.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_immediate_termination_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_immediate_termination.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_immediate_termination_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" /
            "immediate_termination_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" /
            "immediate_termination_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "immediate_termination.rs"]', static_root)
        self.assertIn("fn _Exit(", immediate_termination)
        self.assertIn("_Exit", static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/exit/_Exit.c",
            "SYS_EXIT_GROUP",
            "SYS_EXIT",
            "exit_group",
            "does not establish",
        ):
            self.assertIn(required, immediate_termination)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn at_quick_exit(",
            "fn quick_exit(",
            "fn _exit(",
            "c_status",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, immediate_termination)
        for required in (
            "raw_clone_sigchld",
            "returns_twice",
            "SYS_exit_group",
            "CRABC_IMMEDIATE_TERMINATION_FREESTANDING",
            "wait_for_child",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains a dynamic TLS model",
            "_Exit",
            "assert_named_syscall e7",
            "assert_named_syscall 3c",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "stdlib.h",
            "_Exit",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("immediate_exit_signature", header_probe)
            self.assertIn("_Exit", header_probe)
        self.assertIn('id = "static-c-immediate-termination"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-immediate-termination"',
            parity_ledger,
        )
        self.assertIn("immediate-termination-header-abi", runner)
        self.assertIn("libc-immediate-termination", runner)

    def test_libc_static_c_abi_posix_exit_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        static_startup = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_startup.rs"
        ).read_text(encoding="utf-8")
        posix_exit = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "posix_exit.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_posix_exit_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_posix_exit.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_posix_exit_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "posix_exit_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "posix_exit_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "posix_exit.rs"]', static_root)
        self.assertIn("fn _exit(", posix_exit)
        self.assertIn("posix_exit::_exit(status)", static_startup)
        self.assertNotIn("fn _exit(", static_startup)
        self.assertIn("_exit", static_exports)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/_exit.c",
            "immediate_termination::_Exit(status)",
            "no raw syscall",
            "no errno",
            "ordinary `exit`",
        ):
            self.assertIn(required, posix_exit)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "fn exit(",
            "fn atexit(",
            "fn abort(",
            "fn quick_exit(",
        ):
            self.assertNotIn(forbidden, posix_exit)
        for required in (
            "raw_clone_sigchld",
            "returns_twice",
            "SYS_exit_group",
            "CRABC_POSIX_EXIT_FREESTANDING",
            "_exit(41)",
            "wait_for_child",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains a dynamic TLS model",
            "_exit",
            "_Exit",
            "assert_posix_exit_forwarding",
            "assert_named_syscall e7",
            "assert_named_syscall 3c",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "unistd.h",
            "_exit",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("posix_exit_signature", header_probe)
            self.assertIn("_exit", header_probe)
        self.assertIn('id = "static-c-posix-exit"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-posix-exit"',
            parity_ledger,
        )
        self.assertIn("posix-exit-header-abi", runner)
        self.assertIn("libc-posix-exit", runner)
    def test_libc_static_c_abi_bsearch_artifact_stays_standalone(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "bsearch.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_bsearch_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_bsearch_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_bsearch.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_bsearch_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "bsearch_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "bsearch_header_abi_probe.cpp"
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

        self.assertIn('#[path = "bsearch.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 C `bsearch` ABI boundary",
            "musl 1.2.6 release commit",
            "src/stdlib/bsearch.c::bsearch",
            "checked multiplication return",
            "midpoint and comparator-branch sequence",
            'pub unsafe extern "C" fn bsearch',
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "__qsort_r",
            "qsort_r",
            "qsort",
            "raw_syscall::",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, implementation)
        self.assertIn("bsearch", static_exports)

        for required in (
            "bsearch_signature",
            "const bsearch_signature function = bsearch",
            "duplicates + 2",
            "compare_record",
            "zero_count_calls == 0",
            "CRABC_BSEARCH_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "crabc_x86_64_bsearch_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for header in (header_c, header_cxx):
            for required in ("bsearch declaration", "bsearch_signature", "bsearch_function"):
                self.assertIn(required, header)
        for required in (
            "bsearch_header_abi_probe.c",
            "bsearch_header_abi_probe.cpp",
            "-D__STRICT_ANSI__",
            "-D_POSIX_C_SOURCE=200809L",
            "-D_XOPEN_SOURCE=700",
            "-D_GNU_SOURCE",
            "-D_BSD_SOURCE",
            "nm --undefined-only",
            "retained a mangled bsearch reference",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "run_bsearch_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "--disassemble=bsearch",
            "bsearch candidate unexpectedly retains TLS",
            "bsearch unexpectedly performs a syscall",
            "__qsort_r qsort qsort_r",
            "candidate accidentally selects ${symbol}",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-bsearch"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-bsearch"',
            parity_ledger,
        )
        self.assertIn("run_bsearch_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_bsearch_header_abi.sh", runner
        )
        self.assertIn("run_libc_bsearch()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_bsearch.sh", runner
        )
        self.assertIn(
            '    bsearch-header-abi)\n        [ "$#" -eq 0 ] || fail "bsearch-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-bsearch)\n        [ "$#" -eq 0 ] || fail "libc-bsearch takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_linear_search_artifact_stays_standalone(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "linear_search.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_linear_search_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_linear_search_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_linear_search.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_linear_search_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "linear_search_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "linear_search_header_abi_probe.cpp"
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

        self.assertIn('#[path = "linear_search.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 C linear-search ABI boundary",
            "musl 1.2.6 release commit",
            "src/search/lsearch.c::{lsearch,lfind}",
            "first-match scan",
            "n + 1",
            'pub unsafe extern "C" fn lfind',
            'pub unsafe extern "C" fn lsearch',
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
            "global_asm!",
        ):
            self.assertNotIn(forbidden, implementation)
        for symbol in ("lfind", "lsearch"):
            self.assertIn(symbol, static_exports)

        for required in (
            "lfind_signature",
            "lsearch_signature",
            "const lfind_signature function = lfind",
            "const lsearch_signature function = lsearch",
            "found != records + 3",
            "comparison_calls != 3",
            "zero_count_calls == 0",
            "CRABC_LINEAR_SEARCH_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "crabc_x86_64_linear_search_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for header in (header_c, header_cxx):
            for required in (
                "lfind declaration",
                "lsearch declaration",
                "lfind_signature",
                "lsearch_signature",
                "lfind_function",
                "lsearch_function",
            ):
                self.assertIn(required, header)
        for required in (
            "linear_search_header_abi_probe.c",
            "linear_search_header_abi_probe.cpp",
            "-D__STRICT_ANSI__",
            "-D_POSIX_C_SOURCE=200809L",
            "-D_XOPEN_SOURCE=700",
            "-D_GNU_SOURCE",
            "-D_BSD_SOURCE",
            "nm --undefined-only",
            "retained a mangled linear-search reference",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "run_linear_search_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "--disassemble=lfind",
            "--disassemble=lsearch",
            "linear-search candidate unexpectedly retains TLS",
            "linear search unexpectedly performs a syscall",
            "outside the test entry shim",
            "bsearch __qsort_r qsort qsort_r",
            "candidate accidentally selects ${symbol}",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-linear-search"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-linear-search"',
            parity_ledger,
        )
        self.assertIn("run_linear_search_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_linear_search_header_abi.sh", runner
        )
        self.assertIn("run_libc_linear_search()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_linear_search.sh", runner
        )
        self.assertIn(
            '    linear-search-header-abi)\n        [ "$#" -eq 0 ] || fail "linear-search-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-linear-search)\n        [ "$#" -eq 0 ] || fail "libc-linear-search takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_qsort_artifact_stays_standalone(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "qsort.rs"
        ).read_text(encoding="utf-8")
        context_abi = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "callback_algorithms.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_qsort_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_qsort_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_qsort.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_qsort_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "qsort_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "qsort_header_abi_probe.cpp"
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

        self.assertIn('#[path = "qsort.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 C `qsort` ABI boundary",
            "musl 1.2.6 release commit",
            "src/stdlib/qsort.c::__qsort_r",
            "src/stdlib/qsort_nr.c::qsort",
            "qsort_with_context",
            "14 * core::mem::size_of::<usize>() + 1",
            "12 * core::mem::size_of::<usize>()",
            "qsort_copy_nonoverlapping",
            'pub unsafe extern "C" fn qsort',
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "global_asm!",
            ".weak qsort_r",
            ".set qsort_r",
            "raw_syscall::",
            "errno::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "qsort_with_context",
            ".weak qsort_r",
            ".set qsort_r, __qsort_r",
            'pub unsafe extern "C" fn __qsort_r',
        ):
            self.assertIn(required, context_abi)
        self.assertIn("qsort", static_exports)

        for required in (
            "qsort_signature",
            "const qsort_signature function = qsort",
            "payload[300]",
            "seen == 0xffu",
            "zero_count_calls == 0",
            "CRABC_QSORT_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "crabc_x86_64_qsort_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)
        for header in (header_c, header_cxx):
            for required in ("qsort declaration", "qsort_signature", "qsort_function"):
                self.assertIn(required, header)
        for required in (
            "qsort_header_abi_probe.c",
            "qsort_header_abi_probe.cpp",
            "-D__STRICT_ANSI__",
            "-D_POSIX_C_SOURCE=200809L",
            "-D_XOPEN_SOURCE=700",
            "-D_GNU_SOURCE",
            "-D_BSD_SOURCE",
            "nm --undefined-only",
            "retained a mangled qsort reference",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "run_qsort_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "--disassemble=qsort",
            "qsort candidate unexpectedly retains TLS",
            "qsort unexpectedly performs a syscall",
            "outside the test entry shim",
            "__qsort_r qsort_r",
            "candidate accidentally selects ${symbol}",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-qsort"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-qsort"',
            parity_ledger,
        )
        self.assertIn("run_qsort_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_qsort_header_abi.sh", runner
        )
        self.assertIn("run_libc_qsort()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_qsort.sh", runner
        )
        self.assertIn(
            '    qsort-header-abi)\n        [ "$#" -eq 0 ] || fail "qsort-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-qsort)\n        [ "$#" -eq 0 ] || fail "libc-qsort takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_callback_algorithms_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        bsearch = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "bsearch.rs"
        ).read_text(encoding="utf-8")
        qsort = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "qsort.rs"
        ).read_text(encoding="utf-8")
        callback_algorithms = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "callback_algorithms.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_callback_algorithms_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_callback_algorithms.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_callback_algorithms_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" /
            "callback_algorithms_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" /
            "callback_algorithms_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "bsearch.rs"]', static_root)
        self.assertIn('#[path = "qsort.rs"]', static_root)
        self.assertIn('#[path = "callback_algorithms.rs"]', static_root)
        self.assertIn("bsearch", bsearch)
        self.assertIn("bsearch", static_export_names)
        self.assertIn("qsort", qsort)
        self.assertIn("qsort", static_export_names)
        for symbol in ("__qsort_r", "qsort_r"):
            self.assertIn(symbol, callback_algorithms)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/bsearch.c::bsearch",
            "checked multiplication return",
            "midpoint and comparator-branch sequence",
            'pub unsafe extern "C" fn bsearch',
        ):
            self.assertIn(required, bsearch)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/qsort.c::__qsort_r",
            "src/stdlib/qsort_nr.c",
            "smoothsort",
            "qsort_with_context",
            ".weak qsort_r",
            ".set qsort_r, __qsort_r",
        ):
            self.assertIn(required, callback_algorithms)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/qsort.c::__qsort_r",
            "src/stdlib/qsort_nr.c::qsort",
            "smoothsort",
            "14 * core::mem::size_of::<usize>() + 1",
            "12 * core::mem::size_of::<usize>()",
            "qsort_copy_nonoverlapping",
            "MaybeUninit",
        ):
            self.assertIn(required, qsort)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "c_status",
            "__tls_get_addr",
            "raw_syscall",
            "alloc::",
        ):
            self.assertNotIn(forbidden, callback_algorithms)
        for forbidden in ("__qsort_r", "qsort_r", "qsort", "raw_syscall", "errno::"):
            self.assertNotIn(forbidden, bsearch)
        for required in (
            "bsearch",
            "qsort",
            "qsort_r",
            "__qsort_r",
            "CRABC_CALLBACK_ALGORITHMS_FREESTANDING",
            "CRABC_CALLBACK_ALGORITHMS_OVERRIDE_QSORT_R",
            "context_mismatch",
            "wide_record",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "qsort_r",
            "weak",
            "same-address",
            "unexpectedly selects TLS",
            "Rust panic machinery",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "stdlib.h",
            "CRABC_EXPECT_QSORT_R",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("bsearch_signature", header_probe)
            self.assertIn("qsort_signature", header_probe)
            self.assertIn("qsort_r_signature", header_probe)
        self.assertIn('id = "static-c-callback-algorithms"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-callback-algorithms"',
            parity_ledger,
        )
        self.assertIn("callback-algorithms-header-abi", runner)
        self.assertIn("libc-callback-algorithms", runner)

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

    def test_libc_static_c_abi_clock_gettime_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        clock_gettime = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clock_gettime.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_clock_gettime_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_clock_gettime_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_clock_gettime.sh"
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

        self.assertIn('#[path = "clock_gettime.rs"]', static_root)
        self.assertIn("pub unsafe extern \"C\" fn clock_gettime(", clock_gettime)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/clock_gettime.c",
            "raw_syscall::SYS_CLOCK_GETTIME",
            "raw_syscall::syscall2(",
            "c_status(result)",
            "initial-TLS errno",
            "vDSO resolver",
        ):
            self.assertIn(required, clock_gettime)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn clock_getres(",
            "fn clock_settime(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, clock_gettime)
        for required in (
            "#include <errno.h>",
            "#include <time.h>",
            "SYS_clock_gettime == 228",
            "CLOCK_REALTIME == 0",
            "check_success_and_errno",
            "check_errors",
            "CLOCK_PROCESS_CPUTIME_ID",
            "CRABC_CLOCK_GETTIME_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_clock_gettime_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall",
            "clock_gettime lacks syscall 228",
            "direct fs initial TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("clock_gettime", static_export_names)
        self.assertIn('id = "static-c-clock-gettime"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-clock-gettime"',
            parity_ledger,
        )
        self.assertIn("run_libc_clock_gettime()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_clock_gettime.sh", runner
        )
        self.assertIn(
            '    libc-clock-gettime)\n        [ "$#" -eq 0 ] || fail "libc-clock-gettime takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_time_observation_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        time_observation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "time_observation.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_time_observation_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_time_observation_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_time_observation.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "time_observation.rs"]', static_root)
        for symbol in (
            "clock",
            "time",
            "timespec_get",
            "clock_getres",
            "gettimeofday",
        ):
            self.assertIn(f"fn {symbol}(", time_observation)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/clock.c",
            "src/time/time.c",
            "src/time/timespec_get.c",
            "src/time/clock_getres.c",
            "src/time/gettimeofday.c",
            "SYS_CLOCK_GETTIME",
            "SYS_CLOCK_GETRES",
            "SYS_GETTIMEOFDAY",
            "vDSO resolver",
            "initial-TLS",
        ):
            self.assertIn(required, time_observation)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "clock_settime",
            "timer_create",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, time_observation)
        self.assertNotIn("fn difftime(", time_observation)
        self.assertNotIn("src/time/difftime.c", time_observation)
        for required in (
            "#include <sys/time.h>",
            "SYS_gettimeofday == 96",
            "SYS_clock_getres == 229",
            "check_wall_clock_and_errno",
            "check_cpu_clock",
            "check_error_conventions",
            "CRABC_TIME_OBSERVATION_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("difftime(", probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_time_observation_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall clock e4",
            "assert_named_syscall clock_getres e5",
            "assert_named_syscall gettimeofday 60",
            "direct fs initial TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-time-observation"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-time-observation"',
            parity_ledger,
        )
        self.assertIn("run_libc_time_observation()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_time_observation.sh", runner
        )
        self.assertIn(
            '    libc-time-observation)\n        [ "$#" -eq 0 ] || fail "libc-time-observation takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_difftime_artifact_stays_binary64_only(self) -> None:
        """The C scalar stays separate from clock and calendar policy."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        difftime_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "difftime.rs"
        probe_path = ROOT / "compat" / "x86_64" / "libc_difftime_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_difftime_start.S"
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_difftime.sh"
        for path in (difftime_path, probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing binary64 difftime input: {path}")

        difftime = difftime_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "time_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "time_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "difftime.rs"]', static_root)
        self.assertIn("fn difftime(", difftime)
        self.assertIn("difftime", static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/difftime.c",
            "wrapping_sub",
            "binary64",
            "xmm0",
        ):
            self.assertIn(required, difftime)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "raw_syscall",
            "set_errno",
            "getenv",
            "tzset",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, difftime)
        for required in (
            "#include <time.h>",
            "difftime declaration",
            "direct_difftime",
            "INT64_MAX",
            "INT64_MIN",
            "2047",
            "CRABC_DIFFTIME_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_difftime_probe", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "cvtsi2sd",
            "env -i",
            "candidate retains TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for header_probe in (header_c, header_cxx):
            self.assertIn("difftime_signature", header_probe)
        self.assertIn('id = "static-c-difftime-binary64"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-difftime"',
            parity_ledger,
        )
        self.assertIn("run_libc_difftime()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_difftime.sh", runner
        )
        self.assertIn(
            '    libc-difftime)\n        [ "$#" -eq 0 ] || fail "libc-difftime takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_timegm_artifact_stays_fixed_utc(self) -> None:
        """The GNU/BSD C inverse is one fixed-UTC conversion leaf only."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        timegm_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "timegm.rs"
        probe_path = ROOT / "compat" / "x86_64" / "libc_timegm_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_timegm_start.S"
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_timegm.sh"
        for path in (timegm_path, probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing fixed-UTC timegm input: {path}")

        timegm = timegm_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "time_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "time_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "timegm.rs"]', static_root)
        self.assertIn("fn timegm(", timegm)
        self.assertIn("timegm", static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/timegm.c",
            "src/time/__tm_to_secs.c",
            "src/time/__secs_to_tm.c",
            "src/time/__year_to_secs.c",
            "src/time/__month_to_secs.c",
            "EOVERFLOW",
            "UTC",
            "initial-TLS errno",
            "month < 0",
        ):
            self.assertIn(required, timegm)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "getenv",
            "tzset",
            "localtime",
            "mktime",
            "strftime",
            "strptime",
            "raw_syscall",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, timegm)
        for required in (
            "#include <time.h>",
            "sizeof(struct tm) == 56",
            "timegm declaration",
            "negative_month",
            "valid_minus_one",
            "overflow",
            "CRABC_TIMEGM_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_timegm_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "timegm",
            "env -i",
            "direct fs initial TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for header_probe in (header_c, header_cxx):
            self.assertIn("timegm_signature", header_probe)
        self.assertIn('id = "static-c-timegm-utc"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-timegm"',
            parity_ledger,
        )
        self.assertIn("run_libc_timegm()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_timegm.sh", runner
        )
        self.assertIn(
            '    libc-timegm)\n        [ "$#" -eq 0 ] || fail "libc-timegm takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_gmtime_r_artifact_stays_fixed_utc(self) -> None:
        """The caller-buffered POSIX UTC conversion remains one static leaf."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        gmtime_r_path = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "gmtime_r.rs"
        probe_path = ROOT / "compat" / "x86_64" / "libc_gmtime_r_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_gmtime_r_start.S"
        artifact_runner_path = ROOT / "compat" / "x86_64" / "run_libc_gmtime_r.sh"
        for path in (gmtime_r_path, probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing fixed-UTC gmtime_r input: {path}")

        gmtime_r = gmtime_r_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "time_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "time_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "gmtime_r.rs"]', static_root)
        self.assertIn("fn gmtime_r(", gmtime_r)
        self.assertIn("gmtime_r", static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/gmtime_r.c",
            "src/time/__secs_to_tm.c",
            "EOVERFLOW",
            "UTC",
            "initial-TLS errno",
            "secs_to_utc_tm",
        ):
            self.assertIn(required, gmtime_r)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "getenv",
            "tzset",
            "localtime",
            "mktime",
            "strftime",
            "strptime",
            "raw_syscall",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, gmtime_r)
        for required in (
            "#include <time.h>",
            "sizeof(struct tm) == 56",
            "gmtime_r declaration",
            "epoch",
            "pre_epoch",
            "leap_day",
            "overflow",
            "CRABC_GMTIME_R_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_gmtime_r_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "gmtime_r",
            "env -i",
            "direct fs initial TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for header_probe in (header_c, header_cxx):
            self.assertIn("gmtime_r_signature", header_probe)
        self.assertIn('id = "static-c-gmtime-r-utc"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-gmtime-r"',
            parity_ledger,
        )
        self.assertIn("run_libc_gmtime_r()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_gmtime_r.sh", runner
        )
        self.assertIn(
            '    libc-gmtime-r)\n        [ "$#" -eq 0 ] || fail "libc-gmtime-r takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_system_configuration_artifact_stays_narrow(
        self,
    ) -> None:
        """A configuration block must be one closed static artifact, not leaves."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        system_configuration_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_configuration.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_system_configuration_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_system_configuration_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_system_configuration.sh"
        )

        for path in (
            system_configuration_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing system-configuration artifact input: {path}")

        system_configuration = system_configuration_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
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

        self.assertIn('#[path = "system_configuration.rs"]', static_root)
        for required in (
            'fn sysconf(',
            'fn confstr(',
            'fn fpathconf(',
            'fn pathconf(',
            'fn getpagesize()',
            'fn getdtablesize()',
            '#[inline(always)]\nfn pathconf_value',
            '#[inline(always)]\nunsafe fn selected_pathconf',
            'raw_syscall::SYS_PRLIMIT64',
            'initial-TLS errno',
            'musl 1.2.6 release commit',
        ):
            self.assertIn(required, system_configuration)
        pathconf_helpers = system_configuration[
            system_configuration.index('#[inline(always)]\nfn pathconf_value') :
            system_configuration.index(
                '/// Return a selected path configuration value for an open descriptor.'
            )
        ]
        self.assertNotIn('raw_syscall', pathconf_helpers)
        for forbidden in (
            'crabc_core',
            'crabc_mimalloc',
            '__tls_get_addr',
            'pthread_',
            'getauxval',
            'raw_syscall::SYS_STATFS',
            'raw_syscall::SYS_FSTATFS',
        ):
            self.assertNotIn(forbidden, system_configuration)
        for required in (
            '#include <errno.h>',
            '#include <limits.h>',
            '#include <sys/resource.h>',
            '#include <sys/syscall.h>',
            '#include <unistd.h>',
            'SYS_statfs == 137',
            'SYS_fstatfs == 138',
            'SYS_prlimit64 == 302',
            'check_common_contract',
            'check_musl_configuration_contract',
            'CRABC_SYSTEM_CONFIGURATION_FREESTANDING',
        ):
            self.assertIn(required, probe)
        for required in (
            'ARCH_SET_FS',
            'mov %rsi, %fs:0',
            'crabc_x86_64_system_configuration_probe',
        ):
            self.assertIn(required, start)
        for required in (
            'static_c_abi_exports.txt',
            'run_unistd_header_abi.sh',
            'run_resource_header_abi.sh',
            '-nostdlib -static',
            '-Wl,-e,_start',
            'R_X86_64_TPOFF',
            'assert_getdtablesize_syscall',
            'path configuration unexpectedly issues a syscall',
            'getdtablesize lacks syscall 302',
        ):
            self.assertIn(required, artifact_runner)
        self.assertIn("getauxval|statfs", artifact_runner)
        archive_policy = artifact_runner[
            artifact_runner.index('readelf --relocs --wide "$archive"') : artifact_runner.index(
                '"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SYSTEM_CONFIGURATION_FREESTANDING'
            )
        ]
        self.assertNotIn("getauxval", archive_policy)
        self.assertNotIn("statfs", archive_policy)
        self.assertNotIn('--whole-archive', artifact_runner)
        for symbol in (
            'confstr',
            'fpathconf',
            'getdtablesize',
            'getpagesize',
            'pathconf',
            'sysconf',
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-system-configuration"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-system-configuration"',
            parity_ledger,
        )
        self.assertIn('run_libc_system_configuration()', runner)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_system_configuration.sh', runner
        )
        self.assertIn(
            '    libc-system-configuration)\n        [ "$#" -eq 0 ] || fail "libc-system-configuration takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_mapping_core_artifact_stays_narrow(self) -> None:
        """The mapping lifecycle is one closed C/header/archive artifact."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        mapping_core_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_mapping.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_mapping_core_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_mapping_core_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_mapping_core.sh"
        )
        header_c_path = ROOT / "compat" / "x86_64" / "mman_header_abi_probe.c"
        header_cxx_path = ROOT / "compat" / "x86_64" / "mman_header_abi_probe.cpp"

        for path in (
            mapping_core_path,
            probe_path,
            start_path,
            artifact_runner_path,
            header_c_path,
            header_cxx_path,
        ):
            self.assertTrue(path.is_file(), f"missing mapping-core artifact input: {path}")

        mapping_core = mapping_core_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        header_c = header_c_path.read_text(encoding="utf-8")
        header_cxx = header_cxx_path.read_text(encoding="utf-8")
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

        self.assertIn('#[path = "memory_mapping.rs"]', static_root)
        self.assertIn("fn c_pointer_status", static_root)
        for required in (
            "src/mman/mmap.c",
            "src/mman/munmap.c",
            "src/mman/mprotect.c",
            "src/mman/madvise.c",
            "src/mman/posix_madvise.c",
            "src/mman/mincore.c",
            "MMAP_OFFSET_MASK",
            "isize::MAX",
            "MAP_FIXED",
            "MAP_ANONYMOUS",
            "selected_static_vm_wait",
            "__vm_wait",
            "wrapping_add",
            "POSIX_MADV_DONTNEED",
            "c_pointer_status(result)",
            "wrapping_neg",
            "msync",
            "mremap",
            "mlock*",
        ):
            self.assertIn(required, mapping_core)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn msync(",
            "fn mremap(",
            "fn mlock(",
            "fn shm_open(",
            "fn memfd_create(",
            "extern \"C\" fn __vm_wait",
        ):
            self.assertNotIn(forbidden, mapping_core)
        for required in (
            "#include <errno.h>",
            "#include <stdint.h>",
            "#include <sys/mman.h>",
            "#include <sys/syscall.h>",
            "SYS_mmap == 9",
            "SYS_mprotect == 10",
            "SYS_munmap == 11",
            "SYS_mincore == 27",
            "SYS_madvise == 28",
            "PTRDIFF_MAX",
            "POSIX_MADV_DONTNEED",
            "CRABC_MAPPING_CORE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "madvise declaration",
            "posix_madvise declaration",
            "mincore declaration",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cxx)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_mapping_core_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_mman_header_abi.sh",
            "run_x86_mapping_reference.sh",
            "run_x86_madvise_reference.sh",
            "run_x86_mincore_reference.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "__vm_wait",
            "assert_named_syscall mmap 9",
            "assert_named_syscall mprotect a",
            "assert_named_syscall munmap b",
            "assert_named_syscall madvise 1c",
            "assert_named_syscall posix_madvise 1c",
            "assert_named_syscall mincore 1b",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "mmap",
            "munmap",
            "mprotect",
            "madvise",
            "posix_madvise",
            "mincore",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-mman-mapping-core"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-mapping-core"', parity_ledger
        )
        self.assertIn("run_libc_mapping_core()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_mapping_core.sh", runner
        )
        self.assertIn(
            '    libc-mapping-core)\n        [ "$#" -eq 0 ] || fail "libc-mapping-core takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_memory_locking_artifact_stays_narrow(self) -> None:
        """Per-range locking remains one private C/header/archive vertical."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_locking.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "memory_locking_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "memory_locking_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_memory_locking_header_abi.sh"
        ).read_text(encoding="utf-8")
        fixture = (
            ROOT / "compat" / "x86_64" / "libc_memory_locking_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_memory_locking_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_memory_locking.sh"
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

        self.assertIn('#[path = "memory_locking.rs"]', static_root)
        for required in (
            "SYS_MLOCK: i64 = 149",
            "SYS_MUNLOCK: i64 = 150",
            "SYS_MLOCK2: i64 = 325",
        ):
            self.assertIn(required, syscall)
        for required in (
            "musl 1.2.6 release commit",
            "src/mman/mlock.c",
            "src/mman/munlock.c",
            "src/linux/mlock2.c",
            "SYS_MLOCK",
            "SYS_MUNLOCK",
            "SYS_MLOCK2",
            "if flags == 0",
            "return unsafe { mlock(address, length) }",
            "c_status(result)",
            "initial-TLS",
            "cancellation-point syscall path",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn mlockall(",
            "fn munlockall(",
            "fn msync(",
            "fn mremap(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, implementation)
        for probe in (header_c, header_cpp):
            for required in ("sys/mman.h", "mlock", "munlock", "mlock2", "MLOCK_ONFAULT"):
                self.assertIn(required, probe)
        for required in (
            "c11-strict",
            "cxx17-strict",
            "c11-posix-2008",
            "cxx17-posix-2008",
            "c11-gnu",
            "cxx17-gnu",
            "GNU mlock2",
            "unmangled",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "SYS_mlock == 149",
            "SYS_munlock == 150",
            "SYS_mlock2 == 325",
            "MLOCK_ONFAULT",
            "permitted_lock_error",
            "overflowing",
            "CRABC_MEMORY_LOCKING_FREESTANDING",
        ):
            self.assertIn(required, fixture)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_memory_locking_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_memory_locking_header_abi.sh",
            "run_x86_mlock_reference.sh",
            "-nostdlib -static",
            "assert_named_syscall mlock 95",
            "assert_named_syscall munlock 96",
            "assert_named_syscall mlock2 145",
            "mlockall munlockall msync mremap",
            "direct fs initial TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("mlock", "munlock", "mlock2"):
            self.assertIn(symbol, static_export_names)
        for command in (
            "./scripts/dev-x86_64.sh memory-locking-header-abi",
            "./scripts/dev-x86_64.sh libc-memory-locking",
        ):
            self.assertIn(command, parity_ledger)
        for required in (
            "run_memory_locking_header_abi()",
            "/workspace/compat/x86_64/run_memory_locking_header_abi.sh",
            "/workspace/compat/x86_64/run_libc_memory_locking.sh",
            '    memory-locking-header-abi)\n        [ "$#" -eq 0 ] || fail "memory-locking-header-abi takes no arguments"',
            '    libc-memory-locking)\n        [ "$#" -eq 0 ] || fail "libc-memory-locking takes no arguments"',
        ):
            self.assertIn(required, runner)

    def test_libc_static_header_layouts_baseline_stays_c_and_cxx_only(self) -> None:
        """The aggregate records must not smuggle in a C++ runtime or exports."""
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_probe.c"
        )
        cxx_probe_path = (
            ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_probe.cpp"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_start.S"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_header_layouts_baseline.sh"
        )
        for path in (probe_path, cxx_probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing header-layout baseline input: {path}")

        probe = probe_path.read_text(encoding="utf-8")
        cxx_probe = cxx_probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
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

        for header in (
            "errno.h",
            "fcntl.h",
            "netinet/in.h",
            "poll.h",
            "signal.h",
            "sys/mman.h",
            "sys/resource.h",
            "sys/select.h",
            "sys/socket.h",
            "sys/stat.h",
            "sys/sysinfo.h",
            "sys/utsname.h",
            "termios.h",
            "time.h",
            "unistd.h",
        ):
            self.assertIn(f"#include <{header}>", probe)
            self.assertIn(f"#include <{header}>", cxx_probe)
        for required in (
            "crabc_x86_64_header_layouts_baseline_cxx_probe",
            "check_observation_records",
            "check_mapping_records",
            "check_descriptor_records",
            "check_signal_and_termios_records",
            "CRABC_HEADER_LAYOUTS_BASELINE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            'extern "C" int crabc_x86_64_header_layouts_baseline_cxx_probe',
            "check_cpp_observation",
            "check_cpp_mapping",
            "check_cpp_descriptor_and_signal",
            "__errno_location",
            "fstat",
            "clock_gettime",
            "mmap",
            "munmap",
            "mprotect",
            "madvise",
            "posix_madvise",
            "mincore",
            "getrlimit",
            "poll",
            "select",
            "socketpair",
            "close",
            "sigemptyset",
            "cfmakeraw",
            "uname",
            "sysinfo",
            "getpagesize",
        ):
            self.assertIn(required, cxx_probe)
        for forbidden in (
            "#include <vector>",
            "#include <string>",
            "#include <type_traits>",
            "throw ",
            "typeid",
            "new ",
            "delete ",
            "thread_local",
            "static std::",
        ):
            self.assertNotIn(forbidden, cxx_probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_header_layouts_baseline_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_types_header_abi.sh",
            "run_stat_header_abi.sh",
            "run_time_header_abi.sh",
            "run_poll_header_abi.sh",
            "run_select_header_abi.sh",
            "run_fcntl_header_abi.sh",
            "run_unistd_header_abi.sh",
            "run_system_header_abi.sh",
            "run_signal_header_abi.sh",
            "run_termios_header_abi.sh",
            "run_mman_header_abi.sh",
            "run_resource_header_abi.sh",
            "run_socket_header_abi.sh",
            "-std=c++17",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-threadsafe-statics",
            "-fno-use-cxa-atexit",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "__gxx_personality_v0",
            "__cxa",
            "_Unwind_",
            "__stack_chk_fail",
            "__tls_get_addr",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "static_c_abi_exports.txt",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "__errno_location",
            "fstat",
            "clock_gettime",
            "mmap",
            "munmap",
            "mprotect",
            "madvise",
            "posix_madvise",
            "mincore",
            "getrlimit",
            "poll",
            "select",
            "socketpair",
            "close",
            "sigemptyset",
            "cfmakeraw",
            "uname",
            "sysinfo",
            "getpagesize",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-header-layouts-baseline"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-header-layouts-baseline"',
            parity_ledger,
        )
        self.assertIn("run_libc_header_layouts_baseline()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_header_layouts_baseline.sh", runner
        )
        self.assertIn(
            '    libc-header-layouts-baseline)\n        [ "$#" -eq 0 ] || fail "libc-header-layouts-baseline takes no arguments"',
            runner,
        )

    def test_libc_uio_cxx_linkage_stays_a_freestanding_cxx_archive_gate(self) -> None:
        """The selected C++ linkage seam must not admit a C++ runtime."""
        c_probe = (
            ROOT / "compat" / "x86_64" / "libc_uio_cxx_linkage_probe.c"
        ).read_text(encoding="utf-8")
        cxx_probe = (
            ROOT / "compat" / "x86_64" / "libc_uio_cxx_linkage_probe.cpp"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_uio_cxx_linkage_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_uio_cxx_linkage.sh"
        ).read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "#include <sys/socket.h>",
            "#include <sys/uio.h>",
            "crabc_x86_64_uio_cxx_linkage_probe",
            "socketpair",
        ):
            self.assertIn(required, c_probe)
        for required in (
            "#include <errno.h>",
            "#include <sys/uio.h>",
            'extern "C" int crabc_x86_64_uio_cxx_linkage_probe',
            "readv",
            "writev",
            "preadv",
            "pwritev",
            "ESPIPE",
        ):
            self.assertIn(required, cxx_probe)
        for forbidden in (
            "#include <vector>",
            "#include <string>",
            "throw ",
            "typeid",
            "new ",
            "delete ",
            "thread_local",
            "static std::",
        ):
            self.assertNotIn(forbidden, cxx_probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_uio_cxx_linkage_entry",
        ):
            self.assertIn(required, start)
        for required in (
            "run_vector_io_header_abi.sh",
            "assert_selected_c_abi_surface",
            "assert_cxx_c_linkage",
            "-std=c++17",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            "-nostdinc++",
            "-nostdlib -static",
            "__gxx_personality_v0",
            "__tls_get_addr",
            "R_X86_64_TPOFF",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("run_libc_uio_cxx_linkage_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_uio_cxx_linkage.sh", runner
        )
        self.assertIn(
            '    libc-uio-cxx-linkage)\n        [ "$#" -eq 0 ] || fail "libc-uio-cxx-linkage takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_clock_nanosleep_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        clock_nanosleep = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clock_nanosleep.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_clock_nanosleep_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_clock_nanosleep_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_clock_nanosleep.sh"
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

        self.assertIn('#[path = "clock_nanosleep.rs"]', static_root)
        self.assertIn("fn clock_nanosleep(", clock_nanosleep)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/clock_nanosleep.c",
            "clock_nanosleep=230",
            "raw_syscall::SYS_CLOCK_NANOSLEEP",
            "raw_syscall::syscall4(",
            "LINUX_ERRNO_MAX",
            "wrapping_neg",
            "positive errno",
            "__syscall_cp",
            "special-cases a relative realtime request",
            "independent of the",
        ):
            self.assertIn(required, clock_nanosleep)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "c_status(",
            "errno::set_errno",
            "fn nanosleep(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, clock_nanosleep)
        for required in (
            "#include <errno.h>",
            "#include <signal.h>",
            "#include <time.h>",
            "raw_clock_gettime",
            "raw_arm_alarm",
            "check_immediate_and_error_conventions",
            "check_relative_interruption",
            "check_absolute_interruption",
            "CRABC_CLOCK_NANOSLEEP_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_clock_nanosleep_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall clock_nanosleep e6",
            "%r10",
            "must return positive errors without touching errno TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("clock_nanosleep", static_export_names)
        self.assertIn('id = "static-c-clock-nanosleep"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-clock-nanosleep"',
            parity_ledger,
        )
        self.assertIn("run_libc_clock_nanosleep()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_clock_nanosleep.sh", runner
        )
        self.assertIn(
            '    libc-clock-nanosleep)\n        [ "$#" -eq 0 ] || fail "libc-clock-nanosleep takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_nanosleep_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        nanosleep = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "nanosleep.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_nanosleep_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_nanosleep_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_nanosleep.sh"
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

        self.assertIn('#[path = "nanosleep.rs"]', static_root)
        self.assertIn("fn nanosleep(", nanosleep)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/nanosleep.c",
            "nanosleep=35",
            "raw_syscall::SYS_NANOSLEEP",
            "raw_syscall::syscall2(",
            "c_status",
            "initial-TLS errno",
            "__syscall_cp",
            "cancellation",
        ):
            self.assertIn(required, nanosleep)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn sleep(",
            "fn usleep(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, nanosleep)
        for required in (
            "#include <errno.h>",
            "#include <signal.h>",
            "#include <time.h>",
            "raw_arm_alarm",
            "check_immediate_and_error_conventions",
            "check_relative_interruption",
            "CRABC_NANOSLEEP_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_nanosleep_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall nanosleep 23",
            "candidate errno does not use direct fs initial TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("nanosleep", static_export_names)
        self.assertIn('id = "static-c-nanosleep"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-nanosleep"', parity_ledger
        )
        self.assertIn("run_libc_nanosleep()", runner)
        self.assertIn("/workspace/compat/x86_64/run_libc_nanosleep.sh", runner)
        self.assertIn(
            '    libc-nanosleep)\n        [ "$#" -eq 0 ] || fail "libc-nanosleep takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_filesystem_access_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        filesystem_access = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "filesystem_access.rs"
        ).read_text(encoding="utf-8")
        probe = (ROOT / "compat" / "x86_64" / "libc_access_probe.c").read_text(
            encoding="utf-8"
        )
        start = (ROOT / "compat" / "x86_64" / "libc_access_start.S").read_text(
            encoding="utf-8"
        )
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_access.sh"
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

        self.assertIn('#[path = "filesystem_access.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/access.c",
            "src/unistd/faccessat.c",
            "src/legacy/euidaccess.c",
            "raw_syscall::SYS_ACCESS",
            "raw_syscall::SYS_FACCESSAT",
            "raw_syscall::SYS_FACCESSAT2",
            "raw_syscall::syscall2(",
            "raw_syscall::syscall3(",
            "raw_syscall::syscall4(",
            "AT_FDCWD",
            "AT_EACCESS",
            ".weak eaccess",
            ".set eaccess, euidaccess",
            "c_status(result)",
            "__syscall_cp",
        ):
            self.assertIn(required, filesystem_access)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn fchmodat(",
            "fn lchmod(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, filesystem_access)
        for required in (
            "CRABC_ACCESS_ROOT",
            "raw_clone_sigchld",
            "SYS_setresuid",
            "AT_SYMLINK_NOFOLLOW",
            "AT_EACCESS",
            "euidaccess",
            "eaccess",
            "CRABC_ACCESS_FREESTANDING",
            "CRABC_ACCESS_OVERRIDE_EACCESS",
            "eaccess_override_calls",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_access_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_access_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "assert_named_syscall access 15",
            "assert_named_syscall faccessat 10d",
            "assert_named_syscall faccessat 1b7",
            "same-address",
            "strong caller eaccess",
            "requires root",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("access", "faccessat", "euidaccess", "eaccess"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-filesystem-access"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-access"', parity_ledger
        )
        self.assertIn("run_libc_access()", runner)
        self.assertIn("/workspace/compat/x86_64/run_libc_access.sh", runner)
        self.assertIn(
            '    libc-access)\n        [ "$#" -eq 0 ] || fail "libc-access takes no arguments"',
            runner,
        )

    def test_static_artifact_negative_export_checks_never_reject_selected_exports(
        self,
    ) -> None:
        """Keep per-artifact exclusions compatible with the shared archive ratchet."""

        selected_exports = {
            line
            for line in (
                ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }

        for artifact_runner in sorted(
            (ROOT / "compat" / "x86_64").glob("run_libc_*.sh")
        ):
            source = artifact_runner.read_text(encoding="utf-8")
            if "assert_selected_c_abi_surface" not in source:
                continue

            excluded_exports: set[str] = set()
            for match in re.finditer(
                r"for unselected in\s+(.*?);\s*do\s*(.*?)\s*done",
                source,
                re.DOTALL,
            ):
                # A freestanding candidate may deliberately prove that it did
                # not pull an unrelated archive sibling. Only archive-surface
                # exclusions must track the shared export manifest.
                if "$candidate_symbols" in match.group(2):
                    continue
                excluded_exports.update(
                    token for token in match.group(1).split() if token != "\\"
                )

            with self.subTest(artifact_runner=artifact_runner.name):
                self.assertSetEqual(
                    selected_exports & excluded_exports,
                    set(),
                    "a shared selected C ABI export cannot remain an artifact-local "
                    "unselected exclusion",
                )

    def test_libc_static_c_abi_descriptor_entry_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        descriptor_entry = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_entry.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "fcntl_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "fcntl_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_entry_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_entry_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_descriptor_entry.sh"
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

        self.assertIn('#[path = "descriptor_entry.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "fn open(",
            "fn openat(",
            "fn creat(",
            "src/fcntl/open.c",
            "src/fcntl/openat.c",
            "src/fcntl/creat.c",
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_OPENAT",
            "raw_syscall::SYS_FCNTL",
            "O_LARGEFILE",
            "O_TMPFILE",
            "(flags & O_TMPFILE) == O_TMPFILE",
            "F_SETFD",
            "FD_CLOEXEC",
            "c_status(result)",
            "__syscall_cp",
            "rdi/rsi/rdx/r10",
        ):
            self.assertIn(required, descriptor_entry)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "pub unsafe extern \"C\" fn fcntl",
            "fn fcntl(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, descriptor_entry)
        for required in (
            "openat_signature",
            "creat_signature",
            "openat_signature)(int, const char *, int, ...)",
            "creat_signature)(const char *, mode_t)",
        ):
            self.assertIn(required, header_c_probe)
        for required in (
            "openat_function",
            "creat_function",
            "decltype(&openat)",
            "decltype(&creat)",
        ):
            self.assertIn(required, header_cxx_probe)
        for required in (
            "#include <fcntl.h>",
            "raw_fcntl",
            "check_open_without_mode",
            "check_open_create_cloexec",
            "check_openat_relative_create",
            "check_creat_truncates",
            "O_CLOEXEC",
            "F_GETFD",
            "CRABC_DESCRIPTOR_ENTRY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_descriptor_entry_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_fcntl_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_open_syscall",
            "assert_named_syscall openat 101",
            "assert_open_cloexec_fixup",
            "%r10",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("open", "openat", "creat"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-descriptor-entry"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-descriptor-entry"',
            parity_ledger,
        )
        self.assertIn("run_libc_descriptor_entry()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_descriptor_entry.sh", runner
        )
        self.assertIn(
            '    libc-descriptor-entry)\n        [ "$#" -eq 0 ] || fail "libc-descriptor-entry takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_fcntl_status_control_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        descriptor_control = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_control.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT
            / "compat"
            / "x86_64"
            / "libc_fcntl_status_control_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT
            / "compat"
            / "x86_64"
            / "libc_fcntl_status_control_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT
            / "compat"
            / "x86_64"
            / "run_libc_fcntl_status_control.sh"
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

        self.assertIn('#[path = "descriptor_control.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "src/fcntl/fcntl.c",
            "global_asm!",
            "fcntl_no_argument",
            "fcntl_scalar",
            "fcntl_unsupported",
            "raw_syscall::SYS_FCNTL",
            "F_GETFD",
            "F_SETFD",
            "F_GETFL",
            "F_SETFL",
            "O_LARGEFILE",
            "if command == F_SETFL",
            "EINVAL",
            "rdi/rsi/rdx",
        ):
            self.assertIn(required, descriptor_control)
        for forbidden in (
            "pub unsafe extern \"C\" fn fcntl",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, descriptor_control)
        for required in (
            "#include <fcntl.h>",
            "check_descriptor_flags",
            "check_status_flags",
            "check_unsupported_commands",
            "F_GETOWN",
            "CRABC_FCNTL_STATUS_CONTROL_FREESTANDING",
            "raw_syscall3",
            "SYS_open",
            "SYS_dup",
            "SYS_close",
            "fcntl(duplicate, F_GETFD) != FD_CLOEXEC",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_fcntl_status_control_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_fcntl_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_fcntl_no_argument_path",
            "assert_fcntl_scalar_path",
            "assert_fcntl_unsupported_path",
            "assert_fixture_tls_capacity",
            "INITIAL_TLS_BYTES",
            "INITIAL_TLS_ALIGNMENT",
            "unexpectedly pulls",
            "O_LARGEFILE",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("fcntl", static_export_names)
        self.assertIn('id = "static-c-fcntl-status-control"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-fcntl-status-control"',
            parity_ledger,
        )
        self.assertIn("run_libc_fcntl_status_control()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_fcntl_status_control.sh", runner
        )
        self.assertIn(
            '    libc-fcntl-status-control)\n        [ "$#" -eq 0 ] || fail "libc-fcntl-status-control takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_fcntl_record_locks_artifact_stays_narrow(
        self,
    ) -> None:
        """The selected pointer fcntl forms retain their bounded lock ABI."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        descriptor_control = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_control.rs"
        ).read_text(encoding="utf-8")
        record_locks = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "record_locks.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_fcntl_record_locks_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_fcntl_record_locks_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_fcntl_record_locks.sh"
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

        self.assertIn('#[path = "record_locks.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "src/fcntl/fcntl.c",
            "F_GETLK",
            "F_SETLK",
            "F_SETLKW",
            "raw_syscall::SYS_FCNTL",
            "raw_syscall::syscall3(",
            "c_status(result)",
            "rdi/rsi/rdx",
            "fcntl_record_lock",
        ):
            self.assertIn(required, record_locks)
        for forbidden in (
            "fn lockf(",
            "fn flock(",
            "F_OFD_",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, record_locks)
        for required in (
            "record_locks::fcntl_record_lock",
            "cmp esi, 5",
            "cmp esi, 6",
            "F_SETLKW",
            "pointer helper",
        ):
            self.assertIn(required, descriptor_control)
        for required in (
            "#include <fcntl.h>",
            "sizeof(struct flock) == 32",
            "offsetof(struct flock, l_pid) == 24",
            "F_GETLK == 5 && F_SETLK == 6 && F_SETLKW == 7",
            "check_unlocked_query",
            "child_observes_parent_lock",
            "check_selected_record_lock_lifecycle",
            "check_unselected_blocking_form",
            "F_UNLCK",
            "EACCES && errno != EAGAIN",
            "CRABC_FCNTL_RECORD_LOCKS_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_fcntl_record_locks_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_fcntl_header_abi.sh",
            "run_x86_fcntl_getlk_reference.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_fcntl_record_lock_path",
            "fcntl_record_lock",
            "F_GETLK/F_SETLK",
            "assert_fixture_tls_capacity",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("fcntl", static_export_names)
        self.assertNotIn("lockf", static_export_names)
        self.assertIn('id = "static-c-fcntl-record-locks"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-fcntl-record-locks"',
            parity_ledger,
        )
        self.assertIn("run_libc_fcntl_record_locks_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_fcntl_record_locks.sh", runner
        )
        self.assertIn(
            '    libc-fcntl-record-locks)\n        [ "$#" -eq 0 ] || fail "libc-fcntl-record-locks takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_flock_artifact_stays_narrow(self) -> None:
        """C flock retains direct kernel semantics without widening lock support."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        flock = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "flock.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "flock_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "flock_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_flock_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_flock_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_flock_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_flock.sh"
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

        self.assertIn('#[path = "flock.rs"]', static_root)
        self.assertIn("SYS_FLOCK: i64 = 73", syscall)
        for required in (
            "musl 1.2.6 release commit",
            "src/linux/flock.c",
            "#[no_mangle]",
            'extern "C" fn flock',
            "raw_syscall::SYS_FLOCK",
            "raw_syscall::syscall2(",
            "c_status(result)",
            "rdi/rsi",
            "LOCK_SH",
            "LOCK_EX",
            "LOCK_NB",
            "LOCK_UN",
        ):
            self.assertIn(required, flock)
        for forbidden in ("fn lockf(", "SYS_FCNTL", "crabc_core", "crabc_mimalloc"):
            self.assertNotIn(forbidden, flock)
        for required in (
            "#include <sys/file.h>",
            "LOCK_SH == 1 && LOCK_EX == 2 && LOCK_NB == 4 && LOCK_UN == 8",
            "SYS_flock == 73",
            "flock_signature",
        ):
            self.assertIn(required, header_c)
        for required in (
            "#include <sys/file.h>",
            "flock_function",
            "decltype(&flock)",
            "LOCK_SH == 1 && LOCK_EX == 2 && LOCK_NB == 4 && LOCK_UN == 8",
        ):
            self.assertIn(required, header_cpp)
        for required in (
            "flock_header_abi_probe.c",
            "flock_header_abi_probe.cpp",
            "include/sys/file.h",
            "include/sys/syscall.h",
            "pinned-musl C/C++ <sys/file.h> ABI",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "#include <sys/file.h>",
            "SYS_flock == 73",
            "raw_syscall1(SYS_dup",
            "flock(file.duplicate, LOCK_UN | LOCK_NB)",
            "child_case",
            "is_lock_conflict",
            "EWOULDBLOCK",
            "EAGAIN",
            "terminate_child",
            "CRABC_FLOCK_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_flock_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_flock_header_abi.sh",
            "run_x86_flock_reference.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_flock_syscall_path",
            "flock lacks Linux syscall 73",
            "assert_fixture_tls_capacity",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("flock", static_export_names)
        self.assertNotIn("lockf", static_export_names)
        self.assertIn('id = "static-c-flock"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-flock"', parity_ledger
        )
        self.assertIn("run_flock_header_abi()", runner)
        self.assertIn("run_libc_flock_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_flock.sh", runner
        )
        self.assertIn(
            '    libc-flock)\n        [ "$#" -eq 0 ] || fail "libc-flock takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_sendfile_artifact_stays_narrow(self) -> None:
        """C sendfile preserves its offset-pointer transfer boundary."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        sendfile = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sendfile.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "sendfile_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "sendfile_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_sendfile_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_sendfile_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_sendfile_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_sendfile.sh"
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

        self.assertIn('#[path = "sendfile.rs"]', static_root)
        self.assertIn("SYS_SENDFILE: i64 = 40", syscall)
        for required in (
            "musl 1.2.6 release commit",
            "src/linux/sendfile.c",
            "#[no_mangle]",
            'extern "C" fn sendfile',
            "raw_syscall::SYS_SENDFILE",
            "raw_syscall::syscall4(",
            "c_ssize_status(result)",
            "offset: *mut c_long",
            "count: usize",
            "rdi/rsi/rdx/r10",
        ):
            self.assertIn(required, sendfile)
        for forbidden in ("fn splice(", "crabc_core", "crabc_mimalloc"):
            self.assertNotIn(forbidden, sendfile)
        for required in (
            "#include <sys/sendfile.h>",
            "sizeof(off_t) == sizeof(int64_t)",
            "sendfile_signature",
            "sendfile64_signature",
            "_LARGEFILE64_SOURCE",
        ):
            self.assertIn(required, header_c)
        for required in (
            "#include <sys/sendfile.h>",
            "sendfile_function",
            "sendfile64_function",
            "_LARGEFILE64_SOURCE",
            "decltype(&sendfile)",
        ):
            self.assertIn(required, header_cpp)
        for required in (
            "sendfile_header_abi_probe.c",
            "sendfile_header_abi_probe.cpp",
            "include/sys/sendfile.h",
            "pinned-musl C/C++ <sys/sendfile.h> ABI",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "#include <sys/sendfile.h>",
            "SYS_sendfile == 40",
            "explicit_offset",
            "current_position",
            "size_t digit_count = 0",
            "digits[digit_count++]",
            "while (digit_count)",
            "CRABC_SENDFILE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("digits[d++]", probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_sendfile_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_sendfile_header_abi.sh",
            "run_x86_sendfile_reference.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_sendfile_syscall_path",
            "sendfile lacks Linux syscall 40",
            "assert_fixture_tls_capacity",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("sendfile", static_export_names)
        self.assertIn('id = "static-c-sendfile"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sendfile"', parity_ledger
        )
        self.assertIn("run_sendfile_header_abi()", runner)
        self.assertIn("run_libc_sendfile_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_sendfile.sh", runner
        )
        self.assertIn(
            '    libc-sendfile)\n        [ "$#" -eq 0 ] || fail "libc-sendfile takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_descriptor_advice_artifact_stays_narrow(self) -> None:
        """Descriptor advice keeps POSIX and GNU error boundaries distinct."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_advice.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "descriptor_advice_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "descriptor_advice_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_descriptor_advice_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_advice_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_advice_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_descriptor_advice.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "descriptor_advice.rs"]', static_root)
        self.assertIn("SYS_FADVISE64: i64 = 221", syscall)
        self.assertIn("SYS_READAHEAD: i64 = 187", syscall)
        for required in (
            "musl 1.2.6 release commit",
            "src/fcntl/posix_fadvise.c",
            "src/linux/readahead.c",
            'extern "C" fn posix_fadvise',
            'extern "C" fn readahead',
            "raw_syscall::SYS_FADVISE64",
            "raw_syscall::SYS_READAHEAD",
            "raw_syscall::syscall4(",
            "raw_syscall::syscall3(",
            "posix_status(result)",
            "c_ssize_status(result)",
            "rdi/rsi/rdx/r10",
        ):
            self.assertIn(required, implementation)
        for forbidden in ("crabc_core", "crabc_mimalloc", "fn fallocate("):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "#include <fcntl.h>",
            "POSIX_FADV_NORMAL == 0",
            "POSIX_FADV_NOREUSE == 5",
            "posix_fadvise_signature",
            "readahead_signature",
            "CRABC_DESCRIPTOR_ADVICE_REQUIRE_READAHEAD_HIDDEN",
        ):
            self.assertIn(required, header_c)
        for required in (
            "#include <fcntl.h>",
            "decltype(&posix_fadvise)",
            "decltype(&readahead)",
            "descriptor_advice_cxx_posix_fadvise64",
            "descriptor_advice_cxx_readahead",
        ):
            self.assertIn(required, header_cpp)
        for required in (
            "c11-strict",
            "cxx17-strict",
            "c11-gnu",
            "cxx17-gnu",
            "c11-largefile64",
            "cxx17-largefile64",
            "expect_readahead_hidden",
            "features.h",
            "retained a mangled descriptor-advice reference",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "#include <fcntl.h>",
            "SYS_readahead == 187",
            "SYS_fadvise64 == 221",
            "POSIX_FADV_NOREUSE",
            "posix_fadvise(descriptor, 0, (off_t)-1",
            "readahead(descriptor, 0, (size_t)-1)",
            "errno != ERANGE",
            "errno != EDOM",
            "file_owned = 1",
            "if (file_owned && raw1(SYS_unlink",
            "CRABC_DESCRIPTOR_ADVICE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_descriptor_advice_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_descriptor_advice_header_abi.sh",
            "run_x86_fs_advice_reference.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_posix_fadvise_syscall_path",
            "posix_fadvise lacks Linux fadvise64 syscall 221",
            "assert_readahead_syscall_path",
            "readahead lacks Linux syscall 187",
            "assert_fixture_tls_capacity",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        self.assertIn("posix_fadvise", static_export_names)
        self.assertIn("readahead", static_export_names)
        self.assertNotIn("posix_fadvise64", static_export_names)
        self.assertNotIn("readahead64", static_export_names)
        self.assertIn('id = "static-c-descriptor-advice"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-descriptor-advice"',
            parity_ledger,
        )
        self.assertIn("run_descriptor_advice_header_abi()", runner)
        self.assertIn("run_libc_descriptor_advice_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_descriptor_advice.sh", runner
        )
        self.assertIn(
            '    libc-descriptor-advice)\n        [ "$#" -eq 0 ] || fail "libc-descriptor-advice takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_posix_fallocate_artifact_stays_narrow(self) -> None:
        """POSIX range allocation returns errors directly without touching errno."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        syscall = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "posix_fallocate.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "fcntl_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cpp = (
            ROOT / "compat" / "x86_64" / "fcntl_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_fcntl_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_posix_fallocate_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_posix_fallocate_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_posix_fallocate.sh"
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

        self.assertIn('#[path = "posix_fallocate.rs"]', static_root)
        self.assertIn("SYS_FALLOCATE: i64 = 285", syscall)
        for required in (
            "musl 1.2.6 release commit",
            "src/fcntl/posix_fallocate.c",
            "#[no_mangle]",
            'extern "C" fn posix_fallocate',
            "raw_syscall::SYS_FALLOCATE",
            "raw_syscall::syscall4(",
            "posix_status(result)",
            "i64::from(offset)",
            "i64::from(length)",
            "rdi/rsi/rdx/r10",
        ):
            self.assertIn(required, implementation)
        for forbidden in ("errno::set_errno", "fn fallocate(", "crabc_core", "crabc_mimalloc"):
            self.assertNotIn(forbidden, implementation)
        for required in (
            "posix_fallocate_signature",
            "posix_fallocate64_signature",
            "_LARGEFILE64_SOURCE",
        ):
            self.assertIn(required, header_c)
        for required in (
            "posix_fallocate_function",
            "posix_fallocate64_function",
            "decltype(&posix_fallocate)",
        ):
            self.assertIn(required, header_cpp)
        self.assertIn("pinned-musl C/C++ <fcntl.h> ABI", header_runner)
        for required in (
            "#include <fcntl.h>",
            "posix_fallocate",
            "RANGE_OFFSET = 4096",
            "RANGE_LENGTH = 4096",
            "8192",
            "errno != ERANGE",
            "EINVAL",
            "EBADF",
            "file_owned = 1",
            "if (file_owned && raw1(SYS_unlink",
            "CRABC_POSIX_FALLOCATE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_posix_fallocate_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_fcntl_header_abi.sh",
            "run_x86_posix_fallocate_reference.sh",
            "features.h",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_posix_fallocate_syscall_path",
            "posix_fallocate lacks Linux fallocate syscall 285",
            "assert_fixture_tls_capacity",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("posix_fallocate", static_export_names)
        self.assertIn('id = "static-c-posix-fallocate"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-posix-fallocate"', parity_ledger
        )
        self.assertIn("run_libc_posix_fallocate_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_posix_fallocate.sh", runner
        )
        self.assertIn(
            '    libc-posix-fallocate)\n        [ "$#" -eq 0 ] || fail "libc-posix-fallocate takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_posix_semaphore_artifact_stays_bounded(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "posix_semaphore.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "posix_semaphore_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "posix_semaphore_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_posix_semaphore_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_posix_semaphore_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_posix_semaphore_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_posix_semaphore.sh"
        ).read_text(encoding="utf-8")
        static_export_names = {
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

        self.assertIn('#[path = "posix_semaphore.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 unnamed POSIX semaphore boundary",
            "musl 1.2.6 release commit",
            "src/thread/sem_init.c",
            "sem_destroy.c",
            "sem_getvalue.c",
            "sem_trywait.c",
            "sem_post.c",
            "sem_timedwait.c",
            "sem_wait.c",
            "PublicSemaphore",
            "SEM_VALUE_MAX",
            "SEM_WAITER_BIT",
            "FUTEX_PRIVATE_FLAG",
            "raw_syscall::SYS_FUTEX",
            "FUTEX_WAIT",
            "FUTEX_WAKE",
            "futex_privilege",
            "trywait_raw",
            "signal-action restart",
        ):
            self.assertIn(required, implementation)
        for symbol in (
            "sem_init",
            "sem_destroy",
            "sem_getvalue",
            "sem_trywait",
            "sem_wait",
            "sem_post",
        ):
            self.assertIn(f"fn {symbol}(", implementation)
        for forbidden in (
            "fn sem_timedwait(",
            "fn sem_open(",
            "fn sem_close(",
            "fn sem_unlink(",
            "crabc_core",
            "crabc_mimalloc",
            "pthread_",
        ):
            self.assertNotIn(forbidden, implementation)

        for header_probe in (header_c_probe, header_cxx_probe):
            for required in (
                "semaphore.h",
                "sizeof(sem_t) == 32",
                "volatile int",
                "timespec",
                "sem_timedwait",
                "sem_open",
            ):
                self.assertIn(required, header_probe)
        self.assertIn("_Alignof(sem_t) == 4", header_c_probe)
        self.assertIn("alignof(sem_t) == 4", header_cxx_probe)
        for required in (
            "ORACLE_CC",
            "semaphore.h",
            "posix_semaphore_header_abi_probe.c",
            "posix_semaphore_header_abi_probe.cpp",
            "mangled POSIX semaphore reference",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <semaphore.h>",
            "sizeof(sem_t) == 32",
            "volatile int",
            "sem_init(&semaphore, 0, 2)",
            "EAGAIN",
            "EOVERFLOW",
            "MAP_SHARED | MAP_ANONYMOUS",
            "SYS_mmap",
            "SYS_fork",
            "SYS_wait4",
            "CRABC_POSIX_SEMAPHORE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_posix_semaphore_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)
        self.assertNotIn("mov %rsi, %fs:0", start)

        for required in (
            "static_c_abi_exports.txt",
            "run_posix_semaphore_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "__errno_location",
            "futex=202",
            "sem_wait-disassembly",
            "sem_post-disassembly",
            "MAP_SHARED",
            "unowned runtime dependency",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        selected = {
            "sem_destroy",
            "sem_getvalue",
            "sem_init",
            "sem_post",
            "sem_trywait",
            "sem_wait",
        }
        self.assertTrue(selected <= static_export_names)
        self.assertFalse(
            static_export_names
            & {"sem_close", "sem_open", "sem_timedwait", "sem_unlink"}
        )
        self.assertIn('id = "static-c-posix-semaphore"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-posix-semaphore"',
            parity_ledger,
        )
        self.assertIn("run_posix_semaphore_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_posix_semaphore_header_abi.sh", runner
        )
        self.assertIn("run_libc_posix_semaphore()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_posix_semaphore.sh", runner
        )
        self.assertIn(
            '    posix-semaphore-header-abi)\n        [ "$#" -eq 0 ] || fail "posix-semaphore-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-posix-semaphore)\n        [ "$#" -eq 0 ] || fail "libc-posix-semaphore takes no arguments"',
            runner,
        )

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

    def test_libc_static_c_abi_sysv_message_shared_memory_artifact_stays_bounded(
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
            / "sysv_message_shared_memory.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT
            / "compat"
            / "x86_64"
            / "sysv_message_shared_memory_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT
            / "compat"
            / "x86_64"
            / "sysv_message_shared_memory_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT
            / "compat"
            / "x86_64"
            / "run_sysv_message_shared_memory_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_sysv_message_shared_memory_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_sysv_message_shared_memory_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_sysv_message_shared_memory.sh"
        ).read_text(encoding="utf-8")
        static_export_names = {
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

        self.assertIn('#[path = "sysv_message_shared_memory.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 System V message-queue/shared-memory C boundary",
            "musl 1.2.6 release commit",
            "src/ipc/ftok.c",
            "src/ipc/msgget.c",
            "src/ipc/shmget.c",
            "arch/x86_64/syscall_arch.h",
            "IPC_64",
            "IPC_TIME64",
            "ipc_command",
            "stat_device_and_inode",
            "SYS_MSGGET",
            "SYS_MSGSND",
            "SYS_MSGRCV",
            "SYS_MSGCTL",
            "SYS_SHMGET",
            "SYS_SHMAT",
            "SYS_SHMDT",
            "SYS_SHMCTL",
            "c_pointer_status",
            "c_ssize_status",
            "isize::MAX",
            "usize::MAX",
            "(void *)-1",
            "cancellation",
        ):
            self.assertIn(required, implementation)
        for symbol in (
            "ftok",
            "msgget",
            "msgsnd",
            "msgrcv",
            "msgctl",
            "shmget",
            "shmat",
            "shmdt",
            "shmctl",
        ):
            self.assertIn(f"fn {symbol}(", implementation)
        for forbidden in ("mq_open", "sem_open", "__tls_get_addr", "pthread_"):
            self.assertNotIn(forbidden, implementation)

        for header_probe in (header_c_probe, header_cxx_probe):
            for required in (
                "sys/ipc.h",
                "sys/msg.h",
                "sys/shm.h",
                "struct ipc_perm",
                "struct msqid_ds",
                "struct msginfo",
                "struct shmid_ds",
                "struct shminfo",
                "struct shm_info",
                "msgbuf",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "EXPECTED_PROFILE_COUNT=8",
            "STRICT_IPC_PROFILES",
            "STRICT_MSGBUF_PROFILES",
            "NON_GNU_SHM_PROFILES",
            "sys/msg.h",
            "sys/shm.h",
            "C++ probe",
            "mangled SysV IPC reference",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <sys/msg.h>",
            "#include <sys/shm.h>",
            "CRABC_SECCOMP_ARGUMENT_THREE_LOW",
            "CRABC_SECCOMP_ARGUMENT_FOUR_LOW",
            "SYS_seccomp",
            "msgsnd(message_queue_id",
            "msgrcv(message_queue_id",
            "PTRDIFF_MAX",
            "SIZE_MAX",
            "(void *)-1",
            "shmat(removed_shared_memory_id",
            "CRABC_SYSV_MESSAGE_SHARED_MEMORY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_sysv_message_shared_memory_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "static_c_abi_exports.txt",
            "run_sysv_message_shared_memory_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall msgget 44",
            "assert_named_syscall msgsnd 45",
            "assert_named_syscall msgrcv 46",
            "assert_named_syscall msgctl 47",
            "assert_named_syscall shmget 1d",
            "assert_named_syscall shmat 1e",
            "assert_named_syscall shmdt 43",
            "assert_named_syscall shmctl 1f",
            "assert_x86_message_register_paths",
            "unselected in mq_close",
            "unowned runtime dependency",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)

        expected_symbols = {
            "ftok",
            "msgget",
            "msgsnd",
            "msgrcv",
            "msgctl",
            "shmget",
            "shmat",
            "shmdt",
            "shmctl",
        }
        self.assertTrue(expected_symbols <= static_export_names)
        self.assertFalse(
            static_export_names
            & {
                "mq_close",
                "mq_getattr",
                "mq_notify",
                "mq_open",
                "mq_receive",
                "mq_send",
                "mq_setattr",
                "mq_timedreceive",
                "mq_timedsend",
                "mq_unlink",
                "sem_close",
                "sem_open",
            }
        )
        self.assertIn('id = "static-c-sysv-message-shared-memory"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-sysv-message-shared-memory"',
            parity_ledger,
        )
        self.assertIn("run_sysv_message_shared_memory_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_sysv_message_shared_memory_header_abi.sh",
            runner,
        )
        self.assertIn("run_libc_sysv_message_shared_memory()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_sysv_message_shared_memory.sh",
            runner,
        )
        self.assertIn(
            '    sysv-message-shared-memory-header-abi)\n        [ "$#" -eq 0 ] || fail "sysv-message-shared-memory-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-sysv-message-shared-memory)\n        [ "$#" -eq 0 ] || fail "libc-sysv-message-shared-memory takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_event_descriptors_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "event_descriptors.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "event_descriptors_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "event_descriptors_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_event_descriptors_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_event_descriptors_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_event_descriptors_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_event_descriptors.sh"
        ).read_text(encoding="utf-8")
        static_export_names = {
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

        self.assertIn('#[path = "event_descriptors.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 event-descriptor C boundary",
            "musl 1.2.6 release commit",
            "src/linux/epoll.c",
            "src/linux/eventfd.c",
            "src/linux/inotify.c",
            "EpollEvent",
            "size_of::<EpollEvent>() == 12",
            "align_of::<EpollEvent>() == 1",
            "offset_of!(EpollEvent, data) == 4",
            "KERNEL_SIGSET_SIZE",
            "raw_syscall::SYS_EPOLL_CREATE1",
            "raw_syscall::SYS_EPOLL_CTL",
            "raw_syscall::SYS_EPOLL_PWAIT",
            "raw_syscall::SYS_EVENTFD2",
            "raw_syscall::SYS_INOTIFY_INIT1",
            "raw_syscall::SYS_INOTIFY_ADD_WATCH",
            "raw_syscall::SYS_INOTIFY_RM_WATCH",
            "r10/r8/r9 respectively",
            "eight-byte signal",
            "Linux 5.10",
            "ENOSYS",
            "cancellation-point",
        ):
            self.assertIn(required, implementation)
        for symbol in (
            "epoll_create",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "epoll_pwait",
            "eventfd",
            "eventfd_read",
            "eventfd_write",
            "inotify_init",
            "inotify_init1",
            "inotify_add_watch",
            "inotify_rm_watch",
        ):
            self.assertIn(f"fn {symbol}(", implementation)
        for forbidden in (
            "fn epoll_pwait2(",
            "fn timerfd_create(",
            "fn signalfd(",
            "fn fanotify_init(",
            "fn aio_read(",
            "fn pthread_",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, implementation)

        for header_probe in (header_c_probe, header_cxx_probe):
            for required in (
                "sys/eventfd.h",
                "sys/inotify.h",
                "eventfd_t",
                "inotify_event",
                "eventfd",
                "eventfd_read",
                "eventfd_write",
                "inotify_init",
                "inotify_init1",
                "inotify_add_watch",
                "inotify_rm_watch",
                "IN_IGNORED",
            ):
                self.assertIn(required, header_probe)
        # The profile runner now retains header-derived function references and
        # checks their undefined ELF spellings with `nm`; handwritten C++
        # redeclarations would no longer prove the header's own linkage.
        self.assertIn("eventfd_cxx_eventfd = eventfd", header_cxx_probe)
        self.assertIn("inotify_cxx_init = inotify_init", header_cxx_probe)
        for required in (
            "EXPECTED_PROFILE_COUNT=8",
            "c-default c11-gnu cxx17-gnu",
            "c11-posix-2008",
            "-nostdinc",
            "-nostdinc++",
            "run_musl_oracle.sh",
            "sys/eventfd.h",
            "sys/inotify.h",
            "compile-only",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <sys/epoll.h>",
            "#include <sys/eventfd.h>",
            "#include <sys/inotify.h>",
            "check_eventfd",
            "check_epoll",
            "check_inotify",
            "EFD_SEMAPHORE",
            "UINT64_MAX",
            "EPOLL_CTL_ADD",
            "modified_token",
            "install_epoll_pwait_signal_argument_filter",
            "CRABC_SECCOMP_ARGUMENT_FOUR_LOW",
            "CRABC_SECCOMP_ARGUMENT_FIVE_LOW",
            "filter[3].immediate",
            "filter[5].immediate",
            "SYS_seccomp",
            "read_created_event",
            "read_ignored_event",
            "CRABC_EVENT_DESCRIPTORS_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_event_descriptors_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "static_c_abi_exports.txt",
            "run_epoll_header_abi.sh",
            "run_event_descriptors_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall epoll_create 123",
            "assert_named_syscall epoll_ctl e9",
            "assert_named_syscall epoll_pwait 119",
            "assert_named_syscall eventfd 122",
            "assert_named_zero_syscall eventfd_read",
            "assert_named_syscall eventfd_write 1",
            "assert_named_syscall inotify_init1 126",
            "assert_named_syscall inotify_add_watch fe",
            "assert_named_syscall inotify_rm_watch ff",
            "assert_x86_event_descriptor_register_paths",
            "for unselected in epoll_pwait2",
            "event-descriptor candidate unexpectedly pulls",
            "unowned runtime dependency",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)

        expected_symbols = {
            "epoll_create",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "epoll_pwait",
            "eventfd",
            "eventfd_read",
            "eventfd_write",
            "inotify_init",
            "inotify_init1",
            "inotify_add_watch",
            "inotify_rm_watch",
        }
        self.assertTrue(expected_symbols <= static_export_names)
        self.assertFalse(
            static_export_names
            & {
                "epoll_pwait2",
                "signalfd4",
                "fanotify_init",
                "fanotify_mark",
                "aio_read",
                "aio_write",
                "io_setup",
                "io_submit",
            }
        )
        self.assertIn('id = "static-c-event-descriptors"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-event-descriptors"',
            parity_ledger,
        )
        self.assertIn("run_event_descriptors_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_event_descriptors_header_abi.sh",
            runner,
        )
        self.assertIn("run_libc_event_descriptors()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_event_descriptors.sh",
            runner,
        )
        self.assertIn(
            '    event-descriptors-header-abi)\n        [ "$#" -eq 0 ] || fail "event-descriptors-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-event-descriptors)\n        [ "$#" -eq 0 ] || fail "libc-event-descriptors takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pathname_lifecycle_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pathname_lifecycle.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "pathname_lifecycle_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "pathname_lifecycle_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_pathname_lifecycle_header_abi.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_pathname_lifecycle_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_pathname_lifecycle_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_pathname_lifecycle.sh"
        ).read_text(encoding="utf-8")
        static_export_names = {
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

        self.assertIn('#[path = "pathname_lifecycle.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 pathname-mutation C boundary",
            "musl 1.2.6 release commit",
            "src/unistd/chdir.c",
            "src/stat/chmod.c",
            "src/stdio/remove.c",
            "src/internal/procfdname.c",
            "PROC_FD_PREFIX",
            "PROC_FD_NAME_SIZE",
            "procfdname",
            "EISDIR",
            "EBADF",
            "F_GETFD",
            "null-buffer extension",
            "no C allocator boundary",
            "Linux 5.10",
            "raw_syscall::SYS_CHDIR",
            "raw_syscall::SYS_GETCWD",
            "raw_syscall::SYS_MKDIR",
            "raw_syscall::SYS_UNLINK",
            "raw_syscall::SYS_RMDIR",
            "raw_syscall::SYS_RENAME",
            "raw_syscall::SYS_LINK",
            "raw_syscall::SYS_SYMLINK",
            "raw_syscall::SYS_READLINK",
            "raw_syscall::SYS_CHMOD",
            "raw_syscall::SYS_FCHMOD",
            "raw_syscall::SYS_TRUNCATE",
            "raw_syscall::SYS_FCNTL",
        ):
            self.assertIn(required, implementation)
        for symbol in (
            "chdir",
            "getcwd",
            "mkdir",
            "unlink",
            "rmdir",
            "remove",
            "rename",
            "link",
            "symlink",
            "readlink",
            "chmod",
            "fchmod",
            "truncate",
        ):
            self.assertIn(f"fn {symbol}(", implementation)
        for forbidden in (
            "fn fchdir(",
            "fn chroot(",
            "fn realpath(",
            "fn renameat(",
            "fn renameat2(",
            "fn unlinkat(",
            "fn linkat(",
            "fn symlinkat(",
            "fn readlinkat(",
            "fn mkdirat(",
            "fn fchmodat(",
            "fn lchmod(",
            "fn opendir(",
            "fn readdir(",
            "fn scandir(",
            "fn getdents(",
            "fn malloc(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, implementation)

        for header_probe in (header_c_probe, header_cxx_probe):
            for required in (
                "fcntl.h",
                "stdio.h",
                "sys/stat.h",
                "sys/types.h",
                "unistd.h",
                "size_t",
                "ssize_t",
                "off_t",
                "mode_t",
                "F_GETFD",
                "O_PATH",
                "S_IFREG",
                "chdir",
                "getcwd",
                "mkdir",
                "unlink",
                "rmdir",
                "remove",
                "rename",
                "link",
                "symlink",
                "readlink",
                "chmod",
                "fchmod",
                "truncate",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "EXPECTED_PROFILE_COUNT=8",
            "c-default c11-gnu cxx17-gnu",
            "CXX_SYMBOLS=(chdir getcwd mkdir unlink rmdir remove rename link",
            "-nostdinc",
            "-nostdinc++",
            "check_cxx_symbols",
            "mangled pathname-lifecycle reference",
            "run_musl_oracle.sh",
            "fcntl.h stdio.h sys/stat.h sys/types.h unistd.h",
            "compile-only",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "#include <fcntl.h>",
            "#include <stdio.h>",
            "#include <sys/stat.h>",
            "#include <sys/syscall.h>",
            "#include <sys/types.h>",
            "#include <unistd.h>",
            "check_getcwd_extension",
            "CRABC_PATHNAME_LIFECYCLE_FREESTANDING",
            "getcwd(0, 0) == 0 && errno == EINVAL",
            "allocated = getcwd(0, 0)",
            "mkdir(root, 0700)",
            "readlink(symbolic, 0, 0)",
            "link(file, hard)",
            "symlink(file, symbolic)",
            "rename(file, renamed)",
            "O_PATH | O_CLOEXEC",
            "fchmod(path_only, 0644)",
            "truncate(renamed, 7)",
            "remove(empty_directory)",
            "remove's EISDIR retry",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_pathname_lifecycle_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "static_c_abi_exports.txt",
            "run_pathname_lifecycle_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall chdir 50",
            "assert_named_syscall getcwd 4f",
            "assert_named_syscall mkdir 53",
            "assert_named_syscall unlink 57",
            "assert_named_syscall rmdir 54",
            "assert_remove_retry_path",
            "assert_named_syscall rename 52",
            "assert_named_syscall link 56",
            "assert_named_syscall symlink 58",
            "assert_named_syscall readlink 59",
            "assert_named_syscall chmod 5a",
            "assert_fchmod_fallback_path",
            "assert_named_syscall truncate 4c",
            "for unselected in fchdir",
            "unowned runtime dependency",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)

        expected_symbols = {
            "chdir",
            "getcwd",
            "mkdir",
            "unlink",
            "rmdir",
            "remove",
            "rename",
            "link",
            "symlink",
            "readlink",
            "chmod",
            "fchmod",
            "truncate",
        }
        self.assertTrue(expected_symbols <= static_export_names)
        self.assertFalse(
            static_export_names
            & {
                "fchdir",
                "chroot",
                "realpath",
                "renameat",
                "renameat2",
                "unlinkat",
                "linkat",
                "symlinkat",
                "readlinkat",
                "mkdirat",
                "fchmodat",
                "scandir",
            }
        )
        self.assertIn('id = "static-c-pathname-lifecycle"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-pathname-lifecycle"',
            parity_ledger,
        )
        self.assertIn("run_pathname_lifecycle_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_pathname_lifecycle_header_abi.sh",
            runner,
        )
        self.assertIn("run_libc_pathname_lifecycle()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_pathname_lifecycle.sh",
            runner,
        )
        self.assertIn(
            '    pathname-lifecycle-header-abi)\n        [ "$#" -eq 0 ] || fail "pathname-lifecycle-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-pathname-lifecycle)\n        [ "$#" -eq 0 ] || fail "libc-pathname-lifecycle takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_extended_attributes_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "extended_attributes.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_extended_attributes_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_extended_attributes_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_extended_attributes.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_xattr_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_export_names = {
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

        symbols = (
            "setxattr",
            "lsetxattr",
            "fsetxattr",
            "getxattr",
            "lgetxattr",
            "fgetxattr",
            "listxattr",
            "llistxattr",
            "flistxattr",
            "removexattr",
            "lremovexattr",
            "fremovexattr",
        )
        self.assertIn('#[path = "extended_attributes.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 C extended-attribute boundary",
            "musl 1.2.6 release commit",
            "src/linux/xattr.c",
            "cancellation-point",
            "Linux 5.10",
            "initial-TLS C `errno`",
        ):
            self.assertIn(required, implementation)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}", implementation)
            self.assertIn(symbol, static_export_names)
        self.assertFalse(
            static_export_names
            & {
                "setxattrat",
                "lsetxattrat",
                "fsetxattrat",
                "getxattrat",
                "lgetxattrat",
                "fgetxattrat",
                "listxattrat",
                "llistxattrat",
                "flistxattrat",
                "removexattrat",
                "lremovexattrat",
                "fremovexattrat",
            }
        )

        for required in (
            "#include <sys/xattr.h>",
            "SYS_setxattr == 188",
            "SYS_fremovexattr == 199",
            "XATTR_CREATE == 1 && XATTR_REPLACE == 2",
            "XATTR_PATH",
            "XATTR_NOFOLLOW_PATH",
            "XATTR_DESCRIPTOR",
            "CRABC_XATTR_UNAVAILABLE",
            "EOPNOTSUPP",
            "ENOSYS",
            "ERANGE",
            "EEXIST",
            "ENODATA",
            "EINVAL",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_extended_attributes_probe",
            "mov $231, %eax",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_xattr_header_abi.sh",
            "-nostdlib -static",
            "R_X86_64_TPOFF",
            "assert_named_syscall setxattr bc",
            "assert_named_syscall lsetxattr bd",
            "assert_named_syscall fsetxattr be",
            "assert_named_syscall getxattr bf",
            "assert_named_syscall lgetxattr c0",
            "assert_named_syscall fgetxattr c1",
            "assert_named_syscall listxattr c2",
            "assert_named_syscall llistxattr c3",
            "assert_named_syscall flistxattr c4",
            "assert_named_syscall removexattr c5",
            "assert_named_syscall lremovexattr c6",
            "assert_named_syscall fremovexattr c7",
            "candidate_branch",
            "unowned runtime dependency",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "EXPECTED_PROFILE_COUNT=11",
            "sys/xattr.h",
            "setxattr lsetxattr fsetxattr",
            "getxattr lgetxattr fgetxattr",
            "listxattr llistxattr flistxattr",
            "removexattr lremovexattr fremovexattr",
            "C++ probe does not retain C linkage",
        ):
            self.assertIn(required, header_runner)

        self.assertIn('id = "static-c-extended-attributes"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-extended-attributes"',
            parity_ledger,
        )
        self.assertIn("run_xattr_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_xattr_header_abi.sh", runner
        )
        self.assertIn("run_libc_extended_attributes()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_extended_attributes.sh", runner
        )
        self.assertIn(
            '    xattr-header-abi)\n        [ "$#" -eq 0 ] || fail "xattr-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-extended-attributes)\n        [ "$#" -eq 0 ] || fail "libc-extended-attributes takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_directory_streams_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "directory_streams.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_directory_streams_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_directory_streams_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_directory_streams.sh"
        ).read_text(encoding="utf-8")
        static_export_names = {
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

        self.assertIn('#[path = "directory_streams.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 C directory-stream boundary",
            "musl 1.2.6 release commit",
            "src/dirent/opendir.c",
            "fdopendir.c",
            "readdir_r.c",
            "versionsort.c",
            "strverscmp.c",
            "posix_getdents.c",
            "private anonymous 4 KiB mapping",
            "C.UTF-8",
            "getdents64",
            "ENOENT",
            "EIO",
            "EOPNOTSUPP",
            "O_PATH",
            "FD_CLOEXEC",
        ):
            self.assertIn(required, implementation)
        for symbol in (
            "opendir",
            "fdopendir",
            "closedir",
            "dirfd",
            "readdir",
            "readdir_r",
            "rewinddir",
            "seekdir",
            "telldir",
            "alphasort",
            "versionsort",
            "getdents",
            "posix_getdents",
        ):
            self.assertIn(f"fn {symbol}", implementation)
            self.assertIn(symbol, static_export_names)
        for forbidden in ("fn scandir", "fn malloc", "fn free"):
            self.assertNotIn(forbidden, implementation)
        self.assertIn("byte_strings::strverscmp", implementation)
        self.assertIn("strverscmp", static_export_names)
        self.assertFalse(
            static_export_names & {"scandir", "malloc", "free"}
        )

        for required in (
            "#include <dirent.h>",
            "SYS_getdents64 == 217",
            "O_DIRECTORY == 0x00010000",
            "check_readdir_stream",
            "check_readdir_r",
            "check_fdopendir",
            "check_getdents",
            "check_alphasort",
            "check_versionsort",
            "foobar-1.1.2",
            "CRABC_DIRECTORY_STREAMS_FREESTANDING",
            "255",
            "EOPNOTSUPP",
        ):
            self.assertIn(required, probe)
        for required in (
            "call __crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_directory_streams_probe",
            "exit_group",
        ):
            self.assertIn(required, start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "run_dirent_header_abi.sh",
            "-nostdlib -static",
            "R_X86_64_TPOFF",
            "assert_named_syscall opendir 101",
            "assert_named_syscall fdopendir 5",
            "assert_named_syscall fdopendir 48",
            "assert_named_syscall fdopendir 9",
            "assert_named_syscall closedir 3",
            "assert_named_syscall closedir b",
            "assert_named_syscall readdir d9",
            "assert_named_syscall rewinddir 8",
            "assert_named_syscall seekdir 8",
            "assert_named_syscall getdents d9",
            "assert_named_syscall posix_getdents d9",
            "scandir malloc free calloc realloc",
            "unowned runtime dependency",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)

        self.assertIn('id = "static-c-directory-streams"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-directory-streams"',
            parity_ledger,
        )
        self.assertIn("run_libc_directory_streams()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_directory_streams.sh", runner
        )
        self.assertIn(
            '    libc-directory-streams)\n        [ "$#" -eq 0 ] || fail "libc-directory-streams takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_ffs_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        ffs = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ffs.rs").read_text(
            encoding="utf-8"
        )
        strings_header = (ROOT / "include" / "strings.h").read_text(encoding="utf-8")
        probe = (ROOT / "compat" / "x86_64" / "libc_ffs_probe.c").read_text(
            encoding="utf-8"
        )
        artifact_runner = (ROOT / "compat" / "x86_64" / "run_libc_ffs.sh").read_text(
            encoding="utf-8"
        )
        header_runner = (ROOT / "compat" / "x86_64" / "run_ffs_header_abi.sh").read_text(
            encoding="utf-8"
        )
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

        symbols = ("ffs", "ffsl", "ffsll")
        self.assertIn('#[path = "ffs.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", ffs)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/misc/ffs.c",
            "src/misc/ffsl.c",
            "src/misc/ffsll.c",
            "src/internal/atomic.h",
            "stateless",
            "allocation-free",
            "trailing_zeros",
            "two's-complement",
        ):
            self.assertIn(required, ffs)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn strtol(",
            "__tls_get_addr",
            "fn fls(",
        ):
            self.assertNotIn(forbidden, ffs)
        for required in (
            "#include <strings.h>",
            "ffs_fn",
            "ffsl_fn",
            "ffsll_fn",
            "first_set_u32",
            "first_set_u64",
            "-2147483647",
            "CRABC_FFS_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains TLS",
            "fixed-locale case comparison",
            "strings.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_FFS",
            "CRABC_REQUIRE_FFS_HIDDEN",
            "-U_GNU_SOURCE",
            "-std=c++17",
            "nm --undefined-only",
            "strings.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('extern "C" {', strings_header)
        self.assertIn('id = "static-c-ffs"', parity_ledger)
        self.assertIn('command = "./scripts/dev-x86_64.sh libc-ffs"', parity_ledger)
        self.assertIn("libc-ffs", runner)

    def test_libc_static_c_abi_gethostid_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "gethostid.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_gethostid_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_gethostid_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_gethostid.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_gethostid_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "gethostid_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "gethostid_header_abi_probe.cpp"
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

        self.assertIn('#[path = "gethostid.rs"]', static_root)
        for required in (
            "Selected static Linux/x86-64 `gethostid` C ABI",
            "musl 1.2.6 release commit",
            "src/misc/gethostid.c::gethostid",
            "deterministic zero host identifier",
            "System V AMD64 ABI",
            'pub extern "C" fn gethostid() -> c_long',
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "raw_syscall::",
            "errno::",
            "uts_identity::",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, implementation)
        self.assertIn("gethostid", static_exports)
        self.assertEqual(
            {symbol for symbol in static_exports if symbol.startswith("gethostid")},
            {"gethostid"},
        )

        for required in (
            "#include <unistd.h>",
            "sizeof(long) == 8",
            "long (*)(void)",
            "const gethostid_signature function = gethostid",
            "gethostid() != 0L",
            "function() != 0L",
            "CRABC_GETHOSTID_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "crabc_x86_64_gethostid_probe",
            "mov $60, %eax",
        ):
            self.assertIn(required, start)

        for header in (header_c, header_cxx):
            for required in (
                "gethostid declaration",
                "gethostid_must_be_hidden",
                "CRABC_REQUIRE_GETHOSTID_HIDDEN",
            ):
                self.assertIn(required, header)
        for required in (
            "gethostid_header_abi_probe.c",
            "gethostid_header_abi_probe.cpp",
            "-D_XOPEN_SOURCE=700",
            "-D_GNU_SOURCE",
            "-D_BSD_SOURCE",
            "-D_POSIX_C_SOURCE=200809L",
            "nm --undefined-only",
            "retained a mangled gethostid reference",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "run_gethostid_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "--disassemble=gethostid",
            "gethostid candidate unexpectedly retains TLS",
            "gethostid unexpectedly performs a call or syscall",
            "candidate selects UTS, secure-execution, or system-configuration behavior",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn('id = "static-c-gethostid"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-gethostid"',
            parity_ledger,
        )
        self.assertIn("run_gethostid_header_abi()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_gethostid_header_abi.sh", runner
        )
        self.assertIn("run_libc_gethostid_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_gethostid.sh", runner
        )
        self.assertIn(
            '    gethostid-header-abi)\n        [ "$#" -eq 0 ] || fail "gethostid-header-abi takes no arguments"',
            runner,
        )
        self.assertIn(
            '    libc-gethostid)\n        [ "$#" -eq 0 ] || fail "libc-gethostid takes no arguments"',
            runner,
        )

    def test_libc_thread_pointer_probe_stays_a_private_opaque_fs_leaf(self) -> None:
        rust_probe = (
            ROOT / "compat" / "x86_64" / "libc_thread_pointer_probe.rs"
        ).read_text(encoding="utf-8")
        thread_pointer = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "thread_pointer.rs"
        ).read_text(encoding="utf-8")
        c_probe = (
            ROOT / "compat" / "x86_64" / "libc_thread_pointer_probe.c"
        ).read_text(encoding="utf-8")
        script = (
            ROOT / "compat" / "x86_64" / "run_libc_thread_pointer.sh"
        ).read_text(encoding="utf-8")

        self.assertIn('libc/src/c_abi/x86_64/thread_pointer.rs', rust_probe)
        self.assertIn('pthread_arch.h::__get_tp()', thread_pointer)
        self.assertIn('9fa28ece75d8a2191de7c5bb53bed224c5947417', thread_pointer)
        self.assertIn("musl's MIT license", thread_pointer)
        self.assertIn('pub(crate) unsafe fn thread_pointer_identity()', thread_pointer)
        self.assertIn('options(readonly, nostack, preserves_flags)', thread_pointer)
        self.assertNotIn('#[no_mangle]', thread_pointer)
        self.assertIn('crabc_x86_64_thread_pointer_probe', c_probe)
        self.assertIn('inline_fs0', c_probe)
        self.assertIn('pthread_create', c_probe)
        self.assertNotIn('pthread_self', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('/usr/local/bin/crabc-x86_64-musl-gcc', script)
        self.assertIn('%fs:0x0', script)
        self.assertIn('R_X86_64_(TPOFF', script)
        self.assertIn('__tls_get_addr', script)
        self.assertIn('-no-pie -pthread', script)
        self.assertNotIn('-I"$ROOT_DIR/include"', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_libc_foundation_probe_composes_only_the_narrow_x86_primitives(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_foundation_probe.rs").read_text(
            encoding="utf-8"
        )
        foundation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "foundation.rs"
        ).read_text(encoding="utf-8")
        c_probe = (ROOT / "compat" / "x86_64" / "libc_foundation_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_foundation.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/foundation.rs', rust_probe)
        self.assertIn('crabc_x86_64_foundation_syscall6', foundation)
        self.assertIn('raw_syscall::syscall6', foundation)
        self.assertIn('errno::set_errno', foundation)
        self.assertIn('target_arch = "x86_64"', foundation)
        self.assertNotIn('pub unsafe extern "C" fn syscall(', foundation)
        self.assertIn('crabc_x86_64_foundation_syscall6(', c_probe)
        self.assertIn('FE_INVALID', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('R_X86_64_TPOFF', script)
        self.assertIn('fno-builtin', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_clone_signal_and_umask_slices_remain_private_or_typed(self) -> None:
        clone = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clone.rs").read_text(
            encoding="utf-8"
        )
        clone_probe = (ROOT / "compat" / "x86_64" / "libc_clone_raw_probe.c").read_text(
            encoding="utf-8"
        )
        clone_runner = (ROOT / "compat" / "x86_64" / "run_libc_clone_raw.sh").read_text(
            encoding="utf-8"
        )
        signal = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_foundation.rs"
        ).read_text(encoding="utf-8")
        signal_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_signal_foundation.sh"
        ).read_text(encoding="utf-8")
        setrlimit_probe = (
            ROOT / "compat" / "x86_64" / "x86_setrlimit_reference_probe.c"
        ).read_text(encoding="utf-8")
        setrlimit_runner = (
            ROOT / "compat" / "x86_64" / "run_x86_setrlimit_reference.sh"
        ).read_text(encoding="utf-8")
        setrlimit_test = (
            ROOT / "crabc-rs" / "tests" / "x86_64_setrlimit.rs"
        ).read_text(encoding="utf-8")
        setpriority_probe = (
            ROOT / "compat" / "x86_64" / "x86_setpriority_reference_probe.c"
        ).read_text(encoding="utf-8")
        setpriority_runner = (
            ROOT / "compat" / "x86_64" / "run_x86_setpriority_reference.sh"
        ).read_text(encoding="utf-8")
        setpriority_test = (
            ROOT / "crabc-rs" / "tests" / "x86_64_setpriority.rs"
        ).read_text(encoding="utf-8")
        umask_probe = (
            ROOT / "compat" / "x86_64" / "x86_umask_reference_probe.c"
        ).read_text(encoding="utf-8")
        umask_runner = (
            ROOT / "compat" / "x86_64" / "run_x86_umask_reference.sh"
        ).read_text(encoding="utf-8")
        umask_test = (ROOT / "crabc-rs" / "tests" / "x86_64_umask.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn("src/thread/x86_64/clone.s", clone)
        self.assertIn("__crabc_x86_clone_raw", clone)
        self.assertNotIn('fn clone(', clone)
        self.assertIn("CRABC_CLONE_ORACLE", clone_probe)
        self.assertIn("SIGCHLD", clone_probe)
        self.assertIn("run_musl_oracle.sh", clone_runner)
        self.assertIn(".note.GNU-stack", clone_runner)
        self.assertNotIn("-p crabc-libc", clone_runner)

        self.assertIn("src/signal/sigaction.c", signal)
        self.assertIn("SA_RESTORER", signal)
        self.assertIn("crabc_x86_64_signal_restorer", signal)
        self.assertIn("read_unaligned", signal)
        self.assertIn("flags as i64 as u64", signal)
        self.assertIn("run_signal_header_abi.sh", signal_runner)
        self.assertIn("run_musl_oracle.sh", signal_runner)
        self.assertNotIn("-p crabc-libc", signal_runner)

        self.assertIn("SYS_prlimit64 == 302", setrlimit_probe)
        self.assertIn("run_in_child", setrlimit_probe)
        self.assertIn("raw-set:musl-read:musl-restore:raw-read", setrlimit_probe)
        self.assertIn("run_musl_oracle.sh", setrlimit_runner)
        self.assertNotIn("-p crabc-libc", setrlimit_runner)
        self.assertIn("RestoreRlimit", setrlimit_test)
        self.assertIn("process::setrlimit", setrlimit_test)
        self.assertIn("x86_64_setrlimit_child_mutates_and_restores", setrlimit_test)
        self.assertIn("#[ignore", setrlimit_test)
        self.assertIn('"--ignored"', setrlimit_test)
        self.assertNotIn("CRABC_RS_X86_64_SETRLIMIT_CHILD", setrlimit_test)

        self.assertIn("SYS_setpriority == 141", setpriority_probe)
        self.assertIn("run_in_child", setpriority_probe)
        self.assertIn("raw-set:musl-read:musl-noop:raw-read", setpriority_probe)
        self.assertIn("raw_setpriority(PRIO_PGRP", setpriority_probe)
        self.assertIn("raw_setpriority(PRIO_USER", setpriority_probe)
        self.assertIn("run_musl_oracle.sh", setpriority_runner)
        self.assertNotIn("-p crabc-libc", setpriority_runner)
        self.assertIn("process::setpriority_process", setpriority_test)
        self.assertIn("process::setpriority_process_group", setpriority_test)
        self.assertIn("process::setpriority_user", setpriority_test)
        self.assertIn("x86_64_setpriority_child_mutates_only_the_calling_process", setpriority_test)
        self.assertIn("#[ignore", setpriority_test)
        self.assertIn('"--ignored"', setpriority_test)

        self.assertIn("SYS_umask == 95", umask_probe)
        self.assertIn("run_in_child", umask_probe)
        self.assertIn("run_musl_oracle.sh", umask_runner)
        self.assertIn("RestoreUmask", umask_test)
        self.assertIn("process::umask", umask_test)

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

    def test_libc_fenv_probe_is_a_fixed_source_only_x87_mxcsr_boundary(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_fenv_probe.rs").read_text(
            encoding="utf-8"
        )
        fenv = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "fenv.rs").read_text(
            encoding="utf-8"
        )
        c_probe = (ROOT / "compat" / "x86_64" / "libc_fenv_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_fenv.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/fenv.rs', rust_probe)
        self.assertIn('musl 1.2.6', fenv)
        self.assertIn('global_asm!', fenv)
        self.assertIn('.global feclearexcept', fenv)
        self.assertIn('stmxcsr', fenv)
        self.assertIn('ldmxcsr', fenv)
        self.assertIn('sizeof(fenv_t) == 32', c_probe)
        self.assertIn('feholdexcept', c_probe)
        self.assertIn('feupdateenv', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('-fno-builtin', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_libc_memory_probe_is_a_fixed_source_only_string_boundary(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_memory_probe.rs").read_text(
            encoding="utf-8"
        )
        memory = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory.rs").read_text(
            encoding="utf-8"
        )
        c_probe = (ROOT / "compat" / "x86_64" / "libc_memory_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_memory.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/memory.rs', rust_probe)
        self.assertIn('musl 1.2.6', memory)
        self.assertIn('global_asm!', memory)
        self.assertIn('.global __memcpy_fwd', memory)
        self.assertIn('rep movsq', memory)
        self.assertIn('rep stosq', memory)
        self.assertIn('std', memory)
        self.assertIn('cld', memory)
        self.assertIn('#include <string.h>', c_probe)
        self.assertIn('test_guard_pages', c_probe)
        self.assertIn('direction_flag_is_clear', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('-fno-builtin', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_libc_setjmp_probe_is_a_fixed_source_only_control_transfer_boundary(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_setjmp_probe.rs").read_text(
            encoding="utf-8"
        )
        assembly = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "setjmp.rs").read_text(
            encoding="utf-8"
        )
        c_probe = (ROOT / "compat" / "x86_64" / "libc_setjmp_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_setjmp.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/setjmp.rs', rust_probe)
        self.assertIn('global_asm!', assembly)
        self.assertIn('.global sigsetjmp', assembly)
        self.assertIn('mov eax, 14', assembly)
        self.assertIn('struct __jmp_buf_tag', c_probe)
        self.assertIn('siglongjmp', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('-fno-builtin', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_libc_atomic_probe_is_a_fixed_source_only_atomic_boundary(self) -> None:
        probe = (ROOT / "compat" / "x86_64" / "libc_atomic_probe.rs").read_text(
            encoding="utf-8"
        )
        atomic = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "atomic.rs").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_atomic.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/atomic.rs', probe)
        self.assertIn('x86_64_compare_exchange_acqrel_i32', atomic)
        self.assertIn('lock cmpxchg', atomic)
        self.assertIn('lock xadd', atomic)
        self.assertIn('x86_64_swap_acqrel_i32', atomic)
        self.assertIn('x86_64-unknown-linux-musl', script)
        self.assertIn('crabc_x86_atomic_probe_compare_exchange', script)
        self.assertIn('crabc_x86_atomic_probe_fetch_add', script)
        self.assertIn('crabc_x86_atomic_probe_fetch_sub', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', probe)

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
                "rustup run nightly-2026-07-24 rustc --edition=2021 --test",
                source_test_command,
            )
            self.assertIn(
                "/workspace/ldso/src/x86_64_relocation.rs",
                source_test_command,
            )
            self.assertIn('"$test_binary" --test-threads=1', source_test_command)
            self.assertNotIn("cargo", source_test_command)

    def test_ldso_initial_graph_relr_stays_bounded_to_the_private_leaf_fixture(self) -> None:
        runner = (ROOT / "compat" / "x86_64" / "run_ldso_initial_graph.sh").read_text(
            encoding="utf-8"
        )
        graph = (ROOT / "ldso" / "src" / "x86_64_initial_graph.rs").read_text(
            encoding="utf-8"
        )
        leaf = (ROOT / "compat" / "x86_64" / "ldso_initial_graph_leaf.c").read_text(
            encoding="utf-8"
        )

        self.assertIn("-Wl,-z,pack-relative-relocs", runner)
        self.assertIn(".relr.dyn", runner)
        self.assertIn("relr_direct_count", runner)
        self.assertIn("relr_bitmap_count", runner)
        self.assertIn("overlapping relocation-table mutation", runner)
        self.assertIn("bitmap-without-address mutation", runner)
        self.assertIn("must name one aligned writable word", runner)
        self.assertIn("duplicate RELR target mutation", runner)
        self.assertIn("libleaf-target-overcap.so", runner)
        self.assertIn("libleaf-record-overcap.so", runner)
        self.assertIn("zero-bit over-cap RELR mutation", runner)
        self.assertIn("MAX_RELR_ENTRIES=512", runner)
        self.assertIn("const MAX_RELOCATION_TARGETS: usize = 512;", graph)
        self.assertIn("const MAX_RELR_ENTRIES: usize = 512;", graph)
        self.assertIn("const MAX_RELR_BYTE_LEN: usize", graph)
        self.assertIn("preflight_relocation_table_layout", graph)
        self.assertIn("preflight_relr_table", graph)
        self.assertIn("apply_relr_table", graph)
        self.assertIn("objects[0].relrsz != 0", graph)
        self.assertIn("objects[1].relrsz != 0", graph)
        self.assertIn("objects[2].relrsz == 0", graph)
        self.assertIn("leaf_relative_slots", leaf)

    def test_ldso_initial_tls_stays_a_private_gnu_dynamic_boundary(self) -> None:
        runner = (ROOT / "compat" / "x86_64" / "run_ldso_initial_tls.sh").read_text(
            encoding="utf-8"
        )
        graph = (ROOT / "ldso" / "src" / "x86_64_initial_graph.rs").read_text(
            encoding="utf-8"
        )
        main = (ROOT / "compat" / "x86_64" / "ldso_initial_tls_main.c").read_text(
            encoding="utf-8"
        )

        for required in (
            "MUSL_LIBC_ARCHIVE",
            "-Wl,-u,__tls_get_addr",
            "require_needed_names",
            "dynamic_symbol_exists",
            "require_undefined_dynamic_names",
            "env -i PATH=/usr/bin:/bin",
            "R_X86_64_TPOFF64",
            "DF_STATIC_TLS",
            "--unresolved-symbols=ignore-all",
            "TLS leaf lacks the required readable BSS PT_LOAD",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("CRABC_MUSL_TLS_GET_ADDR_SHIM", runner)
        self.assertNotIn("CRABC_MUSL_TLS_GET_ADDR_SHIM", main)
        for required in (
            "R_X86_64_DTPMOD64",
            "R_X86_64_DTPOFF64",
            "__tls_get_addr",
            "plan_initial_tls",
            "install_initial_tls",
            "ARCH_SET_FS",
            "R_X86_64_TLSDESC => None",
            "object.tls_module_id = 0",
            "object.tls_module_id = module_count",
            "TLS_TCB_MODULE_SIZE_TABLE_OFFSET",
        ):
            self.assertIn(required, graph)

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
        for forbidden in ("raw_syscall", "getrandom", "malloc", "fn secure_getenv"):
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

    def test_math_log_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_log.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_log_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_log_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_math_log_header_abi.sh"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_log.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_log_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_log.py"
        ).read_text(encoding="utf-8")

        for required in (
            "math-log-header-abi)",
            "run_math_log_header_abi()",
            "libc-math-log)",
            "run_libc_math_log_probe()",
            "/workspace/compat/x86_64/run_libc_math_log.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "run_math_log_header_abi.sh",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd subsd subss mulsd mulss divsd divss cvtsd2ss cvtss2sd",
            "logl log1p log1pf",
            "math_special",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_log",
            "direct_logf",
            "LOG_RECORD_WORDS 4",
            "LOG_RECORD_COUNT",
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
            "close-to-one directed-zero",
        ):
            self.assertIn(required, probe)
        for required in ("double_unary", "float_unary", "direct_log", "direct_logf"):
            self.assertIn(required, header)
        for required in ("math_log_header_abi_probe.cpp", "-mfpmath=387", "unmangled"):
            self.assertIn(required, header_runner)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/log.c",
            "src/math/logf.c",
            "__log_data",
            "close-to-one",
            "-ffp-contract=off",
            'include_str!("math_log_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/log.c"',
            '"src/math/logf.c"',
            '"src/math/log_data.c"',
            '"src/math/logf_data.c"',
            '"src/math/__math_divzero.c"',
            '"src/math/__math_invalidf.c"',
            '"15.2.0"',
            '"-frounding-math"',
            '"-ffp-contract=off"',
            '"-mfpmath=sse"',
            "PRIVATE_RENAMES",
            "retained_notices",
        ):
            self.assertIn(required, generator)
        for required in (
            "Copyright (c) 2018, Arm Limited.",
            "musl's MIT license",
            "\t.globl\tlog\n",
            "\t.globl\tlogf\n",
            "crabc_x86_math_log_data",
            "cvtsd2ss",
            "cvtss2sd",
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

    def test_math_sin_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_sin.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_sin_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_sin_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_math_sin_header_abi.sh"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_sin.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_sin_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_sin.py"
        ).read_text(encoding="utf-8")

        for required in (
            "math-sin-header-abi)",
            "run_math_sin_header_abi()",
            "libc-math-sin)",
            "run_libc_math_sin_probe()",
            "/workspace/compat/x86_64/run_libc_math_sin.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "run_math_sin_header_abi.sh",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate does not retain local",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd addss subsd subss mulsd mulss cvtsd2ss cvtss2sd",
            "sinl sincos sincosf",
            "math_special",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_sin",
            "direct_sinf",
            "SIN_RECORD_WORDS 4",
            "SIN_RECORD_COUNT",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x4415af1d78b58c40",
            "0x60ad78ec",
            "0x7ff0000000000042",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in ("double_unary", "float_unary", "direct_sin", "direct_sinf"):
            self.assertIn(required, header)
        for required in ("math_sin_header_abi_probe.cpp", "-mfpmath=387", "unmangled"):
            self.assertIn(required, header_runner)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/sin.c",
            "src/math/sinf.c",
            "__rem_pio2_large.c",
            "floor.c",
            "-ffp-contract=off",
            'include_str!("math_sin_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/sin.c"',
            '"src/math/sinf.c"',
            '"src/math/__sin.c"',
            '"src/math/__rem_pio2_large.c"',
            '"src/math/floor.c"',
            '"src/math/scalbn.c"',
            '"15.2.0"',
            '"-frounding-math"',
            '"-ffp-contract=off"',
            '"-mfpmath=sse"',
            "PRIVATE_RENAMES",
            "retained_notices",
        ):
            self.assertIn(required, generator)
        for required in (
            "Sun Microsystems",
            "musl's MIT license",
            "\t.globl\tsin\n",
            "\t.globl\tsinf\n",
            "\t.local crabc_x86_math_sin_kernel_sin",
            "\t.local crabc_x86_math_sin_reduce_pio2_large",
            "\t.local crabc_x86_math_sin_provider_floor",
            "cvtsd2ss",
            "cvtss2sd",
        ):
            self.assertIn(required, assembly)

    def test_math_tan_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_tan.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_tan_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_tan_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_math_tan_header_abi.sh"
        ).read_text(encoding="utf-8")
        leaf = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_tan.rs").read_text(
            encoding="utf-8"
        )
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_tan_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_tan.py"
        ).read_text(encoding="utf-8")

        for required in (
            "math-tan-header-abi)",
            "run_math_tan_header_abi()",
            "libc-math-tan)",
            "run_libc_math_tan_probe()",
            "/workspace/compat/x86_64/run_libc_math_tan.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "run_math_tan_header_abi.sh",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate does not retain local",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd addss subsd subss mulsd mulss divsd cvtsd2ss cvtss2sd",
            "sin sinf sinl sincos sincosf",
            "math_special",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_tan",
            "direct_tanf",
            "TAN_RECORD_WORDS 4",
            "TAN_RECORD_COUNT",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x4415af1d78b58c40",
            "0x60ad78ec",
            "0x7ff0000000000042",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in ("double_unary", "float_unary", "direct_tan", "direct_tanf"):
            self.assertIn(required, header)
        for required in ("math_tan_header_abi_probe.cpp", "-mfpmath=387", "unmangled"):
            self.assertIn(required, header_runner)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/tan.c",
            "src/math/tanf.c",
            "__rem_pio2_large.c",
            "floor.c",
            "-ffp-contract=off",
            'include_str!("math_tan_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/tan.c"',
            '"src/math/tanf.c"',
            '"src/math/__tan.c"',
            '"src/math/__rem_pio2_large.c"',
            '"src/math/floor.c"',
            '"src/math/scalbn.c"',
            '"15.2.0"',
            '"-frounding-math"',
            '"-ffp-contract=off"',
            '"-mfpmath=sse"',
            "PRIVATE_RENAMES",
            "retained_notices",
        ):
            self.assertIn(required, generator)
        for required in (
            "Sun Microsystems",
            "musl's MIT license",
            "\t.globl\ttan\n",
            "\t.globl\ttanf\n",
            "\t.local crabc_x86_math_tan_kernel_tan",
            "\t.local crabc_x86_math_tan_reduce_pio2_large",
            "\t.local crabc_x86_math_tan_provider_floor",
            "cvtsd2ss",
            "cvtss2sd",
        ):
            self.assertIn(required, assembly)

    def test_math_tanh_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_tanh.sh").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_math_tanh_probe.c").read_text(
            encoding="utf-8"
        )
        header = (
            ROOT / "compat" / "x86_64" / "math_tanh_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_math_tanh_header_abi.sh"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_tanh.rs"
        ).read_text(encoding="utf-8")
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_tanh_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_tanh.py"
        ).read_text(encoding="utf-8")

        for required in (
            "math-tanh-header-abi)",
            "run_math_tanh_header_abi()",
            "libc-math-tanh)",
            "run_libc_math_tanh_probe()",
            "/workspace/compat/x86_64/run_libc_math_tanh.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "run_math_tanh_header_abi.sh",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate does not retain local",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd addss subsd subss mulsd mulss divsd divss cvtsd2ss",
            "tanl sinh sinhf",
            "expm1 expm1f expm1l",
            "math_special",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_tanh",
            "direct_tanhf",
            "TANH_RECORD_WORDS 4",
            "TANH_RECORD_COUNT",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x3fd058ae00000000",
            "0x3fe193ea00000000",
            "0x4034000000000000",
            "0x3e82c578",
            "0x3f0c9f54",
            "0x41200000",
            "0x7ff0000000000042",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in ("double_unary", "float_unary", "direct_tanh", "direct_tanhf"):
            self.assertIn(required, header)
        for required in (
            "math_tanh_header_abi_probe.cpp",
            "-mfpmath=387",
            "unmangled",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/tanh.c",
            "src/math/tanhf.c",
            "src/math/expm1.c",
            "src/math/expm1f.c",
            "-ffp-contract=off",
            'include_str!("math_tanh_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/tanh.c"',
            '"src/math/tanhf.c"',
            '"src/math/expm1.c"',
            '"src/math/expm1f.c"',
            '"15.2.0"',
            '"-frounding-math"',
            '"-ffp-contract=off"',
            '"-mfpmath=sse"',
            "PRIVATE_RENAMES",
            "retained_notices",
        ):
            self.assertIn(required, generator)
        for required in (
            "Sun Microsystems",
            "musl's MIT license",
            "\t.globl\ttanh\n",
            "\t.globl\ttanhf\n",
            "\t.local crabc_x86_math_tanh_provider_expm1",
            "\t.local crabc_x86_math_tanh_provider_expm1f",
            "cvtsd2ss",
        ):
            self.assertIn(required, assembly)

    def test_math_atanh_runner_keeps_the_binary32_binary64_static_boundary(self) -> None:
        dispatcher = RUNNER.read_text(encoding="utf-8")
        runner = (ROOT / "compat" / "x86_64" / "run_libc_math_atanh.sh").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "libc_math_atanh_probe.c"
        ).read_text(encoding="utf-8")
        header = (
            ROOT / "compat" / "x86_64" / "math_atanh_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_math_atanh_header_abi.sh"
        ).read_text(encoding="utf-8")
        leaf = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_atanh.rs"
        ).read_text(encoding="utf-8")
        assembly = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_atanh_musl_x86_64.S"
        ).read_text(encoding="utf-8")
        generator = (
            ROOT / "compat" / "x86_64" / "generate_libc_math_atanh.py"
        ).read_text(encoding="utf-8")

        for required in (
            "math-atanh-header-abi)",
            "run_math_atanh_header_abi()",
            "libc-math-atanh)",
            "run_libc_math_atanh_probe()",
            "/workspace/compat/x86_64/run_libc_math_atanh.sh",
        ):
            self.assertIn(required, dispatcher)
        for required in (
            "-nostdlib -static",
            "--no-undefined",
            "--gc-sections",
            "run_math_atanh_header_abi.sh",
            "strong crabc-owned",
            "weak compiler-builtins",
            "candidate does not retain local",
            "candidate accidentally retains unselected",
            "candidate retains TLS",
            "addsd addss subsd subss mulsd mulss divsd divss cvtsd2ss",
            "tanl tanh tanhf tanhl",
            "log logf logl log1p log1pf",
            "math_special",
        ):
            self.assertIn(required, runner)
        for required in (
            "direct_atanh",
            "direct_atanhf",
            "ATANH_RECORD_WORDS 4",
            "ATANH_RECORD_COUNT",
            "binary64_inputs",
            "binary32_inputs",
            "FE_TONEAREST",
            "FE_DOWNWARD",
            "FE_UPWARD",
            "FE_TOWARDZERO",
            "fegetround",
            "fetestexcept",
            "0x3df0000000000000",
            "0x3fe0000000000000",
            "0x3ff0000000000000",
            "0x3f000000",
            "0x3f800000",
            "0x7ff0000000000042",
            "0x7f800042",
        ):
            self.assertIn(required, probe)
        for required in ("double_unary", "float_unary", "direct_atanh", "direct_atanhf"):
            self.assertIn(required, header)
        for required in (
            "math_atanh_header_abi_probe.cpp",
            "-mfpmath=387",
            "unmangled",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "9fa28ece75d8a2191de7c5bb53bed224c5947417",
            "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
            "src/math/atanh.c",
            "src/math/atanhf.c",
            "src/math/log1p.c",
            "src/math/log1pf.c",
            "-ffp-contract=off",
            'include_str!("math_atanh_musl_x86_64.S")',
            "public x86 support",
        ):
            self.assertIn(required, leaf)
        for required in (
            "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
            '"src/math/atanh.c"',
            '"src/math/atanhf.c"',
            '"src/math/log1p.c"',
            '"src/math/log1pf.c"',
            '"15.2.0"',
            '"-frounding-math"',
            '"-ffp-contract=off"',
            '"-mfpmath=sse"',
            "PRIVATE_RENAMES",
            "retained_notices",
        ):
            self.assertIn(required, generator)
        for required in (
            "Sun Microsystems",
            "musl's MIT license",
            "\t.globl\tatanh\n",
            "\t.globl\tatanhf\n",
            "\t.local crabc_x86_math_atanh_provider_log1p",
            "\t.local crabc_x86_math_atanh_provider_log1pf",
            "cvtsd2ss",
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

    def test_facade_keeps_native_pattern_archives_checked(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        fnmatch_verifier = (
            ROOT / "compat" / "x86_64" / "verify_fnmatch_direct.sh"
        ).read_text(encoding="utf-8")
        glob_verifier = (
            ROOT / "compat" / "x86_64" / "verify_glob_direct.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("--test x86_64_fnmatch", source)
        self.assertIn("--release --example fnmatch_direct_probe", source)
        self.assertIn("compat/x86_64/verify_fnmatch_direct.sh", source)
        self.assertIn("allocation-free matcher", source)
        self.assertIn("--test x86_64_glob", source)
        self.assertIn("--features alloc --release --example glob_direct_probe", source)
        self.assertIn("compat/x86_64/verify_glob_direct.sh", source)
        self.assertIn("fixed Rust allocator", source)
        for required in (
            "Advanced Micro Devices X86-64",
            "crabc_rs_fnmatch_direct_probe",
            "fnmatch __errno_location malloc calloc realloc free",
            "readelf",
            "nm",
        ):
            self.assertIn(required, fnmatch_verifier)
        for required in (
            "Advanced Micro Devices X86-64",
            "crabc_rs_glob_direct_probe",
            "glob globfree fnmatch",
            "opendir readdir readdir64 closedir scandir",
            "__errno_location",
            "malloc calloc realloc reallocarray free",
            "readelf",
            "nm",
        ):
            self.assertIn(required, glob_verifier)


if __name__ == "__main__":
    unittest.main()
