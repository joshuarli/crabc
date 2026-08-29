#!/usr/bin/env python3
"""Validate the closed, non-symbol x86-64 runtime-parity ledger.

This is repository test infrastructure, not a runtime dependency.  It records
which AArch64 capability and gate families need independent native x86 proof;
it never treats a source-only foundation slice as public target support.
"""

from __future__ import annotations

import argparse
import hashlib
import tomllib
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
UPSTREAMS_PATH = ROOT / "compat" / "upstreams.toml"
HEADER_LAYOUT_MANIFEST_PATH = ROOT / "compat" / "x86_64" / "headers-layouts.toml"
HEADER_LAYOUT_FOUNDATION_MANIFEST_PATH = (
    ROOT / "compat" / "x86_64" / "headers-layouts-foundation.toml"
)
PUBLIC_HEADER_INVENTORY_PATH = ROOT / "compat" / "x86_64" / "public_headers.txt"
PUBLIC_HEADER_SURFACE_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_public_header_surface.sh"
LINUX_5_10_UAPI_VERIFIER_PATH = ROOT / "compat" / "x86_64" / "run_linux_5_10_uapi.sh"
CANDIDATE_HEADER_CLOSURE_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_candidate_header_closure.sh"
)
UAPI_WRAPPER_MATRIX_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_uapi_wrapper_matrix.sh"
)
EPOLL_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_epoll_header_abi.sh"
TIMEVAL_TRANSITIVE_HEADER_ABI_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_timeval_transitive_header_abi.sh"
)
SYS_TIME_DIRECT_HEADER_ABI_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_sys_time_direct_header_abi.sh"
)
X86_64_EVIDENCE_DOCKERFILE_PATH = ROOT / "docker" / "Dockerfile.x86_64"
EXPECTED_SCHEMA = "crabc.x86_64-runtime-parity/v3"
EXPECTED_TARGET = "x86_64-unknown-linux-musl"
EXPECTED_PLATFORM = "Linux/x86-64 little-endian"
EXPECTED_KERNEL_MSRV = "5.10"
EXPECTED_HEADER_LAYOUT_SCHEMA = "crabc.x86_64-headers-layouts/v1"
EXPECTED_HEADER_LAYOUT_FOUNDATION_SCHEMA = "crabc.x86_64-headers-layouts-foundation/v6"
EXPECTED_PUBLIC_HEADER_COUNT = 183
EXPECTED_PUBLIC_HEADER_SHA256 = "2cdcd860a423d99afef8360b6376447cf17ae926f1cd47416be817d421fca80f"
EXPECTED_PUBLIC_HEADER_UAPI_GAPS = {
    "sys/kd.h": "linux/kd.h",
    "sys/soundcard.h": "linux/soundcard.h",
    "sys/vt.h": "linux/vt.h",
}
EXPECTED_UAPI_WRAPPER_MATRIX_ID = "linux-5.10-uapi-wrapper-profile-matrix"
EXPECTED_UAPI_WRAPPER_MATRIX_COMMAND = "./scripts/dev-x86_64.sh uapi-wrapper-matrix"
EXPECTED_UAPI_WRAPPER_MATRIX_HEADERS = tuple(EXPECTED_PUBLIC_HEADER_UAPI_GAPS)
EXPECTED_UAPI_WRAPPER_MATRIX_ROW_COUNT = 21
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ID = "x86-epoll-header-profile-matrix"
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_COMMAND = "./scripts/dev-x86_64.sh epoll-header-abi"
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_SUBJECT_HEADER = "sys/epoll.h"
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_DIRECT_MACRO_HEADER = "sys/ioctl.h"
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ROW_COUNT = 7
EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_ID = (
    "x86-timeval-transitive-header-profile-matrix"
)
EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_COMMAND = (
    "./scripts/dev-x86_64.sh timeval-transitive-header-abi"
)
EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_HEADERS = (
    "sys/time.h",
    "utmpx.h",
    "utmp.h",
    "lastlog.h",
    "sys/timex.h",
)
EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_SYS_TIME_REQUIRED_TRANSITIVE_HEADER = (
    "sys/select.h"
)
EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_ROW_COUNT = 35
EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_ID = (
    "x86-sys-time-direct-header-profile-matrix"
)
EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_COMMAND = (
    "./scripts/dev-x86_64.sh sys-time-direct-header-abi"
)
EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_SUBJECT_HEADER = "sys/time.h"
EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_ROW_COUNT = 7
EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY = {
    "daemon.h",
    "dn_expand.h",
    "linux/capability.h",
    "lrand48.h",
    "pthread_atfork.h",
    "stdatomic.h",
    "strverscmp.h",
    "sys/module.h",
}
EXPECTED_LINUX_5_10_UAPI_ARCHIVE = (
    "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.tar.xz"
)
EXPECTED_LINUX_5_10_UAPI_VERSION = "5.10"
EXPECTED_LINUX_5_10_UAPI_UPSTREAM_PIN = "compat/upstreams.toml#linux_5_10_uapi"
EXPECTED_LINUX_5_10_UAPI_SOURCE_SHA256 = (
    "dcdf99e43e98330d925016985bfbc7b83c66d367b714b2de0cbbfcbf83d8ca43"
)
EXPECTED_LINUX_5_10_UAPI_ARCHITECTURE = "x86_64"
EXPECTED_LINUX_5_10_UAPI_HEADERS_INSTALL_ARCH = "x86"
EXPECTED_LINUX_5_10_UAPI_HEADER_COUNT = 935
EXPECTED_LINUX_5_10_UAPI_HEADER_MANIFEST_SHA256 = (
    "00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e"
)
EXPECTED_CANDIDATE_HEADER_CLOSURE_RECORD_COUNT = 382

EXPECTED_HEADER_FOUNDATION_LANGUAGE_PROFILES = {
    "c11-gnu": {
        "language": "c",
        "standard": "c11",
        "macros": ["_GNU_SOURCE"],
        "state": "partial-verified",
    },
    "cxx17-gnu": {
        "language": "c++",
        "standard": "c++17",
        "macros": ["_GNU_SOURCE"],
        "state": "planned",
    },
    "c11-strict": {
        "language": "c",
        "standard": "c11",
        "macros": [],
        "state": "planned",
    },
    "c11-posix-2008": {
        "language": "c",
        "standard": "c11",
        "macros": ["_POSIX_C_SOURCE=200809L"],
        "state": "planned",
    },
    "c11-xopen-700": {
        "language": "c",
        "standard": "c11",
        "macros": ["_XOPEN_SOURCE=700"],
        "state": "planned",
    },
    "c11-bsd": {
        "language": "c",
        "standard": "c11",
        "macros": ["_BSD_SOURCE"],
        "state": "planned",
    },
    "cxx17-strict": {
        "language": "c++",
        "standard": "c++17",
        "macros": [],
        "state": "planned",
    },
}
EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES = tuple(EXPECTED_HEADER_FOUNDATION_LANGUAGE_PROFILES)

EXPECTED_HEADER_FOUNDATION_CLASS_IDS = (
    "pinned-non-uapi",
    "pinned-uapi-inputs",
    "project-only-extensions",
)
EXPECTED_HEADER_FOUNDATION_CURRENT_PROFILES = ("c11-gnu", "cxx17-gnu")
EXPECTED_HEADER_FOUNDATION_FUTURE_PROFILES = (
    "c11-strict",
    "c11-posix-2008",
    "c11-xopen-700",
    "c11-bsd",
    "cxx17-strict",
)
EXPECTED_HEADER_FOUNDATION_CLASS_FACETS = {
    "pinned-non-uapi": (
        "public-path-inventory",
        "candidate-tree-presence",
        "c11-gnu-consumability",
        "epoll-header-profile-matrix",
        "timeval-transitive-header-profile-matrix",
        "sys-time-direct-header-profile-matrix",
        "candidate-transitive-closure",
        "cxx17-consumability",
        "feature-visibility",
        "callable-prototype-layout",
        "callable-linkage-ownership",
        "legacy-direct-layout-inputs",
        "static-c-cxx-composition",
    ),
    "pinned-uapi-inputs": (
        "public-path-inventory",
        "candidate-tree-presence",
        "uapi-input-provenance",
        "uapi-wrapper-profile-matrix",
        "candidate-transitive-closure",
        "cxx17-consumability",
        "feature-visibility",
        "callable-prototype-layout",
        "callable-linkage-ownership",
    ),
    "project-only-extensions": (
        "project-only-extension-policy",
        "candidate-tree-presence",
        "candidate-transitive-closure",
        "cxx17-consumability",
        "feature-visibility",
        "callable-prototype-layout",
        "callable-linkage-ownership",
    ),
}
EXPECTED_HEADER_FOUNDATION_CLASS_LINKAGE_OWNERS = {
    "pinned-non-uapi": (
        "current-static-c-exports",
        "unlisted-public-callables",
        "noncallable-header-abi",
    ),
    "pinned-uapi-inputs": (
        "current-static-c-exports",
        "unlisted-public-callables",
        "noncallable-header-abi",
    ),
    "project-only-extensions": (
        "current-static-c-exports",
        "unlisted-public-callables",
        "noncallable-header-abi",
    ),
}
EXPECTED_HEADER_FOUNDATION_PROFILE_OBLIGATIONS = {
    ("pinned-non-uapi", "c11-gnu"): (
        "applicable",
        "partial-verified",
        ("public-header-c-consumability",),
    ),
    ("pinned-non-uapi", "cxx17-gnu"): (
        "oracle-required",
        "planned",
        ("oracle-derived-cxx17-matrix",),
    ),
    ("pinned-non-uapi", "c11-strict"): (
        "oracle-required",
        "planned",
        ("strict-posix-xopen-gnu-bsd-matrix",),
    ),
    ("pinned-non-uapi", "c11-posix-2008"): (
        "oracle-required",
        "planned",
        ("strict-posix-xopen-gnu-bsd-matrix",),
    ),
    ("pinned-non-uapi", "c11-xopen-700"): (
        "oracle-required",
        "planned",
        ("strict-posix-xopen-gnu-bsd-matrix",),
    ),
    ("pinned-non-uapi", "c11-bsd"): (
        "oracle-required",
        "planned",
        ("strict-posix-xopen-gnu-bsd-matrix",),
    ),
    ("pinned-non-uapi", "cxx17-strict"): (
        "oracle-required",
        "planned",
        ("oracle-derived-cxx17-matrix",),
    ),
    ("pinned-uapi-inputs", "c11-gnu"): (
        "applicable",
        "partial-verified",
        ("pinned-linux-5.10-uapi-input", EXPECTED_UAPI_WRAPPER_MATRIX_ID),
    ),
    ("pinned-uapi-inputs", "cxx17-gnu"): (
        "applicable",
        "partial-verified",
        ("pinned-linux-5.10-uapi-input", EXPECTED_UAPI_WRAPPER_MATRIX_ID),
    ),
    ("pinned-uapi-inputs", "c11-strict"): (
        "applicable",
        "partial-verified",
        ("pinned-linux-5.10-uapi-input", EXPECTED_UAPI_WRAPPER_MATRIX_ID),
    ),
    ("pinned-uapi-inputs", "c11-posix-2008"): (
        "applicable",
        "partial-verified",
        ("pinned-linux-5.10-uapi-input", EXPECTED_UAPI_WRAPPER_MATRIX_ID),
    ),
    ("pinned-uapi-inputs", "c11-xopen-700"): (
        "applicable",
        "partial-verified",
        ("pinned-linux-5.10-uapi-input", EXPECTED_UAPI_WRAPPER_MATRIX_ID),
    ),
    ("pinned-uapi-inputs", "c11-bsd"): (
        "applicable",
        "partial-verified",
        ("pinned-linux-5.10-uapi-input", EXPECTED_UAPI_WRAPPER_MATRIX_ID),
    ),
    ("pinned-uapi-inputs", "cxx17-strict"): (
        "applicable",
        "partial-verified",
        ("pinned-linux-5.10-uapi-input", EXPECTED_UAPI_WRAPPER_MATRIX_ID),
    ),
    ("project-only-extensions", "c11-gnu"): (
        "oracle-required",
        "planned",
        ("project-only-header-classification",),
    ),
    ("project-only-extensions", "cxx17-gnu"): (
        "oracle-required",
        "planned",
        ("project-only-header-classification", "oracle-derived-cxx17-matrix"),
    ),
    ("project-only-extensions", "c11-strict"): (
        "oracle-required",
        "planned",
        ("project-only-header-classification", "strict-posix-xopen-gnu-bsd-matrix"),
    ),
    ("project-only-extensions", "c11-posix-2008"): (
        "oracle-required",
        "planned",
        ("project-only-header-classification", "strict-posix-xopen-gnu-bsd-matrix"),
    ),
    ("project-only-extensions", "c11-xopen-700"): (
        "oracle-required",
        "planned",
        ("project-only-header-classification", "strict-posix-xopen-gnu-bsd-matrix"),
    ),
    ("project-only-extensions", "c11-bsd"): (
        "oracle-required",
        "planned",
        ("project-only-header-classification", "strict-posix-xopen-gnu-bsd-matrix"),
    ),
    ("project-only-extensions", "cxx17-strict"): (
        "oracle-required",
        "planned",
        ("project-only-header-classification", "oracle-derived-cxx17-matrix"),
    ),
}

EXPECTED_HEADER_FOUNDATION_FACETS = {
    "public-path-inventory": (
        "partial-verified",
        "all-pinned-public-headers",
        "libc.headers-layouts",
        ("public-header-c-consumability",),
    ),
    "candidate-tree-presence": (
        "partial-verified",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("public-header-c-consumability",),
    ),
    "c11-gnu-consumability": (
        "partial-verified",
        "pinned-non-uapi",
        "libc.headers-layouts",
        ("public-header-c-consumability",),
    ),
    "epoll-header-profile-matrix": (
        "partial-verified",
        "sys/epoll.h plus selected sys/ioctl.h macro encoding subset",
        "libc.headers-layouts",
        (EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ID,),
    ),
    "timeval-transitive-header-profile-matrix": (
        "partial-verified",
        "sys/time.h plus utmpx.h, utmp.h, lastlog.h, and sys/timex.h timeval transitive layout subset",
        "libc.headers-layouts",
        (EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_ID,),
    ),
    "sys-time-direct-header-profile-matrix": (
        "partial-verified",
        "sys/time.h selected declaration layout feature macro and C++ declaration-linkage subset",
        "libc.headers-layouts",
        (EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_ID,),
    ),
    "uapi-input-provenance": (
        "partial-verified",
        "pinned-uapi-inputs",
        "libc.headers-layouts",
        ("pinned-linux-5.10-uapi-input",),
    ),
    "uapi-wrapper-profile-matrix": (
        "partial-verified",
        "pinned-uapi-inputs",
        "libc.headers-layouts",
        (EXPECTED_UAPI_WRAPPER_MATRIX_ID,),
    ),
    "project-only-extension-policy": (
        "planned",
        "project-only-extensions",
        "libc.c-abi-compat",
        ("project-only-header-classification",),
    ),
    "candidate-transitive-closure": (
        "planned",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("isolated-candidate-header-closure",),
    ),
    "cxx17-consumability": (
        "planned",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("isolated-candidate-header-closure", "oracle-derived-cxx17-matrix"),
    ),
    "feature-visibility": (
        "planned",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("strict-posix-xopen-gnu-bsd-matrix",),
    ),
    "callable-prototype-layout": (
        "planned",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("generated-x86-prototype-layout-matrix",),
    ),
    "callable-linkage-ownership": (
        "planned",
        "all-pinned-and-project-only-public-headers",
        "libc.c-abi-compat",
        ("declared-callable-linkage-audit",),
    ),
    "legacy-direct-layout-inputs": (
        "partial-verified",
        "v1-direct-probe-union",
        "libc.headers-layouts",
        ("headers-layouts.toml",),
    ),
    "static-c-cxx-composition": (
        "partial-verified",
        "selected-existing-static-archive-leaves",
        "libc.headers-layouts",
        ("static-c-header-layouts-baseline",),
    ),
}

EXPECTED_HEADER_FOUNDATION_LINKAGE_OWNERS = {
    "current-static-c-exports": (
        "partial-verified",
        "all symbols listed by static_c_abi_exports",
        "libc.c-abi-compat",
        ("compat/x86_64/static_c_abi_exports.txt", "selected-static-artifacts"),
    ),
    "unlisted-public-callables": (
        "planned",
        "every public callable declaration not selected by the current static export ratchet",
        "libc.c-abi-compat",
        ("declared-callable-linkage-audit",),
    ),
    "noncallable-header-abi": (
        "planned",
        "public typedefs constants macros records and inline-only header contracts",
        "libc.headers-layouts",
        ("generated-x86-prototype-layout-matrix",),
    ),
}

EXPECTED_HEADER_LAYOUT_PROBES = {
    "project": "./scripts/dev-x86_64.sh header-abi-project",
    "math-complex": "./scripts/dev-x86_64.sh math-complex-header-abi",
    "sys-reg": "./scripts/dev-x86_64.sh sys-reg-header-abi",
    "types": "./scripts/dev-x86_64.sh types-header-abi",
    "stat": "./scripts/dev-x86_64.sh stat-header-abi",
    "ctype": "./scripts/dev-x86_64.sh ctype-header-abi",
    "integer-arithmetic": "./scripts/dev-x86_64.sh integer-arithmetic-header-abi",
    "integer-parse": "./scripts/dev-x86_64.sh integer-parse-header-abi",
    "intmax-arithmetic": "./scripts/dev-x86_64.sh intmax-arithmetic-header-abi",
    "credential-observation": "./scripts/dev-x86_64.sh credential-observation-header-abi",
    "child-reaping": "./scripts/dev-x86_64.sh child-reaping-header-abi",
    "immediate-termination": "./scripts/dev-x86_64.sh immediate-termination-header-abi",
    "callback-algorithms": "./scripts/dev-x86_64.sh callback-algorithms-header-abi",
    "ffs": "./scripts/dev-x86_64.sh ffs-header-abi",
    "byte-strings": "./scripts/dev-x86_64.sh byte-strings-header-abi",
    "memory-search": "./scripts/dev-x86_64.sh memory-search-header-abi",
    "string-copy": "./scripts/dev-x86_64.sh string-copy-header-abi",
    "random-entropy": "./scripts/dev-x86_64.sh random-entropy-header-abi",
    "time": "./scripts/dev-x86_64.sh time-header-abi",
    "poll": "./scripts/dev-x86_64.sh poll-header-abi",
    "select": "./scripts/dev-x86_64.sh select-header-abi",
    "fcntl": "./scripts/dev-x86_64.sh fcntl-header-abi",
    "unistd": "./scripts/dev-x86_64.sh unistd-header-abi",
    "system": "./scripts/dev-x86_64.sh system-header-abi",
    "syscall": "./scripts/dev-x86_64.sh syscall-header-abi",
    "signal": "./scripts/dev-x86_64.sh signal-header-abi",
    "termios": "./scripts/dev-x86_64.sh termios-header-abi",
    "mman": "./scripts/dev-x86_64.sh mman-header-abi",
    "resource": "./scripts/dev-x86_64.sh resource-header-abi",
    "socket": "./scripts/dev-x86_64.sh socket-header-abi",
    "epoll": "./scripts/dev-x86_64.sh epoll-header-abi",
    "timeval-transitive": "./scripts/dev-x86_64.sh timeval-transitive-header-abi",
    "sys-time-direct": "./scripts/dev-x86_64.sh sys-time-direct-header-abi",
}

EXPECTED_HEADER_LAYOUT_SOURCES = {
    "project": (
        "compat/x86_64/project_header_abi_probe.c",
        "compat/x86_64/run_project_header_abi.sh",
    ),
    "math-complex": (
        "compat/x86_64/math_complex_header_abi_probe.c",
        "compat/x86_64/math_complex_header_abi_probe.cpp",
        "compat/x86_64/run_math_complex_header_abi.sh",
    ),
    "sys-reg": (
        "compat/x86_64/sys_reg_header_abi_probe.c",
        "compat/x86_64/run_sys_reg_header_abi.sh",
    ),
    "types": (
        "compat/x86_64/types_header_abi_probe.c",
        "compat/x86_64/types_header_abi_probe.cpp",
        "compat/x86_64/run_types_header_abi.sh",
    ),
    "stat": (
        "compat/x86_64/stat_header_abi_probe.c",
        "compat/x86_64/stat_header_abi_probe.cpp",
        "compat/x86_64/run_stat_header_abi.sh",
    ),
    "ctype": (
        "compat/x86_64/ctype_header_abi_probe.c",
        "compat/x86_64/ctype_header_abi_probe.cpp",
        "compat/x86_64/run_ctype_header_abi.sh",
    ),
    "integer-arithmetic": (
        "compat/x86_64/integer_arithmetic_header_abi_probe.c",
        "compat/x86_64/integer_arithmetic_header_abi_probe.cpp",
        "compat/x86_64/run_integer_arithmetic_header_abi.sh",
    ),
    "integer-parse": (
        "compat/x86_64/integer_parse_header_abi_probe.c",
        "compat/x86_64/integer_parse_header_abi_probe.cpp",
        "compat/x86_64/run_integer_parse_header_abi.sh",
    ),
    "intmax-arithmetic": (
        "compat/x86_64/intmax_arithmetic_header_abi_probe.c",
        "compat/x86_64/intmax_arithmetic_header_abi_probe.cpp",
        "compat/x86_64/run_intmax_arithmetic_header_abi.sh",
    ),
    "credential-observation": (
        "compat/x86_64/credential_observation_header_abi_probe.c",
        "compat/x86_64/credential_observation_header_abi_probe.cpp",
        "compat/x86_64/run_credential_observation_header_abi.sh",
    ),
    "child-reaping": (
        "compat/x86_64/child_reaping_header_abi_probe.c",
        "compat/x86_64/child_reaping_header_abi_probe.cpp",
        "compat/x86_64/run_child_reaping_header_abi.sh",
    ),
    "immediate-termination": (
        "compat/x86_64/immediate_termination_header_abi_probe.c",
        "compat/x86_64/immediate_termination_header_abi_probe.cpp",
        "compat/x86_64/run_immediate_termination_header_abi.sh",
    ),
    "callback-algorithms": (
        "compat/x86_64/callback_algorithms_header_abi_probe.c",
        "compat/x86_64/callback_algorithms_header_abi_probe.cpp",
        "compat/x86_64/run_callback_algorithms_header_abi.sh",
    ),
    "ffs": (
        "compat/x86_64/ffs_header_abi_probe.c",
        "compat/x86_64/ffs_header_abi_probe.cpp",
        "compat/x86_64/run_ffs_header_abi.sh",
    ),
    "byte-strings": (
        "compat/x86_64/byte_strings_header_abi_probe.c",
        "compat/x86_64/byte_strings_header_abi_probe.cpp",
        "compat/x86_64/run_byte_strings_header_abi.sh",
    ),
    "memory-search": (
        "compat/x86_64/memory_search_header_abi_probe.c",
        "compat/x86_64/memory_search_header_abi_probe.cpp",
        "compat/x86_64/run_memory_search_header_abi.sh",
    ),
    "string-copy": (
        "compat/x86_64/string_copy_header_abi_probe.c",
        "compat/x86_64/string_copy_header_abi_probe.cpp",
        "compat/x86_64/run_string_copy_header_abi.sh",
    ),
    "random-entropy": (
        "compat/x86_64/random_entropy_header_abi_probe.c",
        "compat/x86_64/random_entropy_header_abi_probe.cpp",
        "compat/x86_64/run_random_entropy_header_abi.sh",
    ),
    "time": (
        "compat/x86_64/time_header_abi_probe.c",
        "compat/x86_64/time_header_abi_probe.cpp",
        "compat/x86_64/run_time_header_abi.sh",
    ),
    "poll": (
        "compat/x86_64/poll_header_abi_probe.c",
        "compat/x86_64/poll_header_abi_probe.cpp",
        "compat/x86_64/run_poll_header_abi.sh",
    ),
    "select": (
        "compat/x86_64/select_header_abi_probe.c",
        "compat/x86_64/select_header_abi_probe.cpp",
        "compat/x86_64/run_select_header_abi.sh",
    ),
    "fcntl": (
        "compat/x86_64/fcntl_header_abi_probe.c",
        "compat/x86_64/fcntl_header_abi_probe.cpp",
        "compat/x86_64/run_fcntl_header_abi.sh",
    ),
    "unistd": (
        "compat/x86_64/unistd_header_abi_probe.c",
        "compat/x86_64/unistd_header_abi_probe.cpp",
        "compat/x86_64/run_unistd_header_abi.sh",
    ),
    "system": (
        "compat/x86_64/system_header_abi_probe.c",
        "compat/x86_64/system_header_abi_probe.cpp",
        "compat/x86_64/run_system_header_abi.sh",
    ),
    "syscall": (
        "compat/x86_64/x86_syscall_header_probe.c",
        "compat/x86_64/run_x86_syscall_header.sh",
    ),
    "signal": (
        "compat/x86_64/signal_header_abi_probe.c",
        "compat/x86_64/signal_header_posix_abi_probe.c",
        "compat/x86_64/run_signal_header_abi.sh",
    ),
    "termios": (
        "compat/x86_64/termios_header_abi_probe.c",
        "compat/x86_64/termios_header_abi_probe.cpp",
        "compat/x86_64/run_termios_header_abi.sh",
    ),
    "mman": (
        "compat/x86_64/mman_header_abi_probe.c",
        "compat/x86_64/mman_header_abi_probe.cpp",
        "compat/x86_64/run_mman_header_abi.sh",
    ),
    "resource": (
        "compat/x86_64/resource_header_abi_probe.c",
        "compat/x86_64/resource_header_abi_probe.cpp",
        "compat/x86_64/run_resource_header_abi.sh",
    ),
    "socket": (
        "compat/x86_64/socket_header_abi_probe.c",
        "compat/x86_64/socket_header_abi_probe.cpp",
        "compat/x86_64/socket_header_ipv6_macro_probe.c",
        "compat/x86_64/run_socket_header_abi.sh",
    ),
    "epoll": (
        "compat/x86_64/epoll_header_abi_probe.c",
        "compat/x86_64/epoll_header_abi_probe.cpp",
        "compat/x86_64/run_epoll_header_abi.sh",
    ),
    "timeval-transitive": (
        "compat/x86_64/timeval_transitive_header_abi_probe.c",
        "compat/x86_64/timeval_transitive_header_abi_probe.cpp",
        "compat/x86_64/run_timeval_transitive_header_abi.sh",
    ),
    "sys-time-direct": (
        "compat/x86_64/sys_time_direct_header_abi_probe.c",
        "compat/x86_64/sys_time_direct_header_abi_probe.cpp",
        "compat/x86_64/run_sys_time_direct_header_abi.sh",
    ),
}

EXPECTED_FAMILIES = (
    "oracle.musl-toolchain",
    "core.architecture",
    "facade.direct",
    "facade.record-owning",
    "libc.raw-syscall",
    "libc.errno-tls",
    "libc.headers-layouts",
    "libc.posix-runtime",
    "libc.pthread-tls",
    "libc.text-math-locale-stdio",
    "libc.resolver",
    "libc.c-abi-compat",
    "ldso.relative-relocation",
    "ldso.dynamic-runtime",
    "crt.static-pie",
    "crt.dynamic-startup",
    "sysroot.static-tls",
    "sysroot.owned-artifact",
    "compat.abi-differential",
    "compat.posix-process",
    "compat.resolver-network",
    "compat.loader-corpus",
    "consumer.rust-std-lto",
    "consumer.source-build",
    "capability.accounting",
    "performance.release",
)

ALLOWED_CATEGORIES = {
    "architecture-foundation",
    "rust-facade",
    "c-abi",
    "runtime-artifact",
    "compatibility-gate",
    "consumer-gate",
    "promotion-gate",
}
ALLOWED_STATUSES = {"foundation-verified", "planned"}
ALLOWED_EVIDENCE_STATES = {"verified", "required"}
KNOWN_AARCH64_GATES = {
    "abi-probe",
    "build",
    "compat",
    "corpus",
    "crabc-rs",
    "dashboard",
    "differential",
    "ldso",
    "libc-test",
    "loader-inventory",
    "lto",
    "lto-native-facade",
    "os-test",
    "perf",
    "perf-native",
    "pthread-stress",
    "resolver-network",
    "rust-std",
    "rust-std-dependent",
    "signal-process",
    "static-pthread-tls",
    "symbols",
    "sysroot",
    "sysroot-dist",
    "sysroot-smoke",
    "test",
    "lua",
}

BYTE_STRING_SYMBOLS = (
    "index",
    "rindex",
    "strchr",
    "strchrnul",
    "strcmp",
    "strcspn",
    "strlen",
    "strncmp",
    "strnlen",
    "strpbrk",
    "strrchr",
    "strspn",
    "strstr",
)

RANDOM_ENTROPY_SYMBOLS = ("getrandom", "getentropy")

MEMORY_SEARCH_SYMBOLS = ("memchr", "memrchr", "memmem")

STRING_COPY_SYMBOLS = (
    "stpcpy",
    "stpncpy",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strlcpy",
    "strlcat",
)

CTYPE_SYMBOLS = (
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

INTEGER_ARITHMETIC_SYMBOLS = (
    "abs",
    "labs",
    "llabs",
    "div",
    "ldiv",
    "lldiv",
)

INTMAX_ARITHMETIC_SYMBOLS = ("imaxabs", "imaxdiv")

INTEGER_PARSE_SYMBOLS = (
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

CREDENTIAL_OBSERVATION_SYMBOLS = ("getgroups", "getresuid", "getresgid")

CHILD_REAPING_SYMBOLS = ("wait", "waitpid", "waitid")

IMMEDIATE_TERMINATION_SYMBOLS = ("_Exit",)

CALLBACK_ALGORITHM_SYMBOLS = ("bsearch", "__qsort_r", "qsort", "qsort_r")

FFS_SYMBOLS = ("ffs", "ffsl", "ffsll")

MATH_COMPLEX_FOUNDATION_SYMBOLS = (
    "__fpclassify",
    "__fpclassifyf",
    "__fpclassifyl",
    "__signbit",
    "__signbitf",
    "__signbitl",
    "creal",
    "crealf",
    "creall",
    "cimag",
    "cimagf",
    "cimagl",
    "conj",
    "conjf",
    "conjl",
)


class LedgerError(ValueError):
    """The parity ledger does not describe a reviewable closed contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LedgerError(message)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise LedgerError(f"cannot load {path}: {error}") from error
    require(isinstance(data, dict), "ledger top level must be a table")
    return data


def nonempty_strings(value: Any, location: str) -> list[str]:
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    result: list[str] = []
    for index, entry in enumerate(value):
        require(isinstance(entry, str) and entry, f"{location}[{index}] must be a non-empty string")
        result.append(entry)
    return result


def string_list(value: Any, location: str, *, allow_empty: bool = False) -> list[str]:
    """Return a string list while retaining a useful location in failures."""
    require(isinstance(value, list), f"{location} must be an array")
    require(allow_empty or bool(value), f"{location} must be a non-empty array")
    result: list[str] = []
    for index, entry in enumerate(value):
        require(isinstance(entry, str) and entry, f"{location}[{index}] must be a non-empty string")
        result.append(entry)
    return result


def repository_path(path_text: str, location: str) -> Path:
    require(isinstance(path_text, str) and path_text, f"{location} is empty")
    path = Path(path_text)
    require(not path.is_absolute(), f"{location} must be repository-relative: {path_text}")
    resolved = (ROOT / path).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise LedgerError(f"{location} escapes the repository: {path_text}") from error
    require(resolved.exists(), f"{location} does not exist: {path_text}")
    return resolved


def direct_project_headers(source: Path) -> set[str]:
    """Return explicit angle-bracket includes from one C or C++ probe source."""
    headers: set[str] = set()
    for line in source.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("#include <"):
            continue
        header = stripped.removeprefix("#include <").split(">", maxsplit=1)[0]
        if header:
            headers.add(f"include/{header}")
    return headers


def validate_header_layout_manifest(
    family: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Keep selected native header evidence explicit without promoting it.

    The manifest is intentionally an index of direct probe includes only. It
    is not a transitive-include inventory or an assertion that an installed
    header, archive, or runtime is complete.
    """
    require(isinstance(manifest, Mapping), "header-layout manifest must be a table")
    expected_manifest_keys = {
        "schema",
        "family",
        "target",
        "platform",
        "kernel_msrv",
        "status",
        "oracle",
        "policy",
        "probe",
    }
    require(
        set(manifest) == expected_manifest_keys,
        "header-layout manifest top-level keys drifted",
    )
    require(
        manifest["schema"] == EXPECTED_HEADER_LAYOUT_SCHEMA,
        "unexpected header-layout manifest schema",
    )
    require(manifest["family"] == "libc.headers-layouts", "header-layout manifest family drifted")
    require(manifest["target"] == EXPECTED_TARGET, "header-layout manifest target drifted")
    require(manifest["platform"] == EXPECTED_PLATFORM, "header-layout manifest platform drifted")
    require(
        manifest["kernel_msrv"] == EXPECTED_KERNEL_MSRV,
        "header-layout manifest kernel MSRV drifted",
    )
    require(manifest["status"] == "planned", "header-layout manifest must remain planned")
    require(manifest["oracle"] == "Pinned musl 1.2.6", "header-layout manifest oracle drifted")

    policy = manifest["policy"]
    require(isinstance(policy, Mapping), "header-layout manifest policy must be a table")
    require(
        dict(policy)
        == {
            "native_execution_only": True,
            "project_headers_first": True,
            "direct_header_inventory": True,
            "transitive_include_closure": False,
            "aggregate_family_completion": False,
            "public_support": False,
        },
        "header-layout manifest policy drifted",
    )

    require(
        family.get("status") == "planned",
        "libc.headers-layouts must remain planned while its manifest is partial",
    )
    require(
        family.get("capabilities") == [],
        "libc.headers-layouts manifest must not claim baseline capabilities",
    )
    manifest_path = repository_path(
        str(family.get("header_manifest", "")),
        "family[libc.headers-layouts].header_manifest",
    )
    require(
        manifest_path == HEADER_LAYOUT_MANIFEST_PATH,
        "libc.headers-layouts must use the checked-in header-layout manifest",
    )
    source_owners = nonempty_strings(
        family["source_owners"], "family[libc.headers-layouts].source_owners"
    )
    require(
        "compat/x86_64/headers-layouts.toml" in source_owners,
        "libc.headers-layouts must own its header-layout manifest",
    )
    require(
        "include" not in source_owners,
        "libc.headers-layouts must not hide header scope behind the include directory",
    )

    evidence = family["native_evidence"]
    assert isinstance(evidence, list)
    dispatch_source = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    require(
        tuple(EXPECTED_HEADER_LAYOUT_SOURCES) == tuple(EXPECTED_HEADER_LAYOUT_PROBES),
        "header-layout validator source roster drifted",
    )
    probes = manifest["probe"]
    require(isinstance(probes, list) and probes, "header-layout manifest probe must be a non-empty array")
    require(
        len(probes) == len(EXPECTED_HEADER_LAYOUT_PROBES),
        "header-layout manifest probe count drifted",
    )

    probe_ids: list[str] = []
    for index, entry in enumerate(probes):
        location = f"header-layout manifest probe[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        require(
            set(entry) == {"id", "command", "state", "kind", "sources", "headers"},
            f"{location} keys drifted",
        )
        identifier = entry["id"]
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(
            identifier == identifier.lower()
            and not identifier.startswith("-")
            and not identifier.endswith("-")
            and all(character in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in identifier),
            f"{location}.id must be lowercase kebab-case",
        )
        require(identifier in EXPECTED_HEADER_LAYOUT_PROBES, f"{location}.id is not a selected header gate")
        command = entry["command"]
        require(isinstance(command, str) and command, f"{location}.command is empty")
        require(
            command == EXPECTED_HEADER_LAYOUT_PROBES[identifier],
            f"{location}.command drifted from its selected header gate",
        )
        require(entry["state"] == "required", f"{location}.state must remain required")
        expected_kind = (
            "macro-runtime"
            if identifier in {"math-complex", "socket"}
            else "compile-only"
        )
        require(entry["kind"] == expected_kind, f"{location}.kind drifted")

        source_names = nonempty_strings(entry["sources"], f"{location}.sources")
        require(
            len(source_names) == len(set(source_names)),
            f"{location}.sources contains a duplicate",
        )
        require(
            tuple(source_names) == EXPECTED_HEADER_LAYOUT_SOURCES[identifier],
            f"{location}.sources drifted from its selected header gate",
        )
        source_paths: list[Path] = []
        for source_index, source_name in enumerate(source_names):
            source_path = repository_path(source_name, f"{location}.sources[{source_index}]")
            require(source_path.is_file(), f"{location}.sources[{source_index}] is not a file")
            require(
                source_name.startswith("compat/x86_64/"),
                f"{location}.sources[{source_index}] must stay in compat/x86_64",
            )
            require(
                source_name in source_owners,
                f"{location}.sources[{source_index}] is not a family source owner",
            )
            source_paths.append(source_path)
        c_sources = [path for path in source_paths if path.suffix in {".c", ".cpp"}]
        runner_sources = [path for path in source_paths if path.suffix == ".sh"]
        require(c_sources, f"{location}.sources must include a C or C++ probe")
        require(len(runner_sources) == 1, f"{location}.sources must include exactly one runner")

        header_names = nonempty_strings(entry["headers"], f"{location}.headers")
        require(
            len(header_names) == len(set(header_names)),
            f"{location}.headers contains a duplicate",
        )
        for header_index, header_name in enumerate(header_names):
            header_path = repository_path(header_name, f"{location}.headers[{header_index}]")
            require(header_path.is_file(), f"{location}.headers[{header_index}] is not a file")
            require(
                header_name.startswith("include/") and header_name.endswith(".h"),
                f"{location}.headers[{header_index}] must be an installed header",
            )
            require(
                header_name in source_owners,
                f"{location}.headers[{header_index}] is not a family source owner",
            )
        direct_headers = set().union(*(direct_project_headers(path) for path in c_sources))
        require(
            set(header_names) == direct_headers,
            f"{location}.headers must exactly match its direct C/C++ includes",
        )

        evidence_matches = [
            record
            for record in evidence
            if isinstance(record, Mapping) and record.get("command") == command
        ]
        require(
            len(evidence_matches) == 1 and evidence_matches[0].get("state") == "required",
            f"{location}.command must map to one required family evidence record",
        )
        subcommand = command.removeprefix("./scripts/dev-x86_64.sh ")
        require(
            subcommand != command
            and (
                f"    {subcommand})" in dispatch_source
                or f"    {subcommand}|" in dispatch_source
                or f"|{subcommand})" in dispatch_source
            ),
            f"{location}.command is absent from the native dispatcher",
        )
        probe_ids.append(identifier)

    require(
        tuple(probe_ids) == tuple(EXPECTED_HEADER_LAYOUT_PROBES),
        "header-layout manifest probe order or roster drifted",
    )
    return {"probe_count": len(probe_ids)}


def static_c_abi_export_names(path: Path) -> list[str]:
    """Load the selected static C export ratchet without treating it as ABI closure."""
    text = path.read_text(encoding="utf-8")
    require(text.endswith("\n"), "static C ABI export contract must end with a newline")
    names = [
        line
        for line in text.splitlines()
        if line and not line.startswith("#")
    ]
    require(names, "static C ABI export contract must name at least one symbol")
    require(names == sorted(names), "static C ABI export contract must remain ASCII-sorted")
    require(len(names) == len(set(names)), "static C ABI export contract has a duplicate symbol")
    for index, name in enumerate(names):
        require(
            all(character.isascii() and (character.isalnum() or character == "_") for character in name),
            f"static C ABI export contract symbol {index} is invalid",
        )
    return names


def validate_header_layout_foundation_manifest(
    family: Mapping[str, Any],
    legacy_manifest: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, int]:
    """Validate the planned all-header accounting contract without promoting it.

    The v6 contract resolves every current pathname into one class and expands
    every class into explicit language/feature obligations. It pins the one
    Linux-UAPI input, resolves selected UAPI-wrapper, epoll-header,
    timeval-transitive, and direct sys/time ABI matrices, and requires a live C11/C++17 empty-TU
    closure diagnostic, while keeping aggregate applicability,
    declaration/layout comparisons, and declared-callable linkage in planned
    evidence lanes.
    """
    require(isinstance(manifest, Mapping), "header-foundation manifest must be a table")
    expected_manifest_keys = {
        "schema",
        "family",
        "target",
        "platform",
        "kernel_msrv",
        "status",
        "oracle",
        "legacy_direct_manifest",
        "pinned_public_inventory",
        "static_c_abi_exports",
        "policy",
        "completion",
        "profile_matrix",
        "uapi_input",
        "uapi_wrapper_matrix",
        "epoll_header_profile_matrix",
        "timeval_transitive_header_profile_matrix",
        "sys_time_direct_header_profile_matrix",
        "closure_diagnostic",
        "language_profile",
        "profile_obligation",
        "header_class",
        "uapi_path",
        "abi_facet",
        "linkage_owner",
    }
    require(
        set(manifest) == expected_manifest_keys,
        "header-foundation manifest top-level keys drifted",
    )
    require(
        manifest["schema"] == EXPECTED_HEADER_LAYOUT_FOUNDATION_SCHEMA,
        "unexpected header-foundation manifest schema",
    )
    require(manifest["family"] == "libc.headers-layouts", "header-foundation manifest family drifted")
    require(manifest["target"] == EXPECTED_TARGET, "header-foundation manifest target drifted")
    require(manifest["platform"] == EXPECTED_PLATFORM, "header-foundation manifest platform drifted")
    require(
        manifest["kernel_msrv"] == EXPECTED_KERNEL_MSRV,
        "header-foundation manifest kernel MSRV drifted",
    )
    require(manifest["status"] == "planned", "header-foundation manifest must remain planned")
    require(manifest["oracle"] == "Pinned musl 1.2.6", "header-foundation manifest oracle drifted")

    policy = manifest["policy"]
    require(isinstance(policy, Mapping), "header-foundation manifest policy must be a table")
    require(
        dict(policy)
        == {
            "native_execution_only": True,
            "project_headers_first": True,
            "inventory_accounting": True,
            "candidate_transitive_include_closure": False,
            "full_c11_consumer_matrix": False,
            "full_cxx17_consumer_matrix": False,
            "feature_visibility_matrix": False,
            "abi_facet_matrix": False,
            "callable_linkage_audit": False,
            "aggregate_family_completion": False,
            "runtime_completion": False,
            "public_support": False,
        },
        "header-foundation manifest policy drifted",
    )
    completion = manifest["completion"]
    require(isinstance(completion, Mapping), "header-foundation manifest completion must be a table")
    require(
        dict(completion)
        == {
            "inventory_accounted": True,
            "project_only_paths_accounted": True,
            "uapi_paths_accounted": True,
            "language_profiles_accounted": True,
            "feature_modes_accounted": True,
            "abi_facets_accounted": True,
            "callable_linkage_owners_accounted": True,
            "legacy_direct_inputs_accounted": True,
            "uapi_wrapper_profile_matrix_slice": True,
            "epoll_header_profile_matrix_slice": True,
            "timeval_transitive_header_profile_matrix_slice": True,
            "sys_time_direct_header_profile_matrix_slice": True,
            "candidate_transitive_include_closure": False,
            "c11_consumer_matrix": False,
            "cxx17_consumer_matrix": False,
            "feature_visibility_matrix": False,
            "abi_facet_matrix": False,
            "callable_linkage_audit": False,
            "runtime_completion": False,
            "family_promotion": False,
            "public_support": False,
        },
        "header-foundation manifest completion drifted",
    )

    require(
        family.get("status") == "planned",
        "libc.headers-layouts must remain planned while header foundation is incomplete",
    )
    require(
        family.get("capabilities") == [],
        "libc.headers-layouts foundation manifest must not claim baseline capabilities",
    )
    foundation_path = repository_path(
        str(family.get("header_foundation_manifest", "")),
        "family[libc.headers-layouts].header_foundation_manifest",
    )
    require(
        foundation_path == HEADER_LAYOUT_FOUNDATION_MANIFEST_PATH,
        "libc.headers-layouts must use the checked-in header-foundation manifest",
    )
    legacy_path = repository_path(
        str(manifest["legacy_direct_manifest"]),
        "header-foundation manifest legacy_direct_manifest",
    )
    require(
        legacy_path == HEADER_LAYOUT_MANIFEST_PATH,
        "header-foundation manifest must retain the checked-in v1 direct manifest",
    )
    require(
        legacy_manifest.get("schema") == EXPECTED_HEADER_LAYOUT_SCHEMA,
        "header-foundation manifest must build on the v1 direct manifest",
    )
    inventory_path = repository_path(
        str(manifest["pinned_public_inventory"]),
        "header-foundation manifest pinned_public_inventory",
    )
    require(
        inventory_path == PUBLIC_HEADER_INVENTORY_PATH,
        "header-foundation manifest must use the checked-in pinned public inventory",
    )
    static_export_path = repository_path(
        str(manifest["static_c_abi_exports"]),
        "header-foundation manifest static_c_abi_exports",
    )
    require(
        static_export_path == ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt",
        "header-foundation manifest must use the selected static C export ratchet",
    )
    source_owners = nonempty_strings(
        family["source_owners"], "family[libc.headers-layouts].source_owners"
    )
    for owner in (
        "docker/Dockerfile.x86_64",
        "compat/upstreams.toml",
        "compat/x86_64/headers-layouts-foundation.toml",
        "compat/x86_64/headers-layouts.toml",
        "compat/x86_64/public_headers.txt",
        "compat/x86_64/run_linux_5_10_uapi.sh",
        "compat/x86_64/run_uapi_wrapper_matrix.sh",
        "compat/x86_64/uapi_wrappers_header_abi_probe.c",
        "compat/x86_64/uapi_wrappers_header_abi_probe.cpp",
        "compat/x86_64/run_epoll_header_abi.sh",
        "compat/x86_64/epoll_header_abi_probe.c",
        "compat/x86_64/epoll_header_abi_probe.cpp",
        "compat/x86_64/run_timeval_transitive_header_abi.sh",
        "compat/x86_64/timeval_transitive_header_abi_probe.c",
        "compat/x86_64/timeval_transitive_header_abi_probe.cpp",
        "compat/x86_64/run_sys_time_direct_header_abi.sh",
        "compat/x86_64/sys_time_direct_header_abi_probe.c",
        "compat/x86_64/sys_time_direct_header_abi_probe.cpp",
        "compat/x86_64/run_candidate_header_closure.sh",
        "compat/x86_64/header_cxx_closure.cpp",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/tests/test_candidate_header_closure.py",
        "compat/x86_64/tests/test_uapi_wrapper_matrix.py",
        "compat/x86_64/tests/test_epoll_header_abi.py",
        "compat/x86_64/tests/test_timeval_transitive_header_abi.py",
        "compat/x86_64/tests/test_sys_time_direct_header_abi.py",
        "compat/x86_64/tests/test_runner.py",
        "scripts/dev-x86_64.sh",
    ):
        require(owner in source_owners, f"libc.headers-layouts must own {owner}")

    profile_matrix = manifest["profile_matrix"]
    require(isinstance(profile_matrix, Mapping), "header-foundation profile_matrix must be a table")
    require(
        dict(profile_matrix)
        == {
            "row_key": "resolved-header-path plus language-profile",
            "final_applicability_states": [
                "applicable",
                "not-applicable",
                "blocked-missing-input",
            ],
            "all_rows_resolved": False,
        },
        "header-foundation profile_matrix drifted",
    )

    upstreams = load_toml(UPSTREAMS_PATH)
    upstream_uapi = upstreams.get("linux_5_10_uapi")
    require(
        isinstance(upstream_uapi, Mapping),
        "compat/upstreams.toml must contain the Linux 5.10 UAPI pin",
    )
    require(
        dict(upstream_uapi)
        == {
            "version": EXPECTED_LINUX_5_10_UAPI_VERSION,
            "source": EXPECTED_LINUX_5_10_UAPI_ARCHIVE,
            "sha256": EXPECTED_LINUX_5_10_UAPI_SOURCE_SHA256,
            "architecture": EXPECTED_LINUX_5_10_UAPI_ARCHITECTURE,
            "headers_install_arch": EXPECTED_LINUX_5_10_UAPI_HEADERS_INSTALL_ARCH,
            "exported_header_count": EXPECTED_LINUX_5_10_UAPI_HEADER_COUNT,
            "exported_header_manifest_sha256": EXPECTED_LINUX_5_10_UAPI_HEADER_MANIFEST_SHA256,
        },
        "compat/upstreams.toml Linux 5.10 UAPI pin drifted",
    )

    uapi_inputs = manifest["uapi_input"]
    require(isinstance(uapi_inputs, list) and len(uapi_inputs) == 1, "header-foundation requires one Linux UAPI input")
    uapi_input = uapi_inputs[0]
    require(isinstance(uapi_input, Mapping), "header-foundation UAPI input must be a table")
    require(
        set(uapi_input)
        == {
            "id",
            "state",
            "upstream_pin",
            "source",
            "version",
            "source_archive",
            "source_sha256",
            "architecture",
            "install_arch",
            "exported_header_count",
            "exported_header_manifest_sha256",
            "provenance_verifier",
            "role",
            "paths",
            "closure_rule",
        },
        "header-foundation UAPI input keys drifted",
    )
    require(uapi_input["id"] == "linux-5.10-uapi", "header-foundation UAPI input id drifted")
    require(
        uapi_input["state"] == "pinned-verified",
        "header-foundation Linux UAPI input must remain pinned and verified",
    )
    require(
        uapi_input["upstream_pin"] == EXPECTED_LINUX_5_10_UAPI_UPSTREAM_PIN,
        "header-foundation Linux UAPI upstream pin drifted",
    )
    require(
        uapi_input["source"] == "Linux 5.10 UAPI export tree",
        "header-foundation Linux UAPI source drifted",
    )
    require(
        uapi_input["version"] == EXPECTED_LINUX_5_10_UAPI_VERSION,
        "header-foundation Linux UAPI version drifted",
    )
    require(
        uapi_input["source_archive"] == EXPECTED_LINUX_5_10_UAPI_ARCHIVE,
        "header-foundation Linux UAPI source archive drifted",
    )
    require(
        uapi_input["source_sha256"] == EXPECTED_LINUX_5_10_UAPI_SOURCE_SHA256,
        "header-foundation Linux UAPI source checksum drifted",
    )
    require(
        uapi_input["architecture"] == EXPECTED_LINUX_5_10_UAPI_ARCHITECTURE
        and uapi_input["install_arch"] == EXPECTED_LINUX_5_10_UAPI_HEADERS_INSTALL_ARCH,
        "header-foundation Linux UAPI architecture contract drifted",
    )
    require(
        uapi_input["exported_header_count"] == EXPECTED_LINUX_5_10_UAPI_HEADER_COUNT,
        "header-foundation Linux UAPI exported-header count drifted",
    )
    require(
        uapi_input["exported_header_manifest_sha256"]
        == EXPECTED_LINUX_5_10_UAPI_HEADER_MANIFEST_SHA256,
        "header-foundation Linux UAPI exported-header manifest digest drifted",
    )
    require(
        {
            "version": uapi_input["version"],
            "source": uapi_input["source_archive"],
            "sha256": uapi_input["source_sha256"],
            "architecture": uapi_input["architecture"],
            "headers_install_arch": uapi_input["install_arch"],
            "exported_header_count": uapi_input["exported_header_count"],
            "exported_header_manifest_sha256": uapi_input[
                "exported_header_manifest_sha256"
            ],
        }
        == dict(upstream_uapi),
        "header-foundation Linux UAPI input diverged from compat/upstreams.toml",
    )
    uapi_verifier_path = repository_path(
        str(uapi_input["provenance_verifier"]),
        "header-foundation Linux UAPI provenance_verifier",
    )
    require(
        uapi_verifier_path == LINUX_5_10_UAPI_VERIFIER_PATH,
        "header-foundation Linux UAPI provenance verifier drifted",
    )
    require(uapi_verifier_path.is_file(), "header-foundation Linux UAPI verifier is missing")
    require(
        isinstance(uapi_input["role"], str) and uapi_input["role"],
        "header-foundation Linux UAPI input needs a role",
    )
    require(
        isinstance(uapi_input["closure_rule"], str)
        and "hash-pinned" in uapi_input["closure_rule"]
        and "ambient host" in uapi_input["closure_rule"],
        "header-foundation Linux UAPI input must reject ambient-host closure",
    )
    uapi_input_paths = string_list(uapi_input["paths"], "header-foundation UAPI input paths")
    require(
        tuple(uapi_input_paths) == tuple(EXPECTED_PUBLIC_HEADER_UAPI_GAPS.values()),
        "header-foundation Linux UAPI input paths drifted",
    )

    uapi_verifier = uapi_verifier_path.read_text(encoding="utf-8")
    dockerfile = X86_64_EVIDENCE_DOCKERFILE_PATH.read_text(encoding="utf-8")
    for phrase in (
        f"readonly LINUX_UAPI_HEADER_COUNT={EXPECTED_LINUX_5_10_UAPI_HEADER_COUNT}",
        "readonly LINUX_UAPI_HEADER_MANIFEST_SHA256="
        f"{EXPECTED_LINUX_5_10_UAPI_HEADER_MANIFEST_SHA256}",
        "header_manifest_sha256=${LINUX_UAPI_HEADER_MANIFEST_SHA256}",
    ):
        require(phrase in uapi_verifier, f"Linux UAPI verifier omits fixed {phrase}")
    for phrase in (
        f"ARG LINUX_UAPI_VERSION={EXPECTED_LINUX_5_10_UAPI_VERSION}",
        f"ARG LINUX_UAPI_SHA256={EXPECTED_LINUX_5_10_UAPI_SOURCE_SHA256}",
        f"ARG LINUX_UAPI_HEADER_COUNT={EXPECTED_LINUX_5_10_UAPI_HEADER_COUNT}",
        "ARG LINUX_UAPI_HEADER_MANIFEST_SHA256="
        f"{EXPECTED_LINUX_5_10_UAPI_HEADER_MANIFEST_SHA256}",
        "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${LINUX_UAPI_VERSION}.tar.xz",
        "sha256sum -c -",
    ):
        require(phrase in dockerfile, f"x86 evidence Dockerfile omits fixed UAPI {phrase}")

    closure_diagnostics = manifest["closure_diagnostic"]
    require(
        isinstance(closure_diagnostics, list) and len(closure_diagnostics) == 1,
        "header-foundation requires one live candidate-header closure diagnostic",
    )
    closure_diagnostic = closure_diagnostics[0]
    require(
        isinstance(closure_diagnostic, Mapping),
        "header-foundation candidate-header closure diagnostic must be a table",
    )
    require(
        set(closure_diagnostic)
        == {
            "id",
            "state",
            "command",
            "required_result",
            "profiles",
            "pinned_public_header_count",
            "candidate_public_header_count",
            "candidate_only_header_count",
            "record_count",
            "scope",
        },
        "header-foundation candidate-header closure diagnostic keys drifted",
    )
    require(
        closure_diagnostic["id"] == "isolated-candidate-header-closure",
        "header-foundation candidate-header closure diagnostic id drifted",
    )
    require(
        closure_diagnostic["state"] == "required-live"
        and closure_diagnostic["required_result"] == "pass",
        "header-foundation candidate-header closure diagnostic must require a live pass",
    )
    require(
        closure_diagnostic["command"]
        == "./scripts/dev-x86_64.sh candidate-header-closure",
        "header-foundation candidate-header closure command drifted",
    )
    require(
        tuple(string_list(closure_diagnostic["profiles"], "header-foundation closure profiles"))
        == ("c11-gnu", "cxx17-gnu"),
        "header-foundation candidate-header closure profiles drifted",
    )
    require(
        closure_diagnostic["pinned_public_header_count"] == EXPECTED_PUBLIC_HEADER_COUNT
        and closure_diagnostic["candidate_public_header_count"]
        == EXPECTED_PUBLIC_HEADER_COUNT + len(EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY)
        and closure_diagnostic["candidate_only_header_count"]
        == len(EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY)
        and closure_diagnostic["record_count"] == EXPECTED_CANDIDATE_HEADER_CLOSURE_RECORD_COUNT,
        "header-foundation candidate-header closure inventory counts drifted",
    )
    require(
        isinstance(closure_diagnostic["scope"], str)
        and "no declaration/layout/linkage/runtime/installed-header/public-support claim"
        in closure_diagnostic["scope"],
        "header-foundation candidate-header closure scope must retain its non-completion boundary",
    )
    require(
        CANDIDATE_HEADER_CLOSURE_RUNNER_PATH.is_file(),
        "header-foundation candidate-header closure runner is missing",
    )
    dispatch_source = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    require(
        "candidate-header-closure)" in dispatch_source,
        "candidate-header-closure is absent from the native dispatcher",
    )

    profiles = manifest["language_profile"]
    require(
        isinstance(profiles, list) and len(profiles) == len(EXPECTED_HEADER_FOUNDATION_LANGUAGE_PROFILES),
        "header-foundation language profile count drifted",
    )
    profile_ids: list[str] = []
    for index, entry in enumerate(profiles):
        location = f"header-foundation language_profile[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        require(
            set(entry) == {"id", "language", "standard", "macros", "state"},
            f"{location} keys drifted",
        )
        identifier = entry["id"]
        require(isinstance(identifier, str), f"{location}.id is invalid")
        require(
            identifier in EXPECTED_HEADER_FOUNDATION_LANGUAGE_PROFILES,
            f"{location}.id is not an expected language profile",
        )
        expected = {"id": identifier, **EXPECTED_HEADER_FOUNDATION_LANGUAGE_PROFILES[identifier]}
        require(dict(entry) == expected, f"{location} drifted from its language/feature contract")
        profile_ids.append(identifier)
    require(
        tuple(profile_ids) == tuple(EXPECTED_HEADER_FOUNDATION_LANGUAGE_PROFILES),
        "header-foundation language profile order or roster drifted",
    )

    uapi_wrapper_matrix = manifest["uapi_wrapper_matrix"]
    require(
        isinstance(uapi_wrapper_matrix, Mapping),
        "header-foundation UAPI wrapper matrix must be a table",
    )
    require(
        set(uapi_wrapper_matrix)
        == {
            "id",
            "state",
            "command",
            "required_result",
            "header_class",
            "headers",
            "profiles",
            "row_count",
            "scope",
            "row",
        },
        "header-foundation UAPI wrapper matrix keys drifted",
    )
    require(
        uapi_wrapper_matrix["id"] == EXPECTED_UAPI_WRAPPER_MATRIX_ID,
        "header-foundation UAPI wrapper matrix id drifted",
    )
    require(
        uapi_wrapper_matrix["state"] == "partial-verified"
        and uapi_wrapper_matrix["required_result"] == "pass",
        "header-foundation UAPI wrapper matrix must remain partial verified evidence",
    )
    require(
        uapi_wrapper_matrix["command"] == EXPECTED_UAPI_WRAPPER_MATRIX_COMMAND,
        "header-foundation UAPI wrapper matrix command drifted",
    )
    require(
        uapi_wrapper_matrix["header_class"] == "pinned-uapi-inputs",
        "header-foundation UAPI wrapper matrix must remain scoped to pinned UAPI inputs",
    )
    matrix_headers = string_list(
        uapi_wrapper_matrix["headers"], "header-foundation UAPI wrapper matrix headers"
    )
    require(
        tuple(matrix_headers) == EXPECTED_UAPI_WRAPPER_MATRIX_HEADERS,
        "header-foundation UAPI wrapper matrix headers drifted",
    )
    matrix_profiles = string_list(
        uapi_wrapper_matrix["profiles"], "header-foundation UAPI wrapper matrix profiles"
    )
    require(
        tuple(matrix_profiles) == EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
        "header-foundation UAPI wrapper matrix profiles drifted",
    )
    require(
        uapi_wrapper_matrix["row_count"] == EXPECTED_UAPI_WRAPPER_MATRIX_ROW_COUNT
        and uapi_wrapper_matrix["row_count"] == len(matrix_headers) * len(matrix_profiles),
        "header-foundation UAPI wrapper matrix row count drifted",
    )
    matrix_scope = uapi_wrapper_matrix["scope"]
    require(
        isinstance(matrix_scope, str)
        and all(
            phrase in matrix_scope
            for phrase in (
                "callable linkage",
                "device/ioctl behavior",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation UAPI wrapper matrix scope must retain its non-completion boundary",
    )
    matrix_rows = uapi_wrapper_matrix["row"]
    require(
        isinstance(matrix_rows, list)
        and len(matrix_rows) == EXPECTED_UAPI_WRAPPER_MATRIX_ROW_COUNT,
        "header-foundation UAPI wrapper matrix row roster drifted",
    )
    expected_matrix_rows = tuple(
        (header, dependency, profile)
        for header, dependency in EXPECTED_PUBLIC_HEADER_UAPI_GAPS.items()
        for profile in EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES
    )
    observed_matrix_rows: list[tuple[str, str, str]] = []
    for index, row in enumerate(matrix_rows):
        location = f"header-foundation uapi_wrapper_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row)
            == {"header", "dependency", "profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        header = row["header"]
        dependency = row["dependency"]
        profile = row["profile"]
        require(
            isinstance(header, str) and isinstance(dependency, str) and isinstance(profile, str),
            f"{location} row key is invalid",
        )
        require(
            EXPECTED_PUBLIC_HEADER_UAPI_GAPS.get(header) == dependency,
            f"{location} Linux-UAPI dependency drifted",
        )
        require(
            profile in EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
            f"{location} profile is not a declared UAPI wrapper profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_matrix_rows.append((header, dependency, profile))
    require(
        tuple(observed_matrix_rows) == expected_matrix_rows,
        "header-foundation UAPI wrapper matrix row order or cross-product drifted",
    )
    require(
        UAPI_WRAPPER_MATRIX_RUNNER_PATH.is_file(),
        "header-foundation UAPI wrapper matrix runner is missing",
    )
    dispatch_source = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    require(
        "uapi-wrapper-matrix)" in dispatch_source,
        "uapi-wrapper-matrix is absent from the native dispatcher",
    )
    family_native_evidence = family.get("native_evidence")
    require(
        isinstance(family_native_evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_UAPI_WRAPPER_MATRIX_COMMAND
    ]
    require(
        len(matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one UAPI wrapper matrix evidence command",
    )
    require(
        matrix_evidence[0].get("state") == "required"
        and isinstance(matrix_evidence[0].get("scope"), str)
        and all(
            phrase in matrix_evidence[0]["scope"]
            for phrase in (
                "callable linkage",
                "device/ioctl behavior",
                "all-header closure",
                "runtime",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts UAPI wrapper matrix evidence must retain its non-completion boundary",
    )

    epoll_header_profile_matrix = manifest["epoll_header_profile_matrix"]
    require(
        isinstance(epoll_header_profile_matrix, Mapping),
        "header-foundation epoll header matrix must be a table",
    )
    require(
        set(epoll_header_profile_matrix)
        == {
            "id",
            "state",
            "command",
            "required_result",
            "header_class",
            "subject_header",
            "direct_macro_header",
            "profiles",
            "row_count",
            "scope",
            "row",
        },
        "header-foundation epoll header matrix keys drifted",
    )
    require(
        epoll_header_profile_matrix["id"] == EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ID,
        "header-foundation epoll header matrix id drifted",
    )
    require(
        epoll_header_profile_matrix["state"] == "partial-verified"
        and epoll_header_profile_matrix["required_result"] == "pass",
        "header-foundation epoll header matrix must remain partial verified evidence",
    )
    require(
        epoll_header_profile_matrix["command"] == EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation epoll header matrix command drifted",
    )
    require(
        epoll_header_profile_matrix["header_class"] == "pinned-non-uapi",
        "header-foundation epoll header matrix must remain scoped to one pinned non-UAPI header",
    )
    require(
        epoll_header_profile_matrix["subject_header"]
        == EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_SUBJECT_HEADER,
        "header-foundation epoll header matrix subject header drifted",
    )
    require(
        epoll_header_profile_matrix["direct_macro_header"]
        == EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_DIRECT_MACRO_HEADER,
        "header-foundation epoll header matrix direct macro header drifted",
    )
    epoll_profiles = string_list(
        epoll_header_profile_matrix["profiles"], "header-foundation epoll header matrix profiles"
    )
    require(
        tuple(epoll_profiles) == EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
        "header-foundation epoll header matrix profiles drifted",
    )
    require(
        epoll_header_profile_matrix["row_count"] == EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ROW_COUNT
        and epoll_header_profile_matrix["row_count"] == len(epoll_profiles),
        "header-foundation epoll header matrix row count drifted",
    )
    epoll_scope = epoll_header_profile_matrix["scope"]
    require(
        isinstance(epoll_scope, str)
        and all(
            phrase in epoll_scope
            for phrase in (
                "direct sys/ioctl.h callable declaration parity",
                "epoll callable linkage",
                "epoll runtime/device behavior",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation epoll header matrix scope must retain its non-completion boundary",
    )
    epoll_rows = epoll_header_profile_matrix["row"]
    require(
        isinstance(epoll_rows, list)
        and len(epoll_rows) == EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation epoll header matrix row roster drifted",
    )
    expected_epoll_rows = EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES
    observed_epoll_rows: list[str] = []
    for index, row in enumerate(epoll_rows):
        location = f"header-foundation epoll_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        profile = row["profile"]
        require(isinstance(profile, str), f"{location} profile is invalid")
        require(
            profile in EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
            f"{location} profile is not a declared epoll header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_epoll_rows.append(profile)
    require(
        tuple(observed_epoll_rows) == expected_epoll_rows,
        "header-foundation epoll header matrix row order or cross-product drifted",
    )
    require(
        EPOLL_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation epoll header matrix runner is missing",
    )
    require(
        "epoll-header-abi)" in dispatch_source,
        "epoll-header-abi is absent from the native dispatcher",
    )
    epoll_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(epoll_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one epoll header matrix evidence command",
    )
    require(
        epoll_matrix_evidence[0].get("state") == "required"
        and isinstance(epoll_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in epoll_matrix_evidence[0]["scope"]
            for phrase in (
                "direct sys/ioctl.h callable declaration parity",
                "epoll callable linkage",
                "epoll runtime/device behavior",
                "all-header closure",
                "runtime",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts epoll header matrix evidence must retain its non-completion boundary",
    )

    timeval_transitive_header_profile_matrix = manifest[
        "timeval_transitive_header_profile_matrix"
    ]
    require(
        isinstance(timeval_transitive_header_profile_matrix, Mapping),
        "header-foundation timeval transitive-header matrix must be a table",
    )
    require(
        set(timeval_transitive_header_profile_matrix)
        == {
            "id",
            "state",
            "command",
            "required_result",
            "header_class",
            "subject_headers",
            "sys_time_required_transitive_header",
            "profiles",
            "row_count",
            "scope",
            "row",
        },
        "header-foundation timeval transitive-header matrix keys drifted",
    )
    require(
        timeval_transitive_header_profile_matrix["id"]
        == EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_ID,
        "header-foundation timeval transitive-header matrix id drifted",
    )
    require(
        timeval_transitive_header_profile_matrix["state"] == "partial-verified"
        and timeval_transitive_header_profile_matrix["required_result"] == "pass",
        "header-foundation timeval transitive-header matrix must remain partial verified evidence",
    )
    require(
        timeval_transitive_header_profile_matrix["command"]
        == EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation timeval transitive-header matrix command drifted",
    )
    require(
        timeval_transitive_header_profile_matrix["header_class"] == "pinned-non-uapi",
        "header-foundation timeval transitive-header matrix must remain scoped to fixed pinned non-UAPI headers",
    )
    timeval_headers = string_list(
        timeval_transitive_header_profile_matrix["subject_headers"],
        "header-foundation timeval transitive-header matrix subject headers",
    )
    require(
        tuple(timeval_headers) == EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_HEADERS,
        "header-foundation timeval transitive-header matrix subject headers drifted",
    )
    require(
        timeval_transitive_header_profile_matrix["sys_time_required_transitive_header"]
        == EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_SYS_TIME_REQUIRED_TRANSITIVE_HEADER,
        "header-foundation timeval transitive-header matrix required dependency drifted",
    )
    timeval_profiles = string_list(
        timeval_transitive_header_profile_matrix["profiles"],
        "header-foundation timeval transitive-header matrix profiles",
    )
    require(
        tuple(timeval_profiles) == EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
        "header-foundation timeval transitive-header matrix profiles drifted",
    )
    require(
        timeval_transitive_header_profile_matrix["row_count"]
        == EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_ROW_COUNT
        and timeval_transitive_header_profile_matrix["row_count"]
        == len(timeval_headers) * len(timeval_profiles),
        "header-foundation timeval transitive-header matrix row count drifted",
    )
    timeval_scope = timeval_transitive_header_profile_matrix["scope"]
    require(
        isinstance(timeval_scope, str)
        and all(
            phrase in timeval_scope
            for phrase in (
                "direct sys/time.h callable declaration/linkage",
                "other sys/time.h feature visibility or macro parity",
                "dependent-header callable linkage",
                "runtime behavior",
                "identical private include graph",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation timeval transitive-header matrix scope must retain its non-completion boundary",
    )
    timeval_rows = timeval_transitive_header_profile_matrix["row"]
    require(
        isinstance(timeval_rows, list)
        and len(timeval_rows) == EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation timeval transitive-header matrix row roster drifted",
    )
    expected_timeval_rows = tuple(
        (header, profile)
        for header in EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_HEADERS
        for profile in EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES
    )
    observed_timeval_rows: list[tuple[str, str]] = []
    for index, row in enumerate(timeval_rows):
        location = f"header-foundation timeval_transitive_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"header", "profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        header = row["header"]
        profile = row["profile"]
        require(
            isinstance(header, str) and isinstance(profile, str),
            f"{location} row key is invalid",
        )
        require(
            header in EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_HEADERS,
            f"{location} header is not selected for timeval transitive evidence",
        )
        require(
            profile in EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
            f"{location} profile is not a declared timeval transitive-header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_timeval_rows.append((header, profile))
    require(
        tuple(observed_timeval_rows) == expected_timeval_rows,
        "header-foundation timeval transitive-header matrix row order or cross-product drifted",
    )
    require(
        TIMEVAL_TRANSITIVE_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation timeval transitive-header matrix runner is missing",
    )
    require(
        "timeval-transitive-header-abi)" in dispatch_source,
        "timeval-transitive-header-abi is absent from the native dispatcher",
    )
    timeval_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(timeval_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one timeval transitive-header matrix evidence command",
    )
    require(
        timeval_matrix_evidence[0].get("state") == "required"
        and isinstance(timeval_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in timeval_matrix_evidence[0]["scope"]
            for phrase in (
                "direct sys/time.h callable declaration/linkage",
                "other sys/time.h feature visibility or macro parity",
                "dependent-header callable linkage",
                "identical private include graph",
                "dependent feature surface",
                "runtime",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts timeval transitive-header matrix evidence must retain its non-completion boundary",
    )

    sys_time_direct_header_profile_matrix = manifest[
        "sys_time_direct_header_profile_matrix"
    ]
    require(
        isinstance(sys_time_direct_header_profile_matrix, Mapping),
        "header-foundation direct sys/time header matrix must be a table",
    )
    require(
        set(sys_time_direct_header_profile_matrix)
        == {
            "id",
            "state",
            "command",
            "required_result",
            "header_class",
            "subject_header",
            "profiles",
            "row_count",
            "scope",
            "row",
        },
        "header-foundation direct sys/time header matrix keys drifted",
    )
    require(
        sys_time_direct_header_profile_matrix["id"]
        == EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_ID,
        "header-foundation direct sys/time header matrix id drifted",
    )
    require(
        sys_time_direct_header_profile_matrix["state"] == "partial-verified"
        and sys_time_direct_header_profile_matrix["required_result"] == "pass",
        "header-foundation direct sys/time header matrix must remain partial verified evidence",
    )
    require(
        sys_time_direct_header_profile_matrix["command"]
        == EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation direct sys/time header matrix command drifted",
    )
    require(
        sys_time_direct_header_profile_matrix["header_class"] == "pinned-non-uapi",
        "header-foundation direct sys/time header matrix must remain scoped to one pinned non-UAPI header",
    )
    sys_time_direct_header = sys_time_direct_header_profile_matrix["subject_header"]
    require(
        sys_time_direct_header == EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_SUBJECT_HEADER,
        "header-foundation direct sys/time header matrix subject header drifted",
    )
    sys_time_direct_profiles = string_list(
        sys_time_direct_header_profile_matrix["profiles"],
        "header-foundation direct sys/time header matrix profiles",
    )
    require(
        tuple(sys_time_direct_profiles) == EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
        "header-foundation direct sys/time header matrix profiles drifted",
    )
    require(
        sys_time_direct_header_profile_matrix["row_count"]
        == EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_ROW_COUNT
        and sys_time_direct_header_profile_matrix["row_count"]
        == len(sys_time_direct_profiles),
        "header-foundation direct sys/time header matrix row count drifted",
    )
    sys_time_direct_scope = sys_time_direct_header_profile_matrix["scope"]
    require(
        isinstance(sys_time_direct_scope, str)
        and all(
            phrase in sys_time_direct_scope
            for phrase in (
                "unselected sys/time.h surface",
                "actual callable artifact linkage",
                "runtime behavior",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation direct sys/time header matrix scope must retain its non-completion boundary",
    )
    sys_time_direct_rows = sys_time_direct_header_profile_matrix["row"]
    require(
        isinstance(sys_time_direct_rows, list)
        and len(sys_time_direct_rows)
        == EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation direct sys/time header matrix row roster drifted",
    )
    observed_sys_time_direct_rows: list[str] = []
    for index, row in enumerate(sys_time_direct_rows):
        location = f"header-foundation sys_time_direct_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        profile = row["profile"]
        require(isinstance(profile, str), f"{location} profile is invalid")
        require(
            profile in EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
            f"{location} profile is not a declared direct sys/time header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_sys_time_direct_rows.append(profile)
    require(
        tuple(observed_sys_time_direct_rows) == EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
        "header-foundation direct sys/time header matrix row order or cross-product drifted",
    )
    require(
        SYS_TIME_DIRECT_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation direct sys/time header matrix runner is missing",
    )
    require(
        "sys-time-direct-header-abi)" in dispatch_source,
        "sys-time-direct-header-abi is absent from the native dispatcher",
    )
    sys_time_direct_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_SYS_TIME_DIRECT_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(sys_time_direct_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one direct sys/time header matrix evidence command",
    )
    require(
        sys_time_direct_matrix_evidence[0].get("state") == "required"
        and isinstance(sys_time_direct_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in sys_time_direct_matrix_evidence[0]["scope"]
            for phrase in (
                "actual callable artifact linkage",
                "runtime behavior",
                "all-header closure",
                "runtime",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts direct sys/time header matrix evidence must retain its non-completion boundary",
    )

    inventory_text = inventory_path.read_text(encoding="utf-8")
    pinned_paths = inventory_text.splitlines()
    require(inventory_text.endswith("\n"), "header-foundation pinned inventory must end with a newline")
    require(
        len(pinned_paths) == EXPECTED_PUBLIC_HEADER_COUNT
        and pinned_paths == sorted(pinned_paths)
        and len(pinned_paths) == len(set(pinned_paths)),
        "header-foundation pinned inventory drifted",
    )
    pinned_path_set = set(pinned_paths)
    uapi_header_paths = tuple(EXPECTED_PUBLIC_HEADER_UAPI_GAPS)
    uapi_header_set = set(uapi_header_paths)
    require(
        uapi_header_set <= pinned_path_set,
        "header-foundation UAPI wrappers must remain pinned public headers",
    )
    require(
        set(timeval_headers) <= pinned_path_set - uapi_header_set,
        "header-foundation timeval transitive-header subjects must remain pinned non-UAPI headers",
    )
    require(
        sys_time_direct_header in pinned_path_set - uapi_header_set,
        "header-foundation direct sys/time subject must remain a pinned non-UAPI header",
    )
    project_only_paths = tuple(sorted(EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY))
    project_only_set = set(project_only_paths)
    class_expected_paths = {
        "pinned-non-uapi": pinned_path_set - uapi_header_set,
        "pinned-uapi-inputs": uapi_header_set,
        "project-only-extensions": project_only_set,
    }
    header_classes = manifest["header_class"]
    require(
        isinstance(header_classes, list) and len(header_classes) == len(EXPECTED_HEADER_FOUNDATION_CLASS_IDS),
        "header-foundation header class count drifted",
    )
    class_paths: dict[str, set[str]] = {}
    class_ids: list[str] = []
    for index, entry in enumerate(header_classes):
        location = f"header-foundation header_class[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        identifier = entry.get("id")
        require(isinstance(identifier, str), f"{location}.id is invalid")
        require(
            identifier in EXPECTED_HEADER_FOUNDATION_CLASS_IDS,
            f"{location}.id is not an expected header class",
        )
        expected_keys = {
            "id",
            "origin",
            "expected_count",
            "language_profiles",
            "future_feature_profiles",
            "abi_facets",
            "linkage_owners",
        }
        expected_keys.add("excluded_paths" if identifier == "pinned-non-uapi" else "paths")
        require(set(entry) == expected_keys, f"{location} keys drifted")
        expected_origin = {
            "pinned-non-uapi": "pinned-inventory-excluding",
            "pinned-uapi-inputs": "explicit-pinned",
            "project-only-extensions": "explicit-project-only",
        }[identifier]
        require(entry["origin"] == expected_origin, f"{location}.origin drifted")
        require(
            entry["expected_count"] == len(class_expected_paths[identifier]),
            f"{location}.expected_count does not match its resolved header class",
        )
        require(
            tuple(string_list(entry["language_profiles"], f"{location}.language_profiles"))
            == EXPECTED_HEADER_FOUNDATION_CURRENT_PROFILES,
            f"{location}.language_profiles drifted",
        )
        require(
            tuple(string_list(entry["future_feature_profiles"], f"{location}.future_feature_profiles"))
            == EXPECTED_HEADER_FOUNDATION_FUTURE_PROFILES,
            f"{location}.future_feature_profiles drifted",
        )
        require(
            tuple(string_list(entry["abi_facets"], f"{location}.abi_facets"))
            == EXPECTED_HEADER_FOUNDATION_CLASS_FACETS[identifier],
            f"{location}.abi_facets drifted",
        )
        require(
            tuple(string_list(entry["linkage_owners"], f"{location}.linkage_owners"))
            == EXPECTED_HEADER_FOUNDATION_CLASS_LINKAGE_OWNERS[identifier],
            f"{location}.linkage_owners drifted",
        )
        if identifier == "pinned-non-uapi":
            paths = string_list(entry["excluded_paths"], f"{location}.excluded_paths")
            require(
                tuple(paths) == uapi_header_paths,
                f"{location}.excluded_paths must be the named Linux-UAPI wrappers",
            )
            resolved_paths = pinned_path_set - set(paths)
        else:
            paths = string_list(entry["paths"], f"{location}.paths")
            require(len(paths) == len(set(paths)), f"{location}.paths contains a duplicate")
            if identifier == "pinned-uapi-inputs":
                require(
                    tuple(paths) == uapi_header_paths,
                    f"{location}.paths must name every Linux-UAPI wrapper",
                )
            else:
                require(
                    tuple(paths) == project_only_paths,
                    f"{location}.paths must name every project-only public header",
                )
                for path in paths:
                    require(
                        (ROOT / "include" / path).is_file(),
                        f"{location}.paths contains a missing project header: {path}",
                    )
            resolved_paths = set(paths)
        require(
            resolved_paths == class_expected_paths[identifier],
            f"{location} does not resolve its exact header inventory",
        )
        class_paths[identifier] = resolved_paths
        class_ids.append(identifier)
    require(
        tuple(class_ids) == EXPECTED_HEADER_FOUNDATION_CLASS_IDS,
        "header-foundation header class order or roster drifted",
    )
    require(
        set().union(*class_paths.values()) == pinned_path_set | project_only_set,
        "header-foundation classes do not cover every pinned and project-only public header",
    )
    accounted_header_count = sum(len(paths) for paths in class_paths.values())
    require(
        accounted_header_count == len(pinned_path_set | project_only_set),
        "header-foundation classes overlap",
    )

    profile_obligations = manifest["profile_obligation"]
    require(
        isinstance(profile_obligations, list)
        and len(profile_obligations) == len(EXPECTED_HEADER_FOUNDATION_PROFILE_OBLIGATIONS),
        "header-foundation profile obligation count drifted",
    )
    obligation_keys: list[tuple[str, str]] = []
    for index, entry in enumerate(profile_obligations):
        location = f"header-foundation profile_obligation[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        require(
            set(entry) == {"header_class", "profile", "applicability", "state", "evidence"},
            f"{location} keys drifted",
        )
        header_class = entry["header_class"]
        profile = entry["profile"]
        require(isinstance(header_class, str) and isinstance(profile, str), f"{location} key is invalid")
        key = (header_class, profile)
        require(
            key in EXPECTED_HEADER_FOUNDATION_PROFILE_OBLIGATIONS,
            f"{location} is not an expected header/profile obligation",
        )
        expected_applicability, expected_state, expected_evidence = (
            EXPECTED_HEADER_FOUNDATION_PROFILE_OBLIGATIONS[key]
        )
        require(
            entry["applicability"] == expected_applicability,
            f"{location}.applicability drifted",
        )
        require(entry["state"] == expected_state, f"{location}.state drifted")
        require(
            tuple(string_list(entry["evidence"], f"{location}.evidence")) == expected_evidence,
            f"{location}.evidence drifted",
        )
        obligation_keys.append(key)
    require(
        tuple(obligation_keys) == tuple(EXPECTED_HEADER_FOUNDATION_PROFILE_OBLIGATIONS),
        "header-foundation profile obligation order or roster drifted",
    )
    profile_matrix_row_count = sum(
        len(class_paths[header_class])
        for header_class, _profile in obligation_keys
    )
    require(
        profile_matrix_row_count == accounted_header_count * len(profile_ids),
        "header-foundation profile obligations do not expand to every header/profile row",
    )

    uapi_paths = manifest["uapi_path"]
    require(
        isinstance(uapi_paths, list) and len(uapi_paths) == len(EXPECTED_PUBLIC_HEADER_UAPI_GAPS),
        "header-foundation UAPI path count drifted",
    )
    observed_uapi_paths: list[tuple[str, str]] = []
    for index, entry in enumerate(uapi_paths):
        location = f"header-foundation uapi_path[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        require(set(entry) == {"header", "dependency", "state"}, f"{location} keys drifted")
        header = entry["header"]
        dependency = entry["dependency"]
        require(
            isinstance(header, str) and isinstance(dependency, str),
            f"{location} header or dependency is invalid",
        )
        require(
            EXPECTED_PUBLIC_HEADER_UAPI_GAPS.get(header) == dependency,
            f"{location} does not name a required Linux-UAPI dependency",
        )
        require(
            entry["state"] == "pinned-input-verified",
            f"{location}.state must retain the verified pinned Linux-UAPI boundary",
        )
        observed_uapi_paths.append((header, dependency))
    require(
        tuple(observed_uapi_paths) == tuple(EXPECTED_PUBLIC_HEADER_UAPI_GAPS.items()),
        "header-foundation UAPI path order or roster drifted",
    )
    require(
        tuple(dependency for _header, dependency in observed_uapi_paths) == tuple(uapi_input_paths),
        "header-foundation UAPI paths must use the explicit Linux 5.10 input",
    )

    facets = manifest["abi_facet"]
    require(
        isinstance(facets, list) and len(facets) == len(EXPECTED_HEADER_FOUNDATION_FACETS),
        "header-foundation ABI facet count drifted",
    )
    facet_ids: list[str] = []
    for index, entry in enumerate(facets):
        location = f"header-foundation abi_facet[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        identifier = entry.get("id")
        require(isinstance(identifier, str), f"{location}.id is invalid")
        expected_keys = {"id", "state", "scope", "owner", "evidence", "description"}
        if identifier == "legacy-direct-layout-inputs":
            expected_keys.add("legacy_probes")
        require(set(entry) == expected_keys, f"{location} keys drifted")
        require(
            identifier in EXPECTED_HEADER_FOUNDATION_FACETS,
            f"{location}.id is not an expected ABI facet",
        )
        expected_state, expected_scope, expected_owner, expected_evidence = (
            EXPECTED_HEADER_FOUNDATION_FACETS[identifier]
        )
        require(entry["state"] == expected_state, f"{location}.state drifted")
        require(entry["scope"] == expected_scope, f"{location}.scope drifted")
        require(entry["owner"] == expected_owner, f"{location}.owner drifted")
        require(
            tuple(string_list(entry["evidence"], f"{location}.evidence")) == expected_evidence,
            f"{location}.evidence drifted",
        )
        require(
            isinstance(entry["description"], str) and entry["description"],
            f"{location}.description is empty",
        )
        if identifier == "legacy-direct-layout-inputs":
            require(
                tuple(string_list(entry["legacy_probes"], f"{location}.legacy_probes"))
                == tuple(EXPECTED_HEADER_LAYOUT_PROBES),
                f"{location}.legacy_probes drifted",
            )
        facet_ids.append(identifier)
    require(
        tuple(facet_ids) == tuple(EXPECTED_HEADER_FOUNDATION_FACETS),
        "header-foundation ABI facet order or roster drifted",
    )

    linkage_owners = manifest["linkage_owner"]
    require(
        isinstance(linkage_owners, list)
        and len(linkage_owners) == len(EXPECTED_HEADER_FOUNDATION_LINKAGE_OWNERS),
        "header-foundation linkage owner count drifted",
    )
    linkage_ids: list[str] = []
    for index, entry in enumerate(linkage_owners):
        location = f"header-foundation linkage_owner[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        require(
            set(entry) == {"id", "state", "scope", "family", "evidence", "description"},
            f"{location} keys drifted",
        )
        identifier = entry["id"]
        require(isinstance(identifier, str), f"{location}.id is invalid")
        require(
            identifier in EXPECTED_HEADER_FOUNDATION_LINKAGE_OWNERS,
            f"{location}.id is not an expected linkage owner",
        )
        expected_state, expected_scope, expected_family, expected_evidence = (
            EXPECTED_HEADER_FOUNDATION_LINKAGE_OWNERS[identifier]
        )
        require(entry["state"] == expected_state, f"{location}.state drifted")
        require(entry["scope"] == expected_scope, f"{location}.scope drifted")
        require(entry["family"] == expected_family, f"{location}.family drifted")
        require(
            tuple(string_list(entry["evidence"], f"{location}.evidence")) == expected_evidence,
            f"{location}.evidence drifted",
        )
        require(
            isinstance(entry["description"], str) and entry["description"],
            f"{location}.description is empty",
        )
        linkage_ids.append(identifier)
    require(
        tuple(linkage_ids) == tuple(EXPECTED_HEADER_FOUNDATION_LINKAGE_OWNERS),
        "header-foundation linkage owner order or roster drifted",
    )
    static_export_names = static_c_abi_export_names(static_export_path)
    require(
        "unlisted-public-callables" in linkage_ids,
        "header-foundation needs the declared-callable catch-all ownership rule",
    )
    require(
        "noncallable-header-abi" in linkage_ids,
        "header-foundation needs the noncallable-header ABI ownership rule",
    )

    return {
        "header_count": accounted_header_count,
        "pinned_header_count": len(pinned_path_set),
        "project_only_header_count": len(project_only_set),
        "uapi_path_count": len(observed_uapi_paths),
        "uapi_wrapper_matrix_row_count": len(observed_matrix_rows),
        "epoll_header_profile_matrix_row_count": len(observed_epoll_rows),
        "timeval_transitive_header_profile_matrix_row_count": len(observed_timeval_rows),
        "sys_time_direct_header_profile_matrix_row_count": len(observed_sys_time_direct_rows),
        "language_profile_count": len(profile_ids),
        "profile_obligation_count": len(obligation_keys),
        "profile_matrix_row_count": profile_matrix_row_count,
        "abi_facet_count": len(facet_ids),
        "linkage_owner_count": len(linkage_ids),
        "static_export_count": len(static_export_names),
    }


def require_public_header_surface_artifact(family: Mapping[str, Any]) -> int:
    """Keep the all-public-header consumability inventory honest and bounded.

    This artifact deliberately proves only project-header-first C11+GNU
    consumption against the pinned musl header tree. Its checked-in inventory
    prevents a future musl/header change from silently shrinking the surface.
    The legacy runner deliberately omits the declared Linux 5.10 UAPI root,
    so its three report records identify that runner boundary rather than a
    missing input in the current evidence image; neither those records nor
    candidate-only headers imply ABI or runtime parity.
    """

    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.headers-layouts].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "public-header-c-consumability"
    ]
    require(
        len(matching) == 1,
        "libc.headers-layouts must contain exactly one public-header-c-consumability artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    require(
        "without declaration, layout, linkage, runtime, or public-support parity" in description,
        "public-header-c-consumability must retain its non-completion boundary",
    )
    require(
        "legacy runner deliberately omits the image's declared `/opt/linux-5.10-uapi/include` root"
        in description,
        "public-header-c-consumability must retain its legacy UAPI-omission boundary",
    )
    owners = nonempty_strings(
        artifact["source_owners"],
        "public-header-c-consumability.source_owners",
    )
    for owner in (
        "compat/x86_64/public_headers.txt",
        "compat/x86_64/run_public_header_surface.sh",
    ):
        require(owner in owners, f"public-header-c-consumability omits {owner}")

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        [entry["command"] for entry in evidence]
        == ["./scripts/dev-x86_64.sh public-header-surface"],
        "public-header-c-consumability must use the closed public-header-surface command",
    )
    dispatch_source = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    require(
        "public-header-surface)" in dispatch_source,
        "public-header-surface is absent from the native dispatcher",
    )

    require(
        PUBLIC_HEADER_INVENTORY_PATH.is_file(),
        "checked-in x86 public-header inventory is missing",
    )
    inventory_text = PUBLIC_HEADER_INVENTORY_PATH.read_text(encoding="utf-8")
    names = inventory_text.splitlines()
    require(inventory_text.endswith("\n"), "public-header inventory must end with a newline")
    require(
        len(names) == EXPECTED_PUBLIC_HEADER_COUNT,
        "public-header inventory count drifted from pinned musl 1.2.6",
    )
    require(names == sorted(names), "public-header inventory must be sorted")
    require(len(names) == len(set(names)), "public-header inventory contains a duplicate")
    for index, name in enumerate(names):
        require(
            name
            and name.endswith(".h")
            and not name.startswith("/")
            and ".." not in name.split("/"),
            f"public-header inventory entry {index} is invalid",
        )
        require(not name.startswith("bits/"), "public-header inventory must exclude musl private bits")
    require(
        hashlib.sha256(inventory_text.encode("utf-8")).hexdigest()
        == EXPECTED_PUBLIC_HEADER_SHA256,
        "public-header inventory content drifted from pinned musl 1.2.6",
    )
    candidate_include = ROOT / "include"
    candidate_names = sorted(
        path.relative_to(candidate_include).as_posix()
        for path in candidate_include.rglob("*.h")
        if path.is_file()
        and not path.is_symlink()
        and "bits" not in path.relative_to(candidate_include).parts
    )
    require(
        not (set(names) - set(candidate_names)),
        "project public-header tree is missing a pinned inventory entry",
    )
    require(
        set(candidate_names) - set(names) == EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY,
        "project candidate-only public-header set drifted",
    )

    require(
        PUBLIC_HEADER_SURFACE_RUNNER_PATH.is_file(),
        "public-header consumability runner is missing",
    )
    runner = PUBLIC_HEADER_SURFACE_RUNNER_PATH.read_text(encoding="utf-8")
    for header, uapi_header in EXPECTED_PUBLIC_HEADER_UAPI_GAPS.items():
        require(
            header in runner and uapi_header in runner,
            f"public-header runner omits recorded UAPI limitation {header} -> {uapi_header}",
        )
    for header in EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY:
        require(
            header not in names,
            f"candidate-only x86 header unexpectedly entered pinned inventory: {header}",
        )
    for phrase in (
        "-std=c11",
        "-D_GNU_SOURCE",
        "-I \"$ROOT_DIR/include\"",
        "run_musl_oracle.sh",
        "not declaration/layout/linkage/runtime/public-support parity",
        "export LC_ALL=C",
        "prepare_report_path()",
        "report path component is a symlink",
        "EXPECTED_PINNED_PUBLIC_HEADER_COUNT=183",
        "EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT=191",
        "EXPECTED_COMPILE_OK_COUNT=180",
        "EXPECTED_REFERENCE_UAPI_UNAVAILABLE_COUNT=3",
        "EXPECTED_CANDIDATE_ONLY_COUNT=8",
        "intentionally does not add the image's declared",
    ):
        require(phrase in runner, f"public-header runner omits {phrase}")
    return len(names)


def require_header_layouts_baseline_artifact(family: Mapping[str, Any]) -> None:
    """Keep the C/C++ static aggregate below header-family promotion.

    It deliberately joins existing selected archive leaves and existing
    direct header gates.  The artifact must never turn that useful linkage
    proof into an installed-header, general-C-ABI, C++ runtime, or x86 support
    claim.
    """

    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.headers-layouts].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-header-layouts-baseline"
    ]
    require(
        len(matching) == 1,
        "libc.headers-layouts must contain exactly one static-c-header-layouts-baseline artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.headers-layouts`",
        "freestanding C++17 companion",
        "unmangled C entry called from C",
        "`__errno_location`",
        "`fstat`",
        "`clock_gettime`",
        "`mmap`/`munmap`/`mprotect`/`madvise`/`posix_madvise`/`mincore`",
        "`getrlimit`",
        "`poll`/`select`",
        "`socketpair`/`close`",
        "`sigemptyset`",
        "`cfmakeraw`",
        "`uname`/`sysinfo`",
        "`getpagesize`",
        "no new C export",
        "`include/**` edit",
        "installed-header closure",
        "C++ runtime",
        "complete C ABI",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-header-layouts-baseline description omits {phrase}",
        )
    owners = set(artifact["source_owners"])
    for owner in (
        "compat/upstreams.toml",
        "compat/x86_64/libc_header_layouts_baseline_probe.c",
        "compat/x86_64/libc_header_layouts_baseline_probe.cpp",
        "compat/x86_64/libc_header_layouts_baseline_start.S",
        "compat/x86_64/run_libc_header_layouts_baseline.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/tests/test_runner.py",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    ):
        require(
            owner in owners,
            f"static-c-header-layouts-baseline must own {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("Variant-II %fs" in item and "no CRT" in item for item in prerequisites),
        "static-c-header-layouts-baseline must retain the fixture-only TLS boundary",
    )
    require(
        any(
            "no C++ standard headers" in item
            and "__gxx_personality_v0" in item
            and "__tls_get_addr" in item
            for item in prerequisites
        ),
        "static-c-header-layouts-baseline must retain the C++ runtime rejection boundary",
    )
    require(
        any(
            "stat=144" in item
            and "timespec=16" in item
            and "termios=60" in item
            and "zero-timeout poll/select" in item
            for item in prerequisites
        ),
        "static-c-header-layouts-baseline must retain its selected record/layout boundary",
    )
    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
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
        require(
            any(header in item for item in header_prerequisites),
            f"static-c-header-layouts-baseline omits project header {header}",
        )
    require(
        any("headers-layouts.toml" in item and "does not alter" in item for item in header_prerequisites),
        "static-c-header-layouts-baseline must retain the closed direct-probe inventory",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-header-layouts-baseline"},
        "static-c-header-layouts-baseline must use the closed libc-header-layouts-baseline command",
    )
    dispatch_source = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    require(
        "libc-header-layouts-baseline)" in dispatch_source,
        "libc-header-layouts-baseline is absent from the native dispatcher",
    )


def require_evidence_state(
    value: Any, location: str, expected_state: str
) -> tuple[list[Mapping[str, Any]], set[str]]:
    """Require one evidence state without promoting its owning family."""
    require(expected_state in ALLOWED_EVIDENCE_STATES, f"{location} has invalid expected state")
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    records: list[Mapping[str, Any]] = []
    states: set[str] = set()
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        state = entry.get("state")
        command = entry.get("command")
        scope = entry.get("scope")
        require(state in ALLOWED_EVIDENCE_STATES, f"{item_location}.state is invalid")
        require(isinstance(command, str) and command, f"{item_location}.command is empty")
        require(isinstance(scope, str) and scope, f"{item_location}.scope is empty")
        states.add(state)
        records.append(entry)
    require(states == {expected_state}, f"{location} must be entirely {expected_state}")
    return records, states


def require_evidence(
    value: Any, location: str, status: str
) -> tuple[list[Mapping[str, Any]], set[str]]:
    expected_state = "verified" if status == "foundation-verified" else "required"
    return require_evidence_state(value, location, expected_state)


def require_oracles(value: Any, location: str) -> None:
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        for key in ("kind", "source", "role"):
            item = entry.get(key)
            require(isinstance(item, str) and item, f"{item_location}.{key} is empty")


def require_verified_slices(
    value: Any,
    location: str,
    status: str,
    family_capabilities: list[str],
) -> list[Mapping[str, Any]]:
    """Validate completed vertical slices for a planned or foundation family.

    Planned families may retain independently completed partial slices. A
    foundation family may retain them as the provenance for its aggregate
    evidence; family-specific promotion ratchets below decide when that
    aggregate has accounted for every declared capability.
    """
    if value is None:
        return []
    require(
        status in {"planned", "foundation-verified"},
        f"{location} is allowed only on a planned or foundation-verified family",
    )
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    records: list[Mapping[str, Any]] = []
    family_capability_set = set(family_capabilities)
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        for key in (
            "id",
            "description",
            "source_owners",
            "x86_abi_prerequisites",
            "x86_header_prerequisites",
            "native_evidence",
            "oracle",
            "capabilities",
        ):
            require(key in entry, f"{item_location} is missing {key}")
        require(isinstance(entry["id"], str) and entry["id"], f"{item_location}.id is empty")
        require(
            isinstance(entry["description"], str) and entry["description"],
            f"{item_location}.description is empty",
        )
        capabilities = nonempty_strings(entry["capabilities"], f"{item_location}.capabilities")
        require(
            len(capabilities) == len(set(capabilities)),
            f"{item_location}.capabilities contains a duplicate",
        )
        outside_family = sorted(set(capabilities) - family_capability_set)
        require(
            not outside_family,
            f"{item_location}.capabilities escape the owning family: {', '.join(outside_family)}",
        )
        for owner_index, path_text in enumerate(
            nonempty_strings(entry["source_owners"], f"{item_location}.source_owners")
        ):
            repository_path(path_text, f"{item_location}.source_owners[{owner_index}]")
        nonempty_strings(entry["x86_abi_prerequisites"], f"{item_location}.x86_abi_prerequisites")
        nonempty_strings(entry["x86_header_prerequisites"], f"{item_location}.x86_header_prerequisites")
        require_evidence_state(entry["native_evidence"], f"{item_location}.native_evidence", "verified")
        require_oracles(entry["oracle"], f"{item_location}.oracle")
        records.append(entry)
    return records


def require_verified_artifacts(
    value: Any,
    location: str,
    status: str,
) -> list[Mapping[str, Any]]:
    """Validate completed artifact evidence that has no semantic capability ID.

    Header/layout and startup foundations can be real selected binaries before
    they implement one of the baseline facade capabilities. Keep those records
    distinct from ``verified_slice``: they prove a named artifact boundary but
    cannot consume, duplicate, or imply ownership of a capability.
    """
    if value is None:
        return []
    require(status == "planned", f"{location} is allowed only on a planned family")
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    records: list[Mapping[str, Any]] = []
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        for key in (
            "id",
            "description",
            "source_owners",
            "x86_abi_prerequisites",
            "x86_header_prerequisites",
            "native_evidence",
            "oracle",
        ):
            require(key in entry, f"{item_location} is missing {key}")
        require(
            "capabilities" not in entry,
            f"{item_location} must not carry capabilities; use verified_slice instead",
        )
        require(isinstance(entry["id"], str) and entry["id"], f"{item_location}.id is empty")
        require(
            isinstance(entry["description"], str) and entry["description"],
            f"{item_location}.description is empty",
        )
        for owner_index, path_text in enumerate(
            nonempty_strings(entry["source_owners"], f"{item_location}.source_owners")
        ):
            repository_path(path_text, f"{item_location}.source_owners[{owner_index}]")
        nonempty_strings(entry["x86_abi_prerequisites"], f"{item_location}.x86_abi_prerequisites")
        nonempty_strings(entry["x86_header_prerequisites"], f"{item_location}.x86_header_prerequisites")
        require_evidence_state(entry["native_evidence"], f"{item_location}.native_evidence", "verified")
        require_oracles(entry["oracle"], f"{item_location}.oracle")
        records.append(entry)
    return records


def require_byte_string_artifact(family: Mapping[str, Any]) -> None:
    """Keep the closed byte-string artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-byte-strings"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-byte-strings artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in BYTE_STRING_SYMBOLS:
        require(symbol in description, f"static-c-byte-strings description omits {symbol}")
    for phrase in (
        "public `index` and `rindex` forwarding wrappers",
        "private `__strchrnul`/`__memrchr` helpers",
        "scalar fallback",
    ):
        require(phrase in description, f"static-c-byte-strings description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence} == {"./scripts/dev-x86_64.sh libc-byte-strings"},
        "static-c-byte-strings must use the closed libc-byte-strings command",
    )


def require_ldso_initial_graph_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet the one private ET_DYN graph without promoting the loader family."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[ldso.dynamic-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "ldso-initial-graph"]
    require(len(matching) == 1, "ldso.dynamic-runtime needs exactly one ldso-initial-graph artifact")
    artifact = matching[0]
    require(family.get("status") == "planned", "ldso-initial-graph must not promote ldso.dynamic-runtime")
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `ldso.dynamic-runtime`",
        "main PIE -> mid.so -> leaf.so",
        "R_X86_64_RELATIVE",
        "R_X86_64_GLOB_DAT",
        "R_X86_64_JUMP_SLOT",
        "PT_GNU_RELRO",
        "leaf-before-mid",
        "main-image DT_INIT/DT_INIT_ARRAY dispatch",
        "DT_RELR",
        "TLS/DTV/__tls_get_addr",
        "public x86 support",
    ):
        require(phrase in description, f"ldso-initial-graph description omits {phrase}")
    expected_sources = {
        "ldso/src/x86_64_initial_graph.rs",
        "compat/x86_64/ldso_initial_graph_start.S",
        "compat/x86_64/ldso_initial_graph_leaf.c",
        "compat/x86_64/ldso_initial_graph_mid.c",
        "compat/x86_64/ldso_initial_graph_main.c",
        "compat/x86_64/ldso_initial_graph_oracle_main.c",
        "compat/x86_64/run_ldso_initial_graph.sh",
        "scripts/dev-x86_64.sh",
    }
    require(
        set(string_list(artifact["source_owners"], "ldso-initial-graph source owners")) == expected_sources,
        "ldso-initial-graph source owners drifted",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence} == {"./scripts/dev-x86_64.sh ldso-initial-graph"},
        "ldso-initial-graph must use the dedicated native command",
    )
    require(
        "run_ldso_initial_graph.sh" in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "ldso-initial-graph dispatcher binding is missing",
    )


def require_random_entropy_artifact(family: Mapping[str, Any]) -> None:
    """Keep the direct entropy artifact's cancellation and TLS boundary explicit."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-random-entropy"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-random-entropy artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in RANDOM_ENTROPY_SYMBOLS:
        require(symbol in description, f"static-c-random-entropy description omits {symbol}")
    for phrase in (
        "pthread cancellation point",
        "disables cancellation",
        "omits pthread cancellation",
        "initial-TLS errno",
    ):
        require(phrase in description, f"static-c-random-entropy description omits {phrase}")
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("syscall_cp" in item and "cancellation point" in item for item in prerequisites),
        "static-c-random-entropy must record musl getrandom cancellation semantics",
    )
    require(
        any("disables cancellation" in item for item in prerequisites),
        "static-c-random-entropy must record musl getentropy cancellation semantics",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-random-entropy"},
        "static-c-random-entropy must use the closed libc-random-entropy command",
    )


def require_memory_search_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless memory-search artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-memory-search"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-memory-search artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in MEMORY_SEARCH_SYMBOLS:
        require(symbol in description, f"static-c-memory-search description omits {symbol}")
    for phrase in (
        "private `__memrchr` helper",
        "stateless",
        "allocation-free",
    ):
        require(phrase in description, f"static-c-memory-search description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-memory-search"},
        "static-c-memory-search must use the closed libc-memory-search command",
    )


def require_string_copy_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless C-string-copy artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-string-copy"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-string-copy artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in STRING_COPY_SYMBOLS:
        require(symbol in description, f"static-c-string-copy description omits {symbol}")
    for phrase in (
        "private `__stpcpy`/`__stpncpy` helpers",
        "stateless",
        "allocation-free",
        "scalar fallback",
    ):
        require(phrase in description, f"static-c-string-copy description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-string-copy"},
        "static-c-string-copy must use the closed libc-string-copy command",
    )


def require_ctype_artifact(family: Mapping[str, Any]) -> None:
    """Keep the fixed-C-locale ctype artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-ctype"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-ctype artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in CTYPE_SYMBOLS:
        require(symbol in description, f"static-c-ctype description omits {symbol}")
    for phrase in (
        "fixed-C-locale ctype block",
        "stateless",
        "allocation-free",
        "`EOF` and every `unsigned char` value",
        "locale selection and `_l` entries",
    ):
        require(phrase in description, f"static-c-ctype description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-ctype"},
        "static-c-ctype must use the closed libc-ctype command",
    )


def require_integer_arithmetic_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless integer-arithmetic artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-integer-arithmetic"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-integer-arithmetic artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in INTEGER_ARITHMETIC_SYMBOLS:
        require(
            symbol in description,
            f"static-c-integer-arithmetic description omits {symbol}",
        )
    for phrase in (
        "integer-arithmetic block",
        "stateless",
        "allocation-free",
        "unrepresentable absolute value",
        "zero divisor",
        "native signed `idiv`",
    ):
        require(
            phrase in description,
            f"static-c-integer-arithmetic description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-integer-arithmetic"},
        "static-c-integer-arithmetic must use the closed libc-integer-arithmetic command",
    )


def require_integer_parse_artifact(family: Mapping[str, Any]) -> None:
    """Keep the bounded integer-parsing artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-integer-parse"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-integer-parse artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in INTEGER_PARSE_SYMBOLS:
        require(
            symbol in description,
            f"static-c-integer-parse description omits {symbol}",
        )
    for phrase in (
        "integer-parsing block",
        "complete selected byte-string scan",
        "fixed-C-locale",
        "`0x` prefixes",
        "`EINVAL` invalid-base/no-conversion",
        "stale errno on success",
        "`ERANGE` saturation",
        "defined-input",
        "allocation-free",
    ):
        require(
            phrase in description,
            f"static-c-integer-parse description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "rdi/rsi/rdx" in item and "intmax_t/uintmax_t" in item
            for item in prerequisites
        ),
        "static-c-integer-parse must record its SysV and LP64 calling contract",
    )
    require(
        any(
            "strtol.c" in item and "intscan.c" in item and "shgetc" in item
            for item in prerequisites
        ),
        "static-c-integer-parse must record its pinned-musl scan mapping",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-integer-parse"},
        "static-c-integer-parse must use the closed libc-integer-parse command",
    )


def require_intmax_arithmetic_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless intmax-arithmetic artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-intmax-arithmetic"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-intmax-arithmetic artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in INTMAX_ARITHMETIC_SYMBOLS:
        require(
            symbol in description,
            f"static-c-intmax-arithmetic description omits {symbol}",
        )
    for phrase in (
        "intmax-arithmetic block",
        "stateless",
        "allocation-free",
        "unrepresentable absolute value",
        "zero divisor",
        "native signed `idiv`",
    ):
        require(
            phrase in description,
            f"static-c-intmax-arithmetic description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-intmax-arithmetic"},
        "static-c-intmax-arithmetic must use the closed libc-intmax-arithmetic command",
    )


def require_credential_observation_artifact(family: Mapping[str, Any]) -> None:
    """Keep the read-only credential-observation artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-credential-observation"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-credential-observation artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in CREDENTIAL_OBSERVATION_SYMBOLS:
        require(
            symbol in description,
            f"static-c-credential-observation description omits {symbol}",
        )
    for phrase in (
        "credential-observation block",
        "read-only",
        "query-then-fill race",
        "GNU",
        "initial-TLS",
    ):
        require(
            phrase in description,
            f"static-c-credential-observation description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-credential-observation"},
        "static-c-credential-observation must use the closed libc-credential-observation command",
    )


def require_child_reaping_artifact(family: Mapping[str, Any]) -> None:
    """Keep the complete direct child-reaping artifact boundary durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-child-reaping"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-child-reaping artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in CHILD_REAPING_SYMBOLS:
        require(
            symbol in description,
            f"static-c-child-reaping description omits {symbol}",
        )
    for phrase in (
        "child-reaping block",
        "WNOHANG",
        "WNOWAIT",
        "cancellation",
        "initial-TLS",
    ):
        require(
            phrase in description,
            f"static-c-child-reaping description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-child-reaping"},
        "static-c-child-reaping must use the closed libc-child-reaping command",
    )


def require_immediate_termination_artifact(family: Mapping[str, Any]) -> None:
    """Keep the no-state C11 immediate-termination boundary durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-immediate-termination"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-immediate-termination artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in IMMEDIATE_TERMINATION_SYMBOLS:
        require(
            symbol in description,
            f"static-c-immediate-termination description omits {symbol}",
        )
    for phrase in (
        "immediate-termination block",
        "exit_group=231",
        "exit=60",
        "no errno",
        "quick_exit",
        "initial-TLS",
    ):
        require(
            phrase in description,
            f"static-c-immediate-termination description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-immediate-termination"},
        "static-c-immediate-termination must use the closed libc-immediate-termination command",
    )


def require_callback_algorithms_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless musl callback-algorithms boundary durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-callback-algorithms"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-callback-algorithms artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in CALLBACK_ALGORITHM_SYMBOLS:
        require(
            f"`{symbol}`" in description,
            f"static-c-callback-algorithms description omits {symbol}",
        )
    for phrase in (
        "callback-algorithms block",
        "smoothsort",
        "same-address",
        "weak",
        "stateless",
        "allocation-free",
        "no syscall",
        "no errno",
        "no initial-TLS",
        "longjmp",
        "C++ exception",
    ):
        require(
            phrase in description,
            f"static-c-callback-algorithms description omits {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-callback-algorithms"},
        "static-c-callback-algorithms must use the closed libc-callback-algorithms command",
    )


def require_clock_gettime_artifact(family: Mapping[str, Any]) -> None:
    """Keep the normal-C-result clock-observation boundary concrete."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-clock-gettime"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-clock-gettime artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "POSIX clock_gettime block",
        "`clock_gettime`",
        "-1/errno",
        "initial-TLS errno",
        "vDSO resolver",
        "clock_getres",
        "clock_settime",
    ):
        require(
            phrase in description,
            f"static-c-clock-gettime description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("clock_gettime=228" in item and "rdi/rsi" in item for item in prerequisites),
        "static-c-clock-gettime must record its two-register syscall ABI",
    )
    require(
        any("vDSO resolver" in item and "dynamic process-lifetime state" in item for item in prerequisites),
        "static-c-clock-gettime must record the vDSO boundary",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-clock-gettime"},
        "static-c-clock-gettime must use the closed libc-clock-gettime command",
    )


def require_system_configuration_artifact(family: Mapping[str, Any]) -> None:
    """Keep the musl-oracle configuration boundary closed and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-system-configuration"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-system-configuration artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "system-configuration block",
        "`sysconf`",
        "`confstr`",
        "`pathconf`",
        "`fpathconf`",
        "`getpagesize`",
        "`getdtablesize`",
        "path- and fd-independent",
        "corresponding AArch64",
        "focused dynamic fixture",
        "full musl sysconf table",
        "startup-owned auxv/getauxval",
    ):
        require(
            phrase in description,
            f"static-c-system-configuration description omits {phrase}",
        )
    owners = set(artifact["source_owners"])
    for owner in (
        "libc/src/c_abi/x86_64/system_configuration.rs",
        "compat/x86_64/libc_system_configuration_probe.c",
        "compat/x86_64/libc_system_configuration_start.S",
        "compat/x86_64/run_libc_system_configuration.sh",
        "compat/x86_64/unistd_header_abi_probe.c",
        "compat/x86_64/unistd_header_abi_probe.cpp",
        "compat/x86_64/run_unistd_header_abi.sh",
        "libc/src/regression_stubs.rs",
        "tests/fixtures/path_configuration_exports_test.c",
        "tests/path_configuration_exports.rs",
    ):
        require(
            owner in owners,
            f"static-c-system-configuration must own {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("prlimit64=302" in item and "rdi/rsi/rdx/r10" in item for item in prerequisites),
        "static-c-system-configuration must record the prlimit64 four-register ABI",
    )
    require(
        any(
            "path- and fd-independent" in item
            and "corresponding AArch64" in item
            and "focused dynamic fixture" in item
            for item in prerequisites
        ),
        "static-c-system-configuration must record the AArch64 musl pathconf proof",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-system-configuration"},
        "static-c-system-configuration must use the closed libc-system-configuration command",
    )


def require_mapping_core_artifact(family: Mapping[str, Any]) -> None:
    """Keep the selected C mapping lifecycle concrete and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-mman-mapping-core"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-mman-mapping-core artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "mapping-core block",
        "`mmap`",
        "`munmap`",
        "`mprotect`",
        "`madvise`",
        "`posix_madvise`",
        "`mincore`",
        "PTRDIFF_MAX",
        "page-rounded",
        "__vm_wait",
        "`msync`",
        "`mremap`",
        "`mlock*`",
        "planned `libc.posix-runtime`",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-mman-mapping-core description omits {phrase}",
        )
    owners = set(artifact["source_owners"])
    for owner in (
        "libc/src/c_abi/x86_64/memory_mapping.rs",
        "compat/x86_64/mman_header_abi_probe.c",
        "compat/x86_64/mman_header_abi_probe.cpp",
        "compat/x86_64/run_mman_header_abi.sh",
        "compat/x86_64/libc_mapping_core_probe.c",
        "compat/x86_64/libc_mapping_core_start.S",
        "compat/x86_64/run_libc_mapping_core.sh",
        "compat/x86_64/static_c_abi_exports.txt",
    ):
        require(
            owner in owners,
            f"static-c-mman-mapping-core must own {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "mmap=9" in item
            and "mprotect=10" in item
            and "munmap=11" in item
            and "mincore=27" in item
            and "madvise=28" in item
            and "rdi/rsi/rdx/r10/r8/r9" in item
            for item in prerequisites
        ),
        "static-c-mman-mapping-core must record its x86 syscall ABI",
    )
    require(
        any(
            "PTRDIFF_MAX" in item
            and "EPERM" in item
            for item in prerequisites
        ),
        "static-c-mman-mapping-core must record its mmap precheck/fallback mapping",
    )
    require(
        any("mprotect.c" in item for item in prerequisites)
        and any("posix_madvise.c" in item for item in prerequisites),
        "static-c-mman-mapping-core must record its mprotect and POSIX-advice mapping",
    )
    require(
        any("local no-op" in item and "__vm_wait" in item for item in prerequisites),
        "static-c-mman-mapping-core must record its VM-wait limitation",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-mapping-core"},
        "static-c-mman-mapping-core must use the closed libc-mapping-core command",
    )


def require_signal_execution_artifact(family: Mapping[str, Any]) -> None:
    """Keep the coherent C process-signal artifact bounded and evidence-led."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-process-signal-execution"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-process-signal-execution artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "process-signal execution block",
        "`kill`",
        "`killpg`",
        "`raise`",
        "`sigqueue`",
        "`sigtimedwait`",
        "`sigwaitinfo`",
        "`sigwait`",
        "application-signal block/restore transaction",
        "EINTR retry",
        "`-1`/errno",
        "fixture-only raw clone/pipe/wait/exit",
        "`tgkill`",
        "sigaltstack",
        "signalfd",
        "planned `libc.posix-runtime`",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-process-signal-execution description omits {phrase}",
        )
    owners = set(artifact["source_owners"])
    for owner in (
        "libc/src/c_abi/x86_64/signal_execution.rs",
        "libc/src/c_abi/x86_64/signal_control.rs",
        "libc/src/c_abi/x86_64/readiness_waits.rs",
        "compat/x86_64/signal_header_abi_probe.c",
        "compat/x86_64/signal_header_posix_abi_probe.c",
        "compat/x86_64/run_signal_header_abi.sh",
        "compat/x86_64/libc_signal_execution_probe.c",
        "compat/x86_64/libc_signal_execution_start.S",
        "compat/x86_64/run_libc_signal_execution.sh",
        "compat/x86_64/static_c_abi_exports.txt",
    ):
        require(
            owner in owners,
            f"static-c-process-signal-execution must own {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "kill=62" in item
            and "rt_sigprocmask=14" in item
            and "rt_sigtimedwait=128" in item
            and "rt_sigqueueinfo=129" in item
            and "gettid=186" in item
            and "tkill=200" in item
            and "rdi/rsi/rdx/r10" in item
            for item in prerequisites
        ),
        "static-c-process-signal-execution must record its x86 syscall ABI",
    )
    require(
        any(
            "0xfffffffc7fffffff" in item
            and "eight bytes" in item
            and "__block_app_sigs/__restore_sigs" in item
            for item in prerequisites
        ),
        "static-c-process-signal-execution must record its musl signal transaction",
    )
    require(
        any(
            "128-byte align-8" in item
            and "offsets 0/4/8" in item
            and "16/20" in item
            and "24" in item
            for item in prerequisites
        ),
        "static-c-process-signal-execution must record queued siginfo layout",
    )
    require(
        any(
            "retries raw EINTR" in item
            and "sigwait" in item
            and "-1" in item
            for item in prerequisites
        ),
        "static-c-process-signal-execution must record musl wait conventions",
    )
    require(
        any(
            "Raw clone=56" in item
            and "fixture EINTR containment" in item
            for item in prerequisites
        ),
        "static-c-process-signal-execution must retain fixture-only child containment",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-signal-execution"},
        "static-c-process-signal-execution must use the closed libc-signal-execution command",
    )


def require_clock_nanosleep_artifact(family: Mapping[str, Any]) -> None:
    """Keep the direct-positive-error clock sleep boundary durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-clock-nanosleep"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-clock-nanosleep artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "POSIX clock_nanosleep block",
        "`clock_nanosleep`",
        "positive errno",
        "CLOCK_REALTIME",
        "__syscall_cp",
        "omits cancellation",
        "separately selected nanosleep leaf",
        "initial-TLS errno",
    ):
        require(
            phrase in description,
            f"static-c-clock-nanosleep description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("clock_nanosleep=230" in item and "rdi/rsi/rdx/r10" in item for item in prerequisites),
        "static-c-clock-nanosleep must record its four-register syscall ABI",
    )
    require(
        any("remaining timespec only on EINTR" in item for item in prerequisites),
        "static-c-clock-nanosleep must record the relative remainder contract",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-clock-nanosleep"},
        "static-c-clock-nanosleep must use the closed libc-clock-nanosleep command",
    )


def require_nanosleep_artifact(family: Mapping[str, Any]) -> None:
    """Keep the normal-C-result nanosleep boundary durable and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-nanosleep"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-nanosleep artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "POSIX nanosleep block",
        "`nanosleep`",
        "-1/errno",
        "initial-TLS errno",
        "__syscall_cp",
        "omits cancellation",
        "`sleep`/`usleep`",
    ):
        require(
            phrase in description,
            f"static-c-nanosleep description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("nanosleep=35" in item and "rdi/rsi" in item for item in prerequisites),
        "static-c-nanosleep must record its two-register syscall ABI",
    )
    require(
        any("remaining timespec only on EINTR" in item for item in prerequisites),
        "static-c-nanosleep must record the EINTR remainder contract",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-nanosleep"},
        "static-c-nanosleep must use the closed libc-nanosleep command",
    )


def require_descriptor_entry_artifact(family: Mapping[str, Any]) -> None:
    """Keep the static C descriptor-entry artifact concrete and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-descriptor-entry"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-descriptor-entry artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "descriptor-entry block",
        "`open`",
        "`openat`",
        "`creat`",
        "O_CLOEXEC",
        "O_LARGEFILE",
        "does not expand C fcntl beyond",
        "cancellation",
    ):
        require(
            phrase in description,
            f"static-c-descriptor-entry description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "open=2" in item
            and "openat=257" in item
            and "rdi/rsi/rdx/r10" in item
            for item in prerequisites
        ),
        "static-c-descriptor-entry must record its open/openat register ABI",
    )
    require(
        any(
            "complete O_TMPFILE" in item and "O_LARGEFILE" in item
            for item in prerequisites
        ),
        "static-c-descriptor-entry must record its optional-mode and O_LARGEFILE contract",
    )
    require(
        any(
            "F_SETFD=2/FD_CLOEXEC=1" in item and "omits all __syscall_cp" in item
            for item in prerequisites
        ),
        "static-c-descriptor-entry must record its private O_CLOEXEC and cancellation boundary",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-descriptor-entry"},
        "static-c-descriptor-entry must use the closed libc-descriptor-entry command",
    )


def require_fcntl_status_control_artifact(family: Mapping[str, Any]) -> None:
    """Keep the bounded variadic C fcntl artifact honest and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-fcntl-status-control"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-fcntl-status-control artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "fcntl status-control block",
        "`F_GETFD`",
        "`F_SETFD`",
        "`F_GETFL`",
        "`F_SETFL`",
        "O_LARGEFILE",
        "-1/EINVAL",
        "does not select generic C fcntl",
        "F_SETLKW cancellation",
    ):
        require(
            phrase in description,
            f"static-c-fcntl-status-control description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "fcntl=72" in item
            and "rdi/rsi/rdx" in item
            and "F_GETFD=1" in item
            and "F_GETFL=3" in item
            and "F_SETFD=2" in item
            and "F_SETFL=4" in item
            for item in prerequisites
        ),
        "static-c-fcntl-status-control must record its variadic register ABI",
    )
    require(
        any(
            "rdx=0" in item and "F_GETFD=1" in item and "F_GETFL=3" in item
            for item in prerequisites
        ),
        "static-c-fcntl-status-control must record its no-vararg boundary",
    )
    require(
        any("O_LARGEFILE=0x8000" in item and "F_SETFL" in item for item in prerequisites),
        "static-c-fcntl-status-control must record its F_SETFL O_LARGEFILE rule",
    )
    require(
        any(
            "-1/EINVAL" in item and "without observing an absent vararg" in item
            for item in prerequisites
        ),
        "static-c-fcntl-status-control must record its unsupported-command boundary",
    )
    require(
        any(
            "src/fcntl/fcntl.c" in item
            and "__syscall_cp" in item
            and "F_GETOWN" in item
            and "F_DUPFD_CLOEXEC" in item
            for item in prerequisites
        ),
        "static-c-fcntl-status-control must record its pinned-musl differences",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-fcntl-status-control"},
        "static-c-fcntl-status-control must use the closed libc-fcntl-status-control command",
    )


def require_ffs_artifact(family: Mapping[str, Any]) -> None:
    """Keep the stateless find-first-set artifact identity and scope durable."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-ffs"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-ffs artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in FFS_SYMBOLS:
        require(symbol in description, f"static-c-ffs description omits {symbol}")
    for phrase in (
        "find-first-set block",
        "stateless",
        "allocation-free",
        "least-significant set bit",
        "two's-complement",
        "no errno/TLS or syscall boundary",
    ):
        require(phrase in description, f"static-c-ffs description omits {phrase}")
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-ffs"},
        "static-c-ffs must use the closed libc-ffs command",
    )


def require_math_complex_foundation_artifact(family: Mapping[str, Any]) -> None:
    """Keep the x87-only math/complex foundation distinct from math parity.

    This artifact is intentionally a narrow ABI leaf inside a still-planned
    family. The checks below make its selected symbols, target-private f80
    representation, static link boundary, and non-completion wording durable
    without letting it consume a broad math capability.
    """
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.text-math-locale-stdio].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-math-complex-foundation"
    ]
    require(
        len(matching) == 1,
        "libc.text-math-locale-stdio must contain exactly one static-c-math-complex-foundation artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in MATH_COMPLEX_FOUNDATION_SYMBOLS:
        require(
            symbol in description,
            f"static-c-math-complex-foundation description omits {symbol}",
        )
    for phrase in (
        "long-double/complex foundation",
        "x87",
        "scalar math",
        "cabs/carg/cproj",
        "complex powers and transcendentals",
        "libm",
        "libc.so",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-math-complex-foundation description omits {phrase}",
        )

    owners = nonempty_strings(
        artifact["source_owners"], "static-c-math-complex-foundation.source_owners"
    )
    for owner in (
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/math_complex.rs",
        "include/complex.h",
        "include/float.h",
        "include/math.h",
        "include/tgmath.h",
        "compat/x86_64/math_complex_header_abi_probe.c",
        "compat/x86_64/math_complex_header_abi_probe.cpp",
        "compat/x86_64/run_math_complex_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_math_complex_probe.c",
        "compat/x86_64/libc_math_complex_start.S",
        "compat/x86_64/run_libc_math_complex.sh",
    ):
        require(
            owner in owners,
            f"static-c-math-complex-foundation omits {owner}",
        )

    abi_prerequisites = nonempty_strings(
        artifact["x86_abi_prerequisites"],
        "static-c-math-complex-foundation.x86_abi_prerequisites",
    )
    require(
        any(
            "st0" in item and "st1" in item and "32-byte" in item
            for item in abi_prerequisites
        ),
        "static-c-math-complex-foundation must record the x87 complex return ABI",
    )
    require(
        any(
            "xmm0" in item and "xmm1" in item
            for item in abi_prerequisites
        ),
        "static-c-math-complex-foundation must record the SSE complex ABI",
    )
    require(
        any(
            "__fpclassify.c" in item
            and "__fpclassifyf.c" in item
            and "__fpclassifyl.c" in item
            and "__signbit.c" in item
            and "__signbitf.c" in item
            and "__signbitl.c" in item
            and "src/complex/" in item
            and "AArch64 binary128" in item
            for item in abi_prerequisites
        ),
        "static-c-math-complex-foundation must record its pinned-musl and target boundary",
    )

    header_prerequisites = nonempty_strings(
        artifact["x86_header_prerequisites"],
        "static-c-math-complex-foundation.x86_header_prerequisites",
    )
    require(
        any(
            "-mfpmath=387" in item
            and "tgmath" in item
            and "unmangled C++" in item
            for item in header_prerequisites
        ),
        "static-c-math-complex-foundation must record the two-mode header gate",
    )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-math-complex"},
        "static-c-math-complex-foundation must use the closed libc-math-complex command",
    )

    static_root = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs").read_text(
        encoding="utf-8"
    )
    require(
        '#[path = "math_complex.rs"]\nmod math_complex;' in static_root,
        "x86 static C ABI must compose the math_complex leaf",
    )
    implementation = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_complex.rs").read_text(
        encoding="utf-8"
    )
    for symbol in MATH_COMPLEX_FOUNDATION_SYMBOLS:
        require(
            f".global {symbol}" in implementation,
            f"math_complex leaf omits {symbol}",
        )
    for instruction in ("fld tbyte ptr", "fchs", "xorpd xmm1"):
        require(
            instruction in implementation,
            f"math_complex leaf omits its required {instruction} ABI operation",
        )

    exports = [
        line
        for line in (ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    ]
    require(
        exports == sorted(exports),
        "static C ABI export contract must remain ASCII-sorted",
    )
    for symbol in MATH_COMPLEX_FOUNDATION_SYMBOLS:
        require(
            symbol in exports,
            f"static C ABI export contract omits {symbol}",
        )

    runner = (ROOT / "compat" / "x86_64" / "run_libc_math_complex.sh").read_text(
        encoding="utf-8"
    )
    for snippet in (
        "-nostdlib -static",
        "--no-undefined",
        "fldt",
        "fchs",
        "cabs",
        "carg",
        "cproj",
        "libm",
    ):
        require(
            snippet in runner,
            f"libc-math-complex runner omits {snippet}",
        )


def baseline_capability_ids(path: Path) -> set[str]:
    """Load the checked-in baseline ledger instead of freezing its ID count here."""
    baseline = load_toml(path)
    capabilities = baseline.get("capability")
    require(isinstance(capabilities, list) and capabilities, "baseline capability ledger has no capability records")
    identifiers: set[str] = set()
    for index, entry in enumerate(capabilities):
        location = f"baseline capability[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        identifier = entry.get("id")
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(identifier not in identifiers, f"baseline capability ledger has duplicate id: {identifier}")
        identifiers.add(identifier)
    return identifiers


def has_musl_oracle(family: Mapping[str, Any]) -> bool:
    """Whether a parity family names musl as an oracle in its own contract."""
    records = family["oracle"]
    assert isinstance(records, list)
    return any(
        isinstance(record, Mapping)
        and isinstance(record.get("source"), str)
        and "musl" in record["source"].lower()
        for record in records
    )


def validate_ledger(
    data: Mapping[str, Any],
    *,
    header_layout_manifest: Mapping[str, Any] | None = None,
    header_layout_foundation_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    require(data.get("schema") == EXPECTED_SCHEMA, "unexpected x86 parity ledger schema")
    require(data.get("target") == EXPECTED_TARGET, "unexpected x86 parity target")
    require(data.get("platform") == EXPECTED_PLATFORM, "unexpected x86 parity platform")
    require(data.get("kernel_msrv") == EXPECTED_KERNEL_MSRV, "unexpected x86 parity kernel MSRV")
    require(data.get("baseline_platform") == "Linux/AArch64 little-endian", "baseline platform changed")
    baseline_path = repository_path(str(data.get("baseline_capability_ledger", "")), "baseline_capability_ledger")
    repository_path(str(data.get("baseline_gate_dispatch", "")), "baseline_gate_dispatch")

    policy = data.get("policy")
    require(isinstance(policy, Mapping), "policy must be a table")
    expected_policy = {
        "native_execution_only": True,
        "public_support": False,
        "no_emulation": True,
        "no_portability_framework": True,
        "no_symbol_count_claim": True,
    }
    require(dict(policy) == expected_policy, "x86 parity policy drifted")

    meanings = data.get("status_meaning")
    require(isinstance(meanings, Mapping), "status_meaning must be a table")
    require(
        all(
            isinstance(meanings.get(name), str) and meanings[name]
            for name in ("foundation_verified", "planned", "verified_artifact")
        ),
        "status meanings are incomplete",
    )

    promotion = data.get("promotion")
    require(isinstance(promotion, Mapping), "promotion must be a table")
    required_families = nonempty_strings(promotion.get("required_families"), "promotion.required_families")
    require(tuple(required_families) == EXPECTED_FAMILIES, "promotion family roster drifted")

    excluded = data.get("excluded_surface")
    require(isinstance(excluded, list) and len(excluded) == 1, "exactly one excluded surface is required")
    excluded_entry = excluded[0]
    require(isinstance(excluded_entry, Mapping), "excluded_surface[0] must be a table")
    require(excluded_entry.get("id") == "allocator.mimalloc-private", "private allocator exclusion changed")
    require(isinstance(excluded_entry.get("reason"), str) and excluded_entry["reason"], "allocator exclusion needs a reason")
    for index, path_text in enumerate(nonempty_strings(excluded_entry.get("evidence"), "excluded_surface[0].evidence")):
        repository_path(path_text, f"excluded_surface[0].evidence[{index}]")

    families = data.get("family")
    require(isinstance(families, list), "family must be an array")
    require(len(families) == len(EXPECTED_FAMILIES), "family count drifted")
    ids: set[str] = set()
    orders: list[int] = []
    by_id: dict[str, Mapping[str, Any]] = {}
    status_counts = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    verified_slice_ids: set[str] = set()
    verified_artifact_ids: set[str] = set()
    verified_record_ids: set[str] = set()
    for index, entry in enumerate(families):
        location = f"family[{index}]"
        require(isinstance(entry, Mapping), f"{location} must be a table")
        for key in (
            "id",
            "order",
            "depends_on",
            "category",
            "description",
            "aarch64_gates",
            "source_owners",
            "x86_abi_prerequisites",
            "x86_header_prerequisites",
            "native_evidence",
            "oracle",
            "capabilities",
            "status",
        ):
            require(key in entry, f"{location} is missing {key}")
        identifier = entry["id"]
        require(isinstance(identifier, str) and identifier, f"{location}.id is empty")
        require(identifier not in ids, f"duplicate family id: {identifier}")
        require(identifier in EXPECTED_FAMILIES, f"unexpected family id: {identifier}")
        order = entry["order"]
        require(isinstance(order, int) and order > 0, f"{location}.order is invalid")
        category = entry["category"]
        status = entry["status"]
        require(category in ALLOWED_CATEGORIES, f"{location}.category is invalid")
        require(status in ALLOWED_STATUSES, f"{location}.status is invalid")
        require(isinstance(entry["description"], str) and entry["description"], f"{location}.description is empty")
        gates = nonempty_strings(entry["aarch64_gates"], f"{location}.aarch64_gates")
        unknown_gates = sorted(set(gates) - KNOWN_AARCH64_GATES)
        require(not unknown_gates, f"{location} names unknown AArch64 gates: {', '.join(unknown_gates)}")
        for owner_index, path_text in enumerate(nonempty_strings(entry["source_owners"], f"{location}.source_owners")):
            repository_path(path_text, f"{location}.source_owners[{owner_index}]")
        nonempty_strings(entry["x86_abi_prerequisites"], f"{location}.x86_abi_prerequisites")
        nonempty_strings(entry["x86_header_prerequisites"], f"{location}.x86_header_prerequisites")
        require_evidence(entry["native_evidence"], f"{location}.native_evidence", status)
        require_oracles(entry["oracle"], f"{location}.oracle")
        family_capabilities = string_list(
            entry["capabilities"], f"{location}.capabilities", allow_empty=True
        )
        verified_slice_capabilities: set[str] = set()
        for slice_entry in require_verified_slices(
            entry.get("verified_slice"),
            f"{location}.verified_slice",
            status,
            family_capabilities,
        ):
            slice_id = slice_entry["id"]
            assert isinstance(slice_id, str)
            require(slice_id not in verified_record_ids, f"duplicate verified record id: {slice_id}")
            verified_record_ids.add(slice_id)
            verified_slice_ids.add(slice_id)
            for capability in nonempty_strings(
                slice_entry["capabilities"], f"{location}.verified_slice[{slice_id}].capabilities"
            ):
                require(
                    capability not in verified_slice_capabilities,
                    f"{location}.verified_slice duplicates a capability: {capability}",
                )
                verified_slice_capabilities.add(capability)
        if identifier == "facade.record-owning" and status == "foundation-verified":
            family_capability_set = set(family_capabilities)
            missing_slice_capabilities = sorted(
                family_capability_set - verified_slice_capabilities
            )
            unexpected_slice_capabilities = sorted(
                verified_slice_capabilities - family_capability_set
            )
            require(
                not missing_slice_capabilities and not unexpected_slice_capabilities,
                f"{location}.verified_slice must exactly cover the foundation family capabilities; "
                f"missing: {', '.join(missing_slice_capabilities) or 'none'}; "
                f"unexpected: {', '.join(unexpected_slice_capabilities) or 'none'}",
            )
        for artifact_entry in require_verified_artifacts(
            entry.get("verified_artifact"),
            f"{location}.verified_artifact",
            status,
        ):
            artifact_id = artifact_entry["id"]
            assert isinstance(artifact_id, str)
            require(
                artifact_id not in verified_record_ids,
                f"duplicate verified record id: {artifact_id}",
            )
            verified_record_ids.add(artifact_id)
            verified_artifact_ids.add(artifact_id)
        ids.add(identifier)
        orders.append(order)
        by_id[identifier] = entry
        status_counts[status] += 1

    require(tuple(entry["id"] for entry in families) == EXPECTED_FAMILIES, "family table order must equal promotion dependency order")
    require(orders == sorted(orders) and len(orders) == len(set(orders)), "family order values must be unique and ascending")
    require(ids == set(EXPECTED_FAMILIES), "family coverage does not match promotion roster")

    if header_layout_manifest is None:
        header_layout_manifest = load_toml(HEADER_LAYOUT_MANIFEST_PATH)
    header_layout_report = validate_header_layout_manifest(
        by_id["libc.headers-layouts"], header_layout_manifest
    )
    public_header_inventory_count = require_public_header_surface_artifact(
        by_id["libc.headers-layouts"]
    )
    if header_layout_foundation_manifest is None:
        header_layout_foundation_manifest = load_toml(HEADER_LAYOUT_FOUNDATION_MANIFEST_PATH)
    header_layout_foundation_report = validate_header_layout_foundation_manifest(
        by_id["libc.headers-layouts"],
        header_layout_manifest,
        header_layout_foundation_manifest,
    )
    require_header_layouts_baseline_artifact(by_id["libc.headers-layouts"])

    require_ldso_initial_graph_artifact(by_id["ldso.dynamic-runtime"])
    require_byte_string_artifact(by_id["libc.posix-runtime"])
    require_random_entropy_artifact(by_id["libc.posix-runtime"])
    require_memory_search_artifact(by_id["libc.posix-runtime"])
    require_string_copy_artifact(by_id["libc.posix-runtime"])
    require_ctype_artifact(by_id["libc.posix-runtime"])
    require_integer_arithmetic_artifact(by_id["libc.posix-runtime"])
    require_integer_parse_artifact(by_id["libc.posix-runtime"])
    require_intmax_arithmetic_artifact(by_id["libc.posix-runtime"])
    require_credential_observation_artifact(by_id["libc.posix-runtime"])
    require_child_reaping_artifact(by_id["libc.posix-runtime"])
    require_immediate_termination_artifact(by_id["libc.posix-runtime"])
    require_callback_algorithms_artifact(by_id["libc.posix-runtime"])
    require_clock_gettime_artifact(by_id["libc.posix-runtime"])
    require_system_configuration_artifact(by_id["libc.posix-runtime"])
    require_mapping_core_artifact(by_id["libc.posix-runtime"])
    require_signal_execution_artifact(by_id["libc.posix-runtime"])
    require_clock_nanosleep_artifact(by_id["libc.posix-runtime"])
    require_nanosleep_artifact(by_id["libc.posix-runtime"])
    require_descriptor_entry_artifact(by_id["libc.posix-runtime"])
    require_fcntl_status_control_artifact(by_id["libc.posix-runtime"])
    require_ffs_artifact(by_id["libc.posix-runtime"])
    require_math_complex_foundation_artifact(by_id["libc.text-math-locale-stdio"])

    musl_oracle = by_id["oracle.musl-toolchain"]
    require(musl_oracle["status"] == "foundation-verified", "musl oracle must remain foundation-verified")
    musl_evidence, _ = require_evidence(
        musl_oracle["native_evidence"], "family[oracle.musl-toolchain].native_evidence", musl_oracle["status"]
    )
    require(
        [entry["command"] for entry in musl_evidence] == ["./scripts/dev-x86_64.sh musl-oracle"],
        "musl oracle must use the closed native musl-oracle command",
    )
    for identifier, family in by_id.items():
        if identifier != "oracle.musl-toolchain" and has_musl_oracle(family):
            dependencies = family["depends_on"]
            assert isinstance(dependencies, list)
            require(
                "oracle.musl-toolchain" in dependencies,
                f"musl-backed family {identifier} must depend on oracle.musl-toolchain",
            )

    baseline_ids = baseline_capability_ids(baseline_path)
    capability_owners: dict[str, str] = {}
    for identifier, family in by_id.items():
        capabilities = string_list(
            family["capabilities"], f"family[{identifier}].capabilities", allow_empty=True
        )
        require(
            len(capabilities) == len(set(capabilities)),
            f"family[{identifier}] maps a capability more than once",
        )
        for capability in capabilities:
            previous = capability_owners.get(capability)
            require(
                previous is None,
                f"baseline capability {capability} is mapped by both {previous} and {identifier}",
            )
            capability_owners[capability] = identifier

    mapped_ids = set(capability_owners)
    stale_ids = sorted(mapped_ids - baseline_ids)
    missing_ids = sorted(baseline_ids - mapped_ids)
    require(not stale_ids, f"parity ledger maps stale baseline capabilities: {', '.join(stale_ids)}")
    require(not missing_ids, f"parity ledger leaves baseline capabilities unmapped: {', '.join(missing_ids)}")

    orders_by_id = {identifier: entry["order"] for identifier, entry in by_id.items()}
    for identifier, entry in by_id.items():
        dependencies = nonempty_strings(entry["depends_on"], f"family[{identifier}].depends_on") if entry["depends_on"] else []
        require(len(dependencies) == len(set(dependencies)), f"family[{identifier}] has duplicate dependencies")
        for dependency in dependencies:
            require(dependency in by_id, f"family[{identifier}] depends on unknown family {dependency}")
            require(orders_by_id[dependency] < orders_by_id[identifier], f"family[{identifier}] dependency {dependency} is not earlier")

    dispatch_source = (ROOT / "scripts" / "dev.sh").read_text(encoding="utf-8")
    used_gates = {gate for family in families for gate in family["aarch64_gates"]}
    missing_dispatch = sorted(gate for gate in used_gates if f"    {gate})" not in dispatch_source and f"    {gate}|" not in dispatch_source)
    require(not missing_dispatch, f"AArch64 gate dispatch does not contain: {', '.join(missing_dispatch)}")

    return {
        "schema": EXPECTED_SCHEMA,
        "family_count": len(families),
        "capability_count": len(baseline_ids),
        "capability_owners": capability_owners,
        "status_counts": status_counts,
        "verified_slice_count": len(verified_slice_ids),
        "verified_artifact_count": len(verified_artifact_ids),
        "header_layout_probe_count": header_layout_report["probe_count"],
        "public_header_inventory_count": public_header_inventory_count,
        "header_foundation_header_count": header_layout_foundation_report["header_count"],
        "header_foundation_pinned_header_count": header_layout_foundation_report[
            "pinned_header_count"
        ],
        "header_foundation_project_only_header_count": header_layout_foundation_report[
            "project_only_header_count"
        ],
        "header_foundation_uapi_path_count": header_layout_foundation_report[
            "uapi_path_count"
        ],
        "header_foundation_uapi_wrapper_matrix_row_count": header_layout_foundation_report[
            "uapi_wrapper_matrix_row_count"
        ],
        "header_foundation_epoll_header_profile_matrix_row_count": header_layout_foundation_report[
            "epoll_header_profile_matrix_row_count"
        ],
        "header_foundation_timeval_transitive_header_profile_matrix_row_count": header_layout_foundation_report[
            "timeval_transitive_header_profile_matrix_row_count"
        ],
        "header_foundation_sys_time_direct_header_profile_matrix_row_count": header_layout_foundation_report[
            "sys_time_direct_header_profile_matrix_row_count"
        ],
        "header_foundation_language_profile_count": header_layout_foundation_report[
            "language_profile_count"
        ],
        "header_foundation_profile_obligation_count": header_layout_foundation_report[
            "profile_obligation_count"
        ],
        "header_foundation_profile_matrix_row_count": header_layout_foundation_report[
            "profile_matrix_row_count"
        ],
        "header_foundation_abi_facet_count": header_layout_foundation_report[
            "abi_facet_count"
        ],
        "header_foundation_linkage_owner_count": header_layout_foundation_report[
            "linkage_owner_count"
        ],
        "header_foundation_static_export_count": header_layout_foundation_report[
            "static_export_count"
        ],
        "promotion_ready": all(family["status"] == "foundation-verified" for family in families),
        "public_support": policy["public_support"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the checked-in ledger (default)")
    arguments = parser.parse_args()
    del arguments
    report = validate_ledger(load_toml(LEDGER_PATH))
    print(
        "x86 parity ledger: PASS "
        f"({report['family_count']} families; "
        f"foundation={report['status_counts']['foundation-verified']}; "
        f"planned={report['status_counts']['planned']}; "
        f"promotion_ready={report['promotion_ready']}; "
        f"public_support={report['public_support']})"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as error:
        raise SystemExit(f"x86 parity ledger: ERROR: {error}") from error
