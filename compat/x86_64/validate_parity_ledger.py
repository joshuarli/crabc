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
IOCTL_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_ioctl_header_abi.sh"
EPOLL_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_epoll_header_abi.sh"
TIMEVAL_TRANSITIVE_HEADER_ABI_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_timeval_transitive_header_abi.sh"
)
SYS_TIME_DIRECT_HEADER_ABI_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_sys_time_direct_header_abi.sh"
)
ACCESS_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_access_header_abi.sh"
X86_64_EVIDENCE_DOCKERFILE_PATH = ROOT / "docker" / "Dockerfile.x86_64"
EXPECTED_SCHEMA = "crabc.x86_64-runtime-parity/v3"
EXPECTED_TARGET = "x86_64-unknown-linux-musl"
EXPECTED_PLATFORM = "Linux/x86-64 little-endian"
EXPECTED_KERNEL_MSRV = "5.10"
EXPECTED_HEADER_LAYOUT_SCHEMA = "crabc.x86_64-headers-layouts/v1"
EXPECTED_HEADER_LAYOUT_FOUNDATION_SCHEMA = "crabc.x86_64-headers-layouts-foundation/v8"
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
EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_ID = "x86-ioctl-header-profile-matrix"
EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_COMMAND = "./scripts/dev-x86_64.sh ioctl-header-abi"
EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_SUBJECT_HEADER = "sys/ioctl.h"
EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_ROW_COUNT = 7
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
EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_ID = "x86-access-header-profile-matrix"
EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_COMMAND = "./scripts/dev-x86_64.sh access-header-abi"
EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS = ("fcntl.h", "unistd.h")
EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_PROFILES = (
    "c-default",
    "c11-gnu",
    "cxx17-gnu",
    "c11-strict",
    "c11-posix-2008",
    "c11-xopen-700",
    "c11-bsd",
    "cxx17-strict",
)
EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_ROW_COUNT = 8
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
EXPECTED_CANDIDATE_HEADER_CLOSURE_RECORD_COUNT = 1337
EXPECTED_CANDIDATE_HEADER_CLOSURE_ORACLE_NOT_APPLICABLE_ROWS = (
    "aio.h:c11-strict",
    "aio.h:cxx17-strict",
)

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
        "state": "partial-verified",
    },
    "c11-strict": {
        "language": "c",
        "standard": "c11",
        "macros": [],
        "state": "partial-verified",
    },
    "c11-posix-2008": {
        "language": "c",
        "standard": "c11",
        "macros": ["_POSIX_C_SOURCE=200809L"],
        "state": "partial-verified",
    },
    "c11-xopen-700": {
        "language": "c",
        "standard": "c11",
        "macros": ["_XOPEN_SOURCE=700"],
        "state": "partial-verified",
    },
    "c11-bsd": {
        "language": "c",
        "standard": "c11",
        "macros": ["_BSD_SOURCE"],
        "state": "partial-verified",
    },
    "cxx17-strict": {
        "language": "c++",
        "standard": "c++17",
        "macros": [],
        "state": "partial-verified",
    },
}
EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES = tuple(EXPECTED_HEADER_FOUNDATION_LANGUAGE_PROFILES)

EXPECTED_HEADER_FOUNDATION_CLASS_IDS = (
    "pinned-non-uapi",
    "pinned-uapi-inputs",
    "project-only-extensions",
)
EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES = tuple(
    EXPECTED_HEADER_FOUNDATION_LANGUAGE_PROFILES
)
EXPECTED_HEADER_FOUNDATION_UNVERIFIED_FEATURE_PROFILES: tuple[str, ...] = ()
EXPECTED_HEADER_FOUNDATION_CLASS_FACETS = {
    "pinned-non-uapi": (
        "public-path-inventory",
        "candidate-tree-presence",
        "c11-gnu-consumability",
        "ioctl-header-profile-matrix",
        "epoll-header-profile-matrix",
        "timeval-transitive-header-profile-matrix",
        "sys-time-direct-header-profile-matrix",
        "access-header-profile-matrix",
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
        ("public-header-c-consumability", "public-header-profile-consumability"),
    ),
    ("pinned-non-uapi", "cxx17-gnu"): (
        "applicable",
        "partial-verified",
        ("public-header-profile-consumability",),
    ),
    ("pinned-non-uapi", "c11-strict"): (
        "mixed-applicability",
        "partial-verified",
        ("public-header-profile-consumability",),
    ),
    ("pinned-non-uapi", "c11-posix-2008"): (
        "applicable",
        "partial-verified",
        ("public-header-profile-consumability",),
    ),
    ("pinned-non-uapi", "c11-xopen-700"): (
        "applicable",
        "partial-verified",
        ("public-header-profile-consumability",),
    ),
    ("pinned-non-uapi", "c11-bsd"): (
        "applicable",
        "partial-verified",
        ("public-header-profile-consumability",),
    ),
    ("pinned-non-uapi", "cxx17-strict"): (
        "mixed-applicability",
        "partial-verified",
        ("public-header-profile-consumability",),
    ),
    ("pinned-uapi-inputs", "c11-gnu"): (
        "applicable",
        "partial-verified",
        (
            "pinned-linux-5.10-uapi-input",
            EXPECTED_UAPI_WRAPPER_MATRIX_ID,
            "public-header-profile-consumability",
        ),
    ),
    ("pinned-uapi-inputs", "cxx17-gnu"): (
        "applicable",
        "partial-verified",
        (
            "pinned-linux-5.10-uapi-input",
            EXPECTED_UAPI_WRAPPER_MATRIX_ID,
            "public-header-profile-consumability",
        ),
    ),
    ("pinned-uapi-inputs", "c11-strict"): (
        "applicable",
        "partial-verified",
        (
            "pinned-linux-5.10-uapi-input",
            EXPECTED_UAPI_WRAPPER_MATRIX_ID,
            "public-header-profile-consumability",
        ),
    ),
    ("pinned-uapi-inputs", "c11-posix-2008"): (
        "applicable",
        "partial-verified",
        (
            "pinned-linux-5.10-uapi-input",
            EXPECTED_UAPI_WRAPPER_MATRIX_ID,
            "public-header-profile-consumability",
        ),
    ),
    ("pinned-uapi-inputs", "c11-xopen-700"): (
        "applicable",
        "partial-verified",
        (
            "pinned-linux-5.10-uapi-input",
            EXPECTED_UAPI_WRAPPER_MATRIX_ID,
            "public-header-profile-consumability",
        ),
    ),
    ("pinned-uapi-inputs", "c11-bsd"): (
        "applicable",
        "partial-verified",
        (
            "pinned-linux-5.10-uapi-input",
            EXPECTED_UAPI_WRAPPER_MATRIX_ID,
            "public-header-profile-consumability",
        ),
    ),
    ("pinned-uapi-inputs", "cxx17-strict"): (
        "applicable",
        "partial-verified",
        (
            "pinned-linux-5.10-uapi-input",
            EXPECTED_UAPI_WRAPPER_MATRIX_ID,
            "public-header-profile-consumability",
        ),
    ),
    ("project-only-extensions", "c11-gnu"): (
        "candidate-only",
        "partial-verified",
        ("project-only-header-classification", "public-header-profile-consumability"),
    ),
    ("project-only-extensions", "cxx17-gnu"): (
        "candidate-only",
        "partial-verified",
        ("project-only-header-classification", "public-header-profile-consumability"),
    ),
    ("project-only-extensions", "c11-strict"): (
        "candidate-only",
        "partial-verified",
        ("project-only-header-classification", "public-header-profile-consumability"),
    ),
    ("project-only-extensions", "c11-posix-2008"): (
        "candidate-only",
        "partial-verified",
        ("project-only-header-classification", "public-header-profile-consumability"),
    ),
    ("project-only-extensions", "c11-xopen-700"): (
        "candidate-only",
        "partial-verified",
        ("project-only-header-classification", "public-header-profile-consumability"),
    ),
    ("project-only-extensions", "c11-bsd"): (
        "candidate-only",
        "partial-verified",
        ("project-only-header-classification", "public-header-profile-consumability"),
    ),
    ("project-only-extensions", "cxx17-strict"): (
        "candidate-only",
        "partial-verified",
        ("project-only-header-classification", "public-header-profile-consumability"),
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
    "ioctl-header-profile-matrix": (
        "partial-verified",
        "sys/ioctl.h selected declaration macro request vocabulary direct winsize layout and C++ declaration-linkage subset",
        "libc.headers-layouts",
        (EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_ID,),
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
    "access-header-profile-matrix": (
        "partial-verified",
        "fcntl.h and unistd.h selected access declaration feature gate and C++ declaration-linkage subset",
        "libc.headers-layouts",
        (EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_ID,),
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
        "partial-verified",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("isolated-candidate-header-closure",),
    ),
    "cxx17-consumability": (
        "partial-verified",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("isolated-candidate-header-closure",),
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
    "utime": "./scripts/dev-x86_64.sh utime-header-abi",
    "pthread-c11": "./scripts/dev-x86_64.sh pthread-c11-header-abi",
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
    "ioctl": "./scripts/dev-x86_64.sh ioctl-header-abi",
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
    "access-header": "./scripts/dev-x86_64.sh access-header-abi",
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
    "utime": (
        "compat/x86_64/utime_header_abi_probe.c",
        "compat/x86_64/utime_header_abi_probe.cpp",
        "compat/x86_64/run_utime_header_abi.sh",
    ),
    "pthread-c11": (
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
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
    "ioctl": (
        "compat/x86_64/ioctl_header_abi_probe.c",
        "compat/x86_64/ioctl_header_abi_probe.cpp",
        "compat/x86_64/run_ioctl_header_abi.sh",
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
    "access-header": (
        "compat/x86_64/access_header_abi_probe.c",
        "compat/x86_64/access_header_abi_probe.cpp",
        "compat/x86_64/run_access_header_abi.sh",
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

FILESYSTEM_ACCESS_SYMBOLS = ("access", "faccessat", "euidaccess", "eaccess")

FFS_SYMBOLS = ("ffs", "ffsl", "ffsll")

SYSV_SEMAPHORE_SYMBOLS = ("semget", "semop", "semtimedop", "semctl")

SYSV_SEMAPHORE_UNION_COMMANDS = (
    "SETVAL",
    "GETALL",
    "SETALL",
    "IPC_SET",
    "IPC_INFO",
    "SEM_INFO",
    "IPC_STAT",
    "SEM_STAT",
    "SEM_STAT_ANY",
)

SYSV_SEMAPHORE_NO_ARGUMENT_COMMANDS = (
    "IPC_RMID=0",
    "GETPID=11",
    "GETVAL=12",
    "GETNCNT=14",
    "GETZCNT=15",
)

SYSV_SEMAPHORE_UNSELECTED_SYMBOLS = (
    "sem_close",
    "sem_destroy",
    "sem_getvalue",
    "sem_init",
    "sem_open",
    "sem_post",
    "sem_timedwait",
    "sem_trywait",
    "sem_unlink",
    "sem_wait",
)

SYSV_MESSAGE_SHARED_MEMORY_SYMBOLS = (
    "ftok",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    "shmget",
    "shmat",
    "shmdt",
    "shmctl",
)

SYSV_MESSAGE_SHARED_MEMORY_UNSELECTED_SYMBOLS = (
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
    "sem_destroy",
    "sem_getvalue",
    "sem_init",
    "sem_open",
    "sem_post",
    "sem_timedwait",
    "sem_trywait",
    "sem_unlink",
    "sem_wait",
)

EVENT_DESCRIPTOR_SYMBOLS = (
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_wait",
    "eventfd",
    "eventfd_read",
    "eventfd_write",
    "inotify_add_watch",
    "inotify_init",
    "inotify_init1",
    "inotify_rm_watch",
)

EVENT_DESCRIPTOR_UNSELECTED_SYMBOLS = (
    "aio_cancel",
    "aio_error",
    "aio_fsync",
    "aio_read",
    "aio_return",
    "aio_suspend",
    "aio_write",
    "epoll_pwait2",
    "fanotify_init",
    "fanotify_mark",
    "lio_listio",
    "signalfd",
    "signalfd4",
    "timerfd_create",
    "timerfd_gettime",
    "timerfd_settime",
)

PATHNAME_LIFECYCLE_SYMBOLS = (
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
)

PATHNAME_LIFECYCLE_UNSELECTED_SYMBOLS = (
    "chroot",
    "fchdir",
    "fchmodat",
    "getdents",
    "lchmod",
    "linkat",
    "mkdirat",
    "opendir",
    "readdir",
    "realpath",
    "renameat",
    "renameat2",
    "scandir",
    "symlinkat",
    "unlinkat",
)

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

    The v8 contract resolves every current pathname into one class and expands
    every class into explicit language/feature obligations. It pins the one
    Linux-UAPI input, resolves selected UAPI-wrapper, ioctl-header, epoll-header,
    timeval-transitive, direct sys/time, and access-header ABI matrices, and
    verifies a seven-profile empty-TU closure diagnostic with two explicit
    pinned-musl aio.h strict-profile applicability results, while keeping
    feature visibility, declaration/layout comparisons, and declared-callable
    linkage in planned evidence lanes.
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
        "ioctl_header_profile_matrix",
        "epoll_header_profile_matrix",
        "timeval_transitive_header_profile_matrix",
        "sys_time_direct_header_profile_matrix",
        "access_header_profile_matrix",
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
            "candidate_transitive_include_closure": True,
            "full_c11_consumer_matrix": True,
            "full_cxx17_consumer_matrix": True,
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
            "ioctl_header_profile_matrix_slice": True,
            "epoll_header_profile_matrix_slice": True,
            "timeval_transitive_header_profile_matrix_slice": True,
            "sys_time_direct_header_profile_matrix_slice": True,
            "access_header_profile_matrix_slice": True,
            "candidate_transitive_include_closure": True,
            "c11_consumer_matrix": True,
            "cxx17_consumer_matrix": True,
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
        "compat/x86_64/run_ioctl_header_abi.sh",
        "compat/x86_64/ioctl_header_abi_probe.c",
        "compat/x86_64/ioctl_header_abi_probe.cpp",
        "compat/x86_64/run_epoll_header_abi.sh",
        "compat/x86_64/epoll_header_abi_probe.c",
        "compat/x86_64/epoll_header_abi_probe.cpp",
        "compat/x86_64/run_timeval_transitive_header_abi.sh",
        "compat/x86_64/timeval_transitive_header_abi_probe.c",
        "compat/x86_64/timeval_transitive_header_abi_probe.cpp",
        "compat/x86_64/run_sys_time_direct_header_abi.sh",
        "compat/x86_64/sys_time_direct_header_abi_probe.c",
        "compat/x86_64/sys_time_direct_header_abi_probe.cpp",
        "compat/x86_64/run_access_header_abi.sh",
        "compat/x86_64/access_header_abi_probe.c",
        "compat/x86_64/access_header_abi_probe.cpp",
        "compat/x86_64/run_candidate_header_closure.sh",
        "compat/x86_64/header_cxx_closure.cpp",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/tests/test_candidate_header_closure.py",
        "compat/x86_64/tests/test_uapi_wrapper_matrix.py",
        "compat/x86_64/tests/test_ioctl_header_abi.py",
        "compat/x86_64/tests/test_epoll_header_abi.py",
        "compat/x86_64/tests/test_timeval_transitive_header_abi.py",
        "compat/x86_64/tests/test_sys_time_direct_header_abi.py",
        "compat/x86_64/tests/test_access_header_abi.py",
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
            "all_rows_resolved": True,
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
            "oracle_not_applicable_rows",
            "scope",
        },
        "header-foundation candidate-header closure diagnostic keys drifted",
    )
    require(
        closure_diagnostic["id"] == "isolated-candidate-header-closure",
        "header-foundation candidate-header closure diagnostic id drifted",
    )
    require(
        closure_diagnostic["state"] == "partial-verified"
        and closure_diagnostic["required_result"] == "pass",
        "header-foundation candidate-header closure diagnostic must remain partial verified and require a live pass",
    )
    require(
        closure_diagnostic["command"]
        == "./scripts/dev-x86_64.sh candidate-header-closure",
        "header-foundation candidate-header closure command drifted",
    )
    require(
        tuple(string_list(closure_diagnostic["profiles"], "header-foundation closure profiles"))
        == EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES,
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
        tuple(
            string_list(
                closure_diagnostic["oracle_not_applicable_rows"],
                "header-foundation closure oracle-not-applicable rows",
            )
        )
        == EXPECTED_CANDIDATE_HEADER_CLOSURE_ORACLE_NOT_APPLICABLE_ROWS,
        "header-foundation candidate-header closure oracle-not-applicable rows drifted",
    )
    require(
        isinstance(closure_diagnostic["scope"], str)
        and "aio.h:c11-strict and aio.h:cxx17-strict" in closure_diagnostic["scope"]
        and "not feature-visibility, declaration/layout/linkage/runtime/installed-header/public-support evidence"
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
    closure_runner = CANDIDATE_HEADER_CLOSURE_RUNNER_PATH.read_text(encoding="utf-8")
    for phrase in (
        "readonly EXPECTED_PROFILE_COUNT=7",
        "readonly EXPECTED_RECORD_COUNT=1337",
        "readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)",
        "readonly -a ORACLE_NOT_APPLICABLE_ROWS=(aio.h:c11-strict aio.h:cxx17-strict)",
        "validate_profile_contract",
        "validate_oracle_not_applicable_contract",
        "profile count drifted",
        "profile list contains duplicate",
        "reference-not-applicable",
        "expected exactly one $row record",
        "observed an undeclared row",
        "grep -Fq 'aio_sigevent'",
        "grep -Fq 'incomplete type'",
        "# schema=crabc.x86_64-candidate-header-closure/v3",
        "# candidate_isolation=-nostdinc for all profiles",
    ):
        require(
            phrase in closure_runner,
            f"candidate-header closure runner omits fixed seven-profile contract: {phrase}",
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

    ioctl_header_profile_matrix = manifest["ioctl_header_profile_matrix"]
    require(
        isinstance(ioctl_header_profile_matrix, Mapping),
        "header-foundation ioctl header matrix must be a table",
    )
    require(
        set(ioctl_header_profile_matrix)
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
        "header-foundation ioctl header matrix keys drifted",
    )
    require(
        ioctl_header_profile_matrix["id"] == EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_ID,
        "header-foundation ioctl header matrix id drifted",
    )
    require(
        ioctl_header_profile_matrix["state"] == "partial-verified"
        and ioctl_header_profile_matrix["required_result"] == "pass",
        "header-foundation ioctl header matrix must remain partial verified evidence",
    )
    require(
        ioctl_header_profile_matrix["command"] == EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation ioctl header matrix command drifted",
    )
    require(
        ioctl_header_profile_matrix["header_class"] == "pinned-non-uapi",
        "header-foundation ioctl header matrix must remain scoped to one pinned non-UAPI header",
    )
    require(
        ioctl_header_profile_matrix["subject_header"]
        == EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_SUBJECT_HEADER,
        "header-foundation ioctl header matrix subject header drifted",
    )
    ioctl_profiles = string_list(
        ioctl_header_profile_matrix["profiles"], "header-foundation ioctl header matrix profiles"
    )
    require(
        tuple(ioctl_profiles) == EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
        "header-foundation ioctl header matrix profiles drifted",
    )
    require(
        ioctl_header_profile_matrix["row_count"] == EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_ROW_COUNT
        and ioctl_header_profile_matrix["row_count"] == len(ioctl_profiles),
        "header-foundation ioctl header matrix row count drifted",
    )
    ioctl_scope = ioctl_header_profile_matrix["scope"]
    require(
        isinstance(ioctl_scope, str)
        and all(
            phrase in ioctl_scope
            for phrase in (
                "signed int variadic ioctl declaration",
                "C++ C-linkage",
                "winsize",
                "FIONREAD",
                "FIONBIO",
                "FIOCLEX",
                "FIONCLEX",
                "ioctl artifact linkage",
                "generic device/request behavior",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation ioctl header matrix scope must retain its non-completion boundary",
    )
    ioctl_rows = ioctl_header_profile_matrix["row"]
    require(
        isinstance(ioctl_rows, list)
        and len(ioctl_rows) == EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation ioctl header matrix row roster drifted",
    )
    observed_ioctl_rows: list[str] = []
    for index, row in enumerate(ioctl_rows):
        location = f"header-foundation ioctl_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        profile = row["profile"]
        require(isinstance(profile, str), f"{location} profile is invalid")
        require(
            profile in EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
            f"{location} profile is not a declared ioctl header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_ioctl_rows.append(profile)
    require(
        tuple(observed_ioctl_rows) == EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES,
        "header-foundation ioctl header matrix row order or cross-product drifted",
    )
    require(
        IOCTL_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation ioctl header matrix runner is missing",
    )
    require(
        "ioctl-header-abi)" in dispatch_source,
        "ioctl-header-abi is absent from the native dispatcher",
    )
    ioctl_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_IOCTL_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(ioctl_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one ioctl header matrix evidence command",
    )
    require(
        ioctl_matrix_evidence[0].get("state") == "required"
        and isinstance(ioctl_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in ioctl_matrix_evidence[0]["scope"]
            for phrase in (
                "signed int variadic ioctl declaration",
                "C++ C-linkage",
                "winsize",
                "ioctl artifact linkage",
                "generic device/request behavior",
                "all-header closure",
                "runtime",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts ioctl header matrix evidence must retain its non-completion boundary",
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

    access_header_profile_matrix = manifest["access_header_profile_matrix"]
    require(
        isinstance(access_header_profile_matrix, Mapping),
        "header-foundation access header matrix must be a table",
    )
    require(
        set(access_header_profile_matrix)
        == {
            "id",
            "state",
            "command",
            "required_result",
            "header_class",
            "subject_headers",
            "profiles",
            "row_count",
            "scope",
            "row",
        },
        "header-foundation access header matrix keys drifted",
    )
    require(
        access_header_profile_matrix["id"] == EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_ID,
        "header-foundation access header matrix id drifted",
    )
    require(
        access_header_profile_matrix["state"] == "partial-verified"
        and access_header_profile_matrix["required_result"] == "pass",
        "header-foundation access header matrix must remain partial verified evidence",
    )
    require(
        access_header_profile_matrix["command"] == EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation access header matrix command drifted",
    )
    require(
        access_header_profile_matrix["header_class"] == "pinned-non-uapi",
        "header-foundation access header matrix must remain scoped to pinned non-UAPI headers",
    )
    access_header_subject_headers = string_list(
        access_header_profile_matrix["subject_headers"],
        "header-foundation access header matrix subject headers",
    )
    require(
        tuple(access_header_subject_headers) == EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS,
        "header-foundation access header matrix subject headers drifted",
    )
    access_header_profiles = string_list(
        access_header_profile_matrix["profiles"],
        "header-foundation access header matrix profiles",
    )
    require(
        tuple(access_header_profiles) == EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation access header matrix profiles drifted",
    )
    require(
        access_header_profile_matrix["row_count"] == EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_ROW_COUNT
        and access_header_profile_matrix["row_count"] == len(access_header_profiles),
        "header-foundation access header matrix row count drifted",
    )
    access_header_scope = access_header_profile_matrix["scope"]
    require(
        isinstance(access_header_scope, str)
        and all(
            phrase in access_header_scope
            for phrase in (
                "GNU-only eaccess/euidaccess feature visibility",
                "actual callable artifact linkage",
                "runtime behavior",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation access header matrix scope must retain its non-completion boundary",
    )
    access_header_rows = access_header_profile_matrix["row"]
    require(
        isinstance(access_header_rows, list)
        and len(access_header_rows) == EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation access header matrix row roster drifted",
    )
    observed_access_header_rows: list[str] = []
    for index, row in enumerate(access_header_rows):
        location = f"header-foundation access_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        profile = row["profile"]
        require(isinstance(profile, str), f"{location} profile is invalid")
        require(
            profile in EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_PROFILES,
            f"{location} profile is not a declared access-header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_access_header_rows.append(profile)
    require(
        tuple(observed_access_header_rows) == EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation access header matrix row order or roster drifted",
    )
    require(
        ACCESS_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation access header matrix runner is missing",
    )
    require(
        "access-header-abi)" in dispatch_source,
        "access-header-abi is absent from the native dispatcher",
    )
    access_header_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(access_header_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one access header matrix evidence command",
    )
    require(
        access_header_matrix_evidence[0].get("state") == "required"
        and isinstance(access_header_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in access_header_matrix_evidence[0]["scope"]
            for phrase in (
                "GNU-only eaccess/euidaccess",
                "actual callable artifact linkage",
                "runtime behavior",
                "all-header closure",
                "runtime",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts access header matrix evidence must retain its non-completion boundary",
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
    require(
        set(access_header_subject_headers) <= pinned_path_set - uapi_header_set,
        "header-foundation access header subjects must remain pinned non-UAPI headers",
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
            == EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES,
            f"{location}.language_profiles drifted",
        )
        require(
            tuple(
                string_list(
                    entry["future_feature_profiles"],
                    f"{location}.future_feature_profiles",
                    allow_empty=True,
                )
            )
            == EXPECTED_HEADER_FOUNDATION_UNVERIFIED_FEATURE_PROFILES,
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
        "ioctl_header_profile_matrix_row_count": len(observed_ioctl_rows),
        "epoll_header_profile_matrix_row_count": len(observed_epoll_rows),
        "timeval_transitive_header_profile_matrix_row_count": len(observed_timeval_rows),
        "sys_time_direct_header_profile_matrix_row_count": len(observed_sys_time_direct_rows),
        "access_header_profile_matrix_row_count": len(observed_access_header_rows),
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


def require_public_header_profile_consumability_artifact(
    family: Mapping[str, Any],
) -> None:
    """Ratchet the seven-profile empty-TU matrix without promoting headers.

    The artifact is intentionally an isolated include-consumer contract. It
    records a narrow pinned-musl applicability fact for two strict aio.h rows,
    while keeping feature visibility, declarations, layouts, linkage, and
    runtime ownership in their separate promotion gates.
    """

    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.headers-layouts].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "public-header-profile-consumability"
    ]
    require(
        len(matching) == 1,
        "libc.headers-layouts must contain exactly one public-header-profile-consumability artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "seven-profile",
        "1,337",
        "183 pinned-musl public headers plus eight project-only headers",
        "`aio.h:c11-strict`",
        "`aio.h:cxx17-strict`",
        "pinned-musl oracle-not-applicable",
        "candidate still must compile",
        "not feature-visibility, declaration/layout, callable-linkage, archive, runtime, installed-header, family-promotion, or public-x86 evidence",
    ):
        require(
            phrase in description,
            f"public-header-profile-consumability description omits {phrase}",
        )

    owners = set(
        nonempty_strings(
            artifact["source_owners"],
            "public-header-profile-consumability.source_owners",
        )
    )
    for owner in (
        "compat/x86_64/public_headers.txt",
        "compat/x86_64/headers-layouts-foundation.toml",
        "compat/x86_64/run_candidate_header_closure.sh",
        "compat/x86_64/header_cxx_closure.cpp",
        "compat/x86_64/tests/test_candidate_header_closure.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/dev-x86_64.sh",
    ):
        require(
            owner in owners,
            f"public-header-profile-consumability omits {owner}",
        )

    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("183 + 8" in item and "7" in item and "1,337" in item for item in prerequisites),
        "public-header-profile-consumability must state its closed row arithmetic",
    )
    require(
        any("aio.h:c11-strict" in item and "aio.h:cxx17-strict" in item for item in prerequisites),
        "public-header-profile-consumability must state both strict aio oracle rows",
    )
    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    require(
        any("-nostdinc" in item and "Linux 5.10 UAPI" in item for item in header_prerequisites),
        "public-header-profile-consumability must retain its isolated header roots",
    )
    require(
        any("feature visibility" in item and "declaration/layout" in item for item in header_prerequisites),
        "public-header-profile-consumability must retain its non-completion boundary",
    )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        [entry["command"] for entry in evidence]
        == ["./scripts/dev-x86_64.sh candidate-header-closure"],
        "public-header-profile-consumability must use the closed candidate-header-closure command",
    )
    scope = evidence[0]["scope"]
    require(
        isinstance(scope, str)
        and "reference-not-applicable" in scope
        and "candidate compilation" in scope
        and "not feature visibility" in scope,
        "public-header-profile-consumability evidence scope drifted",
    )
    dispatch_source = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    require(
        "candidate-header-closure)" in dispatch_source,
        "public-header-profile-consumability command is absent from the native dispatcher",
    )


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
        "bounded packed `DT_RELR`",
        "direct-address and bitmap",
        "512-record/512-target caps per object",
        "zero-bit bitmap runs",
        "duplicate RELR target",
        "over-cap RELR stream",
        "`DT_RELA`-only",
        "general or interpreter `DT_RELR`",
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


def require_ldso_initial_tls_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet the private GNU-Dynamic TLS graph without promoting the loader."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[ldso.dynamic-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "ldso-initial-tls"]
    require(len(matching) == 1, "ldso.dynamic-runtime needs exactly one ldso-initial-tls artifact")
    artifact = matching[0]
    require(family.get("status") == "planned", "ldso-initial-tls must not promote ldso.dynamic-runtime")
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `ldso.dynamic-runtime`",
        "main PIE (without PT_TLS) -> mid.so -> leaf.so",
        "GNU-Dynamic TLS",
        "Variant-II",
        "R_X86_64_DTPMOD64",
        "R_X86_64_DTPOFF64",
        "__tls_get_addr",
        "TBSS",
        "DTV",
        "R_X86_64_TPOFF64",
        "DF_STATIC_TLS",
        "pinned musl 1.2.6 static __tls_get_addr",
        "TLSDESC",
        "DTV growth",
        "pthread/TCB parity",
        "dynamic CRT/sysroot",
        "public x86 support",
    ):
        require(phrase in description, f"ldso-initial-tls description omits {phrase}")
    expected_sources = {
        "ldso/src/x86_64_initial_graph.rs",
        "compat/x86_64/ldso_initial_graph_start.S",
        "compat/x86_64/ldso_initial_tls_leaf.c",
        "compat/x86_64/ldso_initial_tls_mid.c",
        "compat/x86_64/ldso_initial_tls_main.c",
        "compat/x86_64/run_ldso_initial_tls.sh",
        "scripts/dev-x86_64.sh",
    }
    require(
        set(string_list(artifact["source_owners"], "ldso-initial-tls source owners")) == expected_sources,
        "ldso-initial-tls source owners drifted",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence} == {"./scripts/dev-x86_64.sh ldso-initial-tls"},
        "ldso-initial-tls must use the dedicated native command",
    )
    runner = (ROOT / "compat" / "x86_64" / "run_ldso_initial_tls.sh").read_text()
    require("MUSL_LIBC_ARCHIVE" in runner, "ldso-initial-tls must use the pinned musl static resolver")
    require("env -i PATH=/usr/bin:/bin" in runner, "ldso-initial-tls must reject ambient execution state")
    require(
        "run_ldso_initial_tls.sh" in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "ldso-initial-tls dispatcher binding is missing",
    )


def require_static_initial_tls_v1_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet the private real-PT_TLS foundation without promoting pthreads."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-initial-tls-v1"]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-initial-tls-v1 artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-initial-tls-v1 must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "Static Initial TLS v1",
        "AT_PHDR",
        "PT_TLS",
        "Variant-II",
        "ARCH_SET_FS",
        "initialized/TBSS/high-alignment",
        "dynamic TLS",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-initial-tls-v1 description omits {phrase}",
        )
    for owner in (
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "compat/x86_64/libc_static_tls_v1_probe.c",
        "compat/x86_64/libc_static_tls_v1_peer.c",
        "compat/x86_64/libc_static_tls_v1_start.S",
        "compat/x86_64/run_libc_static_tls_v1.sh",
    ):
        require(
            owner in artifact["source_owners"],
            f"static-c-initial-tls-v1 source owners omit {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "AT_PHDR=3" in item
            and "AT_PHENT=4" in item
            and "AT_PHNUM=5" in item
            and "PT_TLS" in item
            for item in prerequisites
        ),
        "static-c-initial-tls-v1 must retain its initial-stack/PT_TLS validation contract",
    )
    require(
        any(
            "PT_PHDR" in item
            and "ET_EXEC" in item
            and "no-PT_PHDR" in item
            and "e_phoff=64" in item
            for item in prerequisites
        ),
        "static-c-initial-tls-v1 must state its validated PT_PHDR/ET_EXEC load-bias contract",
    )
    require(
        any(
            "p_filesz" in item
            and "p_memsz-p_filesz" in item
            and "ARCH_SET_FS" in item
            for item in prerequisites
        ),
        "static-c-initial-tls-v1 must retain exact template-copy and FS-install rules",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-static-tls-v1"},
        "static-c-initial-tls-v1 must use the closed libc-static-tls-v1 command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "original stack",
        "ET_EXEC no-PT_PHDR",
        "fallback ELF version",
        "PT_TLS p_filesz",
        "real initialized/TBSS/high-alignment PT_TLS",
        "dynamic TLS",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-initial-tls-v1 evidence scope omits {phrase}",
        )


def require_static_crt_initial_tls_handoff_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet the one real CRT-to-libc TLS composition without promotion."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-crt-initial-tls-handoff"
    ]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-crt-initial-tls-handoff artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-crt-initial-tls-handoff must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "Static Initial TLS v1",
        "still-planned `libc.pthread-tls`",
        "rcrt1.o",
        "crti.o",
        "crtn.o",
        "__crabc_x86_static_tls_bootstrap",
        "__libc_start_main",
        "preinit, init, main",
        "32-registration",
        "atexit",
        "PT_TLS.p_filesz",
        "general CRT/startup",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-crt-initial-tls-handoff description omits {phrase}",
        )
    for owner in (
        "crt/build_x86_64.py",
        "crt/src/x86_64_rcrt1.rs",
        "crt/src/x86_64_startup.rs",
        "crt/src/x86_64_crti.rs",
        "crt/src/x86_64_crtn.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/static_startup.rs",
        "libc/src/c_abi/x86_64/immediate_termination.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "include/stdlib.h",
        "compat/x86_64/libc_crt_static_tls_probe.c",
        "compat/x86_64/libc_crt_static_tls_peer.c",
        "compat/x86_64/run_libc_crt_static_tls.sh",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    ):
        require(
            owner in artifact["source_owners"],
            f"static-c-crt-initial-tls-handoff source owners omit {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "GLOBAL HIDDEN",
        "GOTPCREL",
        "R_X86_64_RELATIVE",
        "PT_PHDR",
        "PT_TLS",
        "Variant-II",
        "ARCH_SET_FS",
        "GOTTPOFF/DTPOFF",
        "__tls_get_addr",
        "__libc_start_main",
        "32-registration",
        "__cxa_finalize",
        "fresh Static Initial TLS v1 image",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-crt-initial-tls-handoff ABI prerequisites omit {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-crt-static-tls"},
        "static-c-crt-initial-tls-handoff must use the closed libc-crt-static-tls command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "pinned-musl",
        "explicit reference adaptation",
        "no archive link fails",
        "PT_PHDR ET_DYN static PIE",
        "archive-owned startup",
        "32-registration",
        "PIMBCAF",
        "PT_TLS p_filesz mutation",
        "exit 127",
        "general CRT",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-crt-initial-tls-handoff evidence scope omits {phrase}",
        )


def require_static_crt1_initial_tls_handoff_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet the conventional ET_EXEC CRT composition without promotion."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-crt1-initial-tls-handoff"
    ]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-crt1-initial-tls-handoff artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-crt1-initial-tls-handoff must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "Static Initial TLS v1",
        "ordinary static `ET_EXEC`",
        "still-planned `libc.pthread-tls`",
        "crt1.o",
        "crti.o",
        "crtn.o",
        "__crabc_x86_static_tls_bootstrap",
        "__libc_start_main",
        "preinit, init, main",
        "32-registration",
        "atexit",
        "PT_TLS.p_filesz",
        "general CRT/startup",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-crt1-initial-tls-handoff description omits {phrase}",
        )
    for owner in (
        "crt/build_x86_64.py",
        "crt/src/x86_64_crt1.rs",
        "crt/src/x86_64_startup.rs",
        "crt/src/x86_64_crti.rs",
        "crt/src/x86_64_crtn.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/static_startup.rs",
        "libc/src/c_abi/x86_64/immediate_termination.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "include/stdlib.h",
        "compat/x86_64/libc_crt_static_tls_probe.c",
        "compat/x86_64/libc_crt_static_tls_peer.c",
        "compat/x86_64/run_libc_crt1_static_tls.sh",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    ):
        require(
            owner in artifact["source_owners"],
            f"static-c-crt1-initial-tls-handoff source owners omit {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "R_X86_64_PLT32",
        "ET_EXEC",
        "no-PT_PHDR",
        "PT_TLS",
        "Variant-II",
        "ARCH_SET_FS",
        "__libc_start_main",
        "32-registration",
        "__cxa_finalize",
        "fresh Static Initial TLS v1 image",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-crt1-initial-tls-handoff ABI prerequisites omit {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-crt1-static-tls"},
        "static-c-crt1-initial-tls-handoff must use the closed libc-crt1-static-tls command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "pinned-musl",
        "explicit reference adaptation",
        "no archive link fails",
        "ET_EXEC",
        "archive-owned startup",
        "32-registration",
        "PIMBCAF",
        "PT_TLS p_filesz mutation",
        "exit 127",
        "general CRT",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-crt1-initial-tls-handoff evidence scope omits {phrase}",
        )


def require_static_pthread_identity_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet static pthread/C11 identity without promoting pthread parity."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-pthread-identity"]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-pthread-identity artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-pthread-identity must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.pthread-tls`",
        "weak same-address",
        "`pthread_self`/`thrd_current`",
        "`pthread_equal`/`thrd_equal`",
        "Variant-II `%fs:0`",
        "canonical one or zero",
        "pthread_t",
        "registry lock",
        "true/false equality",
        "general pthread runtime",
        "`thread.pthread-c11`",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-pthread-identity description omits {phrase}",
        )
    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/pthread_identity.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/errno.h",
        "include/features.h",
        "include/pthread.h",
        "include/threads.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_pthread_identity_probe.c",
        "compat/x86_64/libc_pthread_identity_start.S",
        "compat/x86_64/run_libc_pthread_identity.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(string_list(artifact["source_owners"], "static-c-pthread-identity source owners"))
        == expected_sources,
        "static-c-pthread-identity source owners drifted",
    )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "arch/x86_64/pthread_arch.h::__get_tp",
        "src/internal/pthread_impl.h::__pthread_self",
        "struct pthread TCB",
        "src/thread/pthread_self.c",
        "src/thread/pthread_equal.c",
        "weak function symbols",
        "canonical 0 or 1",
        "CLONE_SETTLS",
        "registry lock",
        "futex=202",
        "munmap=11",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-pthread-identity ABI prerequisites omit {phrase}",
        )
    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "pthread_self",
        "thrd_current/thrd_equal",
        "28-context C/C++",
        "unmangled C linkage",
        "no broad header or pthread implementation claim",
    ):
        require(
            phrase in header_text,
            f"static-c-pthread-identity header prerequisites omit {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-pthread-identity"},
        "static-c-pthread-identity must use the closed libc-pthread-identity command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "weak",
        "one address",
        "`%fs:0`",
        "exactly one for equal and zero for distinct",
        "two concurrently live normal workers",
        "selected explicit-exit worker",
        "parent errno preservation",
        "general pthread/C11-thread behavior",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-pthread-identity evidence scope omits {phrase}",
        )
    static_exports = {
        line
        for line in (ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt").read_text().splitlines()
        if line and not line.startswith("#")
    }
    require(
        {"pthread_self", "pthread_equal", "thrd_current", "thrd_equal"} <= static_exports,
        "static-c-pthread-identity static export contract omits an identity symbol",
    )
    require(
        "run_libc_pthread_identity.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-pthread-identity dispatcher binding is missing",
    )


def require_static_c11_lifecycle_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet typed static C11 lifecycle without promoting pthread/C11 parity."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-c11-lifecycle"]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-c11-lifecycle artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-c11-lifecycle must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.pthread-tls`",
        "typed `thrd_create`/`thrd_join`/`thrd_exit`",
        "never cast to the pointer-returning pthread callback type",
        "Variant-II `%fs:0` TP",
        "INT_MIN",
        "INT_MAX",
        "tagged private join word",
        "Candidate-only",
        "cross-mode",
        "not musl parity evidence",
        "thread.pthread-c11",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-c11-lifecycle description omits {phrase}",
        )
    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "libc/src/c_abi/x86_64/pthread_identity.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/errno.h",
        "include/features.h",
        "include/limits.h",
        "include/pthread.h",
        "include/threads.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_c11_lifecycle_probe.c",
        "compat/x86_64/libc_c11_lifecycle_start.S",
        "compat/x86_64/run_libc_c11_lifecycle.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(string_list(artifact["source_owners"], "static-c-c11-lifecycle source owners"))
        == expected_sources,
        "static-c-c11-lifecycle source owners drifted",
    )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "src/thread/thrd_create.c",
        "src/thread/pthread_create.c::start_c11",
        "src/thread/thrd_join.c",
        "src/thread/thrd_exit.c",
        "SelectedWorkerStart::C11",
        "sign-extends c_int",
        "INT_MIN",
        "INT_MAX",
        "pointer as an int",
        "int as a pointer",
        "clone=56",
        "CLONE_SETTLS",
        "futex=202",
        "munmap=11",
        "no handle use after successful join",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-c11-lifecycle ABI prerequisites omit {phrase}",
        )
    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "errno.h",
        "limits.h",
        "pthread.h",
        "threads.h",
        "28-context C/C++",
        "thrd_create/thrd_join/thrd_exit/current/equality",
        "C noreturn function-type spelling",
        "C++ plain function-pointer spelling",
        "not a broad header or pthread/C11 implementation claim",
    ):
        require(
            phrase in header_text,
            f"static-c-c11-lifecycle header prerequisites omit {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-c11-lifecycle"},
        "static-c-c11-lifecycle must use the closed libc-c11-lifecycle command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "`-nostdlib -static` candidate",
        "typed thrd_create/thrd_join/thrd_exit",
        "INT_MIN/INT_MAX",
        "two simultaneously live TP-identical workers",
        "64-slot exhaustion/reuse",
        "null start",
        "C11-to-pthread_exit",
        "pthread-to-thrd_exit",
        "thrd_error or EINVAL",
        "no interpreter/DT_NEEDED/unresolved symbol",
        "general pthread/C11 behavior",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-c11-lifecycle evidence scope omits {phrase}",
        )
    static_exports = {
        line
        for line in (ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt").read_text().splitlines()
        if line and not line.startswith("#")
    }
    require(
        {"thrd_create", "thrd_join", "thrd_exit"} <= static_exports,
        "static-c-c11-lifecycle static export contract omits a C11 lifecycle symbol",
    )
    require(
        "run_libc_c11_lifecycle.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-c11-lifecycle dispatcher binding is missing",
    )


def require_static_pthread_c11_detach_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet private static detach without promoting pthread/C11 parity."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-pthread-c11-detach"
    ]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-pthread-c11-detach artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-pthread-c11-detach must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.pthread-tls`",
        "prompt `pthread_detach`/`thrd_detach`",
        "Joinable",
        "Detached",
        "CLONE_CHILD_CLEARTID",
        "Candidate-only",
        "not musl parity evidence",
        "detached-at-create attributes",
        "thread.pthread-c11",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-pthread-c11-detach description omits {phrase}",
        )
    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "libc/src/c_abi/x86_64/pthread_identity.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/errno.h",
        "include/features.h",
        "include/pthread.h",
        "include/threads.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_pthread_detach_probe.c",
        "compat/x86_64/libc_pthread_detach_start.S",
        "compat/x86_64/run_libc_pthread_detach.sh",
        "compat/x86_64/run_libc_static_tls_v1.sh",
        "compat/x86_64/run_libc_pthread_create_join_tls.sh",
        "compat/x86_64/run_libc_c11_lifecycle.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(
            string_list(
                artifact["source_owners"],
                "static-c-pthread-c11-detach source owners",
            )
        )
        == expected_sources,
        "static-c-pthread-c11-detach source owners drifted",
    )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "src/thread/pthread_detach.c",
        "src/thread/thrd_detach.c",
        "Joinable",
        "DetachedReclaiming",
        "registry lock",
        "clone=56",
        "CLONE_SETTLS",
        "CLONE_CHILD_CLEARTID",
        "state-only",
        "futex=202",
        "munmap=11",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-pthread-c11-detach ABI prerequisites omit {phrase}",
        )
    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "errno.h",
        "pthread.h",
        "threads.h",
        "28-context C/C++",
        "pthread_detach/thrd_detach",
        "unmangled C linkage",
        "not a broad header or pthread/C11 implementation claim",
    ):
        require(
            phrase in header_text,
            f"static-c-pthread-c11-detach header prerequisites omit {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-pthread-detach"},
        "static-c-pthread-c11-detach must use the closed libc-pthread-detach command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "`-nostdlib -static` candidate",
        "pthread/C11 workers",
        "pthread_exit/thrd_exit",
        "parent errno",
        "Candidate-only",
        "self-detach",
        "null-handle",
        "double-detach",
        "join-vs-detach/detach-vs-detach",
        "64-slot reuse",
        "CLONE_CHILD_CLEARTID",
        "no interpreter/DT_NEEDED/unresolved symbol",
        "no-syscall state transition",
        "general pthread/C11 behavior",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-pthread-c11-detach evidence scope omits {phrase}",
        )
    static_exports = {
        line
        for line in (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text().splitlines()
        if line and not line.startswith("#")
    }
    require(
        {"pthread_detach", "thrd_detach"} <= static_exports,
        "static-c-pthread-c11-detach static export contract omits a detach symbol",
    )
    require(
        "run_libc_pthread_detach.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-pthread-c11-detach dispatcher binding is missing",
    )


def require_static_thrd_sleep_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet one direct C11 sleep adapter without promoting C11 parity."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-thrd-sleep"]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-thrd-sleep artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-thrd-sleep must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.pthread-tls`",
        "C11 `thrd_sleep`",
        "clock_nanosleep(CLOCK_REALTIME, 0, ...)",
        "`EINTR` is `-1`",
        "`-2`",
        "without mutating C errno",
        "cancellation-point machinery",
        "`thrd_yield`",
        "thread.pthread-c11",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-thrd-sleep description omits {phrase}",
        )
    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs",
        "libc/src/c_abi/x86_64/clock_nanosleep.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/bits/syscall.h",
        "include/errno.h",
        "include/features.h",
        "include/signal.h",
        "include/sys/syscall.h",
        "include/sys/types.h",
        "include/threads.h",
        "include/time.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_thrd_sleep_probe.c",
        "compat/x86_64/libc_thrd_sleep_start.S",
        "compat/x86_64/run_libc_thrd_sleep.sh",
        "compat/x86_64/run_libc_c11_lifecycle.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(string_list(artifact["source_owners"], "static-c-thrd-sleep source owners"))
        == expected_sources,
        "static-c-thrd-sleep source owners drifted",
    )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "src/thread/thrd_sleep.c",
        "clock_nanosleep(CLOCK_REALTIME, 0, duration, remaining)",
        "EINTR to -1",
        "every other failure to -2",
        "clock_nanosleep=230",
        "r10",
        "direct positive errno",
        "c_status",
        "SIGALRM",
        "cancellation point",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-thrd-sleep ABI prerequisites omit {phrase}",
        )
    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "threads.h",
        "time.h",
        "errno.h",
        "signal.h",
        "sys/syscall.h",
        "28-context C/C++",
        "thrd_sleep signature",
        "unmangled C linkage",
        "not a broad header or pthread/C11 implementation claim",
    ):
        require(
            phrase in header_text,
            f"static-c-thrd-sleep header prerequisites omit {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-thrd-sleep"},
        "static-c-thrd-sleep must use the closed libc-thrd-sleep command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "`-nostdlib -static` candidate",
        "zero-duration",
        "invalid tv_nsec",
        "null-duration -2",
        "SIGALRM interruption as -1",
        "positive remaining interval",
        "preserving errno",
        "clock_nanosleep=230",
        "r10 fourth-argument path",
        "no interpreter/DT_NEEDED/unresolved symbol",
        "cancellation",
        "thrd_yield",
        "general pthread/C11 behavior",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-thrd-sleep evidence scope omits {phrase}",
        )
    static_exports = {
        line
        for line in (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text().splitlines()
        if line and not line.startswith("#")
    }
    require(
        "thrd_sleep" in static_exports,
        "static-c-thrd-sleep static export contract omits thrd_sleep",
    )
    require(
        "run_libc_thrd_sleep.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-thrd-sleep dispatcher binding is missing",
    )


def require_static_pthread_normal_mutex_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet private normal mutex evidence without promoting pthread parity."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-pthread-normal-mutex"
    ]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-pthread-normal-mutex artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-pthread-normal-mutex must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.pthread-tls`",
        "`PTHREAD_MUTEX_NORMAL`",
        "all-zero 40-byte aligned public record",
        "EBUSY|INT_MIN",
        "private futex",
        "six bounded two-worker rounds",
        "ENOTSUP",
        "recursive/errorcheck/robust/PI/pshared behavior",
        "separately selected C11 plain-sync artifact",
        "thread.pthread-c11",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-pthread-normal-mutex description omits {phrase}",
        )
    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/atomic.rs",
        "libc/src/c_abi/x86_64/pthread_mutex.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/bits/syscall.h",
        "include/errno.h",
        "include/features.h",
        "include/pthread.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/run_types_header_abi.sh",
        "compat/x86_64/run_libc_static_tls_v1.sh",
        "compat/x86_64/run_libc_pthread_create_join_tls.sh",
        "compat/x86_64/run_libc_c11_lifecycle.sh",
        "compat/x86_64/run_libc_thrd_sleep.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_pthread_mutex_normal_probe.c",
        "compat/x86_64/libc_pthread_mutex_normal_start.S",
        "compat/x86_64/run_libc_pthread_mutex_normal.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(
            string_list(
                artifact["source_owners"],
                "static-c-pthread-normal-mutex source owners",
            )
        )
        == expected_sources,
        "static-c-pthread-normal-mutex source owners drifted",
    )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "src/thread/pthread_mutex_init.c",
        "pthread_mutex_trylock.c",
        "pthread_mutex_lock.c",
        "pthread_mutex_timedlock.c",
        "pthread_mutex_unlock.c",
        "pthread_mutex_destroy.c",
        "40 bytes",
        "8-byte alignment",
        "offsets 0/4/8",
        "EBUSY=16",
        "EBUSY|INT_MIN",
        "futex=202",
        "FUTEX_WAIT_PRIVATE=128",
        "FUTEX_WAKE_PRIVATE=129",
        "r10",
        "atomic compare-exchange",
        "atomic exchange",
        "EINTR",
        "without mutating C errno",
        "no TCB/gettid",
        "dynamic TLS",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-pthread-normal-mutex ABI prerequisites omit {phrase}",
        )
    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "pthread.h",
        "errno.h",
        "bits/alltypes.h",
        "bits/syscall.h",
        "40 bytes",
        "8-byte alignment",
        "init/destroy/lock/trylock/unlock",
        "28-context C/C++",
        "unmangled C-linkage",
        "not claim a broad installed header or pthread/C11 implementation",
    ):
        require(
            phrase in header_text,
            f"static-c-pthread-normal-mutex header prerequisites omit {phrase}",
        )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-pthread-mutex-normal"},
        "static-c-pthread-normal-mutex must use the closed libc-pthread-mutex-normal command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "`-nostdlib -static` candidate",
        "NULL-attribute",
        "static/all-zero normal initialization",
        "held `EBUSY`",
        "errno preservation",
        "destruction after quiescence",
        "private-futex handoff/mutual exclusion",
        "six bounded two-worker contention rounds",
        "lock cmpxchg",
        "exchange/xchg release",
        "futex=202",
        "FUTEX_WAIT_PRIVATE=128",
        "FUTEX_WAKE_PRIVATE=129",
        "no interpreter/DT_NEEDED/unresolved symbol",
        "general pthread synchronization",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-pthread-normal-mutex evidence scope omits {phrase}",
        )
    static_exports = {
        line
        for line in (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text().splitlines()
        if line and not line.startswith("#")
    }
    require(
        {
            "pthread_mutex_init",
            "pthread_mutex_destroy",
            "pthread_mutex_lock",
            "pthread_mutex_trylock",
            "pthread_mutex_unlock",
        }
        <= static_exports,
        "static-c-pthread-normal-mutex static export contract omits a normal mutex symbol",
    )
    require(
        "run_libc_pthread_mutex_normal.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-pthread-normal-mutex dispatcher binding is missing",
    )


def require_static_pthread_private_cond_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet one private waiter/barrier/requeue block without promotion.

    This artifact is intentionally a selected static C boundary, not a claim
    that the pthread family, its condition attributes, or the C11 condition
    surface is complete.  Keep the exact public records, sibling normal mutex,
    raw futex ABI, and candidate-only attribute rejection durable here.
    """

    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-pthread-cond-private"
    ]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-pthread-cond-private artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-pthread-cond-private must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.pthread-tls`",
        "`pthread_cond_init`/`pthread_cond_destroy`/`pthread_cond_wait`/`pthread_cond_signal`/`pthread_cond_broadcast`",
        "all-zero 48-byte aligned public `pthread_cond_t`",
        "`PTHREAD_MUTEX_NORMAL` 40-byte record",
        "private stack waiter/list/barrier/notify protocol",
        "FIFO requeue handoff",
        "four bounded 64-handoff ping-pong rounds",
        "candidate-only `ENOTSUP` rejection",
        "condition attributes",
        "process-shared state",
        "timed waits",
        "cancellation",
        "C11 condition behavior beyond that plain adapter",
        "thread.pthread-c11",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-pthread-cond-private description omits {phrase}",
        )

    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/atomic.rs",
        "libc/src/c_abi/x86_64/pthread_mutex.rs",
        "libc/src/c_abi/x86_64/pthread_cond.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/bits/syscall.h",
        "include/errno.h",
        "include/features.h",
        "include/pthread.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/run_types_header_abi.sh",
        "compat/x86_64/run_libc_pthread_create_join_tls.sh",
        "compat/x86_64/run_libc_c11_lifecycle.sh",
        "compat/x86_64/run_libc_thrd_sleep.sh",
        "compat/x86_64/run_libc_pthread_mutex_normal.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_pthread_cond_private_probe.c",
        "compat/x86_64/libc_pthread_cond_private_start.S",
        "compat/x86_64/run_libc_pthread_cond_private.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(
            string_list(
                artifact["source_owners"],
                "static-c-pthread-cond-private source owners",
            )
        )
        == expected_sources,
        "static-c-pthread-cond-private source owners drifted",
    )

    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "pthread_cond_init.c",
        "pthread_cond_destroy.c",
        "pthread_cond_wait.c",
        "pthread_cond_timedwait.c",
        "pthread_cond_signal.c",
        "pthread_cond_broadcast.c",
        "__wait.c",
        "48 bytes",
        "8-byte alignment",
        "offsets 8/40",
        "offset 32",
        "40 bytes",
        "offsets 0/4/8",
        "EBUSY=16",
        "EBUSY|INT_MIN",
        "futex=202",
        "FUTEX_WAIT_PRIVATE=128",
        "FUTEX_WAKE_PRIVATE=129",
        "FUTEX_REQUEUE_PRIVATE=131",
        "r10",
        "r8",
        "EINTR",
        "without mutating C errno",
        "dynamic TLS",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-pthread-cond-private ABI prerequisites omit {phrase}",
        )

    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "pthread.h",
        "errno.h",
        "bits/alltypes.h",
        "bits/syscall.h",
        "48 bytes",
        "8-byte alignment",
        "40 bytes",
        "pthread_cond_init/pthread_cond_destroy/pthread_cond_wait/pthread_cond_signal/pthread_cond_broadcast",
        "28-context C/C++",
        "unmangled C-linkage",
        "not claim a broad installed header or pthread/C11 implementation",
    ):
        require(
            phrase in header_text,
            f"static-c-pthread-cond-private header prerequisites omit {phrase}",
        )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-pthread-cond-private"},
        "static-c-pthread-cond-private must use the closed libc-pthread-cond-private command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "`-nostdlib -static` candidate",
        "static/all-zero and NULL-attribute initialization",
        "candidate-only non-NULL attribute ENOTSUP rejection",
        "stale errno preservation",
        "no-waiter signal",
        "one-waiter signal",
        "two-waiter broadcast",
        "quiescent destruction",
        "four bounded 64-handoff ping-pong rounds",
        "private waiter/barrier/requeue handoff",
        "futex=202",
        "FUTEX_WAIT_PRIVATE=128",
        "FUTEX_WAKE_PRIVATE=129",
        "FUTEX_REQUEUE_PRIVATE=131",
        "x86 r10/r8 requeue route",
        "no interpreter/DT_NEEDED/unresolved symbol",
        "process-shared/timed/cancellation/C11 condition behavior",
        "general pthread synchronization",
        "public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-pthread-cond-private evidence scope omits {phrase}",
        )

    static_exports = {
        line
        for line in (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text().splitlines()
        if line and not line.startswith("#")
    }
    selected_condition_exports = {
        "pthread_cond_init",
        "pthread_cond_destroy",
        "pthread_cond_wait",
        "pthread_cond_signal",
        "pthread_cond_broadcast",
    }
    require(
        {symbol for symbol in static_exports if symbol.startswith("pthread_cond")}
        == selected_condition_exports,
        "static-c-pthread-cond-private must expose exactly its five selected condition symbols",
    )
    require(
        "run_libc_pthread_cond_private.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-pthread-cond-private dispatcher binding is missing",
    )


def require_static_c11_plain_sync_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet one C11 plain-sync bridge without promoting pthread parity.

    This is deliberately a narrow C11 spelling of the already selected normal
    mutex and private condition engines. It keeps the C type distinction,
    direct private sibling routing, and candidate-only non-plain boundary from
    becoming an accidental C11 or pthread-family completion claim.
    """

    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-c11-plain-sync"
    ]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-c11-plain-sync artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-c11-plain-sync must not promote libc.pthread-tls",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.pthread-tls`",
        "`mtx_init(..., mtx_plain)`/`mtx_destroy`/`mtx_lock`/`mtx_trylock`/`mtx_unlock`",
        "`cnd_init`/`cnd_destroy`/`cnd_wait`/`cnd_signal`/`cnd_broadcast`",
        "40-byte aligned `mtx_t`",
        "48-byte aligned `cnd_t`",
        "interposable pthread C ABI",
        "`EBUSY` to `thrd_busy`",
        "direct zero result",
        "`thrd_success`/`thrd_error`",
        "four bounded 64-handoff predicate ping-pong rounds",
        "candidate-only `thrd_error` rejection",
        "recursive/timed mutexes",
        "static C11 initialization",
        "cancellation",
        "TSS",
        "once",
        "dynamic/loader TLS",
        "C11-family completion",
        "pthread/TLS parity",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-c11-plain-sync description omits {phrase}",
        )

    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/atomic.rs",
        "libc/src/c_abi/x86_64/pthread_mutex.rs",
        "libc/src/c_abi/x86_64/pthread_cond.rs",
        "libc/src/c_abi/x86_64/c11_sync.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/bits/syscall.h",
        "include/errno.h",
        "include/features.h",
        "include/pthread.h",
        "include/threads.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/run_types_header_abi.sh",
        "compat/x86_64/run_libc_c11_lifecycle.sh",
        "compat/x86_64/run_libc_thrd_sleep.sh",
        "compat/x86_64/run_libc_pthread_cond_private.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_c11_plain_sync_probe.c",
        "compat/x86_64/libc_c11_plain_sync_start.S",
        "compat/x86_64/run_libc_c11_plain_sync.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(
            string_list(
                artifact["source_owners"],
                "static-c-c11-plain-sync source owners",
            )
        )
        == expected_sources,
        "static-c-c11-plain-sync source owners drifted",
    )

    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "mtx_init.c",
        "mtx_destroy.c",
        "mtx_lock.c",
        "mtx_trylock.c",
        "mtx_unlock.c",
        "cnd_init.c",
        "cnd_destroy.c",
        "cnd_wait.c",
        "cnd_signal.c",
        "cnd_broadcast.c",
        "mtx_timedlock.c",
        "cnd_timedwait.c",
        "40 bytes",
        "48 bytes",
        "8-byte alignment",
        "mtx_plain=0",
        "EBUSY=16",
        "thrd_busy=1",
        "futex=202",
        "FUTEX_WAIT_PRIVATE=128",
        "FUTEX_WAKE_PRIVATE=129",
        "FUTEX_REQUEUE_PRIVATE=131",
        "r10",
        "r8",
        "without changing C errno",
        "dynamic TLS",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-c11-plain-sync ABI prerequisites omit {phrase}",
        )

    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "threads.h",
        "pthread.h",
        "errno.h",
        "bits/alltypes.h",
        "bits/syscall.h",
        "distinct mtx_t/pthread_mutex_t",
        "cnd_t/pthread_cond_t",
        "40-byte/48-byte",
        "28-context C/C++",
        "mtx_init/mtx_destroy/mtx_lock/mtx_trylock/mtx_unlock",
        "cnd_init/cnd_destroy/cnd_wait/cnd_signal/cnd_broadcast",
        "unmangled C linkage",
        "does not claim all C11 headers or C11 runtime completion",
    ):
        require(
            phrase in header_text,
            f"static-c-c11-plain-sync header prerequisites omit {phrase}",
        )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-c11-plain-sync"},
        "static-c-c11-plain-sync must use the closed libc-c11-plain-sync command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "`-nostdlib -static` candidate",
        "mtx_plain initialization",
        "held thrd_busy trylock",
        "one-waiter cnd_signal",
        "two-waiter cnd_broadcast",
        "stale errno preservation",
        "quiescent destruction",
        "four bounded 64-handoff predicate ping-pong rounds",
        "Candidate-only recursive/timed mtx_init rejection",
        "exactly the ten selected C11 exports",
        "direct private sibling routing",
        "mtx lock cmpxchg",
        "unlock exchange/xchg",
        "futex=202",
        "FUTEX_WAIT_PRIVATE=128",
        "FUTEX_WAKE_PRIVATE=129",
        "FUTEX_REQUEUE_PRIVATE=131",
        "x86 r10/r8 requeue route",
        "no interpreter/DT_NEEDED/unresolved symbol",
        "cancellation, TSS, once",
        "family completion, promotion, and public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-c11-plain-sync evidence scope omits {phrase}",
        )

    static_exports = {
        line
        for line in (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text().splitlines()
        if line and not line.startswith("#")
    }
    selected_mutex_exports = {
        "mtx_init",
        "mtx_destroy",
        "mtx_lock",
        "mtx_trylock",
        "mtx_unlock",
    }
    selected_condition_exports = {
        "cnd_init",
        "cnd_destroy",
        "cnd_wait",
        "cnd_signal",
        "cnd_broadcast",
    }
    require(
        {symbol for symbol in static_exports if symbol.startswith("mtx_")}
        == selected_mutex_exports,
        "static-c-c11-plain-sync must expose exactly its five selected mtx symbols",
    )
    require(
        {symbol for symbol in static_exports if symbol.startswith("cnd_")}
        == selected_condition_exports,
        "static-c-c11-plain-sync must expose exactly its five selected cnd symbols",
    )
    require(
        "run_libc_c11_plain_sync.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-c11-plain-sync dispatcher binding is missing",
    )


def require_static_pthread_c11_once_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet one normal-return pthread/C11 once artifact without promotion.

    The private artifact deliberately shares only the selected static-worker,
    atomic, and raw-futex seams. It must not turn the normal-return 0/1/2/3
    control-word route into cancellation, fork, TSS, or pthread-family parity.
    """

    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-pthread-c11-once"
    ]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-pthread-c11-once artifact",
    )
    require(
        len(artifacts) == 14,
        "libc.pthread-tls must retain exactly fourteen private verified artifacts",
    )
    require(
        family.get("status") == "planned",
        "static-c-pthread-c11-once must not promote libc.pthread-tls",
    )

    family_description = family["description"]
    assert isinstance(family_description, str)
    for phrase in (
        "Fourteen separately verified static artifacts",
        "private normal-return pthread/C11 once state machine",
        "not pthread/TLS parity",
    ):
        require(
            phrase in family_description,
            f"libc.pthread-tls description omits {phrase} after the once artifact",
        )
    family_sources = string_list(
        family["source_owners"], "libc.pthread-tls source owners"
    )
    for owner in (
        "libc/src/c_abi/x86_64/pthread_once.rs",
        "compat/x86_64/libc_pthread_c11_once_probe.c",
        "compat/x86_64/libc_pthread_c11_once_start.S",
        "compat/x86_64/run_libc_pthread_c11_once.sh",
    ):
        require(
            owner in family_sources,
            f"libc.pthread-tls source owners omit {owner} after the once artifact",
        )
    family_abi_text = " ".join(
        string_list(
            family["x86_abi_prerequisites"],
            "libc.pthread-tls ABI prerequisites",
        )
    )
    for phrase in (
        "pthread_once.c::{__pthread_once,__pthread_once_full}",
        "call_once.c",
        "__wait.c::__wait",
        "pthread_impl.h::__wake",
        "selected state machine is 0 initial, 1 initializer, 2 complete, and 3 initializer-with-waiters",
        "INT_MAX",
        "does not establish musl's weak pthread_once ELF binding or exact ELF parity",
    ):
        require(
            phrase in family_abi_text,
            f"libc.pthread-tls ABI prerequisites omit {phrase} after the once artifact",
        )
    family_header_text = " ".join(
        string_list(
            family["x86_header_prerequisites"],
            "libc.pthread-tls header prerequisites",
        )
    )
    for phrase in (
        "pthread_once/call_once",
        "four-byte pthread_once_t/once_flag",
        "28-context C/C++",
    ):
        require(
            phrase in family_header_text,
            f"libc.pthread-tls header prerequisites omit {phrase} after the once artifact",
        )

    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `libc.pthread-tls`",
        "exactly `pthread_once` and `call_once`",
        "four-byte aligned `pthread_once_t`/`once_flag`",
        "all-zero static initializers",
        "0 initial, 1 initializer, 2 complete, and 3 initializer-with-waiters",
        "compare-exchange 0->1",
        "private-futex state-3 waiting",
        "release exchange to 2",
        "interposable pthread C ABI",
        "static/all-zero initialization",
        "exactly one normal-return initializer",
        "two contending workers",
        "relaxed payload/count observations without an independent release/acquire edge",
        "stale errno preservation",
        "cancellation cleanup/reset",
        "initializer pthread_exit/thrd_exit",
        "recursive same-control entry",
        "fork/atfork interaction",
        "TSS",
        "dynamic/loader TLS",
        "weak pthread_once ELF binding",
        "exact ELF parity",
        "family completion",
        "promotion",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-pthread-c11-once description omits {phrase}",
        )

    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/atomic.rs",
        "libc/src/c_abi/x86_64/pthread_once.rs",
        "libc/src/c_abi/x86_64/pthread_identity.rs",
        "libc/src/c_abi/x86_64/pthread_mutex.rs",
        "libc/src/c_abi/x86_64/pthread_cond.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/bits/syscall.h",
        "include/errno.h",
        "include/features.h",
        "include/pthread.h",
        "include/threads.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/run_types_header_abi.sh",
        "compat/x86_64/run_libc_pthread_mutex_normal.sh",
        "compat/x86_64/run_libc_c11_lifecycle.sh",
        "compat/x86_64/run_libc_thrd_sleep.sh",
        "compat/x86_64/run_libc_c11_plain_sync.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_pthread_c11_once_probe.c",
        "compat/x86_64/libc_pthread_c11_once_start.S",
        "compat/x86_64/run_libc_pthread_c11_once.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(
            string_list(
                artifact["source_owners"],
                "static-c-pthread-c11-once source owners",
            )
        )
        == expected_sources,
        "static-c-pthread-c11-once source owners drifted",
    )

    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "pthread_once.c::{__pthread_once,__pthread_once_full}",
        "call_once.c",
        "__wait.c::__wait",
        "pthread_impl.h::__wake",
        "four-byte align-4",
        "PTHREAD_ONCE_INIT=0",
        "ONCE_FLAG_INIT=0",
        "0 initial, 1 initializer, 2 complete, and 3 initializer-with-waiters",
        "compare-exchange claims 0->1",
        "release exchange publishes 2",
        "futex=202",
        "FUTEX_WAIT_PRIVATE=128",
        "FUTEX_WAKE_PRIVATE=129",
        "INT_MAX",
        "r10",
        "EAGAIN, EINTR",
        "without changing C errno",
        "interposable pthread C ABI",
        "cancellation reset",
        "dynamic TLS",
        "relaxed atomics only",
        "no independent release/acquire edge",
        "weak pthread_once ELF binding",
        "exact ELF parity",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-pthread-c11-once ABI prerequisites omit {phrase}",
        )

    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "pthread.h",
        "threads.h",
        "errno.h",
        "bits/alltypes.h",
        "bits/syscall.h",
        "four-byte align-4",
        "pthread_once_t/once_flag identity",
        "PTHREAD_ONCE_INIT/ONCE_FLAG_INIT",
        "pthread_once/call_once",
        "28-context C/C++",
        "unmangled C linkage",
        "does not claim broad installed-header, full C11, or pthread runtime completion",
    ):
        require(
            phrase in header_text,
            f"static-c-pthread-c11-once header prerequisites omit {phrase}",
        )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-pthread-c11-once"},
        "static-c-pthread-c11-once must use the closed libc-pthread-c11-once command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "`-nostdlib -static` candidate",
        "pthread_once/call_once static/all-zero initialization",
        "exactly one normal-return initializer",
        "two contending workers that reach state 3",
        "once publication of relaxed payload/count observations without an independent release/acquire edge",
        "stale errno preservation",
        "exactly the two selected once exports",
        "direct private shared-state routing",
        "interposable pthread call",
        "locked compare-exchange",
        "release exchange/xchg",
        "futex=202",
        "FUTEX_WAIT_PRIVATE=128",
        "FUTEX_WAKE_PRIVATE=129",
        "INT_MAX wake-all",
        "no interpreter/DT_NEEDED/unresolved symbol",
        "cancellation reset",
        "initializer pthread_exit/thrd_exit",
        "recursive same-control entry",
        "fork/atfork",
        "TSS",
        "weak pthread_once ELF binding or exact ELF parity",
        "family completion, promotion, and public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-pthread-c11-once evidence scope omits {phrase}",
        )

    oracle_entries = artifact["oracle"]
    assert isinstance(oracle_entries, list)
    source_oracles = [
        entry
        for entry in oracle_entries
        if isinstance(entry, dict) and entry.get("kind") == "c-posix"
    ]
    require(
        len(source_oracles) == 1,
        "static-c-pthread-c11-once must retain one pinned-musl C/POSIX/C11 oracle",
    )
    source_oracle = source_oracles[0]
    source = source_oracle.get("source")
    role = source_oracle.get("role")
    require(
        source
        == "Pinned musl 1.2.6 release commit 9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "static-c-pthread-c11-once musl oracle pin drifted",
    )
    require(
        isinstance(role, str)
        and "src/thread/pthread_once.c" in role
        and "src/thread/call_once.c" in role
        and "src/thread/__wait.c" in role
        and "src/internal/pthread_impl.h::__wake" in role,
        "static-c-pthread-c11-once musl source mapping omits __wake provenance",
    )

    static_exports = {
        line
        for line in (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text().splitlines()
        if line and not line.startswith("#")
    }
    selected_once_exports = {"pthread_once", "call_once"}
    require(
        selected_once_exports <= static_exports,
        "static-c-pthread-c11-once must expose pthread_once and call_once",
    )
    for unselected in ("__pthread_once", "__pthread_once_full"):
        require(
            unselected not in static_exports,
            f"static-c-pthread-c11-once must not expose private {unselected}",
        )
    require(
        "run_libc_pthread_c11_once.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-pthread-c11-once dispatcher binding is missing",
    )


def require_static_pthread_c11_tsd_artifact(family: Mapping[str, Any]) -> None:
    """Keep the selected pthread-key/C11-TSS lifecycle private and bounded.

    This artifact proves destructor ordering for the existing selected worker
    seam, not musl's global thread list, cancellation protocol, or general TSD
    behavior. Its count, source provenance, header ABI, and explicit
    exclusions must remain durable while the parent family remains planned.
    """

    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.pthread-tls].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-pthread-c11-tsd"
    ]
    require(
        len(matching) == 1,
        "libc.pthread-tls must contain exactly one static-c-pthread-c11-tsd artifact",
    )
    require(
        len(artifacts) == 14,
        "libc.pthread-tls must retain exactly fourteen private verified artifacts",
    )
    require(
        family.get("status") == "planned",
        "static-c-pthread-c11-tsd must not promote libc.pthread-tls",
    )

    family_description = family["description"]
    assert isinstance(family_description, str)
    for phrase in (
        "Fourteen separately verified static artifacts",
        "bounded private pthread-key/C11-TSS lifecycle table",
        "not pthread/TLS parity",
    ):
        require(
            phrase in family_description,
            f"libc.pthread-tls description omits {phrase} after the TSD artifact",
        )
    family_sources = string_list(
        family["source_owners"], "libc.pthread-tls source owners"
    )
    for owner in (
        "libc/src/c_abi/x86_64/pthread_tsd.rs",
        "compat/x86_64/libc_pthread_c11_tsd_probe.c",
        "compat/x86_64/libc_pthread_c11_tsd_start.S",
        "compat/x86_64/run_libc_pthread_c11_tsd.sh",
    ):
        require(
            owner in family_sources,
            f"libc.pthread-tls source owners omit {owner} after the TSD artifact",
        )
    family_abi_text = " ".join(
        string_list(
            family["x86_abi_prerequisites"],
            "libc.pthread-tls ABI prerequisites",
        )
    )
    for phrase in (
        "pthread_key_create.c::{__pthread_key_create,__pthread_key_delete,__pthread_tsd_run_dtors}",
        "pthread_getspecific.c::__pthread_getspecific",
        "pthread_setspecific.c::pthread_setspecific",
        "tss_create.c",
        "tss_delete.c",
        "tss_set.c",
        "pthread_create.c::{start,start_c11,__pthread_exit}",
        "PTHREAD_KEYS_MAX=128",
        "PTHREAD_DESTRUCTOR_ITERATIONS=TSS_DTOR_ITERATIONS=4",
        "main-thread process-exit destructors",
        "weak/same-address TSD aliases",
    ):
        require(
            phrase in family_abi_text,
            f"libc.pthread-tls ABI prerequisites omit {phrase} after the TSD artifact",
        )
    family_header_text = " ".join(
        string_list(
            family["x86_header_prerequisites"],
            "libc.pthread-tls header prerequisites",
        )
    )
    for phrase in (
        "limits.h",
        "pthread-key",
        "C11-TSS",
        "pthread_key_t",
        "tss_t",
        "PTHREAD_KEYS_MAX=128/TSS_DTOR_ITERATIONS=4",
    ):
        require(
            phrase in family_header_text,
            f"libc.pthread-tls header prerequisites omit {phrase} after the TSD artifact",
        )

    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "libc.pthread-tls",
        "pthread_key_create",
        "pthread_key_delete",
        "pthread_getspecific",
        "pthread_setspecific",
        "tss_create",
        "tss_delete",
        "tss_get",
        "tss_set",
        "private 128-key table",
        "permanent process-main value table",
        "null destructor still reserves a key",
        "deletion clears only those selected tables without a callback",
        "four ascending-key passes",
        "before join-result publication or",
        "SYS_exit",
        "128-key exhaustion/reuse",
        "fourth-pass rearming",
        "Invalid/deleted keys and non-selected callers deliberately fail closed",
        "bootstrapped `%fs:0` plus Linux TID pair",
        "weak/same-address TSD aliases",
        "exact ELF parity",
        "main-thread process-exit destructors",
        "foreign threads",
        "cancellation and cleanup handlers",
        "concurrent key-deletion/destructor interaction",
        "fork/atfork",
        "dynamic or loader TLS/DTV",
        "general TCB or all-thread list",
        "full pthread/TLS or x86-64 parity",
        "promotion",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-pthread-c11-tsd description omits {phrase}",
        )

    expected_sources = {
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/pthread_tsd.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/pthread_identity.rs",
        "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "include/bits/alltypes.h",
        "include/bits/syscall.h",
        "include/errno.h",
        "include/features.h",
        "include/limits.h",
        "include/pthread.h",
        "include/threads.h",
        "compat/x86_64/pthread_c11_header_abi_probe.c",
        "compat/x86_64/pthread_c11_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_c11_header_abi.sh",
        "compat/x86_64/run_types_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_pthread_c11_tsd_probe.c",
        "compat/x86_64/libc_pthread_c11_tsd_start.S",
        "compat/x86_64/run_libc_pthread_c11_tsd.sh",
        "compat/x86_64/run_libc_static_tls_v1.sh",
        "compat/x86_64/run_libc_pthread_create_join_tls.sh",
        "compat/x86_64/run_libc_c11_lifecycle.sh",
        "compat/x86_64/run_libc_thrd_sleep.sh",
        "compat/x86_64/run_libc_pthread_cond_private.sh",
        "compat/x86_64/run_libc_c11_plain_sync.sh",
        "compat/x86_64/run_libc_pthread_c11_once.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "STATUS.md",
        "x86-64.md",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    }
    require(
        set(
            string_list(
                artifact["source_owners"],
                "static-c-pthread-c11-tsd source owners",
            )
        )
        == expected_sources,
        "static-c-pthread-c11-tsd source owners drifted",
    )

    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    prerequisite_text = " ".join(prerequisites)
    for phrase in (
        "pthread_key_create.c::{__pthread_key_create,__pthread_key_delete,__pthread_tsd_run_dtors}",
        "pthread_getspecific.c::__pthread_getspecific",
        "pthread_setspecific.c::pthread_setspecific",
        "tss_create.c",
        "tss_delete.c",
        "tss_set.c",
        "pthread_create.c::{start,start_c11,__pthread_exit}",
        "pthread_key_t and tss_t type-identical 32-bit keys",
        "PTHREAD_KEYS_MAX=128",
        "PTHREAD_DESTRUCTOR_ITERATIONS=4",
        "TSS_DTOR_ITERATIONS=4",
        "null-destructor key",
        "EAGAIN",
        "thrd_error",
        "process-main table",
        "bootstrapped `%fs:0` plus Linux gettid identity",
        "without calling the old destructor",
        "before result publication and SYS_exit",
        "clears a non-null value before",
        "drops the metadata lock across the callback",
        "fourth-pass rearm remains stored",
        "invalid/deleted keys and non-selected callers",
        "main-thread process-exit destructors",
        "foreign thread registration",
        "cancellation/cleanup",
        "concurrent key-deletion/destructor interaction",
        "fork/atfork",
        "dynamic/loader TLS/DTV",
        "general TCB layout",
        "weak/same-address TSD aliases",
        "exact ELF parity",
        "clone=56",
        "SYS_exit=60",
        "no direct allocator",
    ):
        require(
            phrase in prerequisite_text,
            f"static-c-pthread-c11-tsd ABI prerequisites omit {phrase}",
        )

    header_prerequisites = artifact["x86_header_prerequisites"]
    assert isinstance(header_prerequisites, list)
    header_text = " ".join(header_prerequisites)
    for phrase in (
        "pthread.h",
        "threads.h",
        "limits.h",
        "errno.h",
        "bits/alltypes.h",
        "bits/syscall.h",
        "pthread_key_t/tss_t identity",
        "PTHREAD_KEYS_MAX=128",
        "PTHREAD_DESTRUCTOR_ITERATIONS=TSS_DTOR_ITERATIONS=4",
        "all eight exact function-pointer declarations",
        "28-context C/C++",
        "pthread_key_create/pthread_key_delete/pthread_getspecific/pthread_setspecific",
        "tss_create/tss_delete/tss_get/tss_set",
        "unmangled C linkage",
        "does not claim a broad installed header, general TSD, full C11, or pthread runtime completion",
    ):
        require(
            phrase in header_text,
            f"static-c-pthread-c11-tsd header prerequisites omit {phrase}",
        )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-pthread-c11-tsd"},
        "static-c-pthread-c11-tsd must use the closed libc-pthread-c11-tsd command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "Pinned-musl project-header C reference",
        "-nostdlib -static",
        "selected main/worker value isolation",
        "all 128 keys occupied with a null destructor and EAGAIN exhaustion",
        "deletion clears a waiting worker's old slot",
        "runs no old destructor",
        "replacement key in that numeric slot",
        "normal pthread return, pthread_exit, C11 return, and thrd_exit",
        "four clear-before-callback rearming destructor passes",
        "before their join result",
        "preserves caller errno",
        "without the private metadata lock",
        "exactly the eight selected TSD exports",
        "32-bit pthread_key_t/tss_t identity",
        "128/4 header constants",
        "direct private sibling routing and exit ordering",
        "no interpreter/DT_NEEDED/unresolved symbol",
        "dynamic TLS resolver",
        "allocator",
        "ambient runtime",
        "main-thread process-exit destructors",
        "foreign threads",
        "cancellation/cleanup",
        "concurrent deletion/destructor interaction",
        "fork/atfork",
        "dynamic/loader TLS/DTV",
        "general TCB/list or pthread/C11 behavior",
        "weak/same-address TSD alias or exact ELF parity",
        "family completion, promotion, and public x86 support",
    ):
        require(
            phrase in scope,
            f"static-c-pthread-c11-tsd evidence scope omits {phrase}",
        )

    oracle_entries = artifact["oracle"]
    assert isinstance(oracle_entries, list)
    source_oracles = [
        entry
        for entry in oracle_entries
        if isinstance(entry, dict) and entry.get("kind") == "c-posix"
    ]
    require(
        len(source_oracles) == 1,
        "static-c-pthread-c11-tsd must retain one pinned-musl C/POSIX/C11 oracle",
    )
    source_oracle = source_oracles[0]
    source = source_oracle.get("source")
    role = source_oracle.get("role")
    require(
        source
        == "Pinned musl 1.2.6 release commit 9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "static-c-pthread-c11-tsd musl oracle pin drifted",
    )
    require(
        isinstance(role, str)
        and "src/thread/pthread_key_create.c" in role
        and "pthread_getspecific.c" in role
        and "pthread_setspecific.c" in role
        and "tss_create.c" in role
        and "tss_delete.c" in role
        and "tss_set.c" in role
        and "pthread_create.c::{start,start_c11,__pthread_exit}" in role,
        "static-c-pthread-c11-tsd musl source mapping omits lifecycle provenance",
    )

    static_exports = {
        line
        for line in (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text().splitlines()
        if line and not line.startswith("#")
    }
    selected_tsd_exports = {
        "pthread_key_create",
        "pthread_key_delete",
        "pthread_getspecific",
        "pthread_setspecific",
        "tss_create",
        "tss_delete",
        "tss_get",
        "tss_set",
    }
    require(
        selected_tsd_exports <= static_exports,
        "static-c-pthread-c11-tsd must expose its eight selected TSD symbols",
    )
    for unselected in (
        "__pthread_key_create",
        "__pthread_key_delete",
        "__pthread_tsd_run_dtors",
    ):
        require(
            unselected not in static_exports,
            f"static-c-pthread-c11-tsd must not expose private {unselected}",
        )
    require(
        "run_libc_pthread_c11_tsd.sh"
        in (ROOT / "scripts" / "dev-x86_64.sh").read_text(),
        "static-c-pthread-c11-tsd dispatcher binding is missing",
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


def require_system_information_artifact(family: Mapping[str, Any]) -> None:
    """Keep the processor/page-count C artifact bounded and source-derived."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-system-information"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-system-information artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "processor/page-count",
        "`get_nprocs_conf`",
        "`get_nprocs`",
        "`get_phys_pages`",
        "`get_avphys_pages`",
        "128-byte",
        "`sched_getaffinity`",
        "CPU-zero",
        "wrapping LP64",
        "LONG_MAX",
        "`getloadavg`",
        "general `sysconf`",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-system-information description omits {phrase}",
        )
    owners = set(artifact["source_owners"])
    for owner in (
        "libc/src/c_abi/x86_64/system_observation.rs",
        "libc/src/c_abi/x86_64/system_configuration.rs",
        "libc/src/c_abi/x86_64/system_information.rs",
        "compat/x86_64/system_header_abi_probe.c",
        "compat/x86_64/system_header_abi_probe.cpp",
        "compat/x86_64/run_system_header_abi.sh",
        "compat/x86_64/libc_system_information_probe.c",
        "compat/x86_64/libc_system_information_start.S",
        "compat/x86_64/run_libc_system_information.sh",
    ):
        require(
            owner in owners,
            f"static-c-system-information must own {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "sched_getaffinity=204" in item
            and "128-byte" in item
            and "rdi/rsi/rdx" in item
            for item in prerequisites
        ),
        "static-c-system-information must record the fixed affinity-mask ABI",
    )
    require(
        any(
            "wrapping_add" in item
            and "wrapping_mul" in item
            and "LONG_MAX" in item
            for item in prerequisites
        ),
        "static-c-system-information must record musl's wrapping page arithmetic",
    )
    require(
        any(
            "uninitialized C sysinfo" in item and "returns -1" in item
            for item in prerequisites
        ),
        "static-c-system-information must record the failed-page-query boundary",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-system-information"},
        "static-c-system-information must use the closed libc-system-information command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "sched_getaffinity=204",
        "sysinfo=99",
        "PR_SET_NO_NEW_PRIVS",
        "CPU helpers return one",
    ):
        require(
            phrase in scope,
            f"static-c-system-information evidence scope omits {phrase}",
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


def require_filesystem_access_artifact(family: Mapping[str, Any]) -> None:
    """Keep the selected C access boundary separate from filesystem parity."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-filesystem-access"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-filesystem-access artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in FILESYSTEM_ACCESS_SYMBOLS:
        require(
            f"`{symbol}`" in description,
            f"static-c-filesystem-access description omits {symbol}",
        )
    for phrase in (
        "filesystem-access block",
        "access=21",
        "faccessat=269",
        "faccessat2=439",
        "same-address",
        "weak",
        "real versus effective",
        "fchmodat/lchmod",
        "does not select",
    ):
        require(
            phrase in description,
            f"static-c-filesystem-access description omits {phrase}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any("access=21" in item and "real IDs" in item and "rdi/rsi" in item for item in prerequisites),
        "static-c-filesystem-access must record its access real-ID register ABI",
    )
    require(
        any(
            "faccessat=269" in item
            and "faccessat2=439" in item
            and "rdi/rsi/rdx/r10" in item
            and "ENOSYS fallback" in item
            for item in prerequisites
        ),
        "static-c-filesystem-access must record its legacy/faccessat2 register and fallback boundary",
    )
    require(
        any(
            "AT_EACCESS" in item and "same-address ELF alias" in item
            for item in prerequisites
        ),
        "static-c-filesystem-access must record its euidaccess/eaccess alias contract",
    )
    headers = artifact["x86_header_prerequisites"]
    assert isinstance(headers, list)
    require(
        any("eight-profile" in item and "GNU-only" in item for item in headers),
        "static-c-filesystem-access must retain its access header feature matrix",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-access"},
        "static-c-filesystem-access must use the closed libc-access command",
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


def require_fcntl_record_locks_artifact(family: Mapping[str, Any]) -> None:
    """Keep selected pointer-bearing fcntl record locks separate and bounded."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-fcntl-record-locks"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-fcntl-record-locks artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "nonblocking fcntl record-lock block",
        "F_GETLK",
        "F_SETLK",
        "32-byte x86 `struct flock`",
        "EACCES/EAGAIN",
        "F_SETLKW cancellation",
        "OFD locks",
        "lockf",
        "flock",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-fcntl-record-locks description omits {phrase}",
        )
    owners = set(artifact["source_owners"])
    for owner in (
        "libc/src/c_abi/x86_64/descriptor_control.rs",
        "libc/src/c_abi/x86_64/record_locks.rs",
        "compat/x86_64/fcntl_header_abi_probe.c",
        "compat/x86_64/fcntl_header_abi_probe.cpp",
        "compat/x86_64/run_fcntl_header_abi.sh",
        "compat/x86_64/run_x86_fcntl_getlk_reference.sh",
        "compat/x86_64/x86_fcntl_getlk_reference_probe.c",
        "compat/x86_64/libc_fcntl_record_locks_probe.c",
        "compat/x86_64/libc_fcntl_record_locks_start.S",
        "compat/x86_64/run_libc_fcntl_record_locks.sh",
    ):
        require(
            owner in owners,
            f"static-c-fcntl-record-locks must own {owner}",
        )
    prerequisites = artifact["x86_abi_prerequisites"]
    assert isinstance(prerequisites, list)
    require(
        any(
            "fcntl=72" in item
            and "rdi/rsi/rdx" in item
            and "F_GETLK=5" in item
            and "F_SETLK=6" in item
            for item in prerequisites
        ),
        "static-c-fcntl-record-locks must record its pointer-vararg register ABI",
    )
    require(
        any(
            "32-byte align-8" in item
            and "offsets 0/2" in item
            and "F_UNLCK" in item
            and "EACCES or EAGAIN" in item
            for item in prerequisites
        ),
        "static-c-fcntl-record-locks must record the x86 flock layout and conflict boundary",
    )
    require(
        any(
            "src/fcntl/fcntl.c" in item
            and "F_SETLKW" in item
            and "__syscall_cp" in item
            for item in prerequisites
        ),
        "static-c-fcntl-record-locks must record its musl cancellation exclusion",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-fcntl-record-locks"},
        "static-c-fcntl-record-locks must use the closed libc-fcntl-record-locks command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "F_GETLK=5/F_SETLK=6",
        "fcntl=72",
        "parent-write-lock child observation",
        "EACCES/EAGAIN",
        "F_SETLKW cancellation",
    ):
        require(
            phrase in scope,
            f"static-c-fcntl-record-locks evidence scope omits {phrase}",
        )


def require_generic_ioctl_artifact(family: Mapping[str, Any]) -> None:
    """Keep the generic ioctl ABI forwarder bounded despite its broad spelling."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-generic-ioctl"]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-generic-ioctl artifact",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "generic ioctl block",
        "signed-int variadic `ioctl` entry",
        "`FIOCLEX`",
        "`FIONCLEX`",
        "three-word pointer-or-integer forwarding path",
        "`FIONREAD`",
        "`FIONBIO`",
        "`EBADF`",
        "does not establish generic device/request behavior",
        "public x86 support",
    ):
        require(phrase in description, f"static-c-generic-ioctl description omits {phrase}")

    owners = set(
        nonempty_strings(artifact["source_owners"], "static-c-generic-ioctl.source_owners")
    )
    for owner in (
        "compat/upstreams.toml",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/ioctl.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "include/sys/ioctl.h",
        "compat/x86_64/ioctl_header_abi_probe.c",
        "compat/x86_64/ioctl_header_abi_probe.cpp",
        "compat/x86_64/run_ioctl_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_ioctl_probe.c",
        "compat/x86_64/libc_ioctl_start.S",
        "compat/x86_64/run_libc_ioctl.sh",
    ):
        require(owner in owners, f"static-c-generic-ioctl source owners omit {owner}")

    prerequisites = nonempty_strings(
        artifact["x86_abi_prerequisites"], "static-c-generic-ioctl.x86_abi_prerequisites"
    )
    require(
        any(
            "ioctl=16" in item
            and "rdi/rsi" in item
            and "rdx" in item
            and "int ioctl(int, int, ...)" in item
            and "low 32 bits" in item
            for item in prerequisites
        ),
        "static-c-generic-ioctl must record its signed-int SysV/Linux ABI",
    )
    require(
        any(
            "src/misc/ioctl.c" in item
            and "FIOCLEX=0x5451" in item
            and "FIONCLEX=0x5450" in item
            and "rdx=0" in item
            and "three-word path" in item
            for item in prerequisites
        ),
        "static-c-generic-ioctl must record its safe no-vararg boundary",
    )
    require(
        any(
            "FIONREAD=0x541b" in item
            and "FIONBIO=0x5421" in item
            and "fcntl=72" in item
            and "initial-TLS errno" in item
            for item in prerequisites
        ),
        "static-c-generic-ioctl must record selected request behavior and errno",
    )
    require(
        any("Private Static Initial TLS v1 bootstrap" in item for item in prerequisites),
        "static-c-generic-ioctl must record its static-TLS prerequisite",
    )

    header_prerequisites = nonempty_strings(
        artifact["x86_header_prerequisites"], "static-c-generic-ioctl.x86_header_prerequisites"
    )
    require(
        any(
            "seven-profile" in item
            and "signed int variadic declaration" in item
            and "unmangled C++ declaration reference" in item
            and "_IOC" in item
            and "not a complete ioctl header" in item
            for item in header_prerequisites
        ),
        "static-c-generic-ioctl must record its direct header boundary",
    )

    static_exports = static_c_abi_export_names(
        ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
    )
    require(
        "ioctl" in static_exports,
        "static-c-generic-ioctl must be included in the selected static export ratchet",
    )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence} == {"./scripts/dev-x86_64.sh libc-ioctl"},
        "static-c-generic-ioctl must use the closed libc-ioctl command",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "FIOCLEX/FIONCLEX rdx=0 dispatch",
                "three-word ioctl=16 path",
                "FIONREAD pointer output",
                "FIONBIO pointer input",
                "generic device/request behavior",
                "public x86 support",
            )
        ),
        "static-c-generic-ioctl evidence must retain its bounded runtime boundary",
    )


def require_sysv_semaphore_artifact(family: Mapping[str, Any]) -> None:
    """Keep the selected variadic SysV-semaphore ABI boundary private and exact."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-sysv-semaphore"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-sysv-semaphore artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-sysv-semaphore must not promote libc.posix-runtime",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in SYSV_SEMAPHORE_SYMBOLS:
        require(
            f"`{symbol}`" in description,
            f"static-c-sysv-semaphore description omits {symbol}",
        )
    for phrase in (
        "SysV semaphore block",
        "variadic `semctl`",
        "`union semun`",
        "no-vararg",
        "SysV message queues",
        "shared memory",
        "POSIX semaphores",
        "SEM_UNDO",
        "cancellation",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-sysv-semaphore description omits {phrase}",
        )

    owners = set(
        nonempty_strings(artifact["source_owners"], "static-c-sysv-semaphore.source_owners")
    )
    for owner in (
        "compat/upstreams.toml",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/sysv_semaphore.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "include/errno.h",
        "include/sys/ipc.h",
        "include/sys/prctl.h",
        "include/sys/sem.h",
        "include/sys/syscall.h",
        "include/sys/types.h",
        "include/time.h",
        "include/bits/alltypes.h",
        "include/bits/syscall.h",
        "compat/x86_64/sysv_semaphore_header_abi_probe.c",
        "compat/x86_64/sysv_semaphore_header_abi_probe.cpp",
        "compat/x86_64/run_sysv_semaphore_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_sysv_semaphore_probe.c",
        "compat/x86_64/libc_sysv_semaphore_start.S",
        "compat/x86_64/run_libc_sysv_semaphore.sh",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/dev-x86_64.sh",
    ):
        require(owner in owners, f"static-c-sysv-semaphore source owners omit {owner}")

    prerequisites = nonempty_strings(
        artifact["x86_abi_prerequisites"], "static-c-sysv-semaphore.x86_abi_prerequisites"
    )
    require(
        any(
            "semget=64" in item
            and "semop=65" in item
            and "semctl=66" in item
            and "semtimedop=220" in item
            and "rdi/rsi/rdx" in item
            and "r10" in item
            for item in prerequisites
        ),
        "static-c-sysv-semaphore must record its Linux syscall register ABI",
    )
    require(
        any(
            "union semun" in item
            and "_SEM_SEMUN_UNDEFINED" in item
            and "INTEGER-class eightbyte" in item
            and "rcx" in item
            and "r10" in item
            for item in prerequisites
        ),
        "static-c-sysv-semaphore must record its semctl union register ABI",
    )
    require(
        any(
            "arch/x86_64/syscall_arch.h" in item
            and "src/ipc/ipc.h" in item
            and "`IPC_64=0`" in item
            and "`IPC_TIME64=0`" in item
            and "`IPC_CMD(cmd)=((cmd & ~IPC_TIME64) | IPC_64)=cmd`" in item
            and "no `0x100` marker" in item
            for item in prerequisites
        ),
        "static-c-sysv-semaphore must record exact musl x86_64 semctl IPC_CMD normalization",
    )
    require(
        any(
            "all nine union-consuming commands" in item
            and all(
                f"`{command}`" in item for command in SYSV_SEMAPHORE_UNION_COMMANDS
            )
            and "every other command" in item
            and all(command in item for command in SYSV_SEMAPHORE_NO_ARGUMENT_COMMANDS)
            and "unknown command values" in item
            and "explicit zero" in item
            and "rcx=0" in item
            and "absent C vararg" in item
            for item in prerequisites
        ),
        "static-c-sysv-semaphore must record exact semctl union/no-vararg command dispatch",
    )

    headers = nonempty_strings(
        artifact["x86_header_prerequisites"],
        "static-c-sysv-semaphore.x86_header_prerequisites",
    )
    require(
        any(
            "eight-profile" in item
            and "sys/sem.h" in item
            and "sys/ipc.h" in item
            and "sys/prctl.h" in item
            and "GNU-only" in item
            and "semtimedop" in item
            and "unmangled C++" in item
            for item in headers
        ),
        "static-c-sysv-semaphore must record its direct SysV semaphore header boundary",
    )

    static_exports = set(
        static_c_abi_export_names(
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        )
    )
    selected = set(SYSV_SEMAPHORE_SYMBOLS)
    require(
        selected <= static_exports,
        "static-c-sysv-semaphore must retain its four selected exports",
    )
    require(
        not (static_exports & set(SYSV_SEMAPHORE_UNSELECTED_SYMBOLS)),
        "static-c-sysv-semaphore must not add unselected SysV IPC or POSIX semaphore exports",
    )

    oracle = artifact["oracle"]
    assert isinstance(oracle, list)
    require(
        any(
            isinstance(entry, Mapping)
            and entry.get("kind") == "c-posix"
            and isinstance(entry.get("role"), str)
            and all(
                source in entry["role"]
                for source in (
                    "src/ipc/semget.c",
                    "src/ipc/semop.c",
                    "semtimedop.c",
                    "semctl.c",
                    "src/ipc/ipc.h",
                    "arch/x86_64/syscall_arch.h",
                )
            )
            for entry in oracle
        ),
        "static-c-sysv-semaphore must retain its pinned-musl SysV semaphore and IPC_CMD source mapping",
    )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-sysv-semaphore"},
        "static-c-sysv-semaphore must use the closed libc-sysv-semaphore command",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "semget",
                "semop",
                "semtimedop",
                "semctl",
                "union semun",
                "no-vararg",
                "IPC_CMD(cmd)=cmd",
                "all nine",
                "executable poisoned-rcx unknown-command regression",
                "explicit zero fourth word",
                "SEM_UNDO",
                "public x86 support",
            )
        ),
        "static-c-sysv-semaphore evidence must retain its exact variadic IPC_CMD runtime regression",
    )


def require_sysv_message_shared_memory_artifact(family: Mapping[str, Any]) -> None:
    """Keep the selected SysV message/shared-memory artifact private and exact."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-sysv-message-shared-memory"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-sysv-message-shared-memory artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-sysv-message-shared-memory must not promote libc.posix-runtime",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in SYSV_MESSAGE_SHARED_MEMORY_SYMBOLS:
        require(
            f"`{symbol}`" in description,
            f"static-c-sysv-message-shared-memory description omits {symbol}",
        )
    for phrase in (
        "SysV message/shared-memory block",
        "message queues",
        "shared memory",
        "POSIX message queues",
        "cancellation",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-sysv-message-shared-memory description omits {phrase}",
        )

    owners = set(
        nonempty_strings(
            artifact["source_owners"],
            "static-c-sysv-message-shared-memory.source_owners",
        )
    )
    for owner in (
        "compat/upstreams.toml",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/stat_compat.rs",
        "libc/src/c_abi/x86_64/sysv_message_shared_memory.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "include/errno.h",
        "include/features.h",
        "include/stdint.h",
        "include/sys/ipc.h",
        "include/sys/msg.h",
        "include/sys/prctl.h",
        "include/sys/shm.h",
        "include/sys/stat.h",
        "include/sys/syscall.h",
        "include/sys/types.h",
        "include/bits/alltypes.h",
        "include/bits/stat.h",
        "include/bits/syscall.h",
        "compat/x86_64/sysv_message_shared_memory_header_abi_probe.c",
        "compat/x86_64/sysv_message_shared_memory_header_abi_probe.cpp",
        "compat/x86_64/run_sysv_message_shared_memory_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_sysv_message_shared_memory_probe.c",
        "compat/x86_64/libc_sysv_message_shared_memory_start.S",
        "compat/x86_64/run_libc_sysv_message_shared_memory.sh",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/dev-x86_64.sh",
    ):
        require(
            owner in owners,
            f"static-c-sysv-message-shared-memory source owners omit {owner}",
        )

    prerequisites = nonempty_strings(
        artifact["x86_abi_prerequisites"],
        "static-c-sysv-message-shared-memory.x86_abi_prerequisites",
    )
    require(
        any(
            "msgget=68" in item
            and "msgsnd=69" in item
            and "msgrcv=70" in item
            and "msgctl=71" in item
            and "shmget=29" in item
            and "shmat=30" in item
            and "shmdt=67" in item
            and "shmctl=31" in item
            and "r10" in item
            and "r8" in item
            for item in prerequisites
        ),
        "static-c-sysv-message-shared-memory must record its Linux syscall register ABI",
    )
    require(
        any(
            "src/ipc/ftok.c" in item
            and "st_ino" in item
            and "st_dev" in item
            and "project-id" in item
            for item in prerequisites
        ),
        "static-c-sysv-message-shared-memory must record the ftok source formula",
    )
    require(
        any(
            "arch/x86_64/syscall_arch.h" in item
            and "src/ipc/ipc.h" in item
            and "`IPC_64=0`" in item
            and "`IPC_TIME64=0`" in item
            and "`IPC_CMD(cmd)=((cmd & ~IPC_TIME64) | IPC_64)=cmd`" in item
            and "no `0x100` marker" in item
            for item in prerequisites
        ),
        "static-c-sysv-message-shared-memory must record exact musl x86 IPC_CMD normalization",
    )
    require(
        any(
            "PTRDIFF_MAX" in item
            and "SIZE_MAX" in item
            and "shmget" in item
            and "MAP_FAILED" in item
            and "(void *)-1" in item
            and "shmat" in item
            for item in prerequisites
        ),
        "static-c-sysv-message-shared-memory must record musl shmget and shmat behavior",
    )
    require(
        any(
            "msgsnd" in item
            and "msgrcv" in item
            and "cancellation" in item
            and "direct static leaf" in item
            for item in prerequisites
        ),
        "static-c-sysv-message-shared-memory must record its cancellation boundary",
    )

    headers = nonempty_strings(
        artifact["x86_header_prerequisites"],
        "static-c-sysv-message-shared-memory.x86_header_prerequisites",
    )
    require(
        any(
            "eight-profile" in item
            and "sys/ipc.h" in item
            and "sys/msg.h" in item
            and "sys/shm.h" in item
            and "msgbuf" in item
            and "GNU-only" in item
            and "unmangled C++" in item
            for item in headers
        ),
        "static-c-sysv-message-shared-memory must record its direct SysV header boundary",
    )

    static_exports = set(
        static_c_abi_export_names(
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        )
    )
    require(
        set(SYSV_MESSAGE_SHARED_MEMORY_SYMBOLS) <= static_exports,
        "static-c-sysv-message-shared-memory must retain its nine selected exports",
    )
    require(
        not (static_exports & set(SYSV_MESSAGE_SHARED_MEMORY_UNSELECTED_SYMBOLS)),
        "static-c-sysv-message-shared-memory must not add unselected POSIX IPC or semaphore exports",
    )

    oracle = artifact["oracle"]
    assert isinstance(oracle, list)
    require(
        any(
            isinstance(entry, Mapping)
            and entry.get("kind") == "c-posix"
            and isinstance(entry.get("role"), str)
            and all(
                source in entry["role"]
                for source in (
                    "src/ipc/ftok.c",
                    "src/ipc/msgget.c",
                    "msgsnd.c",
                    "msgrcv.c",
                    "msgctl.c",
                    "src/ipc/shmget.c",
                    "shmat.c",
                    "shmdt.c",
                    "shmctl.c",
                    "src/ipc/ipc.h",
                    "arch/x86_64/syscall_arch.h",
                )
            )
            for entry in oracle
        ),
        "static-c-sysv-message-shared-memory must retain its pinned-musl IPC source mapping",
    )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-sysv-message-shared-memory"},
        "static-c-sysv-message-shared-memory must use the closed libc-sysv-message-shared-memory command",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "ftok",
                "message queue",
                "shared-memory",
                "r10/r8",
                "PTRDIFF_MAX",
                "MAP_FAILED",
                "cancellation",
                "public x86 support",
            )
        ),
        "static-c-sysv-message-shared-memory evidence must retain its exact static IPC runtime regression",
    )


def require_event_descriptors_artifact(family: Mapping[str, Any]) -> None:
    """Keep the selected static C event-descriptor boundary private and exact."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-event-descriptors"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-event-descriptors artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-event-descriptors must not promote libc.posix-runtime",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in EVENT_DESCRIPTOR_SYMBOLS:
        require(
            f"`{symbol}`" in description,
            f"static-c-event-descriptors description omits {symbol}",
        )
    for phrase in (
        "event-descriptor block",
        "epoll_pwait2",
        "timerfd",
        "signalfd",
        "fanotify",
        "AIO",
        "cancellation",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-event-descriptors description omits {phrase}",
        )

    owners = set(
        nonempty_strings(
            artifact["source_owners"], "static-c-event-descriptors.source_owners"
        )
    )
    for owner in (
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/event_descriptors.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "include/errno.h",
        "include/fcntl.h",
        "include/signal.h",
        "include/stdint.h",
        "include/sys/epoll.h",
        "include/sys/eventfd.h",
        "include/sys/inotify.h",
        "include/sys/prctl.h",
        "include/sys/syscall.h",
        "include/sys/types.h",
        "include/unistd.h",
        "include/bits/alltypes.h",
        "include/bits/syscall.h",
        "compat/x86_64/epoll_header_abi_probe.c",
        "compat/x86_64/epoll_header_abi_probe.cpp",
        "compat/x86_64/run_epoll_header_abi.sh",
        "compat/x86_64/event_descriptors_header_abi_probe.c",
        "compat/x86_64/event_descriptors_header_abi_probe.cpp",
        "compat/x86_64/run_event_descriptors_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_event_descriptors_probe.c",
        "compat/x86_64/libc_event_descriptors_start.S",
        "compat/x86_64/run_libc_event_descriptors.sh",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    ):
        require(
            owner in owners,
            f"static-c-event-descriptors source owners omit {owner}",
        )

    prerequisites = nonempty_strings(
        artifact["x86_abi_prerequisites"],
        "static-c-event-descriptors.x86_abi_prerequisites",
    )
    require(
        any(
            "epoll_create1=291" in item
            and "epoll_ctl=233" in item
            and "epoll_pwait=281" in item
            and "eventfd2=290" in item
            and "inotify_init1=294" in item
            and "inotify_add_watch=254" in item
            and "inotify_rm_watch=255" in item
            and "rdi/rsi/rdx/r10/r8/r9" in item
            for item in prerequisites
        ),
        "static-c-event-descriptors must record its Linux syscall register ABI",
    )
    require(
        any(
            "12-byte align-1" in item
            and "events at offset 0" in item
            and "data union at offset 4" in item
            and "eight-byte kernel sigset" in item
            and "r8 signal-mask pointer" in item
            and "r9" in item
            for item in prerequisites
        ),
        "static-c-event-descriptors must record packed epoll and signal-mask ABI",
    )
    require(
        any(
            "eventfd_t" in item
            and "read=0/write=1" in item
            and "exactly eight bytes" in item
            and "positive short" in item
            and "-1 without manufacturing errno" in item
            for item in prerequisites
        ),
        "static-c-event-descriptors must record exact eventfd transfer behavior",
    )
    require(
        any(
            "16-byte align-4" in item
            and "wd/mask/cookie/len at 0/4/8/12" in item
            and "name at 16" in item
            and "caller-owned" in item
            for item in prerequisites
        ),
        "static-c-event-descriptors must record the x86 inotify record ABI",
    )
    require(
        any(
            "src/linux/epoll.c, eventfd.c, and inotify.c" in item
            and "Linux 5.10" in item
            and "ENOSYS" in item
            for item in prerequisites
        ),
        "static-c-event-descriptors must record its pinned-musl source mapping and no-ENOSYS boundary",
    )
    require(
        any(
            "cancellation" in item and "direct static leaf" in item
            for item in prerequisites
        ),
        "static-c-event-descriptors must record its cancellation boundary",
    )
    require(
        any(
            "PT_TLS errno datum" in item
            and "initial-exec TPOFF" in item
            and "__tls_get_addr" in item
            for item in prerequisites
        ),
        "static-c-event-descriptors must record its static TLS boundary",
    )

    headers = nonempty_strings(
        artifact["x86_header_prerequisites"],
        "static-c-event-descriptors.x86_header_prerequisites",
    )
    require(
        any(
            "seven-profile" in item
            and "sys/epoll.h" in item
            and "eight-profile" in item
            and "sys/eventfd.h" in item
            and "sys/inotify.h" in item
            and "unmangled C++" in item
            for item in headers
        ),
        "static-c-event-descriptors must record its direct event-descriptor header boundary",
    )

    static_exports = set(
        static_c_abi_export_names(
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        )
    )
    require(
        set(EVENT_DESCRIPTOR_SYMBOLS) <= static_exports,
        "static-c-event-descriptors must retain its twelve selected exports",
    )
    require(
        not (static_exports & set(EVENT_DESCRIPTOR_UNSELECTED_SYMBOLS)),
        "static-c-event-descriptors must not add unselected event-descriptor exports",
    )

    oracle = artifact["oracle"]
    assert isinstance(oracle, list)
    require(
        any(
            isinstance(entry, Mapping)
            and entry.get("kind") == "c-posix"
            and isinstance(entry.get("role"), str)
            and all(
                source in entry["role"]
                for source in (
                    "src/linux/epoll.c",
                    "src/linux/eventfd.c",
                    "src/linux/inotify.c",
                )
            )
            and "no-ENOSYS" in entry["role"]
            and "cancellation" in entry["role"]
            for entry in oracle
        ),
        "static-c-event-descriptors must retain its pinned-musl event source mapping",
    )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-event-descriptors"},
        "static-c-event-descriptors must use the closed libc-event-descriptors command",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "epoll_create1=291",
                "epoll_ctl=233",
                "epoll_pwait=281",
                "eventfd2=290",
                "inotify_init1=294",
                "inotify_add_watch=254",
                "inotify_rm_watch=255",
                "epoll_ctl r10",
                "epoll_pwait r10/r8/r9",
                "BPF-verified signal-mask pointer",
                "eight-byte kernel sigset",
                "packed token preservation",
                "eventfd ordinary/semaphore/error behavior",
                "inotify create/remove/ignored/error behavior",
                "cancellation",
                "ENOSYS fallback",
                "epoll_pwait2",
                "timerfd",
                "signalfd",
                "fanotify",
                "AIO",
                "public x86 support",
            )
        ),
        "static-c-event-descriptors evidence must retain its exact static event-descriptor runtime regression",
    )


def require_pathname_lifecycle_artifact(family: Mapping[str, Any]) -> None:
    """Keep the selected static pathname boundary private and exact."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-pathname-lifecycle"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-pathname-lifecycle artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-pathname-lifecycle must not promote libc.posix-runtime",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in PATHNAME_LIFECYCLE_SYMBOLS:
        require(
            f"`{symbol}`" in description,
            f"static-c-pathname-lifecycle description omits {symbol}",
        )
    for phrase in (
        "pathname-mutation/lifecycle block",
        "caller-buffer",
        "O_PATH",
        "null-buffer getcwd extension",
        "general pathname parsing",
        "cancellation",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-pathname-lifecycle description omits {phrase}",
        )

    owners = set(
        nonempty_strings(
            artifact["source_owners"], "static-c-pathname-lifecycle.source_owners"
        )
    )
    for owner in (
        "compat/upstreams.toml",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/pathname_lifecycle.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "include/errno.h",
        "include/fcntl.h",
        "include/stddef.h",
        "include/stdio.h",
        "include/sys/stat.h",
        "include/sys/syscall.h",
        "include/sys/types.h",
        "include/unistd.h",
        "include/bits/alltypes.h",
        "include/bits/fcntl.h",
        "include/bits/stat.h",
        "include/bits/syscall.h",
        "compat/x86_64/pathname_lifecycle_header_abi_probe.c",
        "compat/x86_64/pathname_lifecycle_header_abi_probe.cpp",
        "compat/x86_64/run_pathname_lifecycle_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_pathname_lifecycle_probe.c",
        "compat/x86_64/libc_pathname_lifecycle_start.S",
        "compat/x86_64/run_libc_pathname_lifecycle.sh",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    ):
        require(
            owner in owners,
            f"static-c-pathname-lifecycle source owners omit {owner}",
        )

    prerequisites = nonempty_strings(
        artifact["x86_abi_prerequisites"],
        "static-c-pathname-lifecycle.x86_abi_prerequisites",
    )
    require(
        any(
            "chdir=80" in item
            and "getcwd=79" in item
            and "rename=82" in item
            and "mkdir=83" in item
            and "rmdir=84" in item
            and "link=86" in item
            and "unlink=87" in item
            and "symlink=88" in item
            and "readlink=89" in item
            and "chmod=90" in item
            and "fchmod=91" in item
            and "truncate=76" in item
            and "fcntl=72" in item
            and "rdi/rsi/rdx" in item
            for item in prerequisites
        ),
        "static-c-pathname-lifecycle must record its Linux syscall register ABI",
    )
    require(
        any(
            "size_t/ssize_t/off_t" in item
            and "mode_t" in item
            and "caller-owned" in item
            and "readlink" in item
            and "getcwd" in item
            for item in prerequisites
        ),
        "static-c-pathname-lifecycle must record its LP64 pathname ABI",
    )
    require(
        any(
            "null-buffer extension" in item
            and "EINVAL" in item
            and "dummy" in item
            and "zero capacity" in item
            and "raw EISDIR" in item
            and "F_GETFD=1" in item
            and "O_PATH" in item
            and "/proc/self/fd" in item
            for item in prerequisites
        ),
        "static-c-pathname-lifecycle must record its getcwd/readlink/remove/fchmod behavior",
    )
    require(
        any(
            "src/unistd/chdir.c" in item
            and "getcwd.c" in item
            and "readlink.c" in item
            and "src/stat/chmod.c" in item
            and "fchmod.c" in item
            and "src/stdio/remove.c" in item
            and "rename.c" in item
            and "src/internal/procfdname.c" in item
            and "Linux 5.10" in item
            for item in prerequisites
        ),
        "static-c-pathname-lifecycle must record its pinned-musl source mapping",
    )
    require(
        any(
            "PT_TLS errno datum" in item
            and "initial-exec TPOFF" in item
            and "__tls_get_addr" in item
            for item in prerequisites
        ),
        "static-c-pathname-lifecycle must record its static TLS boundary",
    )

    headers = nonempty_strings(
        artifact["x86_header_prerequisites"],
        "static-c-pathname-lifecycle.x86_header_prerequisites",
    )
    require(
        any(
            "eight-profile" in item
            and "fcntl.h" in item
            and "stdio.h" in item
            and "sys/stat.h" in item
            and "unistd.h" in item
            and "O_PATH" in item
            and "unmangled C++" in item
            for item in headers
        ),
        "static-c-pathname-lifecycle must record its direct pathname header boundary",
    )

    static_exports = set(
        static_c_abi_export_names(
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        )
    )
    require(
        set(PATHNAME_LIFECYCLE_SYMBOLS) <= static_exports,
        "static-c-pathname-lifecycle must retain its thirteen selected exports",
    )
    require(
        not (static_exports & set(PATHNAME_LIFECYCLE_UNSELECTED_SYMBOLS)),
        "static-c-pathname-lifecycle must not add unselected pathname exports",
    )

    static_root = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
    ).read_text(encoding="utf-8")
    require(
        '#[path = "pathname_lifecycle.rs"]\nmod pathname_lifecycle;' in static_root,
        "x86 static C ABI must compose the pathname_lifecycle leaf",
    )

    oracle = artifact["oracle"]
    assert isinstance(oracle, list)
    require(
        any(
            isinstance(entry, Mapping)
            and entry.get("kind") == "c-posix"
            and isinstance(entry.get("role"), str)
            and all(
                source in entry["role"]
                for source in (
                    "src/unistd/chdir.c",
                    "getcwd.c",
                    "readlink.c",
                    "src/stat/chmod.c",
                    "fchmod.c",
                    "src/stdio/remove.c",
                    "rename.c",
                    "src/internal/procfdname.c",
                )
            )
            and "null-buffer getcwd extension" in entry["role"]
            for entry in oracle
        ),
        "static-c-pathname-lifecycle must retain its pinned-musl pathname source mapping",
    )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-pathname-lifecycle"},
        "static-c-pathname-lifecycle must use the closed libc-pathname-lifecycle command",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "`-nostdlib -static` candidate",
                "getcwd=79",
                "chdir=80",
                "rename=82",
                "mkdir=83",
                "rmdir=84",
                "link=86",
                "unlink=87",
                "symlink=88",
                "readlink=89",
                "chmod=90",
                "fchmod=91",
                "truncate=76",
                "fcntl=72",
                "caller-buffer getcwd",
                "EINVAL null-buffer",
                "readlink zero-capacity",
                "remove EISDIR retry",
                "O_PATH fchmod fallback",
                "public x86 support",
            )
        ),
        "static-c-pathname-lifecycle evidence must retain its exact static pathname runtime regression",
    )


def require_descriptor_lifecycle_artifact(family: Mapping[str, Any]) -> None:
    """Keep the composed descriptor proof private and tied to its boundaries."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-c-descriptor-lifecycle"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-descriptor-lifecycle artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-descriptor-lifecycle must not promote libc.posix-runtime",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "descriptor-lifecycle composition",
        "`open`",
        "`openat`",
        "`creat`",
        "`fstat`/`fstatat`",
        "O_CLOEXEC",
        "O_LARGEFILE",
        "shared open-file-description status",
        "Fixture-local raw Linux calls",
        "does not establish a general C runtime",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-descriptor-lifecycle description omits {phrase}",
        )

    owners = set(
        nonempty_strings(
            artifact["source_owners"], "static-c-descriptor-lifecycle.source_owners"
        )
    )
    for owner in (
        "compat/upstreams.toml",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "libc/src/c_abi/x86_64/stat_compat.rs",
        "libc/src/c_abi/x86_64/descriptor_entry.rs",
        "libc/src/c_abi/x86_64/descriptor_control.rs",
        "libc/src/c_abi/x86_64/descriptor_io.rs",
        "include/fcntl.h",
        "include/stddef.h",
        "include/sys/stat.h",
        "include/unistd.h",
        "compat/x86_64/fcntl_header_abi_probe.c",
        "compat/x86_64/run_fcntl_header_abi.sh",
        "compat/x86_64/stat_header_abi_probe.c",
        "compat/x86_64/run_stat_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_descriptor_lifecycle_probe.c",
        "compat/x86_64/libc_descriptor_lifecycle_start.S",
        "compat/x86_64/run_libc_descriptor_lifecycle.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "scripts/dev-x86_64.sh",
    ):
        require(
            owner in owners,
            f"static-c-descriptor-lifecycle source owners omit {owner}",
        )

    prerequisites = nonempty_strings(
        artifact["x86_abi_prerequisites"],
        "static-c-descriptor-lifecycle.x86_abi_prerequisites",
    )
    require(
        any(
            "open=2" in item
            and "openat=257" in item
            and "fcntl=72" in item
            and "rdi/rsi/rdx" in item
            and "r10" in item
            and "F_GETFD/F_GETFL" in item
            for item in prerequisites
        ),
        "static-c-descriptor-lifecycle must record its entry and variadic fcntl ABI",
    )
    require(
        any(
            "fstat=5" in item
            and "fstatat" in item
            and "newfstatat=262" in item
            and "144-byte x86 LP64 record" in item
            and "r10" in item
            for item in prerequisites
        ),
        "static-c-descriptor-lifecycle must record its selected stat ABI",
    )
    require(
        any(
            "FD_CLOEXEC" in item
            and "shared open file description" in item
            and "O_APPEND" in item
            and "initial-TLS errno" in item
            for item in prerequisites
        ),
        "static-c-descriptor-lifecycle must record descriptor-state and errno ownership",
    )
    require(
        any(
            "PT_TLS errno datum" in item
            and "Variant-II thread-pointer self word" in item
            for item in prerequisites
        ),
        "static-c-descriptor-lifecycle must record its fixture-only TLS boundary",
    )

    headers = nonempty_strings(
        artifact["x86_header_prerequisites"],
        "static-c-descriptor-lifecycle.x86_header_prerequisites",
    )
    require(
        any(
            "fcntl C/C++ gate" in item
            and "stat C/C++ gate" in item
            and "not header closure" in item
            for item in headers
        ),
        "static-c-descriptor-lifecycle must retain its existing header-gate boundary",
    )

    static_exports = static_c_abi_export_names(
        ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
    )
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
        require(
            symbol in static_exports,
            f"static-c-descriptor-lifecycle must retain selected export {symbol}",
        )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-descriptor-lifecycle"},
        "static-c-descriptor-lifecycle must use the closed libc-descriptor-lifecycle command",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "Pinned-musl C reference",
                "`-nostdlib -static` candidate",
                "PT_TLS capacity",
                "PID-isolated descriptor-relative lifecycle",
                "O_CLOEXEC/O_LARGEFILE",
                "fstat/fstatat",
                "dup/dup2/dup3",
                "public x86 support",
            )
        ),
        "static-c-descriptor-lifecycle evidence must retain its bounded composition scope",
    )


def require_timestamp_updates_artifact(family: Mapping[str, Any]) -> None:
    """Keep the selected timestamp C ABI real, bounded, and non-promoting."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry for entry in artifacts if entry.get("id") == "static-c-timestamp-updates"
    ]
    require(
        len(matching) == 1,
        "libc.posix-runtime must contain exactly one static-c-timestamp-updates artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-timestamp-updates must not promote libc.posix-runtime",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "timestamp-update block",
        "`utimensat`",
        "`futimens`",
        "strong `__futimesat`",
        "weak same-address `futimesat`",
        "`futimes`",
        "`lutimes`",
        "`utimes`",
        "`utime`",
        "`UTIME_NOW`",
        "`UTIME_OMIT`",
        "real Rust `rcrt1.o`/`crti.o`/`crtn.o`",
        "does not establish general filesystem policy",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-timestamp-updates description omits {phrase}",
        )

    owners = set(
        nonempty_strings(
            artifact["source_owners"], "static-c-timestamp-updates.source_owners"
        )
    )
    for owner in (
        "compat/upstreams.toml",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/timestamp_updates.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "libc/src/c_abi/x86_64/syscall.rs",
        "libc/src/c_abi/x86_64/static_tls.rs",
        "libc/src/c_abi/x86_64/static_startup.rs",
        "crt/src/x86_64_rcrt1.rs",
        "crt/src/x86_64_crti.rs",
        "crt/src/x86_64_crtn.rs",
        "include/sys/stat.h",
        "include/sys/time.h",
        "include/utime.h",
        "compat/x86_64/utime_header_abi_probe.c",
        "compat/x86_64/utime_header_abi_probe.cpp",
        "compat/x86_64/run_utime_header_abi.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/libc_timestamp_updates_probe.c",
        "compat/x86_64/run_libc_timestamp_updates.sh",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/dev-x86_64.sh",
        "scripts/check_structure.py",
    ):
        require(owner in owners, f"static-c-timestamp-updates source owners omit {owner}")

    prerequisites = nonempty_strings(
        artifact["x86_abi_prerequisites"],
        "static-c-timestamp-updates.x86_abi_prerequisites",
    )
    require(
        any(
            "utimensat=280" in item
            and "rdi/rsi/rdx/r10" in item
            and "rcx" in item
            and "16-byte align-8" in item
            for item in prerequisites
        ),
        "static-c-timestamp-updates must record its x86 syscall and record ABI",
    )
    require(
        any(
            "src/stat/utimensat.c" in item
            and "src/stat/futimesat.c" in item
            and "all-UTIME_NOW" in item
            and "weak same-address" in item
            and "ENOSYS fallback" in item
            for item in prerequisites
        ),
        "static-c-timestamp-updates must record the selected musl conversion/alias boundary",
    )
    require(
        any(
            "archive-owned initial-TLS errno PT_TLS" in item
            and "Real rcrt1" in item
            and "__tls_get_addr" in item
            for item in prerequisites
        ),
        "static-c-timestamp-updates must record its archive-owned TLS/startup boundary",
    )

    headers = nonempty_strings(
        artifact["x86_header_prerequisites"],
        "static-c-timestamp-updates.x86_header_prerequisites",
    )
    require(
        any(
            "utime header gate" in item
            and "unmangled C++ linkage" in item
            and "does not close any installed header family" in item
            for item in headers
        ),
        "static-c-timestamp-updates must retain its direct header boundary",
    )

    static_exports = static_c_abi_export_names(
        ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
    )
    for symbol in (
        "utimensat",
        "futimens",
        "__futimesat",
        "futimesat",
        "futimes",
        "lutimes",
        "utimes",
        "utime",
    ):
        require(
            symbol in static_exports,
            f"static-c-timestamp-updates must retain selected export {symbol}",
        )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-timestamp-updates"},
        "static-c-timestamp-updates must use the closed libc-timestamp-updates command",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "Pinned-musl C reference",
                "rcrt1/crti/crtn static-PIE candidate",
                "weak same-address futimesat",
                "flags in r10",
                "UTIME_NOW/UTIME_OMIT",
                "dynamic TLS",
                "public x86 support",
            )
        ),
        "static-c-timestamp-updates evidence must retain its bounded runtime boundary",
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
    require_public_header_profile_consumability_artifact(
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
    require_ldso_initial_tls_artifact(by_id["ldso.dynamic-runtime"])
    require_static_initial_tls_v1_artifact(by_id["libc.pthread-tls"])
    require_static_crt_initial_tls_handoff_artifact(by_id["libc.pthread-tls"])
    require_static_crt1_initial_tls_handoff_artifact(by_id["libc.pthread-tls"])
    require_static_pthread_identity_artifact(by_id["libc.pthread-tls"])
    require_static_c11_lifecycle_artifact(by_id["libc.pthread-tls"])
    require_static_pthread_c11_detach_artifact(by_id["libc.pthread-tls"])
    require_static_thrd_sleep_artifact(by_id["libc.pthread-tls"])
    require_static_pthread_normal_mutex_artifact(by_id["libc.pthread-tls"])
    require_static_pthread_private_cond_artifact(by_id["libc.pthread-tls"])
    require_static_c11_plain_sync_artifact(by_id["libc.pthread-tls"])
    require_static_pthread_c11_once_artifact(by_id["libc.pthread-tls"])
    require_static_pthread_c11_tsd_artifact(by_id["libc.pthread-tls"])
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
    require_system_information_artifact(by_id["libc.posix-runtime"])
    require_mapping_core_artifact(by_id["libc.posix-runtime"])
    require_signal_execution_artifact(by_id["libc.posix-runtime"])
    require_clock_nanosleep_artifact(by_id["libc.posix-runtime"])
    require_nanosleep_artifact(by_id["libc.posix-runtime"])
    require_descriptor_entry_artifact(by_id["libc.posix-runtime"])
    require_filesystem_access_artifact(by_id["libc.posix-runtime"])
    require_fcntl_status_control_artifact(by_id["libc.posix-runtime"])
    require_fcntl_record_locks_artifact(by_id["libc.posix-runtime"])
    require_generic_ioctl_artifact(by_id["libc.posix-runtime"])
    require_sysv_semaphore_artifact(by_id["libc.posix-runtime"])
    require_sysv_message_shared_memory_artifact(by_id["libc.posix-runtime"])
    require_event_descriptors_artifact(by_id["libc.posix-runtime"])
    require_pathname_lifecycle_artifact(by_id["libc.posix-runtime"])
    require_descriptor_lifecycle_artifact(by_id["libc.posix-runtime"])
    require_timestamp_updates_artifact(by_id["libc.posix-runtime"])
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
        "header_foundation_ioctl_header_profile_matrix_row_count": header_layout_foundation_report[
            "ioctl_header_profile_matrix_row_count"
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
        "header_foundation_access_header_profile_matrix_row_count": header_layout_foundation_report[
            "access_header_profile_matrix_row_count"
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
