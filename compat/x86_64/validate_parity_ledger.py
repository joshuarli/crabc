#!/usr/bin/env python3
"""Validate the closed, non-symbol x86-64 runtime-parity ledger.

This is repository test infrastructure, not a runtime dependency.  It records
which AArch64 capability and gate families need independent native x86 proof;
it never treats a source-only foundation slice as public target support.
"""

from __future__ import annotations

import argparse
from contextvars import ContextVar
import hashlib
import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Mapping


LOCAL_MODULE_DIR = Path(__file__).resolve().parent
if str(LOCAL_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(LOCAL_MODULE_DIR))

from feature_archive_roster import (  # noqa: E402
    FeatureArchiveRosterError,
    load_cargo_x86_features,
    parse_feature_archive_roster,
    validate_ledger_bindings,
)
from header_callable_visibility_matrix import (  # noqa: E402
    MatrixError,
    build_file_report as build_callable_visibility_report,
    canonical_json as canonical_callable_visibility_json,
    load_contract as load_callable_visibility_contract,
)
from header_abi_matrix import (  # noqa: E402
    HeaderAbiMatrixError,
    load_contract as load_header_abi_matrix_contract,
    validate_checked_report as validate_header_abi_matrix_report,
)
from header_record_layout_matrix import (  # noqa: E402
    RecordLayoutMatrixError,
    load_contract as load_header_record_layout_matrix_contract,
    validate_checked_report as validate_header_record_layout_matrix_report,
)
from header_declaration_macro_visibility_matrix import (  # noqa: E402
    HeaderDeclarationMacroVisibilityMatrixError,
    canonical_json as canonical_declaration_macro_visibility_json,
    load_contract as load_declaration_macro_visibility_contract,
    validate_checked_report as validate_declaration_macro_visibility_report,
)
from header_callable_disposition import (  # noqa: E402
    HeaderCallableDispositionError,
    load_contract as load_header_callable_disposition_contract,
    validate_checked_report as validate_header_callable_disposition_report,
)
from selected_header_install_projection import (  # noqa: E402
    ProjectionError,
    load_contract as load_selected_header_install_projection_contract,
)
import run_qualification_manifest as qualification_manifest_runner  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_C_ABI_EXPORTS_PATH = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
X86_64_DISPATCHER_PATH = ROOT / "scripts" / "dev-x86_64.sh"
STATIC_PRODUCT_CONTRACT_PATH = ROOT / "compat" / "x86_64" / "static-product.toml"
PROTOCOL_DATABASE_PROVIDER_PATH = (
    ROOT / "compat" / "x86_64" / "protocol-database-provider.toml"
)
UPSTREAMS_PATH = ROOT / "compat" / "upstreams.toml"
HEADER_LAYOUT_MANIFEST_PATH = ROOT / "compat" / "x86_64" / "headers-layouts.toml"
HEADER_LAYOUT_FOUNDATION_MANIFEST_PATH = (
    ROOT / "compat" / "x86_64" / "headers-layouts-foundation.toml"
)
HEADER_LAYOUTS_AGGREGATE_PATH = ROOT / "compat" / "x86_64" / "headers_layouts_aggregate.py"
HEADER_LAYOUTS_AGGREGATE_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_headers_layouts_aggregate.sh"
)
HEADER_LAYOUTS_AGGREGATE_REPORT_PATH = (
    ROOT / "compat" / "x86_64" / "generated" / "headers_layouts_aggregate" / "report.json"
)
HEADER_CALLABLE_VISIBILITY_MATRIX_CONTRACT_PATH = (
    ROOT / "compat" / "x86_64" / "header_callable_visibility_matrix.toml"
)
HEADER_CALLABLE_VISIBILITY_MATRIX_REPORT_PATH = (
    ROOT / "compat" / "x86_64" / "generated" / "header_callable_visibility_matrix" / "report.json"
)
HEADER_CALLABLE_VISIBILITY_MATRIX_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_header_callable_visibility_matrix.sh"
)
HEADER_CALLABLE_EXTENSION_CONTRACT_PATH = (
    ROOT / "compat" / "x86_64" / "header_callable_extension_contract.toml"
)
HEADER_ABI_MATRIX_CONTRACT_PATH = ROOT / "compat" / "x86_64" / "header_abi_matrix.toml"
HEADER_ABI_MATRIX_REPORT_PATH = (
    ROOT / "compat" / "x86_64" / "generated" / "header_abi_matrix" / "report.json"
)
HEADER_ABI_MATRIX_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_header_abi_matrix.sh"
HEADER_RECORD_LAYOUT_MATRIX_CONTRACT_PATH = (
    ROOT / "compat" / "x86_64" / "header_record_layout_matrix.toml"
)
HEADER_RECORD_LAYOUT_MATRIX_REPORT_PATH = (
    ROOT / "compat" / "x86_64" / "generated" / "header_record_layout_matrix" / "report.json"
)
HEADER_RECORD_LAYOUT_MATRIX_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_header_record_layout_matrix.sh"
)
HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_CONTRACT_PATH = (
    ROOT / "compat" / "x86_64" / "header_declaration_macro_visibility_matrix.toml"
)
HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_REPORT_PATH = (
    ROOT
    / "compat"
    / "x86_64"
    / "generated"
    / "header_declaration_macro_visibility_matrix"
    / "report.json"
)
HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_header_declaration_macro_visibility_matrix.sh"
)
HEADER_CALLABLE_PROVIDER_LINKAGE_AUDIT_PATH = (
    ROOT / "compat" / "x86_64" / "header_callable_provider_linkage_audit.py"
)
HEADER_CALLABLE_PROVIDER_LINKAGE_AUDIT_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_header_callable_provider_linkage_audit.sh"
)
HEADER_CALLABLE_DISPOSITION_CONTRACT_PATH = (
    ROOT / "compat" / "x86_64" / "header_callable_disposition.toml"
)
HEADER_CALLABLE_DISPOSITION_REPORT_PATH = (
    ROOT / "compat" / "x86_64" / "header_callable_disposition.json"
)
HEADER_CALLABLE_DISPOSITION_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_header_callable_disposition.sh"
)
PUBLIC_HEADER_INVENTORY_PATH = ROOT / "compat" / "x86_64" / "public_headers.txt"
PUBLIC_HEADER_SURFACE_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_public_header_surface.sh"
LINUX_5_10_UAPI_VERIFIER_PATH = ROOT / "compat" / "x86_64" / "run_linux_5_10_uapi.sh"
CANDIDATE_HEADER_CLOSURE_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_candidate_header_closure.sh"
)
INSTALLED_HEADER_TREE_CLOSURE_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_installed_header_tree_closure.sh"
)
SELECTED_HEADER_INSTALL_PROJECTION_CONTRACT_PATH = (
    ROOT / "compat" / "x86_64" / "selected-header-install-projection.toml"
)
SELECTED_HEADER_INSTALL_PROJECTION_VALIDATOR_PATH = (
    ROOT / "compat" / "x86_64" / "selected_header_install_projection.py"
)
SELECTED_HEADER_INSTALL_PROJECTION_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_selected_header_install_projection.sh"
)
UAPI_WRAPPER_MATRIX_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_uapi_wrapper_matrix.sh"
)
IOCTL_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_ioctl_header_abi.sh"
SYS_IO_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_sys_io_header_abi.sh"
EPOLL_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_epoll_header_abi.sh"
EVENT_DESCRIPTORS_HEADER_ABI_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_event_descriptors_header_abi.sh"
)
DIRENT_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_dirent_header_abi.sh"
STDLIB_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_stdlib_header_abi.sh"
TIMEVAL_TRANSITIVE_HEADER_ABI_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_timeval_transitive_header_abi.sh"
)
SYS_TIME_DIRECT_HEADER_ABI_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_sys_time_direct_header_abi.sh"
)
ACCESS_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_access_header_abi.sh"
XATTR_HEADER_ABI_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_xattr_header_abi.sh"
X86_64_EVIDENCE_DOCKERFILE_PATH = ROOT / "docker" / "Dockerfile.x86_64"
QUALIFICATION_POSIX_ABI_CONTRACT_PATH = (
    ROOT / "compat" / "x86_64" / "qualification_posix_abi.json"
)
AARCH64_PARITY_INVENTORY_VALIDATOR_PATH = (
    ROOT / "compat" / "x86_64" / "aarch64_parity_inventory.py"
)
EXPECTED_SCHEMA = "crabc.x86_64-runtime-parity/v3"
EXPECTED_STATIC_PRODUCT_SCHEMA = "crabc.x86_64-owned-static-product/v1"
EXPECTED_TARGET = "x86_64-unknown-linux-musl"
EXPECTED_PLATFORM = "Linux/x86-64 little-endian"
EXPECTED_KERNEL_MSRV = "5.10"
EXPECTED_HEADER_LAYOUT_SCHEMA = "crabc.x86_64-headers-layouts/v1"
EXPECTED_HEADER_LAYOUT_FOUNDATION_SCHEMA = "crabc.x86_64-headers-layouts-foundation/v19"
EXPECTED_HEADER_LAYOUTS_AGGREGATE_COMMAND = "./scripts/dev-x86_64.sh headers-layouts-aggregate"
EXPECTED_HEADER_COMPLETION_ALGORITHM = "header-foundation-v1"
EXPECTED_HEADER_COMPLETION_INSTALLED_SURFACE_KEYS = [
    "abi_facets_accounted",
    "access_header_profile_matrix_slice",
    "c11_consumer_matrix",
    "candidate_transitive_include_closure",
    "cxx17_consumer_matrix",
    "dirent_header_profile_matrix_slice",
    "epoll_header_profile_matrix_slice",
    "event_descriptors_header_profile_matrix_slice",
    "feature_modes_accounted",
    "inventory_accounted",
    "ioctl_header_profile_matrix_slice",
    "language_profiles_accounted",
    "legacy_direct_inputs_accounted",
    "project_only_paths_accounted",
    "selected_header_install_projection",
    "stdlib_header_profile_matrix_slice",
    "sys_io_header_profile_matrix_slice",
    "sys_time_direct_header_profile_matrix_slice",
    "timeval_transitive_header_profile_matrix_slice",
    "uapi_paths_accounted",
    "uapi_wrapper_profile_matrix_slice",
    "xattr_header_profile_matrix_slice",
]
EXPECTED_HEADER_COMPLETION_DIMENSIONS = [
    "installed-surface",
    "declaration-identity",
    "declaration-source-forms",
    "callable-visibility",
    "prototype-or-named-declarations",
    "record-byte-layouts",
    "callable-ownership-routing",
]
EXPECTED_HEADER_COMPLETION_NONREQUIREMENTS = [
    "archive-extraction",
    "final-provider-archive-closure",
    "promotion-public-support",
    "runtime-semantics",
    "selected-provider-linkage-audit",
    "static-export-complement",
    "unprovided-callable-count",
]
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
EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_ID = "x86-sys-io-header-profile-matrix"
EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_COMMAND = "./scripts/dev-x86_64.sh sys-io-header-abi"
EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS = ("sys/io.h", "bits/io.h")
EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_PROFILES = (
    "c11-gnu",
    "cxx17-gnu",
    "c11-strict",
    "c11-posix-2008",
    "c11-xopen-700",
    "c11-bsd",
    "cxx17-strict",
)
EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_ROW_COUNT = 7
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ID = "x86-epoll-header-profile-matrix"
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_COMMAND = "./scripts/dev-x86_64.sh epoll-header-abi"
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_SUBJECT_HEADER = "sys/epoll.h"
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_DIRECT_MACRO_HEADER = "sys/ioctl.h"
EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ROW_COUNT = 7
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_ID = (
    "x86-event-descriptors-header-profile-matrix"
)
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_COMMAND = (
    "./scripts/dev-x86_64.sh event-descriptors-header-abi"
)
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS = (
    "sys/eventfd.h",
    "sys/inotify.h",
)
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_IMMEDIATE_FEATURE_HEADER = "fcntl.h"
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_PROFILES = (
    "c-default",
    "c11-gnu",
    "cxx17-gnu",
    "c11-strict",
    "c11-posix-2008",
    "c11-xopen-700",
    "c11-bsd",
    "cxx17-strict",
)
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_DIRECT_SURFACE_VISIBILITY = "unconditional"
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_AT_EMPTY_PATH_VISIBLE_PROFILES = (
    "c-default",
    "c11-gnu",
    "cxx17-gnu",
    "c11-bsd",
)
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_AT_EMPTY_PATH_HIDDEN_PROFILES = (
    "c11-strict",
    "c11-posix-2008",
    "c11-xopen-700",
    "cxx17-strict",
)
EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_ROW_COUNT = 16
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_ID = "x86-dirent-header-profile-matrix"
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_COMMAND = "./scripts/dev-x86_64.sh dirent-header-abi"
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_SUBJECT_HEADER = "dirent.h"
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_BASE_PROFILES = (
    "c11-gnu",
    "cxx17-gnu",
    "c11-strict",
    "c11-posix-2008",
    "c11-xopen-700",
    "c11-bsd",
    "cxx17-strict",
)
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_LARGEFILE64_PROFILES = (
    "c11-gnu-largefile64",
    "cxx17-gnu-largefile64",
    "c11-strict-largefile64",
    "cxx17-strict-largefile64",
)
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_SEEK_TELL_VISIBLE_PROFILES = (
    "c11-gnu",
    "cxx17-gnu",
    "c11-xopen-700",
    "c11-bsd",
    "c11-gnu-largefile64",
    "cxx17-gnu-largefile64",
)
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_GETDENTS_TYPE_MACROS_VISIBLE_PROFILES = (
    "c11-gnu",
    "cxx17-gnu",
    "c11-bsd",
    "c11-gnu-largefile64",
    "cxx17-gnu-largefile64",
)
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_VERSIONSORT_VISIBLE_PROFILES = (
    "c11-gnu",
    "cxx17-gnu",
    "c11-gnu-largefile64",
    "cxx17-gnu-largefile64",
)
EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_ROW_COUNT = 11
EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_ID = "x86-stdlib-header-profile-matrix"
EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_COMMAND = "./scripts/dev-x86_64.sh stdlib-header-abi"
EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_SUBJECT_HEADER = "stdlib.h"
EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_PROFILES = (
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
)
EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_ROW_COUNT = 12
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
EXPECTED_XATTR_HEADER_PROFILE_MATRIX_ID = "x86-xattr-header-profile-matrix"
EXPECTED_XATTR_HEADER_PROFILE_MATRIX_COMMAND = "./scripts/dev-x86_64.sh xattr-header-abi"
EXPECTED_XATTR_HEADER_PROFILE_MATRIX_SUBJECT_HEADER = "sys/xattr.h"
EXPECTED_XATTR_HEADER_PROFILE_MATRIX_PROFILES = (
    "c-default",
    "c11-gnu",
    "cxx17-gnu",
    "c11-strict",
    "cxx17-strict",
    "c11-posix-2008",
    "cxx17-posix-2008",
    "c11-xopen-700",
    "cxx17-xopen-700",
    "c11-bsd",
    "cxx17-bsd",
)
EXPECTED_XATTR_HEADER_PROFILE_MATRIX_ROW_COUNT = 11
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
REVIEWED_PROJECT_HEADER_C_ABI_DISPOSITION = "retained-reviewed-project-c-abi-extension"
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
EXPECTED_INSTALLED_HEADER_TREE_CLOSURE_COMMAND = (
    "./scripts/dev-x86_64.sh installed-header-tree-closure"
)
EXPECTED_SELECTED_HEADER_INSTALL_PROJECTION_COMMAND = (
    "./scripts/dev-x86_64.sh selected-header-install-projection"
)
EXPECTED_HEADER_ABI_MATRIX_COMMAND = "./scripts/dev-x86_64.sh header-abi-matrix"
EXPECTED_HEADER_ABI_MATRIX_SUMMARY = {
    "candidate_public_header_count": 191,
    "comparison_counts": {
        "candidate-only-reviewed-native-callable-extension": 28,
        "candidate-only-reviewed-project-c-abi-extension": 56,
        "matched": 1252,
        "oracle-not-applicable": 1,
    },
    "complete": False,
    "incomplete_reasons": [
        "0 comparable header/profile rows have prototype or named declaration-form differences",
        "1 pinned-musl header/profile rows are oracle-not-applicable",
        "record byte layouts, archive linkage, runtime behavior, family promotion, and public support remain outside this partial matrix",
    ],
    "mismatch_fact_counts": {},
    "mismatch_row_count": 0,
    "pinned_public_header_count": 183,
    "profile_count": 7,
    "reviewed_native_callable_extension_fact_count": 28,
    "reviewed_native_callable_extension_row_count": 28,
    "row_count": 1337,
}
EXPECTED_HEADER_RECORD_LAYOUT_MATRIX_COMMAND = (
    "./scripts/dev-x86_64.sh header-record-layout-matrix"
)
EXPECTED_HEADER_RECORD_LAYOUT_MATRIX_SUMMARY = {
    "candidate_field_categories": {
        "bit-field": 329,
        "flexible-tail": 31,
        "non-addressable-field": 10,
    },
    "candidate_public_header_count": 191,
    "candidate_record_categories": {"anonymous-only": 452, "incomplete": 118},
    "candidate_record_count": 2615,
    "comparison_counts": {
        "candidate-only-reviewed-project-c-abi-extension": 56,
        "matched": 1280,
        "oracle-not-applicable": 1,
    },
    "complete": False,
    "incomplete_reasons": [
        "0 comparable header/profile rows have record-byte-layout differences",
        "1 pinned-musl header/profile rows are oracle-not-applicable",
        "record-byte-layouts remain partial until every applicable named record and field is matched",
        "archive linkage, runtime behavior, family promotion, and public support remain outside this matrix",
    ],
    "pinned_public_header_count": 183,
    "profile_count": 7,
    "reference_field_categories": {
        "bit-field": 329,
        "flexible-tail": 31,
        "non-addressable-field": 10,
    },
    "reference_record_categories": {"anonymous-only": 438, "incomplete": 115},
    "reference_record_count": 2562,
    "row_count": 1337,
}
EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_COMMAND = (
    "./scripts/dev-x86_64.sh header-declaration-macro-visibility-matrix"
)
EXPECTED_HEADER_CALLABLE_PROVIDER_LINKAGE_AUDIT_COMMAND = (
    "./scripts/dev-x86_64.sh header-callable-provider-linkage-audit"
)
EXPECTED_HEADER_CALLABLE_DISPOSITION_COMMAND = (
    "./scripts/dev-x86_64.sh header-callable-disposition"
)
EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_SUMMARY = {
    "candidate_only_identity_count": 0,
    "candidate_only_identity_kind_counts": {},
    "candidate_public_header_count": 191,
    "comparable_row_count": 1252,
    "comparison_counts": {
        "candidate-only-reviewed-native-callable-extension": 28,
        "candidate-only-reviewed-project-c-abi-extension": 56,
        "matched": 1252,
        "oracle-not-applicable": 1,
    },
    "complete": False,
    "incomplete_reasons": [
        "0 comparable pinned header/profile rows have declaration or macro identity visibility differences",
        "1 pinned-musl header/profile rows are oracle-not-applicable",
        "declaration-form equality, record byte layouts, archive linkage, runtime behavior, family promotion, and public support remain outside this partial matrix",
    ],
    "matched_identity_count": 294885,
    "mismatch_row_count": 0,
    "oracle_not_applicable_candidate_fact_count": 104,
    "oracle_not_applicable_row_count": 1,
    "pinned_public_header_count": 183,
    "pinned_row_count": 1281,
    "profile_count": 7,
    "project_only_candidate_fact_count": 2137,
    "project_only_header_count": 8,
    "project_only_row_count": 56,
    "reference_only_identity_count": 0,
    "reference_only_identity_kind_counts": {},
    "reviewed_native_callable_extension_identity_count": 28,
    "reviewed_native_callable_extension_row_count": 28,
    "row_count": 1337,
    "source_form_comparison_counts": {
        "candidate-only-reviewed-native-callable-extension": 28,
        "candidate-only-reviewed-project-c-abi-extension": 56,
        "matched": 1252,
        "oracle-not-applicable": 1,
    },
    "source_form_difference_count": 0,
    "source_form_difference_row_count": 0,
    "source_form_only_difference_row_count": 0,
}

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
        "sys-io-header-profile-matrix",
        "epoll-header-profile-matrix",
        "event-descriptors-header-profile-matrix",
        "dirent-header-profile-matrix",
        "stdlib-header-profile-matrix",
        "timeval-transitive-header-profile-matrix",
        "sys-time-direct-header-profile-matrix",
        "access-header-profile-matrix",
        "xattr-header-profile-matrix",
        "candidate-transitive-closure",
        "cxx17-consumability",
        "feature-visibility",
        "callable-feature-visibility",
        "callable-prototype-layout",
        "record-byte-layout-matrix",
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
        "callable-feature-visibility",
        "callable-prototype-layout",
        "record-byte-layout-matrix",
        "callable-linkage-ownership",
    ),
    "project-only-extensions": (
        "project-only-extension-policy",
        "candidate-tree-presence",
        "candidate-transitive-closure",
        "cxx17-consumability",
        "feature-visibility",
        "callable-feature-visibility",
        "callable-prototype-layout",
        "record-byte-layout-matrix",
        "callable-linkage-ownership",
    ),
}
EXPECTED_HEADER_FOUNDATION_CLASS_LINKAGE_OWNERS = {
    "pinned-non-uapi": (
        "current-static-c-exports",
        "header-callable-disposition",
        "noncallable-header-abi",
    ),
    "pinned-uapi-inputs": (
        "current-static-c-exports",
        "header-callable-disposition",
        "noncallable-header-abi",
    ),
    "project-only-extensions": (
        "current-static-c-exports",
        "header-callable-disposition",
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
    "sys-io-header-profile-matrix": (
        "partial-verified",
        "sys/io.h/bits/io.h x86 port-I/O inline declaration compiler-constraint and C++ C-linkage subset",
        "libc.headers-layouts",
        (EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_ID,),
    ),
    "epoll-header-profile-matrix": (
        "partial-verified",
        "sys/epoll.h plus selected sys/ioctl.h macro encoding subset",
        "libc.headers-layouts",
        (EXPECTED_EPOLL_HEADER_PROFILE_MATRIX_ID,),
    ),
    "event-descriptors-header-profile-matrix": (
        "partial-verified",
        "sys/eventfd.h and sys/inotify.h unconditional declaration layout macro and C++ linkage subset plus immediate fcntl.h AT_EMPTY_PATH feature boundary",
        "libc.headers-layouts",
        (EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_ID,),
    ),
    "dirent-header-profile-matrix": (
        "partial-verified",
        "dirent.h selected declaration layout large-file alias feature gate and C++ requested C-linkage subset",
        "libc.headers-layouts",
        (EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_ID,),
    ),
    "stdlib-header-profile-matrix": (
        "partial-verified",
        "stdlib.h selected declaration layout feature gate C++ requested C-linkage and NULL subset",
        "libc.headers-layouts",
        (EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_ID,),
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
    "xattr-header-profile-matrix": (
        "partial-verified",
        "sys/xattr.h complete selected declaration scalar flag visibility and C++ requested C-linkage subset",
        "libc.headers-layouts",
        (EXPECTED_XATTR_HEADER_PROFILE_MATRIX_ID,),
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
        "partial-verified",
        "project-only-extensions",
        "libc.c-abi-compat",
        (
            "project-only-header-classification",
            "x86-selected-header-install-projection",
        ),
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
        "partial-verified",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("all-header-declaration-macro-feature-visibility-matrix",),
    ),
    "callable-feature-visibility": (
        "partial-verified",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("all-header-callable-feature-visibility-matrix",),
    ),
    "callable-prototype-layout": (
        "partial-verified",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("generated-x86-prototype-layout-matrix",),
    ),
    "record-byte-layout-matrix": (
        "partial-verified",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("all-header-record-byte-layout-matrix",),
    ),
    "callable-linkage-ownership": (
        "partial-verified",
        "all-pinned-and-project-only-public-headers",
        "libc.headers-layouts",
        ("generated-header-callable-disposition",),
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
    "header-callable-disposition": (
        "partial-verified",
        "every selected external callable has a current selected provider assignment or an exact named deferred owner, while every missing pinned-musl declaration, if any, has a separate exact record",
        "libc.headers-layouts",
        ("generated-header-callable-disposition",),
    ),
    "noncallable-header-abi": (
        "partial-verified",
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
    "stddef": "./scripts/dev-x86_64.sh stddef-header-abi",
    "stat": "./scripts/dev-x86_64.sh stat-header-abi",
    "utime": "./scripts/dev-x86_64.sh utime-header-abi",
    "pthread-c11": "./scripts/dev-x86_64.sh pthread-c11-header-abi",
    "pthread-cancellation": "./scripts/dev-x86_64.sh pthread-cancellation-header-abi",
    "stdio-standard": "./scripts/dev-x86_64.sh stdio-standard-header-abi",
    "ctype": "./scripts/dev-x86_64.sh ctype-header-abi",
    "integer-arithmetic": "./scripts/dev-x86_64.sh integer-arithmetic-header-abi",
    "integer-parse": "./scripts/dev-x86_64.sh integer-parse-header-abi",
    "float-parse": "./scripts/dev-x86_64.sh float-parse-header-abi",
    "intmax-arithmetic": "./scripts/dev-x86_64.sh intmax-arithmetic-header-abi",
    "credential-observation": "./scripts/dev-x86_64.sh credential-observation-header-abi",
    "login-name": "./scripts/dev-x86_64.sh login-name-header-abi",
    "child-reaping": "./scripts/dev-x86_64.sh child-reaping-header-abi",
    "immediate-termination": "./scripts/dev-x86_64.sh immediate-termination-header-abi",
    "callback-algorithms": "./scripts/dev-x86_64.sh callback-algorithms-header-abi",
    "ffs": "./scripts/dev-x86_64.sh ffs-header-abi",
    "memccpy": "./scripts/dev-x86_64.sh memccpy-header-abi",
    "aio-error": "./scripts/dev-x86_64.sh aio-error-header-abi",
    "byte-strings": "./scripts/dev-x86_64.sh byte-strings-header-abi",
    "memory-search": "./scripts/dev-x86_64.sh memory-search-header-abi",
    "string-copy": "./scripts/dev-x86_64.sh string-copy-header-abi",
    "random-entropy": "./scripts/dev-x86_64.sh random-entropy-header-abi",
    "time": "./scripts/dev-x86_64.sh time-header-abi",
    "poll": "./scripts/dev-x86_64.sh poll-header-abi",
    "select": "./scripts/dev-x86_64.sh select-header-abi",
    "fcntl": "./scripts/dev-x86_64.sh fcntl-header-abi",
    "ioctl": "./scripts/dev-x86_64.sh ioctl-header-abi",
    "sys-io": "./scripts/dev-x86_64.sh sys-io-header-abi",
    "unistd": "./scripts/dev-x86_64.sh unistd-header-abi",
    "system": "./scripts/dev-x86_64.sh system-header-abi",
    "syscall": "./scripts/dev-x86_64.sh syscall-header-abi",
    "signal": "./scripts/dev-x86_64.sh signal-header-abi",
    "termios": "./scripts/dev-x86_64.sh termios-header-abi",
    "mman": "./scripts/dev-x86_64.sh mman-header-abi",
    "resource": "./scripts/dev-x86_64.sh resource-header-abi",
    "socket": "./scripts/dev-x86_64.sh socket-header-abi",
    "tcp": "./scripts/dev-x86_64.sh tcp-header-abi",
    "nameser": "./scripts/dev-x86_64.sh nameser-header-abi",
    "quota": "./scripts/dev-x86_64.sh quota-header-abi",
    "sched-cpu-macros": "./scripts/dev-x86_64.sh sched-cpu-macros-header-abi",
    "fanotify": "./scripts/dev-x86_64.sh fanotify-header-abi",
    "inet-address": "./scripts/dev-x86_64.sh inet-address-header-abi",
    "epoll": "./scripts/dev-x86_64.sh epoll-header-abi",
    "timeval-transitive": "./scripts/dev-x86_64.sh timeval-transitive-header-abi",
    "sys-time-direct": "./scripts/dev-x86_64.sh sys-time-direct-header-abi",
    "access-header": "./scripts/dev-x86_64.sh access-header-abi",
    "xattr-header": "./scripts/dev-x86_64.sh xattr-header-abi",
    "machine-context": "./scripts/dev-x86_64.sh machine-context-header-abi",
    "event-descriptors": "./scripts/dev-x86_64.sh event-descriptors-header-abi",
    "dirent": "./scripts/dev-x86_64.sh dirent-header-abi",
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
    "stddef": (
        "compat/x86_64/stddef_header_abi_probe.c",
        "compat/x86_64/stddef_header_abi_probe.cpp",
        "compat/x86_64/run_stddef_header_abi.sh",
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
    "pthread-cancellation": (
        "compat/x86_64/pthread_cancellation_header_abi_probe.c",
        "compat/x86_64/pthread_cancellation_header_abi_probe.cpp",
        "compat/x86_64/run_pthread_cancellation_header_abi.sh",
    ),
    "stdio-standard": (
        "compat/x86_64/stdio_standard_header_abi_probe.c",
        "compat/x86_64/stdio_standard_header_abi_probe.cpp",
        "compat/x86_64/run_stdio_standard_header_abi.sh",
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
    "float-parse": (
        "compat/x86_64/float_parse_header_abi_probe.c",
        "compat/x86_64/float_parse_header_abi_probe.cpp",
        "compat/x86_64/run_float_parse_header_abi.sh",
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
    "login-name": (
        "compat/x86_64/login_name_header_abi_probe.c",
        "compat/x86_64/login_name_header_abi_probe.cpp",
        "compat/x86_64/run_login_name_header_abi.sh",
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
    "memccpy": (
        "compat/x86_64/memccpy_header_abi_probe.c",
        "compat/x86_64/memccpy_header_abi_probe.cpp",
        "compat/x86_64/run_memccpy_header_abi.sh",
    ),
    "aio-error": (
        "compat/x86_64/aio_error_header_abi_probe.c",
        "compat/x86_64/aio_error_header_abi_probe.cpp",
        "compat/x86_64/run_aio_error_header_abi.sh",
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
    "sys-io": (
        "compat/x86_64/sys_io_header_abi_probe.c",
        "compat/x86_64/sys_io_header_abi_probe.cpp",
        "compat/x86_64/run_sys_io_header_abi.sh",
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
    "tcp": (
        "compat/x86_64/tcp_header_abi_probe.c",
        "compat/x86_64/tcp_header_abi_probe.cpp",
        "compat/x86_64/run_tcp_header_abi.sh",
    ),
    "nameser": (
        "compat/x86_64/nameser_header_abi_probe.c",
        "compat/x86_64/nameser_header_abi_probe.cpp",
        "compat/x86_64/run_nameser_header_abi.sh",
    ),
    "quota": (
        "compat/x86_64/quota_header_abi_probe.c",
        "compat/x86_64/quota_header_abi_probe.cpp",
        "compat/x86_64/run_quota_header_abi.sh",
    ),
    "sched-cpu-macros": (
        "compat/x86_64/sched_cpu_macros_header_abi_probe.c",
        "compat/x86_64/sched_cpu_macros_header_abi_probe.cpp",
        "compat/x86_64/run_sched_cpu_macros_header_abi.sh",
    ),
    "fanotify": (
        "compat/x86_64/fanotify_header_abi_probe.c",
        "compat/x86_64/fanotify_header_abi_probe.cpp",
        "compat/x86_64/run_fanotify_header_abi.sh",
    ),
    "inet-address": (
        "compat/x86_64/inet_address_header_abi_probe.c",
        "compat/x86_64/inet_address_header_abi_probe.cpp",
        "compat/x86_64/run_inet_address_header_abi.sh",
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
    "xattr-header": (
        "compat/x86_64/xattr_header_abi_probe.c",
        "compat/x86_64/xattr_header_abi_probe.cpp",
        "compat/x86_64/run_xattr_header_abi.sh",
    ),
    "machine-context": (
        "compat/x86_64/machine_context_header_abi_probe.c",
        "compat/x86_64/machine_context_header_abi_probe.cpp",
        "compat/x86_64/run_machine_context_header_abi.sh",
    ),
    "event-descriptors": (
        "compat/x86_64/event_descriptors_header_abi_probe.c",
        "compat/x86_64/event_descriptors_header_abi_probe.cpp",
        "compat/x86_64/run_event_descriptors_header_abi.sh",
    ),
    "dirent": (
        "compat/x86_64/dirent_header_abi_probe.c",
        "compat/x86_64/dirent_header_abi_probe.cpp",
        "compat/x86_64/run_dirent_header_abi.sh",
    ),
}

# The <resolv.h> direct probe remains the only manifest header root. Its strict
# C include trace separately owns this pinned-musl x86 closure; sys/types.h is
# intentionally absent because other header-layout gates own that path.
EXPECTED_NAMESER_STRICT_C_TRACE_HEADERS = (
    "include/resolv.h",
    "include/stdint.h",
    "include/bits/alltypes.h",
    "include/bits/stdint.h",
    "include/arpa/nameser.h",
    "include/stddef.h",
    "include/netinet/in.h",
    "include/features.h",
    "include/inttypes.h",
    "include/sys/socket.h",
    "include/bits/socket.h",
)

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
    "strverscmp",
    "strcspn",
    "strlen",
    "strncmp",
    "strnlen",
    "strpbrk",
    "strrchr",
    "strspn",
    "strstr",
)

LEGACY_MEMORY_SYMBOLS = ("bcopy", "bzero")

MEMCCPY_SYMBOLS = ("memccpy",)

MEMPCPY_SYMBOLS = ("mempcpy",)

STRSEP_SYMBOLS = ("strsep",)

STRTOK_SYMBOLS = ("strtok",)

RANDOM_ENTROPY_SYMBOLS = ("getrandom", "getentropy")

MEMORY_SEARCH_SYMBOLS = ("memchr", "memrchr", "memmem")

MEMCCPY_SYMBOLS = ("memccpy",)

AIO_ERROR_SYMBOLS = ("aio_error",)

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

ERROR_STRING_SYMBOLS = ("strerror", "strerror_r", "__xpg_strerror_r")
STRING_DUPLICATION_SYMBOLS = ("strdup", "strndup")

STRSIGNAL_SYMBOLS = ("strsignal",)

L64A_SYMBOLS = ("l64a",)

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

FLOAT_PARSE_SYMBOLS = ("strtof", "strtod", "strtold", "atof")

FLOAT_PARSE_LOCALE_SYMBOLS = (
    "atof",
    "ecvt",
    "fcvt",
    "gcvt",
    "getsubopt",
    "strtod",
    "strtod_l",
    "strtof",
    "strtof_l",
    "strtold",
    "strtold_l",
    "wcstod",
    "wcstof",
    "wcstoimax",
    "wcstol",
    "wcstold",
    "wcstoll",
    "wcstoul",
    "wcstoull",
    "wcstoumax",
    "__strtod_l",
    "__strtof_l",
    "__strtold_l",
)

FLOAT_PARSE_LOCALE_PUBLIC_SYMBOLS = tuple(
    symbol for symbol in FLOAT_PARSE_LOCALE_SYMBOLS if not symbol.startswith("__")
)

STDIO_STANDARD_STREAM_DATA_SYMBOLS = ("stdin", "stdout", "stderr")

STDIO_STANDARD_STREAM_FUNCTION_SYMBOLS = (
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

STDIO_STANDARD_STREAM_SYMBOLS = (
    *STDIO_STANDARD_STREAM_DATA_SYMBOLS,
    *STDIO_STANDARD_STREAM_FUNCTION_SYMBOLS,
)

STDIO_FOPEN64_ALIAS_SYMBOLS = ("fopen64",)

CREDENTIAL_OBSERVATION_SYMBOLS = ("getgroups", "getresuid", "getresgid")

LOGIN_NAME_SYMBOLS = ("getlogin", "getlogin_r")

SECURE_ENVIRONMENT_SYMBOLS = ("secure_getenv",)

CHILD_REAPING_SYMBOLS = ("wait", "waitpid", "waitid")

WAIT_EXTENSION_SYMBOLS = ("wait3", "wait4")

LEGACY_SIGNAL_ALIAS_SYMBOLS = ("bsd_signal", "__sysv_signal")

SYSV_SIGNAL_HELPER_SYMBOLS = ("sighold", "sigignore", "sigrelse", "sigset")

PROCESS_SIGNAL_SYMBOLS = (
    "__libc_current_sigrtmax",
    "__libc_current_sigrtmin",
    "__sysv_signal",
    "bsd_signal",
    "kill",
    "killpg",
    "psiginfo",
    "psignal",
    "raise",
    "sigaction",
    "sigaddset",
    "sigaltstack",
    "sigandset",
    "sigdelset",
    "sigemptyset",
    "sigfillset",
    "sighold",
    "sigignore",
    "siginterrupt",
    "sigisemptyset",
    "sigismember",
    "sigorset",
    "sigpause",
    "sigpending",
    "sigprocmask",
    "sigqueue",
    "sigrelse",
    "sigset",
    "signal",
    "signalfd",
    "sigsuspend",
    "sigtimedwait",
    "sigwait",
    "sigwaitinfo",
)

PROCESS_SIGNAL_FEATURES = (
    "x86-signal-legacy-aliases",
    "x86-signal-sysv-helpers",
    "x86-signal-reporting",
)

PROCESS_SIGNAL_OPT_IN_SYMBOLS = (
    "__sysv_signal",
    "bsd_signal",
    "psiginfo",
    "psignal",
    "sighold",
    "sigignore",
    "sigrelse",
    "sigset",
)

PROCESS_SIGNAL_COMPONENT_RUNNERS = (
    "run_libc_sigrtmax.sh",
    "run_libc_sigrtmin.sh",
    "run_libc_signal_legacy_aliases.sh",
    "run_libc_signal_execution.sh",
    "run_libc_signal_control.sh",
    "run_libc_sigaddset_sigdelset_sigfillset.sh",
    "run_libc_signal_altstack.sh",
    "run_libc_sigandset_sigorset.sh",
    "run_libc_signal_sysv_helpers.sh",
    "run_libc_siginterrupt.sh",
    "run_libc_sigisemptyset.sh",
    "run_libc_sigpause.sh",
    "run_libc_sigpending.sh",
    "run_libc_signalfd.sh",
    "run_libc_readiness_waits.sh",
    "run_libc_psignal.sh",
)

IMMEDIATE_TERMINATION_SYMBOLS = ("_Exit",)
POSIX_EXIT_SYMBOLS = ("_exit",)
SCHED_YIELD_SYMBOLS = ("sched_yield",)
SCHED_GETCPU_SYMBOLS = ("sched_getcpu",)
SCHED_CPUCOUNT_SYMBOLS = ("__sched_cpucount",)
SCHED_PRIORITY_BOUNDS_SYMBOLS = (
    "sched_get_priority_max",
    "sched_get_priority_min",
)

CALLBACK_ALGORITHM_SYMBOLS = ("bsearch", "__qsort_r", "qsort", "qsort_r")

CLOCK_SETTIME_ERROR_ABI_SYMBOLS = ("clock_settime",)

CLOCK_ADJTIME_ERROR_ABI_SYMBOLS = ("clock_adjtime",)

TIMER_GETOVERRUN_ERROR_ABI_SYMBOLS = ("timer_getoverrun",)

TIMER_DELETE_RAW_ERROR_ABI_SYMBOLS = ("timer_delete",)

TIMER_GETTIME_ERROR_ABI_SYMBOLS = ("timer_gettime",)

TIMER_SETTIME_ERROR_ABI_SYMBOLS = ("timer_settime",)

TIME_OBSERVATION_SYMBOLS = (
    "clock",
    "time",
    "timespec_get",
    "clock_getres",
    "gettimeofday",
)

DIFFTIME_BINARY64_SYMBOLS = ("difftime",)

TIMEGM_UTC_SYMBOLS = ("timegm",)

GMTIME_R_UTC_SYMBOLS = ("gmtime_r",)

GETPAGESIZE_SYMBOLS = ("getpagesize",)

MEMORY_SYNC_SYMBOLS = ("msync",)

MEMFD_CREATE_SYMBOLS = ("memfd_create",)

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
    "sem_open",
    "sem_timedwait",
    "sem_unlink",
)

POSIX_SEMAPHORE_SYMBOLS = (
    "sem_destroy",
    "sem_getvalue",
    "sem_init",
    "sem_post",
    "sem_trywait",
    "sem_wait",
)

POSIX_SEMAPHORE_UNSELECTED_SYMBOLS = (
    "sem_close",
    "sem_open",
    "sem_timedwait",
    "sem_unlink",
)

MQ_SETATTR_SYMBOLS = ("mq_setattr",)

MQ_SETATTR_UNSELECTED_SYMBOLS = (
    "mq_close",
    "mq_getattr",
    "mq_notify",
    "mq_open",
    "mq_receive",
    "mq_send",
    "mq_timedreceive",
    "mq_timedsend",
    "mq_unlink",
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
    "mq_timedreceive",
    "mq_timedsend",
    "mq_unlink",
    "sem_close",
    "sem_open",
    "sem_timedwait",
    "sem_unlink",
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
    "aio_fsync",
    "aio_read",
    "aio_return",
    "aio_suspend",
    "aio_write",
    "epoll_pwait2",
    "fanotify_init",
    "fanotify_mark",
    "lio_listio",
    "signalfd4",
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

FCHDIR_SYMBOLS = ("fchdir",)
ULIMIT_SYMBOLS = ("ulimit",)

PATHNAME_LIFECYCLE_UNSELECTED_SYMBOLS = (
    "chroot",
    "fchmodat",
    "realpath",
    "renameat",
    "scandir",
    "symlinkat",
)

DIRECTORY_STREAM_SYMBOLS = (
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
)

DIRECTORY_STREAM_UNSELECTED_SYMBOLS = (
    "calloc",
    "free",
    "malloc",
    "realloc",
    "scandir",
)

FILESYSTEM_DIRECTORY_SYMBOLS = (
    "alphasort",
    "ftw",
    "nftw",
    "readdir_r",
    "scandir",
    "telldir",
    "versionsort",
)

FILESYSTEM_DIRECTORY_FEATURES = (
    "x86-scandir",
    "x86-filesystem-traversal",
)

FILESYSTEM_DIRECTORY_COMPONENT_RUNNERS = (
    "run_libc_directory_streams.sh",
    "run_libc_scandir.sh",
    "run_libc_filesystem_traversal.sh",
)

FILESYSTEM_EXTENSIONS_SYMBOLS = (
    "mktemp",
    "name_to_handle_at",
    "open_by_handle_at",
    "tempnam",
    "tmpnam",
)

FILESYSTEM_EXTENSIONS_FEATURES = (
    "x86-temporary-names",
    "x86-file-handles",
)

FILESYSTEM_EXTENSIONS_COMPONENT_RUNNERS = (
    "run_libc_mktemp.sh",
    "run_libc_file_handles.sh",
    "run_libc_temporary_names.sh",
)

EXTENDED_ATTRIBUTE_SYMBOLS = (
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

EXTENDED_ATTRIBUTE_UNSELECTED_SYMBOLS = (
    "fgetxattrat",
    "flistxattrat",
    "fremovexattrat",
    "fsetxattrat",
    "getxattrat",
    "listxattrat",
    "lgetxattrat",
    "llistxattrat",
    "lremovexattrat",
    "lsetxattrat",
    "removexattrat",
    "setxattrat",
)

INET_ADDRESS_SYMBOLS = (
    "__inet_aton",
    "inet_addr",
    "inet_aton",
    "inet_ntop",
    "inet_pton",
)

NETWORK_BYTE_ORDER_SYMBOLS = (
    "htonl",
    "htons",
    "ntohl",
    "ntohs",
)

IN6ADDR_ANY_SYMBOLS = ("in6addr_any",)
IN6ADDR_LOOPBACK_SYMBOLS = ("in6addr_loopback",)

NUMERIC_NETDB_SYMBOLS = (
    "freeaddrinfo",
    "gai_strerror",
    "getaddrinfo",
    "getnameinfo",
)

HSTRERROR_SYMBOLS = ("hstrerror",)

ENDSERVENT_SYMBOLS = ("endservent",)

PROTOCOL_DATABASE_SYMBOLS = (
    "endprotoent",
    "getprotobyname",
    "getprotobynumber",
    "getprotoent",
    "setprotoent",
)

DN_SKIPNAME_SYMBOLS = ("dn_skipname",)

DN_EXPAND_SYMBOLS = ("__dn_expand", "dn_expand")

NS_FLAGDATA_SYMBOLS = ("_ns_flagdata",)

NS_GET16_SYMBOLS = ("ns_get16",)

NS_GET32_SYMBOLS = ("ns_get32",)

NS_PUT16_SYMBOLS = ("ns_put16",)

NS_PUT32_SYMBOLS = ("ns_put32",)

NS_SKIPRR_SYMBOLS = ("ns_skiprr",)

NAMESER_MESSAGE_PARSER_SYMBOLS = (
    "ns_initparse",
    "ns_parserr",
    "ns_name_uncompress",
)

INET_NTOA_SYMBOLS = ("inet_ntoa",)

GETHOSTID_SYMBOLS = ("gethostid",)
ISSETUGID_SYMBOLS = ("issetugid",)
LEGACY_MISC_SYMBOLS = (
    "encrypt",
    "fmtmsg",
    "get_avphys_pages",
    "get_nprocs",
    "get_nprocs_conf",
    "get_phys_pages",
    "issetugid",
    "setkey",
)
LEGACY_DES_COMPAT_SYMBOLS = ("encrypt", "setkey")
LEGACY_MISC_OPT_IN_SYMBOLS = ("encrypt", "fmtmsg", "setkey")
GETTID_SYMBOLS = ("gettid",)
GETLOADAVG_SYMBOLS = ("getloadavg",)
SLEEP_SYMBOLS = ("sleep",)
POSIX_CLOSE_SYMBOLS = ("posix_close",)
ENDHOSTENT_SYMBOLS = ("endhostent", "endnetent")
SETHOSTENT_SYMBOLS = ("sethostent", "setnetent")

INET_CLASSFUL_SYMBOLS = ("inet_lnaof", "inet_makeaddr")

INET_NETOF_SYMBOLS = ("inet_netof",)

INET_NETWORK_SYMBOLS = ("inet_network",)

GETSUBOPT_SYMBOLS = ("getsubopt",)
BSEARCH_SYMBOLS = ("bsearch",)

LINEAR_SEARCH_SYMBOLS = ("lfind", "lsearch")

INTRUSIVE_QUEUE_SYMBOLS = ("insque", "remque")

QSORT_SYMBOLS = ("qsort",)

INET_ADDRESS_UNSELECTED_SYMBOLS = (
    "calloc",
    "free",
    "gethostbyaddr",
    "gethostbyname",
    "malloc",
    "realloc",
)

PROCESS_GLOBALS_GETOPT_SYMBOLS = (
    "__optpos",
    "__optreset",
    "__posix_getopt",
    "__progname",
    "__progname_full",
    "getopt",
    "getopt_long",
    "getopt_long_only",
    "optarg",
    "opterr",
    "optind",
    "optopt",
    "optreset",
    "program_invocation_name",
    "program_invocation_short_name",
)

# Frozen AArch64 `process.globals` ledger roster, sorted.
PROCESS_GLOBALS_SYMBOLS = tuple(sorted((
    "___environ", "__daylight", "__environ", "__h_errno_location", "__optpos",
    "__optreset", "__progname", "__progname_full", "__signgam", "__timezone",
    "__tzname", "_environ", "__posix_getopt", "daylight", "environ", "getenv",
    "getopt", "getopt_long", "getopt_long_only", "h_errno", "optarg", "opterr",
    "optind", "optopt", "optreset", "program_invocation_name",
    "program_invocation_short_name", "putenv", "signgam", "timezone", "tzname",
)))

SEARCH_TREE_INTRUSIVE_SYMBOLS = (
    "tdelete",
    "tdestroy",
    "tfind",
    "tsearch",
    "twalk",
)

SEARCH_HASH_TABLE_SYMBOLS = (
    "hcreate",
    "hcreate_r",
    "hdestroy",
    "hdestroy_r",
    "hsearch",
    "hsearch_r",
)

GETTEXT_CATALOG_SYMBOLS = (
    "bind_textdomain_codeset",
    "bindtextdomain",
    "catclose",
    "catgets",
    "catopen",
    "dcgettext",
    "dcngettext",
    "dgettext",
    "dngettext",
    "gettext",
    "ngettext",
    "textdomain",
)

QSORT_HELPER_SYMBOLS = ("__qsort_r",)

AUXV_OBSERVATION_SYMBOLS = ("__getauxval", "getauxval")

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

COMPLEX_PROJECTION_SYMBOLS = ("cproj", "cprojf", "cprojl")

ELEMENTARY_SQRT_FENV_SYMBOLS = ("sqrt", "sqrtf", "sqrtl")

FENV_SENSITIVE_ROUNDING_SYMBOLS = (
    "nearbyint",
    "nearbyintf",
    "nearbyintl",
    "rint",
    "rintf",
    "rintl",
)

MATH_ELEMENTARY_FENV_SENSITIVE_SYMBOLS = (
    "exp10",
    "exp10f",
    "exp10l",
    "fdim",
    "fdimf",
    "fdiml",
    "nearbyint",
    "nearbyintf",
    "nearbyintl",
    "pow10",
    "pow10f",
    "pow10l",
    "rint",
    "rintf",
    "rintl",
)

MATH_X87_EXTENDED_SYMBOLS = (
    "acosl",
    "asinl",
    "atanl",
    "atan2l",
    "ceill",
    "exp2l",
    "expl",
    "expm1l",
    "fabsl",
    "floorl",
    "fmodl",
    "log10l",
    "log1pl",
    "log2l",
    "logl",
    "lrintl",
    "llrintl",
    "rintl",
    "remainderl",
    "remquol",
    "sqrtl",
    "truncl",
)

MATH_X87_EXTENDED_LOCAL_SYMBOLS = tuple(
    symbol for symbol in MATH_X87_EXTENDED_SYMBOLS
    if symbol not in ("rintl", "sqrtl")
)

MATH_ELEMENTARY_LONG_DOUBLE_SYMBOLS = (
    "acoshl",
    "acosl",
    "asinhl",
    "asinl",
    "atan2l",
    "atanhl",
    "atanl",
    "cbrtl",
    "ceill",
    "copysignl",
    "coshl",
    "cosl",
    "exp2l",
    "expl",
    "expm1l",
    "fabsl",
    "floorl",
    "fmal",
    "fmaxl",
    "fminl",
    "fmodl",
    "hypotl",
    "log10l",
    "log1pl",
    "log2l",
    "logl",
    "powl",
    "roundl",
    "sincosl",
    "sinhl",
    "sinl",
    "sqrtl",
    "tanhl",
    "tanl",
    "truncl",
)

MATH_COMPLEX_COMPLETE_SYMBOLS = (
    "cabs", "cabsf", "cabsl", "cacos", "cacosf", "cacosh", "cacoshf",
    "cacoshl", "cacosl", "carg", "cargf", "cargl", "casin", "casinf",
    "casinh", "casinhf", "casinhl", "casinl", "catan", "catanf",
    "catanh", "catanhf", "catanhl", "catanl", "ccos", "ccosf", "ccosh",
    "ccoshf", "ccoshl", "ccosl", "cexp", "cexpf", "cexpl", "cimag",
    "cimagf", "cimagl", "clog", "clogf", "clogl", "conj", "conjf",
    "conjl", "cpow", "cpowf", "cpowl", "cproj", "cprojf", "cprojl",
    "creal", "crealf", "creall", "csin", "csinf", "csinh", "csinhf",
    "csinhl", "csinl", "csqrt", "csqrtf", "csqrtl", "ctan", "ctanf",
    "ctanh", "ctanhf", "ctanhl", "ctanl",
)

MATH_SPECIAL_SYMBOLS = (
    "__fpclassify", "__fpclassifyf", "__fpclassifyl", "__lgammal_r",
    "__signbit", "__signbitf", "__signbitl", "drem", "dremf", "erf",
    "erfc", "erfcf", "erfcl", "erff", "erfl", "finite", "finitef",
    "frexp", "frexpf", "frexpl", "ilogb", "ilogbf", "ilogbl", "j0",
    "j0f", "j1", "j1f", "jn", "jnf", "ldexp", "ldexpf", "ldexpl",
    "lgamma", "lgamma_r", "lgammaf", "lgammaf_r", "lgammal",
    "lgammal_r", "llrint", "llrintf", "llrintl", "llround", "llroundf",
    "llroundl", "logb", "logbf", "logbl", "lrint", "lrintf", "lrintl",
    "lround", "lroundf", "lroundl", "modf", "modff", "modfl", "nan",
    "nanf", "nanl", "nextafter", "nextafterf", "nextafterl", "nexttoward",
    "nexttowardf", "nexttowardl", "remainder", "remainderf", "remainderl",
    "remquo", "remquof", "remquol", "scalb", "scalbf", "scalbln",
    "scalblnf", "scalblnl", "scalbn", "scalbnf", "scalbnl",
    "significand", "significandf", "tgamma", "tgammaf", "tgammal", "y0",
    "y0f", "y1", "y1f", "yn", "ynf",
)

FDIM_SYMBOLS = ("fdim", "fdimf")

MATH_MINMAX_SYMBOLS = ("fmax", "fmaxf", "fmin", "fminf")

MATH_BIT_SIGN_SYMBOLS = ("fabs", "fabsf", "copysign", "copysignf")

MATH_TRUNC_SYMBOLS = ("trunc", "truncf")

MATH_FMOD_SYMBOLS = ("fmod", "fmodf")

MATH_CBRT_SYMBOLS = ("cbrt", "cbrtf")

MATH_EXP2_SYMBOLS = ("exp2", "exp2f")

MATH_EXPM1_SYMBOLS = ("expm1", "expm1f")

MATH_LOG10_SYMBOLS = ("log10", "log10f")

MATH_CEIL_SYMBOLS = ("ceil", "ceilf")

MATH_FLOOR_SYMBOLS = ("floor", "floorf")

MATH_ROUND_SYMBOLS = ("round", "roundf")

MATH_LOG2_SYMBOLS = ("log2", "log2f")

NAMED_LOCALE_MULTIBYTE_SYMBOLS = (
    "__ctype_get_mb_cur_max",
    "btowc",
    "localeconv",
    "mblen",
    "mbrlen",
    "mbrtowc",
    "mbsinit",
    "mbsrtowcs",
    "mbstowcs",
    "mbtowc",
    "setlocale",
    "wcrtomb",
    "wcsrtombs",
    "wcstombs",
    "wctob",
    "wctomb",
)
LOCALE_PROFILE_SYMBOLS = ("setlocale", "localeconv")

BOUNDED_REGEX_SYMBOLS = (
    "regcomp",
    "regexec",
    "regerror",
    "regfree",
)
LOCALE_WIDE_ICONV_SYMBOLS = ("iconv_open", "iconv", "iconv_close")
WIDE_CHARACTER_SYMBOLS = (
    "wcslen", "wcsnlen", "wcscpy", "wcsncpy", "wcpcpy", "wcpncpy",
    "wcscat", "wcsncat", "wcscmp", "wcsncmp", "wcschr", "wcsrchr",
    "wcsstr", "wcscspn", "wcsspn", "wcspbrk", "wcsxfrm", "wcscoll",
    "wcstok", "wcscasecmp", "wcsncasecmp", "wmemchr", "wmemcmp",
    "wmemcpy", "wmemmove", "wmemset", "wcwidth", "wcswidth",
    "iswalnum", "iswalpha", "iswblank", "iswcntrl", "iswdigit",
    "iswgraph", "iswlower", "iswprint", "iswpunct", "iswspace",
    "iswupper", "iswxdigit", "iswctype", "wctype", "towlower",
    "towupper", "towctrans", "wctrans",
)
WCSWCS_SYMBOLS = ("wcswcs",)
LOCALE_OBJECT_WIDE_SYMBOLS = (
    "newlocale", "freelocale", "uselocale", "duplocale", "nl_langinfo",
    "nl_langinfo_l", "iswalnum_l", "iswalpha_l", "iswblank_l",
    "iswcntrl_l", "iswdigit_l", "iswgraph_l", "iswlower_l",
    "iswprint_l", "iswpunct_l", "iswspace_l", "iswupper_l",
    "iswxdigit_l", "iswctype_l", "wctype_l", "towlower_l",
    "towupper_l", "towctrans_l", "wctrans_l", "wcscasecmp_l",
    "wcsncasecmp_l", "wcscoll_l", "wcsxfrm_l",
)
LOCALE_NARROW_SYMBOLS = (
    "isalnum_l", "isalpha_l", "isblank_l", "iscntrl_l", "isdigit_l",
    "isgraph_l", "islower_l", "isprint_l", "ispunct_l", "isspace_l",
    "isupper_l", "isxdigit_l", "tolower_l", "toupper_l", "strcasecmp",
    "strcasecmp_l", "strncasecmp", "strncasecmp_l", "strcoll",
    "strcoll_l", "strxfrm", "strxfrm_l",
)
LOCALE_CTYPE_LOCATOR_SYMBOLS = (
    "__ctype_b_loc",
    "__ctype_tolower_loc",
    "__ctype_toupper_loc",
)
LOCALE_ERROR_STRING_SYMBOLS = ("__strerror_l", "strerror_l")


class LedgerError(ValueError):
    """The parity ledger does not describe a reviewable closed contract."""


VerifiedArtifactCacheEntry = tuple[
    object,
    str,
    tuple[Mapping[str, Any], ...],
]

# A ledger pass has many named checks over the same verified-artifact lists.
# Keep only already-successful structural validation in the current pass: a
# later call, a direct helper call, and an invalid list must each validate
# independently. ContextVar keeps nested or concurrent validation isolated.
_verified_artifact_cache: ContextVar[
    dict[int, VerifiedArtifactCacheEntry] | None
] = ContextVar("x86_verified_artifact_cache", default=None)


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


def require_aarch64_parity_inventory() -> None:
    """Run the checked derived AArch64-to-x86 inventory beside this ledger."""
    require(
        AARCH64_PARITY_INVENTORY_VALIDATOR_PATH.is_file(),
        "checked AArch64 parity inventory validator is missing",
    )
    specification = importlib.util.spec_from_file_location(
        "_checked_x86_aarch64_parity_inventory",
        AARCH64_PARITY_INVENTORY_VALIDATOR_PATH,
    )
    require(
        specification is not None and specification.loader is not None,
        "cannot load checked AArch64 parity inventory validator",
    )
    module = importlib.util.module_from_spec(specification)
    try:
        specification.loader.exec_module(module)
        validate = getattr(module, "validate_inventory")
        report = validate()
    except Exception as error:  # Recast a nested evidence failure at this boundary.
        raise LedgerError(f"AArch64 parity inventory failed: {error}") from error
    require(isinstance(report, Mapping), "AArch64 parity inventory report is invalid")
    frozen_baseline = report.get("frozen_baseline")
    require(
        isinstance(frozen_baseline, Mapping),
        "AArch64 parity inventory frozen baseline is invalid",
    )
    require(
        frozen_baseline.get("schema")
        == "crabc.x86_64-frozen-aarch64-baseline/v1",
        "AArch64 parity inventory frozen baseline schema is invalid",
    )
    boundary = report.get("x86_boundary")
    require(isinstance(boundary, Mapping), "AArch64 parity inventory x86 boundary is invalid")
    baseline = report.get("baseline")
    require(isinstance(baseline, Mapping), "AArch64 parity inventory baseline is invalid")
    require(
        frozen_baseline.get("capability_count") == baseline.get("capability_count"),
        "AArch64 parity inventory frozen capability count is invalid",
    )
    require(
        frozen_baseline.get("required_family_count")
        == boundary.get("promotion_family_count"),
        "AArch64 parity inventory frozen family count is invalid",
    )
    require(boundary.get("promotion_ready") is False, "AArch64 parity inventory must retain promotion_ready=false")
    require(boundary.get("public_support") is False, "AArch64 parity inventory must retain public_support=false")


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
        family.get("status") == "foundation-verified",
        "libc.headers-layouts must be foundation-verified while its direct manifest remains partial",
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


def validate_feature_archive_roster(
    data: Mapping[str, Any], verified_records: Mapping[str, Mapping[str, Any]]
) -> dict[str, int]:
    """Bind every x86 Cargo feature profile to its explicit archive evidence."""

    try:
        rows = parse_feature_archive_roster(
            data.get("feature_archive"), load_cargo_x86_features()
        )
        return validate_ledger_bindings(
            rows,
            static_exports=static_c_abi_export_names(STATIC_C_ABI_EXPORTS_PATH),
            verified_records=verified_records,
            dispatcher_path=X86_64_DISPATCHER_PATH,
        )
    except FeatureArchiveRosterError as error:
        raise LedgerError(str(error)) from error


def require_header_callable_visibility_matrix(
    manifest: Mapping[str, Any],
) -> int:
    """Keep the all-header callable visibility report finite and non-promoting."""

    matrix = manifest["callable_feature_visibility_matrix"]
    require(isinstance(matrix, Mapping), "header-foundation callable visibility matrix must be a table")
    require(
        set(matrix)
        == {
            "id",
            "state",
            "contract",
            "generated_report",
            "command",
            "required_result",
            "profiles",
            "pinned_public_header_count",
            "candidate_public_header_count",
            "record_count",
            "scope",
        },
        "header-foundation callable visibility matrix keys drifted",
    )
    require(
        matrix["id"] == "all-header-callable-feature-visibility-matrix",
        "header-foundation callable visibility matrix id drifted",
    )
    require(
        matrix["state"] == "partial-verified"
        and matrix["required_result"] == "checked-finite-report",
        "header-foundation callable visibility matrix must remain a checked partial report",
    )
    contract_path = repository_path(
        str(matrix["contract"]), "header-foundation callable visibility matrix contract"
    )
    report_path = repository_path(
        str(matrix["generated_report"]), "header-foundation callable visibility matrix report"
    )
    require(
        contract_path == HEADER_CALLABLE_VISIBILITY_MATRIX_CONTRACT_PATH,
        "header-foundation callable visibility matrix contract path drifted",
    )
    require(
        report_path == HEADER_CALLABLE_VISIBILITY_MATRIX_REPORT_PATH,
        "header-foundation callable visibility matrix report path drifted",
    )
    command = "./scripts/dev-x86_64.sh header-callable-visibility-matrix"
    require(matrix["command"] == command, "header-foundation callable visibility matrix command drifted")
    expected_profiles = (
        "c11-gnu",
        "cxx17-gnu",
        "c11-strict",
        "c11-posix-2008",
        "c11-xopen-700",
        "c11-bsd",
        "cxx17-strict",
    )
    require(
        tuple(string_list(matrix["profiles"], "header-foundation callable visibility profiles"))
        == expected_profiles,
        "header-foundation callable visibility profile roster drifted",
    )
    require(
        matrix["pinned_public_header_count"] == EXPECTED_PUBLIC_HEADER_COUNT
        and matrix["candidate_public_header_count"]
        == EXPECTED_PUBLIC_HEADER_COUNT + len(EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY)
        and matrix["record_count"] == EXPECTED_CANDIDATE_HEADER_CLOSURE_RECORD_COUNT,
        "header-foundation callable visibility matrix count contract drifted",
    )
    require(
        isinstance(matrix["scope"], str)
        and "callable name-and-class visibility" in matrix["scope"]
        and "prototype and macro-replacement equality" in matrix["scope"]
        and "reviewed native callable extension" in matrix["scope"]
        and "archive linkage, runtime behavior, family promotion, and public support" in matrix["scope"],
        "header-foundation callable visibility matrix must retain its non-completion scope",
    )

    try:
        contract = load_callable_visibility_contract()
        report = build_callable_visibility_report(contract)
    except MatrixError as error:
        raise LedgerError(f"callable visibility matrix input is invalid: {error}") from error
    require(
        contract.inventory == ROOT / "compat" / "x86_64" / "header_callable_inventory.json"
        and contract.public_headers == PUBLIC_HEADER_INVENTORY_PATH
        and contract.generated_report == report_path
        and contract.callable_extension_contract == HEADER_CALLABLE_EXTENSION_CONTRACT_PATH
        and contract.profiles == expected_profiles,
        "callable visibility matrix contract inputs drifted",
    )
    rendered = canonical_callable_visibility_json(report)
    try:
        checked = report_path.read_text(encoding="utf-8")
    except OSError as error:
        raise LedgerError(f"cannot read checked callable visibility matrix: {error}") from error
    require(
        checked == rendered,
        "checked callable visibility matrix is stale; regenerate with --write",
    )
    summary = report.get("summary")
    require(isinstance(summary, Mapping), "callable visibility matrix summary is invalid")
    require(
        summary
        == {
            "candidate_only_callable_count": 28,
            "candidate_public_header_count": 191,
            "comparable_row_count": 1252,
            "comparison_counts": {
                "candidate-only-reviewed-native-callable-extension": 28,
                "candidate-only-reviewed-project-c-abi-extension": 56,
                "matched": 1252,
                "oracle-not-applicable": 1,
            },
            "complete": False,
            "incomplete_reasons": [
                "1 pinned-musl header/profile rows are oracle-not-applicable",
            ],
            "matched_callable_count": 34692,
            "mismatch_row_count": 0,
            "oracle_not_applicable_candidate_visible_callable_count": 21,
            "oracle_not_applicable_row_count": 1,
            "pinned_public_header_count": 183,
            "pinned_row_count": 1281,
            "profile_count": 7,
            "project_only_callable_count": 407,
            "project_only_header_count": 8,
            "project_only_row_count": 56,
            "reference_only_callable_count": 0,
            "reviewed_native_callable_extension_callable_count": 28,
            "reviewed_native_callable_extension_row_count": 28,
            "row_count": 1337,
        },
        "callable visibility matrix finite baseline drifted",
    )
    scope = report.get("scope")
    require(
        isinstance(scope, Mapping)
        and scope.get("compiler_derived_inventory") is True
        and scope.get("direct_public_include_visibility") is True
        and scope.get("callable_names_and_classes_only") is True
        and scope.get("prototype_or_macro_replacement_equality") is False
        and scope.get("noncallable_abi") is False
        and scope.get("linkage_or_runtime") is False
        and scope.get("reviewed_native_callable_extensions") is True
        and scope.get("family_promotion") is False
        and scope.get("public_support") is False,
        "callable visibility matrix scope drifted",
    )
    require(
        HEADER_CALLABLE_VISIBILITY_MATRIX_RUNNER_PATH.is_file(),
        "header callable visibility matrix runner is missing",
    )
    runner = HEADER_CALLABLE_VISIBILITY_MATRIX_RUNNER_PATH.read_text(encoding="utf-8")
    for phrase in (
        "header_callable_inventory.py",
        "header_callable_visibility_matrix.py",
        "--check",
        "checked finite report",
        "requires native Linux",
    ):
        require(phrase in runner, f"header callable visibility matrix runner omits {phrase}")
    dispatch = X86_64_DISPATCHER_PATH.read_text(encoding="utf-8")
    require(
        "header-callable-visibility-matrix)" in dispatch,
        "header callable visibility matrix is absent from the native dispatcher",
    )
    return int(summary["row_count"])


def require_header_abi_matrix(manifest: Mapping[str, Any]) -> int:
    """Bind the finite prototype/named-ABI report without promoting headers."""

    matrix = manifest["prototype_layout_matrix"]
    require(isinstance(matrix, Mapping), "header-foundation prototype/layout matrix must be a table")
    require(
        set(matrix)
        == {
            "id",
            "state",
            "contract",
            "generated_report",
            "command",
            "required_result",
            "profiles",
            "pinned_public_header_count",
            "candidate_public_header_count",
            "record_count",
            "comparison_counts",
            "mismatch_fact_counts",
            "scope",
        },
        "header-foundation prototype/layout matrix keys drifted",
    )
    require(
        matrix["id"] == "generated-x86-prototype-layout-matrix"
        and matrix["state"] == "partial-verified"
        and matrix["required_result"] == "checked-finite-report",
        "header-foundation prototype/layout matrix identity drifted",
    )
    contract_path = repository_path(
        str(matrix["contract"]), "header-foundation prototype/layout matrix contract"
    )
    report_path = repository_path(
        str(matrix["generated_report"]), "header-foundation prototype/layout matrix report"
    )
    require(
        contract_path == HEADER_ABI_MATRIX_CONTRACT_PATH
        and report_path == HEADER_ABI_MATRIX_REPORT_PATH,
        "header-foundation prototype/layout matrix paths drifted",
    )
    require(
        matrix["command"] == EXPECTED_HEADER_ABI_MATRIX_COMMAND,
        "header-foundation prototype/layout matrix command drifted",
    )
    require(
        tuple(string_list(matrix["profiles"], "header-foundation prototype/layout matrix profiles"))
        == EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES,
        "header-foundation prototype/layout matrix profile roster drifted",
    )
    require(
        matrix["pinned_public_header_count"] == EXPECTED_PUBLIC_HEADER_COUNT
        and matrix["candidate_public_header_count"]
        == EXPECTED_PUBLIC_HEADER_COUNT + len(EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY)
        and matrix["record_count"] == EXPECTED_CANDIDATE_HEADER_CLOSURE_RECORD_COUNT
        and matrix["comparison_counts"] == EXPECTED_HEADER_ABI_MATRIX_SUMMARY["comparison_counts"]
        and matrix["mismatch_fact_counts"]
        == EXPECTED_HEADER_ABI_MATRIX_SUMMARY["mismatch_fact_counts"],
        "header-foundation prototype/layout matrix count contract drifted",
    )
    scope = matrix["scope"]
    require(
        isinstance(scope, str)
        and "function signatures" in scope
        and "named typedefs" in scope
        and "macro replacement forms" in scope
        and "record byte layouts" in scope
        and "reviewed native callable extension" in scope
        and "archive linkage, runtime behavior, family promotion, or public support" in scope,
        "header-foundation prototype/layout matrix must retain its partial scope",
    )

    try:
        contract = load_header_abi_matrix_contract()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        require(isinstance(report, Mapping), "checked header ABI matrix report must be a table")
        validate_header_abi_matrix_report(report, contract)
    except (HeaderAbiMatrixError, OSError, json.JSONDecodeError) as error:
        raise LedgerError(f"header ABI matrix input is invalid: {error}") from error
    require(
        contract.generated_report == report_path
        and contract.public_headers == PUBLIC_HEADER_INVENTORY_PATH
        and contract.callable_extension_contract == HEADER_CALLABLE_EXTENSION_CONTRACT_PATH
        and contract.callable_inventory
        == ROOT / "compat" / "x86_64" / "header_callable_inventory.json",
        "header ABI matrix contract inputs drifted",
    )
    summary = report["summary"]
    require(
        summary == EXPECTED_HEADER_ABI_MATRIX_SUMMARY,
        "header ABI matrix finite baseline drifted",
    )

    require(HEADER_ABI_MATRIX_RUNNER_PATH.is_file(), "header ABI matrix runner is missing")
    runner = HEADER_ABI_MATRIX_RUNNER_PATH.read_text(encoding="utf-8")
    for phrase in (
        "header_abi_matrix.py",
        "--check",
        "Pinned musl",
        "Linux 5.10",
        "partial declaration-form inventory",
        "requires native Linux",
    ):
        require(phrase in runner, f"header ABI matrix runner omits {phrase}")
    dispatch = X86_64_DISPATCHER_PATH.read_text(encoding="utf-8")
    require(
        "header-abi-matrix)" in dispatch,
        "header ABI matrix is absent from the native dispatcher",
    )
    return int(summary["row_count"])


def require_header_record_layout_matrix(manifest: Mapping[str, Any]) -> int:
    """Bind finite record-byte-layout facts without promoting headers."""

    matrix = manifest["record_layout_matrix"]
    require(
        isinstance(matrix, Mapping),
        "header-foundation record byte-layout matrix must be a table",
    )
    require(
        set(matrix)
        == {
            "id",
            "state",
            "contract",
            "generated_report",
            "command",
            "required_result",
            "profiles",
            "pinned_public_header_count",
            "candidate_public_header_count",
            "record_count",
            "comparison_counts",
            "candidate_record_count",
            "reference_record_count",
            "candidate_record_categories",
            "reference_record_categories",
            "candidate_field_categories",
            "reference_field_categories",
            "scope",
        },
        "header-foundation record byte-layout matrix keys drifted",
    )
    require(
        matrix["id"] == "all-header-record-byte-layout-matrix"
        and matrix["state"] == "partial-verified"
        and matrix["required_result"] == "checked-finite-report",
        "header-foundation record byte-layout matrix identity drifted",
    )
    contract_path = repository_path(
        str(matrix["contract"]), "header-foundation record byte-layout matrix contract"
    )
    report_path = repository_path(
        str(matrix["generated_report"]), "header-foundation record byte-layout matrix report"
    )
    require(
        contract_path == HEADER_RECORD_LAYOUT_MATRIX_CONTRACT_PATH
        and report_path == HEADER_RECORD_LAYOUT_MATRIX_REPORT_PATH,
        "header-foundation record byte-layout matrix paths drifted",
    )
    require(
        matrix["command"] == EXPECTED_HEADER_RECORD_LAYOUT_MATRIX_COMMAND,
        "header-foundation record byte-layout matrix command drifted",
    )
    require(
        tuple(string_list(matrix["profiles"], "header-foundation record byte-layout matrix profiles"))
        == EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES,
        "header-foundation record byte-layout matrix profile roster drifted",
    )
    summary = EXPECTED_HEADER_RECORD_LAYOUT_MATRIX_SUMMARY
    require(
        matrix["pinned_public_header_count"] == EXPECTED_PUBLIC_HEADER_COUNT
        and matrix["candidate_public_header_count"]
        == EXPECTED_PUBLIC_HEADER_COUNT + len(EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY)
        and matrix["record_count"] == EXPECTED_CANDIDATE_HEADER_CLOSURE_RECORD_COUNT
        and matrix["comparison_counts"] == summary["comparison_counts"]
        and matrix["candidate_record_count"] == summary["candidate_record_count"]
        and matrix["reference_record_count"] == summary["reference_record_count"]
        and matrix["candidate_record_categories"] == summary["candidate_record_categories"]
        and matrix["reference_record_categories"] == summary["reference_record_categories"]
        and matrix["candidate_field_categories"] == summary["candidate_field_categories"]
        and matrix["reference_field_categories"] == summary["reference_field_categories"],
        "header-foundation record byte-layout matrix count contract drifted",
    )
    scope = matrix["scope"]
    require(
        isinstance(scope, str)
        and "complete named records" in scope
        and "named field offsets" in scope
        and "non-addressable" in scope
        and "archive linkage, runtime behavior, family promotion, or public support" in scope,
        "header-foundation record byte-layout matrix must retain its partial scope",
    )

    try:
        contract = load_header_record_layout_matrix_contract()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        require(isinstance(report, Mapping), "checked record byte-layout matrix report must be a table")
        validate_header_record_layout_matrix_report(report, contract)
    except (RecordLayoutMatrixError, OSError, json.JSONDecodeError) as error:
        raise LedgerError(f"record byte-layout matrix input is invalid: {error}") from error
    require(
        contract.generated_report == report_path
        and contract.public_headers == PUBLIC_HEADER_INVENTORY_PATH
        and contract.callable_inventory
        == ROOT / "compat" / "x86_64" / "header_callable_inventory.json",
        "record byte-layout matrix contract inputs drifted",
    )
    report_summary = report["summary"]
    require(
        report_summary == EXPECTED_HEADER_RECORD_LAYOUT_MATRIX_SUMMARY,
        "record byte-layout matrix finite baseline drifted",
    )

    require(
        HEADER_RECORD_LAYOUT_MATRIX_RUNNER_PATH.is_file(),
        "record byte-layout matrix runner is missing",
    )
    runner = HEADER_RECORD_LAYOUT_MATRIX_RUNNER_PATH.read_text(encoding="utf-8")
    for phrase in (
        "header_record_layout_matrix.py",
        "--check",
        "pinned musl",
        "Linux 5.10",
        "checked 1,337-row matrix",
        "foundation-verified",
        "requires native Linux",
    ):
        require(phrase in runner, f"record byte-layout matrix runner omits {phrase}")
    dispatch = X86_64_DISPATCHER_PATH.read_text(encoding="utf-8")
    require(
        "header-record-layout-matrix)" in dispatch,
        "record byte-layout matrix is absent from the native dispatcher",
    )
    return int(report_summary["row_count"])


def require_header_declaration_macro_visibility_matrix(
    manifest: Mapping[str, Any],
) -> int:
    """Bind the derived generic visibility report below header-family promotion."""

    matrix = manifest["feature_visibility_matrix"]
    require(
        isinstance(matrix, Mapping),
        "header-foundation declaration/macro visibility matrix must be a table",
    )
    require(
        set(matrix)
        == {
            "id",
            "state",
            "contract",
            "generated_report",
            "command",
            "required_result",
            "profiles",
            "pinned_public_header_count",
            "candidate_public_header_count",
            "record_count",
            "comparison_counts",
            "identity_difference_counts",
            "source_form_difference_count",
            "source_form_difference_row_count",
            "source_form_only_difference_row_count",
            "scope",
        },
        "header-foundation declaration/macro visibility matrix keys drifted",
    )
    require(
        matrix["id"] == "all-header-declaration-macro-feature-visibility-matrix"
        and matrix["state"] == "partial-verified"
        and matrix["required_result"] == "checked-finite-report",
        "header-foundation declaration/macro visibility matrix identity drifted",
    )
    contract_path = repository_path(
        str(matrix["contract"]), "header-foundation declaration/macro visibility matrix contract"
    )
    report_path = repository_path(
        str(matrix["generated_report"]), "header-foundation declaration/macro visibility matrix report"
    )
    require(
        contract_path == HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_CONTRACT_PATH
        and report_path == HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_REPORT_PATH,
        "header-foundation declaration/macro visibility matrix paths drifted",
    )
    require(
        matrix["command"] == EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_COMMAND,
        "header-foundation declaration/macro visibility matrix command drifted",
    )
    require(
        tuple(
            string_list(matrix["profiles"], "header-foundation declaration/macro visibility profiles")
        )
        == EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES,
        "header-foundation declaration/macro visibility profile roster drifted",
    )
    require(
        matrix["pinned_public_header_count"] == EXPECTED_PUBLIC_HEADER_COUNT
        and matrix["candidate_public_header_count"]
        == EXPECTED_PUBLIC_HEADER_COUNT + len(EXPECTED_PUBLIC_HEADER_CANDIDATE_ONLY)
        and matrix["record_count"] == EXPECTED_CANDIDATE_HEADER_CLOSURE_RECORD_COUNT
        and matrix["comparison_counts"]
        == EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_SUMMARY["comparison_counts"]
        and matrix["identity_difference_counts"]
        == {
            "candidate_only": EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_SUMMARY[
                "candidate_only_identity_count"
            ],
            "reference_only": EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_SUMMARY[
                "reference_only_identity_count"
            ],
        }
        and matrix["source_form_difference_count"]
        == EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_SUMMARY[
            "source_form_difference_count"
        ]
        and matrix["source_form_difference_row_count"]
        == EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_SUMMARY[
            "source_form_difference_row_count"
        ]
        and matrix["source_form_only_difference_row_count"]
        == EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_SUMMARY[
            "source_form_only_difference_row_count"
        ],
        "header-foundation declaration/macro visibility matrix count contract drifted",
    )
    scope = matrix["scope"]
    require(
        isinstance(scope, str)
        and "named function, typedef, record, enum, variable, and macro identities" in scope
        and "same-identity source-form differences" in scope
        and "checked candidate fact summaries and digests" in scope
        and "reviewed native callable extension" in scope
        and "declaration-form equality, macro replacements, record byte layouts" in scope
        and "archive linkage, runtime behavior, family promotion, and public support" in scope,
        "header-foundation declaration/macro visibility matrix must retain its partial scope",
    )

    try:
        contract = load_declaration_macro_visibility_contract()
        checked = report_path.read_text(encoding="utf-8")
        report = json.loads(checked)
        require(isinstance(report, Mapping), "checked declaration/macro visibility report must be a table")
        validate_declaration_macro_visibility_report(report, contract)
    except (
        HeaderDeclarationMacroVisibilityMatrixError,
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise LedgerError(f"declaration/macro visibility matrix input is invalid: {error}") from error
    require(
        contract.source_abi_contract == HEADER_ABI_MATRIX_CONTRACT_PATH
        and contract.source_abi_report == HEADER_ABI_MATRIX_REPORT_PATH
        and contract.callable_visibility_contract == HEADER_CALLABLE_VISIBILITY_MATRIX_CONTRACT_PATH
        and contract.callable_extension_contract == HEADER_CALLABLE_EXTENSION_CONTRACT_PATH
        and contract.public_headers == PUBLIC_HEADER_INVENTORY_PATH
        and contract.generated_report == report_path
        and contract.profiles == EXPECTED_HEADER_FOUNDATION_CLOSURE_PROFILES,
        "declaration/macro visibility matrix contract inputs drifted",
    )
    require(
        checked == canonical_declaration_macro_visibility_json(report),
        "checked declaration/macro visibility report is not canonical",
    )
    summary = report["summary"]
    require(
        summary == EXPECTED_HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_SUMMARY,
        "declaration/macro visibility matrix finite baseline drifted",
    )
    scope_report = report["scope"]
    require(
        isinstance(scope_report, Mapping)
        and scope_report.get("derived_from_checked_declaration_form_matrix") is True
        and scope_report.get("compiler_derived_source") is True
        and scope_report.get("named_declaration_and_macro_identity") is True
        and scope_report.get("declaration_form_equality") is False
        and scope_report.get("record_byte_layouts") is False
        and scope_report.get("archive_linkage") is False
        and scope_report.get("runtime") is False
        and scope_report.get("reviewed_native_callable_extensions") is True
        and scope_report.get("family_promotion") is False
        and scope_report.get("public_support") is False,
        "declaration/macro visibility matrix scope drifted",
    )
    require(
        HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_RUNNER_PATH.is_file(),
        "declaration/macro visibility matrix runner is missing",
    )
    runner = HEADER_DECLARATION_MACRO_VISIBILITY_MATRIX_RUNNER_PATH.read_text(encoding="utf-8")
    for phrase in (
        "run_header_abi_matrix.sh",
        "header_declaration_macro_visibility_matrix.py",
        "--check",
        "identity report",
        "requires native Linux",
    ):
        require(phrase in runner, f"declaration/macro visibility matrix runner omits {phrase}")
    dispatch = X86_64_DISPATCHER_PATH.read_text(encoding="utf-8")
    require(
        "header-declaration-macro-visibility-matrix)" in dispatch,
        "declaration/macro visibility matrix is absent from the native dispatcher",
    )
    return int(summary["row_count"])


def validate_header_layout_foundation_manifest(
    family: Mapping[str, Any],
    legacy_manifest: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, int]:
    """Validate the completed all-header foundation without public promotion.

    The v14 contract resolves every current pathname into one class and expands
    every class into explicit language/feature obligations. It pins the one
    Linux-UAPI input, resolves selected UAPI-wrapper, ioctl-header, x86 sys/io
    inline-port-I/O, epoll-header, timeval-transitive, direct sys/time, and
    access-header ABI matrices, and
    verifies a seven-profile empty-TU closure diagnostic with two explicit
    pinned-musl aio.h strict-profile applicability results. It now records an
    explicit default/feature/unprovided callable provider partition while
    keeps complete archive extraction and general declaration/layout closure
    planned while the checked derived declaration/macro identity matrix makes
    the remaining generic feature-visibility differences finite.
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
        "header_completion_assessment",
        "aggregate_control",
        "profile_matrix",
        "uapi_input",
        "uapi_wrapper_matrix",
        "ioctl_header_profile_matrix",
        "sys_io_header_profile_matrix",
        "epoll_header_profile_matrix",
        "event_descriptors_header_profile_matrix",
        "dirent_header_profile_matrix",
        "stdlib_header_profile_matrix",
        "timeval_transitive_header_profile_matrix",
        "sys_time_direct_header_profile_matrix",
        "access_header_profile_matrix",
        "xattr_header_profile_matrix",
        "closure_diagnostic",
        "feature_visibility_matrix",
        "callable_feature_visibility_matrix",
        "prototype_layout_matrix",
        "record_layout_matrix",
        "callable_disposition",
        "selected_callable_provider_linkage_audit",
        "selected_header_install_projection",
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
    require(
        manifest["status"] == "foundation-verified",
        "header-foundation manifest must be foundation-verified",
    )
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
            "selected_header_install_projection": True,
            "full_c11_consumer_matrix": True,
            "full_cxx17_consumer_matrix": True,
            "feature_visibility_matrix": True,
            "callable_feature_visibility_matrix": True,
            "prototype_layout_matrix": True,
            "record_layout_matrix": True,
            "abi_facet_matrix": False,
            "callable_disposition": True,
            "selected_callable_provider_linkage_audit": True,
            "callable_linkage_audit": False,
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
            "sys_io_header_profile_matrix_slice": True,
            "epoll_header_profile_matrix_slice": True,
            "event_descriptors_header_profile_matrix_slice": True,
            "dirent_header_profile_matrix_slice": True,
            "stdlib_header_profile_matrix_slice": True,
            "timeval_transitive_header_profile_matrix_slice": True,
            "sys_time_direct_header_profile_matrix_slice": True,
            "access_header_profile_matrix_slice": True,
            "xattr_header_profile_matrix_slice": True,
            "candidate_transitive_include_closure": True,
            "selected_header_install_projection": True,
            "c11_consumer_matrix": True,
            "cxx17_consumer_matrix": True,
            "feature_visibility_matrix": True,
            "callable_feature_visibility_matrix": True,
            "prototype_layout_matrix": True,
            "record_layout_matrix": True,
            "abi_facet_matrix": False,
            "callable_disposition": True,
            "selected_callable_provider_linkage_audit": True,
            "callable_linkage_audit": False,
            "runtime_completion": False,
            "family_promotion": False,
            "public_support": False,
        },
        "header-foundation manifest completion drifted",
    )

    header_completion_assessment = manifest["header_completion_assessment"]
    require(
        isinstance(header_completion_assessment, Mapping),
        "header-foundation completion assessment must be a table",
    )
    require(
        set(header_completion_assessment)
        == {
            "algorithm",
            "installed_surface_completion_keys",
            "required_dimensions",
            "deferred_linkage_owner_family",
            "deferred_linkage_owner_obligation",
            "explicit_nonrequirements",
            "description",
        },
        "header-foundation completion assessment keys drifted",
    )
    require(
        header_completion_assessment.get("algorithm")
        == EXPECTED_HEADER_COMPLETION_ALGORITHM
        and header_completion_assessment.get("installed_surface_completion_keys")
        == EXPECTED_HEADER_COMPLETION_INSTALLED_SURFACE_KEYS
        and header_completion_assessment.get("required_dimensions")
        == EXPECTED_HEADER_COMPLETION_DIMENSIONS
        and header_completion_assessment.get("deferred_linkage_owner_family")
        == "libc.c-abi-compat"
        and header_completion_assessment.get("deferred_linkage_owner_obligation")
        == "final-callable-provider-archive-closure"
        and header_completion_assessment.get("explicit_nonrequirements")
        == EXPECTED_HEADER_COMPLETION_NONREQUIREMENTS,
        "header-foundation completion assessment contract drifted",
    )
    description = header_completion_assessment.get("description")
    require(
        isinstance(description, str)
        and "pure" in description
        and "finite deferred provider/archive complement" in description
        and "does not require" in description
        and "public support" in description,
        "header-foundation completion assessment description drifted",
    )
    require(
        all(key in completion for key in EXPECTED_HEADER_COMPLETION_INSTALLED_SURFACE_KEYS),
        "header-foundation completion assessment installed surface coverage drifted",
    )

    selected_provider_audit = manifest["selected_callable_provider_linkage_audit"]
    require(
        isinstance(selected_provider_audit, Mapping),
        "header-foundation selected provider audit must be a table",
    )
    require(
        set(selected_provider_audit)
        == {
            "id",
            "state",
            "owner",
            "command",
            "candidate_external_callable_count",
            "default_static_callable_count",
            "verified_feature_callable_count",
            "verified_feature_profile_count",
            "topology_only_profile_count",
            "ordinary_archive_extraction",
            "uses_whole_archive",
            "full_callable_closure",
            "family_promotion",
            "public_support",
            "description",
        },
        "header-foundation selected provider audit keys drifted",
    )
    require(
        dict(selected_provider_audit)
        == {
            "id": "selected-header-callable-provider-linkage-audit",
            "state": "partial-verified",
            "owner": "libc.headers-layouts",
            "command": EXPECTED_HEADER_CALLABLE_PROVIDER_LINKAGE_AUDIT_COMMAND,
            "candidate_external_callable_count": 1526,
            "default_static_callable_count": 1123,
            "verified_feature_callable_count": 78,
            "verified_feature_profile_count": 28,
            "topology_only_profile_count": 1,
            "ordinary_archive_extraction": True,
            "uses_whole_archive": False,
            "full_callable_closure": False,
            "family_promotion": False,
            "public_support": False,
            "description": selected_provider_audit["description"],
        },
        "header-foundation selected provider audit contract drifted",
    )
    description = selected_provider_audit["description"]
    require(
        isinstance(description, str)
        and "ordinary" in description
        and "verified feature profiles" in description
        and "exact roster-derived direct additions" in description
        and "derived unprovided complement" in description
        and "full callable closure" in description
        and "public x86 support" in description,
        "header-foundation selected provider audit description drifted",
    )

    callable_disposition = manifest["callable_disposition"]
    require(
        isinstance(callable_disposition, Mapping),
        "header-foundation callable disposition must be a table",
    )
    require(
        set(callable_disposition)
        == {
            "id",
            "state",
            "owner",
            "command",
            "contract",
            "report",
            "candidate_external_callable_count",
            "default_static_callable_count",
            "verified_feature_callable_count",
            "missing_reference_declaration_name_count",
            "missing_reference_declaration_record_count",
            "missing_reference_declaration_routing_complete",
            "header_ownership_routing_complete",
            "header_declaration_parity_complete",
            "final_provider_archive_closure_complete",
            "family_promotion",
            "public_support",
            "description",
        },
        "header-foundation callable disposition keys drifted",
    )
    require(
        dict(callable_disposition)
        == {
            "id": "header-callable-disposition",
            "state": "partial-verified",
            "owner": "libc.headers-layouts",
            "command": EXPECTED_HEADER_CALLABLE_DISPOSITION_COMMAND,
            "contract": "compat/x86_64/header_callable_disposition.toml",
            "report": "compat/x86_64/header_callable_disposition.json",
            "candidate_external_callable_count": 1526,
            "default_static_callable_count": 1123,
            "verified_feature_callable_count": 78,
            "missing_reference_declaration_name_count": 0,
            "missing_reference_declaration_record_count": 0,
            "missing_reference_declaration_routing_complete": True,
            "header_ownership_routing_complete": True,
            "header_declaration_parity_complete": False,
            "final_provider_archive_closure_complete": False,
            "family_promotion": False,
            "public_support": False,
            "description": callable_disposition["description"],
        },
        "header-foundation callable disposition contract drifted",
    )
    description = callable_disposition["description"]
    require(
        isinstance(description, str)
        and "selected external callable names" in description
        and "reviewed native callable extension" in description
        and "exact roster-derived direct additions" in description
        and "derived deferred planned-provider complement" in description
        and "Zero missing pinned-musl declaration names" in description
        and "archive extraction" in description
        and "final C ABI provider/archive closure" in description
        and "public x86 support" in description,
        "header-foundation callable disposition description drifted",
    )
    require(
        repository_path(str(callable_disposition["contract"]), "header-foundation callable disposition contract")
        == HEADER_CALLABLE_DISPOSITION_CONTRACT_PATH,
        "header-foundation callable disposition contract path drifted",
    )
    require(
        repository_path(str(callable_disposition["report"]), "header-foundation callable disposition report")
        == HEADER_CALLABLE_DISPOSITION_REPORT_PATH,
        "header-foundation callable disposition report path drifted",
    )

    selected_install_projection = manifest["selected_header_install_projection"]
    require(
        isinstance(selected_install_projection, Mapping),
        "header-foundation selected install projection must be a table",
    )
    require(
        set(selected_install_projection)
        == {
            "id",
            "state",
            "owner",
            "target_obligation",
            "command",
            "selected_public_header_count",
            "excluded_project_only_header_count",
            "profile_count",
            "projection_row_count",
            "bits_policy",
            "source_tree_mutation",
            "callable_provider_closure",
            "family_promotion",
            "public_support",
            "description",
        },
        "header-foundation selected install projection keys drifted",
    )
    require(
        dict(selected_install_projection)
        == {
            "id": "x86-selected-header-install-projection",
            "state": "partial-verified",
            "owner": "libc.headers-layouts",
            "target_obligation": "project-only-extension-policy",
            "command": EXPECTED_SELECTED_HEADER_INSTALL_PROJECTION_COMMAND,
            "selected_public_header_count": 183,
            "excluded_project_only_header_count": 8,
            "profile_count": 7,
            "projection_row_count": 1281,
            "bits_policy": "retain-all-project-bits-private-headers",
            "source_tree_mutation": False,
            "callable_provider_closure": False,
            "family_promotion": False,
            "public_support": False,
            "description": selected_install_projection["description"],
        },
        "header-foundation selected install projection contract drifted",
    )
    description = selected_install_projection["description"]
    require(
        isinstance(description, str)
        and "183 pinned-musl public paths" in description
        and "eight classified source-only" in description
        and "1,281 C11/C++17" in description
        and "shared source include tree" in description
        and "callable providers" in description
        and "public x86 support" in description,
        "header-foundation selected install projection description drifted",
    )

    require(
        family.get("status") == "foundation-verified",
        "libc.headers-layouts must be foundation-verified once the header foundation is complete",
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
        "compat/x86_64/headers_layouts_aggregate.py",
        "compat/x86_64/run_headers_layouts_aggregate.sh",
        "compat/x86_64/tests/test_headers_layouts_aggregate.py",
        "compat/x86_64/generated/headers_layouts_aggregate/report.json",
        "compat/x86_64/feature_archive_roster.py",
        "compat/x86_64/header_callable_inventory.toml",
        "compat/x86_64/header_callable_inventory.py",
        "compat/x86_64/header_callable_inventory.json",
        "compat/x86_64/header_callable_extension_contract.toml",
        "compat/x86_64/header_callable_extension_contract.py",
        "compat/x86_64/tests/test_header_callable_extension_contract.py",
        "compat/x86_64/header_callable_disposition.toml",
        "compat/x86_64/header_callable_disposition.py",
        "compat/x86_64/header_callable_disposition.json",
        "compat/x86_64/run_header_callable_disposition.sh",
        "compat/x86_64/header_callable_visibility_matrix.toml",
        "compat/x86_64/header_callable_visibility_matrix.py",
        "compat/x86_64/generated/header_callable_visibility_matrix/report.json",
        "compat/x86_64/run_header_callable_visibility_matrix.sh",
        "compat/x86_64/header_abi_matrix.toml",
        "compat/x86_64/header_abi_matrix.py",
        "compat/x86_64/generated/header_abi_matrix/report.json",
        "compat/x86_64/run_header_abi_matrix.sh",
        "compat/x86_64/header_record_layout_matrix.toml",
        "compat/x86_64/header_record_layout_matrix.py",
        "compat/x86_64/generated/header_record_layout_matrix/report.json",
        "compat/x86_64/run_header_record_layout_matrix.sh",
        "compat/x86_64/header_declaration_macro_visibility_matrix.toml",
        "compat/x86_64/header_declaration_macro_visibility_matrix.py",
        "compat/x86_64/generated/header_declaration_macro_visibility_matrix/report.json",
        "compat/x86_64/run_header_declaration_macro_visibility_matrix.sh",
        "compat/x86_64/header_callable_linkage_audit.py",
        "compat/x86_64/run_header_callable_linkage_audit.sh",
        "compat/x86_64/header_callable_provider_linkage_audit.py",
        "compat/x86_64/run_header_callable_provider_linkage_audit.sh",
        "compat/x86_64/public_headers.txt",
        "compat/x86_64/selected-header-install-projection.toml",
        "compat/x86_64/selected_header_install_projection.py",
        "compat/x86_64/selected_header_install_projection_cxx.cpp",
        "compat/x86_64/run_selected_header_install_projection.sh",
        "compat/x86_64/run_linux_5_10_uapi.sh",
        "compat/x86_64/run_uapi_wrapper_matrix.sh",
        "compat/x86_64/uapi_wrappers_header_abi_probe.c",
        "compat/x86_64/uapi_wrappers_header_abi_probe.cpp",
        "compat/x86_64/run_ioctl_header_abi.sh",
        "compat/x86_64/ioctl_header_abi_probe.c",
        "compat/x86_64/ioctl_header_abi_probe.cpp",
        "compat/x86_64/run_sys_io_header_abi.sh",
        "compat/x86_64/sys_io_header_abi_probe.c",
        "compat/x86_64/sys_io_header_abi_probe.cpp",
        "compat/x86_64/tests/test_sys_io_header_abi.py",
        "include/sys/io.h",
        "include/bits/io.h",
        "compat/x86_64/run_epoll_header_abi.sh",
        "compat/x86_64/epoll_header_abi_probe.c",
        "compat/x86_64/epoll_header_abi_probe.cpp",
        "compat/x86_64/run_dirent_header_abi.sh",
        "compat/x86_64/dirent_header_abi_probe.c",
        "compat/x86_64/dirent_header_abi_probe.cpp",
        "compat/x86_64/run_stdlib_header_abi.sh",
        "compat/x86_64/stdlib_header_abi_probe.c",
        "compat/x86_64/stdlib_header_abi_probe.cpp",
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
        "compat/x86_64/tests/test_selected_header_install_projection.py",
        "compat/x86_64/tests/test_feature_archive_roster.py",
        "compat/x86_64/tests/test_header_callable_inventory.py",
        "compat/x86_64/tests/test_header_callable_disposition.py",
        "compat/x86_64/tests/test_header_callable_provider_linkage_audit.py",
        "compat/x86_64/tests/test_header_callable_visibility_matrix.py",
        "compat/x86_64/tests/test_header_abi_matrix.py",
        "compat/x86_64/tests/test_header_record_layout_matrix.py",
        "compat/x86_64/tests/test_wchar_uchar_header_source.py",
        "compat/x86_64/tests/test_header_declaration_macro_visibility_matrix.py",
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

    aggregate_control = manifest["aggregate_control"]
    require(
        isinstance(aggregate_control, Mapping),
        "header-foundation aggregate control must be a table",
    )
    require(
        set(aggregate_control)
        == {
            "id",
            "state",
            "owner",
            "command",
            "generated_report",
            "required_result",
            "direct_manifest",
            "direct_probe_count",
            "profile_obligation_count",
            "accounting_keys",
            "completion_algorithm",
            "language_profiles",
            "header_classes",
            "abi_facets",
            "linkage_owners",
            "evidence_tables",
            "supporting_commands",
            "source_owners",
            "family_promotion",
            "public_support",
            "description",
            "runner",
        },
        "header-foundation aggregate control keys drifted",
    )
    require(
        aggregate_control.get("id") == "x86-headers-layouts-accounting-control"
        and aggregate_control.get("state") == "partial-verified"
        and aggregate_control.get("owner") == "libc.headers-layouts"
        and aggregate_control.get("command") == EXPECTED_HEADER_LAYOUTS_AGGREGATE_COMMAND
        and aggregate_control.get("required_result")
        == "checked-header-foundation-assessment-report"
        and aggregate_control.get("completion_algorithm")
        == EXPECTED_HEADER_COMPLETION_ALGORITHM
        and aggregate_control.get("direct_manifest") == "compat/x86_64/headers-layouts.toml"
        and aggregate_control.get("direct_probe_count") == 55
        and aggregate_control.get("profile_obligation_count") == 21
        and aggregate_control.get("family_promotion") is False
        and aggregate_control.get("public_support") is False,
        "header-foundation aggregate control contract drifted",
    )
    require(
        isinstance(aggregate_control.get("description"), str)
        and "finite" in aggregate_control["description"]
        and "pure header-completion assessment" in aggregate_control["description"]
        and "downstream provider/archive obligations" in aggregate_control["description"]
        and "cannot claim C-ABI archive completion" in aggregate_control["description"],
        "header-foundation aggregate control description drifted",
    )
    aggregate_report_path = repository_path(
        str(aggregate_control.get("generated_report", "")),
        "header-foundation aggregate control generated report",
    )
    require(
        aggregate_report_path == HEADER_LAYOUTS_AGGREGATE_REPORT_PATH,
        "header-foundation aggregate control report path drifted",
    )
    aggregate_owners = nonempty_strings(
        aggregate_control.get("source_owners"),
        "header-foundation aggregate control source owners",
    )
    require(
        aggregate_owners
        == [
            "compat/x86_64/headers_layouts_aggregate.py",
            "compat/x86_64/run_headers_layouts_aggregate.sh",
            "compat/x86_64/tests/test_headers_layouts_aggregate.py",
            "compat/x86_64/generated/headers_layouts_aggregate/report.json",
        ],
        "header-foundation aggregate control source-owner roster drifted",
    )
    for owner in aggregate_owners:
        require(owner in source_owners, f"header-foundation aggregate control source owner is not owned: {owner}")
    require(
        HEADER_LAYOUTS_AGGREGATE_PATH.is_file()
        and HEADER_LAYOUTS_AGGREGATE_RUNNER_PATH.is_file()
        and HEADER_LAYOUTS_AGGREGATE_REPORT_PATH.is_file(),
        "header-foundation aggregate control files are missing",
    )

    accounting_keys = nonempty_strings(
        aggregate_control.get("accounting_keys"),
        "header-foundation aggregate control accounting keys",
    )
    require(
        accounting_keys == sorted(accounting_keys)
        and accounting_keys == sorted(completion),
        "header-foundation aggregate control accounting coverage drifted",
    )
    language_profile_ids = [
        entry.get("id")
        for entry in manifest.get("language_profile", [])
        if isinstance(entry, Mapping)
    ]
    header_class_ids = [
        entry.get("id")
        for entry in manifest.get("header_class", [])
        if isinstance(entry, Mapping)
    ]
    abi_facet_ids = [
        entry.get("id")
        for entry in manifest.get("abi_facet", [])
        if isinstance(entry, Mapping)
    ]
    linkage_owner_ids = [
        entry.get("id")
        for entry in manifest.get("linkage_owner", [])
        if isinstance(entry, Mapping)
    ]
    require(
        aggregate_control.get("language_profiles") == language_profile_ids
        and aggregate_control.get("header_classes") == header_class_ids
        and aggregate_control.get("abi_facets") == abi_facet_ids
        and aggregate_control.get("linkage_owners") == linkage_owner_ids,
        "header-foundation aggregate control roster coverage drifted",
    )
    expected_evidence_tables = [
        "closure_diagnostic",
        "feature_visibility_matrix",
        "callable_feature_visibility_matrix",
        "prototype_layout_matrix",
        "record_layout_matrix",
        "callable_disposition",
        "selected_callable_provider_linkage_audit",
        "selected_header_install_projection",
        "uapi_wrapper_matrix",
        "ioctl_header_profile_matrix",
        "sys_io_header_profile_matrix",
        "epoll_header_profile_matrix",
        "event_descriptors_header_profile_matrix",
        "dirent_header_profile_matrix",
        "stdlib_header_profile_matrix",
        "timeval_transitive_header_profile_matrix",
        "sys_time_direct_header_profile_matrix",
        "access_header_profile_matrix",
        "xattr_header_profile_matrix",
    ]
    require(
        aggregate_control.get("evidence_tables") == expected_evidence_tables,
        "header-foundation aggregate control evidence-table coverage drifted",
    )
    expected_supporting_commands = [
        "./scripts/dev-x86_64.sh musl-oracle",
        "./scripts/dev-x86_64.sh linux-5-10-uapi",
        "./scripts/dev-x86_64.sh installed-header-tree-closure",
        "./scripts/dev-x86_64.sh header-callable-linkage-audit",
        "./scripts/dev-x86_64.sh project-header-extension-policy",
    ]
    require(
        aggregate_control.get("supporting_commands") == expected_supporting_commands,
        "header-foundation aggregate control supporting command coverage drifted",
    )
    expected_runner_commands: list[str] = []
    for table in expected_evidence_tables:
        value = manifest[table]
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            require(isinstance(entry, Mapping), f"header-foundation aggregate evidence {table} is invalid")
            command = entry.get("command")
            require(isinstance(command, str) and command, f"header-foundation aggregate evidence {table} command is invalid")
            expected_runner_commands.append(command)
    expected_runner_commands.extend(expected_supporting_commands)
    runners = aggregate_control.get("runner")
    require(isinstance(runners, list), "header-foundation aggregate control runners are invalid")
    runner_commands: list[str] = []
    for index, runner in enumerate(runners):
        require(isinstance(runner, Mapping), f"header-foundation aggregate runner {index} drifted")
        command = runner.get("command")
        expected_keys = (
            {"command", "script", "outcome"}
            if command == "./scripts/dev-x86_64.sh header-callable-linkage-audit"
            else {"command", "script"}
        )
        require(set(runner) == expected_keys, f"header-foundation aggregate runner {index} drifted")
        script = runner.get("script")
        require(isinstance(command, str) and isinstance(script, str), f"header-foundation aggregate runner {index} is invalid")
        if command == "./scripts/dev-x86_64.sh header-callable-linkage-audit":
            require(
                script == "compat/x86_64/run_header_callable_linkage_audit.sh"
                and runner.get("outcome") == "accounted-incomplete",
                "header-foundation aggregate accounted-incomplete runner drifted",
            )
        runner_commands.append(command)
        script_path = repository_path(script, f"header-foundation aggregate runner {index} script")
        require(script_path.suffix == ".sh", f"header-foundation aggregate runner {index} is not a shell runner")
    require(
        runner_commands == expected_runner_commands
        and len(runner_commands) == len(set(runner_commands)),
        "header-foundation aggregate runner command coverage drifted",
    )
    dispatcher = X86_64_DISPATCHER_PATH.read_text(encoding="utf-8")
    require(
        "    headers-layouts-aggregate)" in dispatcher
        and HEADER_LAYOUTS_AGGREGATE_RUNNER_PATH.name in dispatcher,
        "header-foundation aggregate control is absent from the native dispatcher",
    )

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

    feature_visibility_matrix_row_count = require_header_declaration_macro_visibility_matrix(
        manifest
    )
    callable_visibility_matrix_row_count = require_header_callable_visibility_matrix(manifest)
    prototype_layout_matrix_row_count = require_header_abi_matrix(manifest)
    record_layout_matrix_row_count = require_header_record_layout_matrix(manifest)

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

    event_descriptors_header_profile_matrix = manifest[
        "event_descriptors_header_profile_matrix"
    ]
    require(
        isinstance(event_descriptors_header_profile_matrix, Mapping),
        "header-foundation event-descriptor header matrix must be a table",
    )
    require(
        set(event_descriptors_header_profile_matrix)
        == {
            "id",
            "state",
            "command",
            "required_result",
            "header_class",
            "subject_headers",
            "immediate_feature_header",
            "profiles",
            "direct_surface_visibility",
            "at_empty_path_visible_profiles",
            "at_empty_path_hidden_profiles",
            "row_count",
            "scope",
            "row",
        },
        "header-foundation event-descriptor header matrix keys drifted",
    )
    require(
        event_descriptors_header_profile_matrix["id"]
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_ID,
        "header-foundation event-descriptor header matrix id drifted",
    )
    require(
        event_descriptors_header_profile_matrix["state"] == "partial-verified"
        and event_descriptors_header_profile_matrix["required_result"] == "pass",
        "header-foundation event-descriptor header matrix must remain partial verified evidence",
    )
    require(
        event_descriptors_header_profile_matrix["command"]
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation event-descriptor header matrix command drifted",
    )
    require(
        event_descriptors_header_profile_matrix["header_class"] == "pinned-non-uapi",
        "header-foundation event-descriptor header matrix must remain scoped to pinned non-UAPI headers",
    )
    event_descriptor_subject_headers = string_list(
        event_descriptors_header_profile_matrix["subject_headers"],
        "header-foundation event-descriptor header matrix subject headers",
    )
    require(
        tuple(event_descriptor_subject_headers)
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS,
        "header-foundation event-descriptor header matrix subject headers drifted",
    )
    require(
        event_descriptors_header_profile_matrix["immediate_feature_header"]
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_IMMEDIATE_FEATURE_HEADER,
        "header-foundation event-descriptor immediate feature header drifted",
    )
    event_descriptor_profiles = string_list(
        event_descriptors_header_profile_matrix["profiles"],
        "header-foundation event-descriptor header matrix profiles",
    )
    require(
        tuple(event_descriptor_profiles)
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation event-descriptor header matrix profiles drifted",
    )
    require(
        event_descriptors_header_profile_matrix["direct_surface_visibility"]
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_DIRECT_SURFACE_VISIBILITY,
        "header-foundation event-descriptor direct-surface visibility drifted",
    )
    event_descriptor_visible_profiles = string_list(
        event_descriptors_header_profile_matrix["at_empty_path_visible_profiles"],
        "header-foundation event-descriptor AT_EMPTY_PATH visible profiles",
    )
    event_descriptor_hidden_profiles = string_list(
        event_descriptors_header_profile_matrix["at_empty_path_hidden_profiles"],
        "header-foundation event-descriptor AT_EMPTY_PATH hidden profiles",
    )
    require(
        tuple(event_descriptor_visible_profiles)
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_AT_EMPTY_PATH_VISIBLE_PROFILES,
        "header-foundation event-descriptor AT_EMPTY_PATH visible profile roster drifted",
    )
    require(
        tuple(event_descriptor_hidden_profiles)
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_AT_EMPTY_PATH_HIDDEN_PROFILES,
        "header-foundation event-descriptor AT_EMPTY_PATH hidden profile roster drifted",
    )
    require(
        not set(event_descriptor_visible_profiles).intersection(event_descriptor_hidden_profiles)
        and set(event_descriptor_visible_profiles).union(event_descriptor_hidden_profiles)
        == set(event_descriptor_profiles),
        "header-foundation event-descriptor AT_EMPTY_PATH visibility partition drifted",
    )
    require(
        event_descriptors_header_profile_matrix["row_count"]
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_ROW_COUNT
        and event_descriptors_header_profile_matrix["row_count"]
        == len(event_descriptor_subject_headers) * len(event_descriptor_profiles),
        "header-foundation event-descriptor header matrix row count drifted",
    )
    event_descriptor_scope = event_descriptors_header_profile_matrix["scope"]
    require(
        isinstance(event_descriptor_scope, str)
        and all(
            phrase in event_descriptor_scope
            for phrase in (
                "unconditional",
                "AT_EMPTY_PATH",
                "actual callable artifact linkage",
                "runtime behavior",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation event-descriptor header matrix scope must retain its narrow non-completion boundary",
    )
    event_descriptor_rows = event_descriptors_header_profile_matrix["row"]
    require(
        isinstance(event_descriptor_rows, list)
        and len(event_descriptor_rows)
        == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation event-descriptor header matrix row roster drifted",
    )
    expected_event_descriptor_rows = tuple(
        (header, profile)
        for header in EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS
        for profile in EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_PROFILES
    )
    observed_event_descriptor_rows: list[tuple[str, str]] = []
    for index, row in enumerate(event_descriptor_rows):
        location = f"header-foundation event_descriptors_header_profile_matrix.row[{index}]"
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
            header in EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS,
            f"{location} header is not a declared event-descriptor subject",
        )
        require(
            profile in EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_PROFILES,
            f"{location} profile is not a declared event-descriptor header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_event_descriptor_rows.append((header, profile))
    require(
        tuple(observed_event_descriptor_rows) == expected_event_descriptor_rows,
        "header-foundation event-descriptor header matrix row order or cross-product drifted",
    )
    require(
        EVENT_DESCRIPTORS_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation event-descriptor header matrix runner is missing",
    )
    require(
        "event-descriptors-header-abi)" in dispatch_source,
        "event-descriptors-header-abi is absent from the native dispatcher",
    )
    event_descriptor_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_EVENT_DESCRIPTORS_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(event_descriptor_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one event-descriptor header matrix evidence command",
    )
    require(
        event_descriptor_matrix_evidence[0].get("state") == "required"
        and isinstance(event_descriptor_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in event_descriptor_matrix_evidence[0]["scope"]
            for phrase in (
                "unconditional",
                "AT_EMPTY_PATH",
                "nm",
                "actual callable artifact linkage",
                "event-descriptor runtime behavior",
                "all-header closure",
                "runtime completion",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts event-descriptor header matrix evidence must retain its narrow non-completion boundary",
    )

    dirent_header_profile_matrix = manifest["dirent_header_profile_matrix"]
    require(
        isinstance(dirent_header_profile_matrix, Mapping),
        "header-foundation dirent header matrix must be a table",
    )
    require(
        set(dirent_header_profile_matrix)
        == {
            "id",
            "state",
            "command",
            "required_result",
            "header_class",
            "subject_header",
            "base_profiles",
            "largefile64_profiles",
            "seek_tell_visible_profiles",
            "getdents_type_macros_visible_profiles",
            "versionsort_visible_profiles",
            "largefile64_alias_visible_profiles",
            "row_count",
            "scope",
            "row",
        },
        "header-foundation dirent header matrix keys drifted",
    )
    require(
        dirent_header_profile_matrix["id"] == EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_ID,
        "header-foundation dirent header matrix id drifted",
    )
    require(
        dirent_header_profile_matrix["state"] == "partial-verified"
        and dirent_header_profile_matrix["required_result"] == "pass",
        "header-foundation dirent header matrix must remain partial verified evidence",
    )
    require(
        dirent_header_profile_matrix["command"] == EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation dirent header matrix command drifted",
    )
    require(
        dirent_header_profile_matrix["header_class"] == "pinned-non-uapi"
        and dirent_header_profile_matrix["subject_header"]
        == EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_SUBJECT_HEADER,
        "header-foundation dirent header matrix subject scope drifted",
    )
    dirent_base_profiles = string_list(
        dirent_header_profile_matrix["base_profiles"],
        "header-foundation dirent base profiles",
    )
    dirent_largefile64_profiles = string_list(
        dirent_header_profile_matrix["largefile64_profiles"],
        "header-foundation dirent large-file profiles",
    )
    require(
        tuple(dirent_base_profiles) == EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_BASE_PROFILES
        and tuple(dirent_largefile64_profiles)
        == EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_LARGEFILE64_PROFILES,
        "header-foundation dirent profile roster drifted",
    )
    for key, expected in (
        (
            "seek_tell_visible_profiles",
            EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_SEEK_TELL_VISIBLE_PROFILES,
        ),
        (
            "getdents_type_macros_visible_profiles",
            EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_GETDENTS_TYPE_MACROS_VISIBLE_PROFILES,
        ),
        (
            "versionsort_visible_profiles",
            EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_VERSIONSORT_VISIBLE_PROFILES,
        ),
        (
            "largefile64_alias_visible_profiles",
            EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_LARGEFILE64_PROFILES,
        ),
    ):
        require(
            tuple(string_list(dirent_header_profile_matrix[key], f"header-foundation dirent {key}"))
            == expected,
            f"header-foundation dirent {key} drifted",
        )
    dirent_profiles = tuple(dirent_base_profiles + dirent_largefile64_profiles)
    require(
        dirent_header_profile_matrix["row_count"]
        == EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_ROW_COUNT
        and dirent_header_profile_matrix["row_count"] == len(dirent_profiles),
        "header-foundation dirent header matrix row count drifted",
    )
    dirent_scope = dirent_header_profile_matrix["scope"]
    require(
        isinstance(dirent_scope, str)
        and all(
            phrase in dirent_scope
            for phrase in (
                "struct dirent",
                "struct posix_dent",
                "GNU-or-BSD IFTODT/DTTOIF/getdents",
                "GNU-only versionsort",
                "unmangled C spellings",
                "actual callable artifact linkage",
                "directory-stream/getdents runtime behavior",
                "archive linkage",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation dirent header matrix scope must retain its narrow non-completion boundary",
    )
    dirent_rows = dirent_header_profile_matrix["row"]
    require(
        isinstance(dirent_rows, list)
        and len(dirent_rows) == EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation dirent header matrix row roster drifted",
    )
    observed_dirent_rows: list[str] = []
    for index, row in enumerate(dirent_rows):
        location = f"header-foundation dirent_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        profile = row["profile"]
        require(
            isinstance(profile, str) and profile in dirent_profiles,
            f"{location} profile is not a declared dirent header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_dirent_rows.append(profile)
    require(
        tuple(observed_dirent_rows) == dirent_profiles,
        "header-foundation dirent header matrix row order or roster drifted",
    )
    require(
        DIRENT_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation dirent header matrix runner is missing",
    )
    require(
        "dirent-header-abi)" in dispatch_source,
        "dirent-header-abi is absent from the native dispatcher",
    )
    dirent_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_DIRENT_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(dirent_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one dirent header matrix evidence command",
    )
    require(
        dirent_matrix_evidence[0].get("state") == "required"
        and isinstance(dirent_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in dirent_matrix_evidence[0]["scope"]
            for phrase in (
                "11-row `dirent.h` C/C++",
                "struct dirent",
                "struct posix_dent",
                "seven base plus four GNU/strict `_LARGEFILE64_SOURCE`",
                "GNU-or-BSD IFTODT/DTTOIF/getdents",
                "GNU-only versionsort",
                "unmangled C spellings",
                "actual callable artifact linkage",
                "directory-stream/getdents runtime behavior",
                "archive linkage",
                "all-header closure",
                "runtime completion",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts dirent header matrix evidence must retain its narrow non-completion boundary",
    )

    stdlib_header_profile_matrix = manifest["stdlib_header_profile_matrix"]
    require(
        isinstance(stdlib_header_profile_matrix, Mapping),
        "header-foundation stdlib header matrix must be a table",
    )
    require(
        set(stdlib_header_profile_matrix)
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
        "header-foundation stdlib header matrix keys drifted",
    )
    require(
        stdlib_header_profile_matrix["id"] == EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_ID,
        "header-foundation stdlib header matrix id drifted",
    )
    require(
        stdlib_header_profile_matrix["state"] == "partial-verified"
        and stdlib_header_profile_matrix["required_result"] == "pass",
        "header-foundation stdlib header matrix must remain partial verified evidence",
    )
    require(
        stdlib_header_profile_matrix["command"] == EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation stdlib header matrix command drifted",
    )
    require(
        stdlib_header_profile_matrix["header_class"] == "pinned-non-uapi"
        and stdlib_header_profile_matrix["subject_header"]
        == EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_SUBJECT_HEADER,
        "header-foundation stdlib header matrix subject scope drifted",
    )
    stdlib_profiles = string_list(
        stdlib_header_profile_matrix["profiles"],
        "header-foundation stdlib profiles",
    )
    require(
        tuple(stdlib_profiles) == EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation stdlib header matrix profile roster drifted",
    )
    require(
        stdlib_header_profile_matrix["row_count"]
        == EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_ROW_COUNT
        and stdlib_header_profile_matrix["row_count"] == len(stdlib_profiles),
        "header-foundation stdlib header matrix row count drifted",
    )
    stdlib_scope = stdlib_header_profile_matrix["scope"]
    require(
        isinstance(stdlib_scope, str)
        and all(
            phrase in stdlib_scope
            for phrase in (
                "twelve isolated C11/C++17",
                "POSIX.1-2008",
                "_LARGEFILE64_SOURCE",
                "negative hidden-name witnesses",
                "unmangled C spellings",
                "NULL/nullptr",
                "stdio.h-first",
                "string.h-first",
                "actual callable artifact linkage",
                "archive linkage",
                "stdlib runtime/lifecycle behavior",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation stdlib header matrix scope must retain its narrow non-completion boundary",
    )
    stdlib_rows = stdlib_header_profile_matrix["row"]
    require(
        isinstance(stdlib_rows, list)
        and len(stdlib_rows) == EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation stdlib header matrix row roster drifted",
    )
    observed_stdlib_rows: list[str] = []
    for index, row in enumerate(stdlib_rows):
        location = f"header-foundation stdlib_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        profile = row["profile"]
        require(
            isinstance(profile, str) and profile in EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_PROFILES,
            f"{location} profile is not a declared stdlib header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_stdlib_rows.append(profile)
    require(
        tuple(observed_stdlib_rows) == EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation stdlib header matrix row order or roster drifted",
    )
    require(
        STDLIB_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation stdlib header matrix runner is missing",
    )
    require(
        "stdlib-header-abi)" in dispatch_source,
        "stdlib-header-abi is absent from the native dispatcher",
    )
    stdlib_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_STDLIB_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(stdlib_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one stdlib header matrix evidence command",
    )
    require(
        stdlib_matrix_evidence[0].get("state") == "required"
        and isinstance(stdlib_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in stdlib_matrix_evidence[0]["scope"]
            for phrase in (
                "12-row `stdlib.h` C/C++",
                "strict/POSIX/XOPEN/GNU/BSD/LFS",
                "hidden-name partitions",
                "GNU/BSD temporary/allocation",
                "GNU locale-conversion",
                "LFS aliases",
                "C++ unmangled C spellings",
                "stdio.h/string.h",
                "actual callable artifact linkage",
                "stdlib runtime or lifecycle behavior",
                "archive linkage",
                "all-header closure",
                "runtime completion",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts stdlib header matrix evidence must retain its narrow non-completion boundary",
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

    sys_io_header_profile_matrix = manifest["sys_io_header_profile_matrix"]
    require(
        isinstance(sys_io_header_profile_matrix, Mapping),
        "header-foundation sys/io header matrix must be a table",
    )
    require(
        set(sys_io_header_profile_matrix)
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
        "header-foundation sys/io header matrix keys drifted",
    )
    require(
        sys_io_header_profile_matrix["id"] == EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_ID,
        "header-foundation sys/io header matrix id drifted",
    )
    require(
        sys_io_header_profile_matrix["state"] == "partial-verified"
        and sys_io_header_profile_matrix["required_result"] == "pass",
        "header-foundation sys/io header matrix must remain partial verified evidence",
    )
    require(
        sys_io_header_profile_matrix["command"]
        == EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation sys/io header matrix command drifted",
    )
    require(
        sys_io_header_profile_matrix["header_class"] == "pinned-non-uapi",
        "header-foundation sys/io header matrix must remain scoped to fixed pinned non-UAPI headers",
    )
    sys_io_headers = string_list(
        sys_io_header_profile_matrix["subject_headers"],
        "header-foundation sys/io header matrix subject headers",
    )
    require(
        tuple(sys_io_headers) == EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_SUBJECT_HEADERS,
        "header-foundation sys/io header matrix subject headers drifted",
    )
    sys_io_profiles = string_list(
        sys_io_header_profile_matrix["profiles"],
        "header-foundation sys/io header matrix profiles",
    )
    require(
        tuple(sys_io_profiles) == EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation sys/io header matrix profiles drifted",
    )
    require(
        sys_io_header_profile_matrix["row_count"]
        == EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_ROW_COUNT
        and sys_io_header_profile_matrix["row_count"] == len(sys_io_profiles),
        "header-foundation sys/io header matrix row count drifted",
    )
    sys_io_scope = sys_io_header_profile_matrix["scope"]
    require(
        isinstance(sys_io_scope, str)
        and all(
            phrase in sys_io_scope
            for phrase in (
                "iopl/ioperm declarations",
                "twelve header-local",
                "musl operand",
                "direction-flag",
                "C++ C linkage",
                "no external inline-helper reference",
                "object-code instructions",
                "does not execute port I/O",
                "iopl/ioperm artifact linkage",
                "system.kernel-admin capability",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation sys/io header matrix scope must retain its non-completion boundary",
    )
    sys_io_rows = sys_io_header_profile_matrix["row"]
    require(
        isinstance(sys_io_rows, list)
        and len(sys_io_rows) == EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation sys/io header matrix row roster drifted",
    )
    observed_sys_io_rows: list[str] = []
    for index, row in enumerate(sys_io_rows):
        location = f"header-foundation sys_io_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        profile = row["profile"]
        require(isinstance(profile, str), f"{location} profile is invalid")
        require(
            profile in EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_PROFILES,
            f"{location} profile is not a declared sys/io header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_sys_io_rows.append(profile)
    require(
        tuple(observed_sys_io_rows) == EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation sys/io header matrix row order or cross-product drifted",
    )
    require(
        SYS_IO_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation sys/io header matrix runner is missing",
    )
    require(
        "sys-io-header-abi)" in dispatch_source,
        "sys-io-header-abi is absent from the native dispatcher",
    )
    sys_io_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_SYS_IO_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(sys_io_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one sys/io header matrix evidence command",
    )
    require(
        sys_io_matrix_evidence[0].get("state") == "required"
        and isinstance(sys_io_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in sys_io_matrix_evidence[0]["scope"]
            for phrase in (
                "iopl/ioperm declarations",
                "twelve header-local",
                "operand/DF",
                "C++ C linkage",
                "object code only",
                "never executes port I/O",
                "iopl/ioperm artifact linkage",
                "kernel-admin capability",
                "all-header closure",
                "runtime completion",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts sys/io header matrix evidence must retain its non-completion boundary",
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

    xattr_header_profile_matrix = manifest["xattr_header_profile_matrix"]
    require(
        isinstance(xattr_header_profile_matrix, Mapping),
        "header-foundation xattr header matrix must be a table",
    )
    require(
        set(xattr_header_profile_matrix)
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
        "header-foundation xattr header matrix keys drifted",
    )
    require(
        xattr_header_profile_matrix["id"] == EXPECTED_XATTR_HEADER_PROFILE_MATRIX_ID,
        "header-foundation xattr header matrix id drifted",
    )
    require(
        xattr_header_profile_matrix["state"] == "partial-verified"
        and xattr_header_profile_matrix["required_result"] == "pass",
        "header-foundation xattr header matrix must remain partial verified evidence",
    )
    require(
        xattr_header_profile_matrix["command"]
        == EXPECTED_XATTR_HEADER_PROFILE_MATRIX_COMMAND,
        "header-foundation xattr header matrix command drifted",
    )
    require(
        xattr_header_profile_matrix["header_class"] == "pinned-non-uapi",
        "header-foundation xattr header matrix must remain scoped to pinned non-UAPI headers",
    )
    require(
        xattr_header_profile_matrix["subject_header"]
        == EXPECTED_XATTR_HEADER_PROFILE_MATRIX_SUBJECT_HEADER,
        "header-foundation xattr header matrix subject header drifted",
    )
    xattr_header_profiles = string_list(
        xattr_header_profile_matrix["profiles"],
        "header-foundation xattr header matrix profiles",
    )
    require(
        tuple(xattr_header_profiles) == EXPECTED_XATTR_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation xattr header matrix profiles drifted",
    )
    require(
        xattr_header_profile_matrix["row_count"]
        == EXPECTED_XATTR_HEADER_PROFILE_MATRIX_ROW_COUNT
        and xattr_header_profile_matrix["row_count"] == len(xattr_header_profiles),
        "header-foundation xattr header matrix row count drifted",
    )
    xattr_header_scope = xattr_header_profile_matrix["scope"]
    require(
        isinstance(xattr_header_scope, str)
        and all(
            phrase in xattr_header_scope
            for phrase in (
                "twelve",
                "unconditional",
                "strict/POSIX/X/Open/GNU/BSD",
                "unmangled C++",
                "actual callable artifact linkage",
                "runtime xattr behavior",
                "all-header closure",
                "runtime completion",
                "family promotion",
                "public support",
            )
        ),
        "header-foundation xattr header matrix scope must retain its non-completion boundary",
    )
    xattr_header_rows = xattr_header_profile_matrix["row"]
    require(
        isinstance(xattr_header_rows, list)
        and len(xattr_header_rows) == EXPECTED_XATTR_HEADER_PROFILE_MATRIX_ROW_COUNT,
        "header-foundation xattr header matrix row roster drifted",
    )
    observed_xattr_header_rows: list[str] = []
    for index, row in enumerate(xattr_header_rows):
        location = f"header-foundation xattr_header_profile_matrix.row[{index}]"
        require(isinstance(row, Mapping), f"{location} must be a table")
        require(
            set(row) == {"profile", "reference", "candidate", "applicability"},
            f"{location} keys drifted",
        )
        profile = row["profile"]
        require(isinstance(profile, str), f"{location} profile is invalid")
        require(
            profile in EXPECTED_XATTR_HEADER_PROFILE_MATRIX_PROFILES,
            f"{location} profile is not a declared xattr-header profile",
        )
        require(
            row["reference"] == "compile-ok"
            and row["candidate"] == "compile-ok"
            and row["applicability"] == "applicable",
            f"{location} must retain the resolved compile-only result",
        )
        observed_xattr_header_rows.append(profile)
    require(
        tuple(observed_xattr_header_rows) == EXPECTED_XATTR_HEADER_PROFILE_MATRIX_PROFILES,
        "header-foundation xattr header matrix row order or roster drifted",
    )
    require(
        XATTR_HEADER_ABI_RUNNER_PATH.is_file(),
        "header-foundation xattr header matrix runner is missing",
    )
    require(
        "xattr-header-abi)" in dispatch_source,
        "xattr-header-abi is absent from the native dispatcher",
    )
    xattr_header_matrix_evidence = [
        entry
        for entry in family_native_evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == EXPECTED_XATTR_HEADER_PROFILE_MATRIX_COMMAND
    ]
    require(
        len(xattr_header_matrix_evidence) == 1,
        "libc.headers-layouts must retain exactly one xattr header matrix evidence command",
    )
    require(
        xattr_header_matrix_evidence[0].get("state") == "required"
        and isinstance(xattr_header_matrix_evidence[0].get("scope"), str)
        and all(
            phrase in xattr_header_matrix_evidence[0]["scope"]
            for phrase in (
                "sys/xattr.h",
                "twelve",
                "unconditional",
                "unmangled C++",
                "actual callable artifact linkage",
                "runtime behavior",
                "all-header closure",
                "runtime",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts xattr header matrix evidence must retain its non-completion boundary",
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
    require(
        xattr_header_profile_matrix["subject_header"]
        in pinned_path_set - uapi_header_set,
        "header-foundation xattr subject must remain a pinned non-UAPI header",
    )
    require(
        set(event_descriptor_subject_headers) <= pinned_path_set - uapi_header_set
        and event_descriptors_header_profile_matrix["immediate_feature_header"]
        in pinned_path_set - uapi_header_set,
        "header-foundation event-descriptor subjects and immediate feature header must remain pinned non-UAPI headers",
    )
    require(
        dirent_header_profile_matrix["subject_header"] in pinned_path_set - uapi_header_set,
        "header-foundation dirent subject must remain a pinned non-UAPI header",
    )
    require(
        stdlib_header_profile_matrix["subject_header"] in pinned_path_set - uapi_header_set,
        "header-foundation stdlib subject must remain a pinned non-UAPI header",
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
        "header-callable-disposition" in linkage_ids,
        "header-foundation needs the checked callable-disposition ownership rule",
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
        "sys_io_header_profile_matrix_row_count": len(observed_sys_io_rows),
        "epoll_header_profile_matrix_row_count": len(observed_epoll_rows),
        "event_descriptors_header_profile_matrix_row_count": len(
            observed_event_descriptor_rows
        ),
        "dirent_header_profile_matrix_row_count": len(observed_dirent_rows),
        "stdlib_header_profile_matrix_row_count": len(observed_stdlib_rows),
        "timeval_transitive_header_profile_matrix_row_count": len(observed_timeval_rows),
        "sys_time_direct_header_profile_matrix_row_count": len(observed_sys_time_direct_rows),
        "access_header_profile_matrix_row_count": len(observed_access_header_rows),
        "xattr_header_profile_matrix_row_count": len(observed_xattr_header_rows),
        "callable_feature_visibility_matrix_row_count": callable_visibility_matrix_row_count,
        "feature_visibility_matrix_row_count": feature_visibility_matrix_row_count,
        "prototype_layout_matrix_row_count": prototype_layout_matrix_row_count,
        "record_layout_matrix_row_count": record_layout_matrix_row_count,
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


def require_posix_native_profile_companions(family: Mapping[str, Any]) -> None:
    """Keep the aggregate's finite companion and source contracts explicit."""

    owners = set(family["source_owners"])
    for owner in (
        "compat/x86_64/native-strptime-reference/strptime.c",
        "compat/x86_64/native-strptime-reference/COPYRIGHT",
        "compat/x86_64/native-strptime-reference/README.md",
        "compat/x86_64/owned_wordexp_upstream_policy.py",
        "compat/x86_64/owned_wordexp_upstream_policy_diagnostics.json",
        "compat/x86_64/owned_wordexp_source_policy_probe.c",
        "compat/x86_64/owned-wordexp-upstream-policy.md",
        "compat/x86_64/owned_wordexp_evidence.py",
        "compat/x86_64/tests/test_owned_wordexp_upstream_policy.py",
        "compat/x86_64/atomic_addressable_abi_dynamic_main.c",
        "compat/x86_64/run_owned_atomic_addressable_profile.sh",
        "compat/x86_64/owned_atomic_addressable_profile.py",
        "compat/x86_64/owned-atomic-addressable-profile.md",
        "compat/x86_64/tests/test_owned_atomic_addressable_profile.py",
        "compat/x86_64/tests/test_owned_atomic_addressable_profile_dispatch.py",
        "compat/x86_64/tests/test_owned_posix_native_dispatch.py",
        "compat/x86_64/tests/test_dynamic_loader_dispatch.py",
        "scripts/dev-x86_64.sh",
    ):
        require(owner in owners, f"libc.posix-runtime must own {owner}")
    evidence = family["native_evidence"]
    require(
        isinstance(evidence, list) and len(evidence) == 1 and isinstance(evidence[0], Mapping)
        and evidence[0].get("state")
            == ("required" if family.get("status") == "planned" else "verified")
        and evidence[0].get("command") == "./scripts/dev-x86_64.sh owned-posix-native --family-execution FILE --crypt-profile FILE --atomic-addressable-profile FILE --wordexp-profile FILE --wordexp-expected-native-inputs FILE --output NEW_DIR",
        "libc.posix-runtime must use the finite native profile command",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and "credential, crypt, and addressable-atomic" in scope
        and "fixed strptime source-and-POSIX contract" in scope
        and "twenty candidate and 104 oracle wordexp diagnostics" in scope
        and "independently captured native-input seal" in scope
        and "candidate passes and fixed musl math defects" in scope
        and "candidate good/musl undefined" in scope
        and "raw_passed=false" in scope
        and "56 retained-reviewed-project-c-abi-extension rows remain unchanged" in scope
        and "Musl or C++ header parity" in scope
        and "native_aggregate_complete only" in scope,
        "libc.posix-runtime finite profile scope is incomplete",
    )
    execution = (ROOT / "compat" / "x86_64" / "owned_posix_native_execution.py").read_text(encoding="utf-8")
    require(
        "--atomic-addressable-profile" in execution
        and "atomic_addressable_profile" in execution,
        "libc.posix-runtime finite atomic profile collector is incomplete",
    )
    require(
        "--wordexp-profile" in execution and "wordexp_profile" in execution
        and "--wordexp-expected-native-inputs" in execution and "wordexp_expected_native_inputs" in execution,
        "libc.posix-runtime finite wordexp profile collector is incomplete",
    )


def require_posix_runtime_family_admission(family: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Admit POSIX only from a current physical aggregate-and-matrix receipt.

    The 97 older POSIX artifact checks below intentionally remain narrow leaf
    ratchets. They may stop requiring a planned owner only after this receipt
    reconstructs all nine frozen capabilities and all 149 spellings from the
    same current source. A changed status or a hand-written evidence state is
    never a substitute for that proof.
    """
    require(family.get("id") == "libc.posix-runtime", "wrong family for POSIX runtime admission")
    status = family.get("status")
    require(status in ALLOWED_STATUSES, "POSIX runtime admission family status is invalid")
    evidence = family.get("native_evidence")
    require(isinstance(evidence, list) and len(evidence) == 1 and isinstance(evidence[0], Mapping),
            "POSIX runtime admission evidence roster differs")
    if status == "planned":
        require("receipt" not in evidence[0], "planned POSIX runtime must not attach a family admission receipt")
        return None

    receipt_value = evidence[0].get("receipt")
    require(isinstance(receipt_value, str) and receipt_value,
            "foundation-verified libc.posix-runtime needs a family admission receipt")
    receipt_path = Path(receipt_value)
    require(not receipt_path.is_absolute() and ".." not in receipt_path.parts,
            "POSIX family admission receipt must be checkout-relative")
    physical = ROOT / receipt_path
    require(physical.is_file() and not physical.is_symlink() and physical.resolve() == physical
            and physical.is_relative_to(ROOT / ".work"),
            "POSIX family admission receipt must be a physical checkout .work file")
    try:
        import owned_posix_native_execution as posix_native

        admission = posix_native.validate_admission_receipt(ROOT, physical)
    except (RuntimeError, OSError, ValueError, TypeError) as error:
        raise LedgerError(f"POSIX family admission receipt rejected: {error}") from error
    require(
        admission.get("schema") == posix_native.ADMISSION_SCHEMA
        and admission.get("status") == "family-admission-verified"
        and admission.get("family") == "libc.posix-runtime"
        and admission.get("family_completion") is True
        and admission.get("native_aggregate_complete") is True
        and admission.get("campaign_complete") is False
        and admission.get("promotion_ready") is False
        and admission.get("public_support") is False,
        "POSIX family admission completion boundary differs",
    )
    proof = admission.get("proof")
    require(isinstance(proof, Mapping)
            and proof.get("capability_count") == 9
            and proof.get("symbol_count") == 149
            and proof.get("static_spelling_cell_count") == 894
            and proof.get("dynamic_spelling_cell_count") == 1788,
            "POSIX family admission frozen capability/spelling proof differs")
    return admission


def posix_runtime_private_artifact_view(
    family: Mapping[str, Any], admission: Mapping[str, Any] | None
) -> Mapping[str, Any]:
    """Keep legacy leaf ratchets narrow until the complete family is admitted."""
    if family.get("status") == "planned":
        require(admission is None, "planned POSIX runtime cannot have an admission receipt")
        return family
    require(admission is not None, "POSIX runtime leaf ratchets need actual family admission")
    # Existing leaf validators correctly reject an isolated artifact as a
    # promotion. Their ``planned`` check is a local non-promotion boundary,
    # not a claim that an independently reconstructed full-family receipt is
    # absent. Preserve the source data and substitute only that local view.
    view = dict(family)
    view["status"] = "planned"
    return view


def require_pthread_runtime_family_admission(
    family: Mapping[str, Any],
    posix_family: Mapping[str, Any],
    posix_admission: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    """Admit pthread only from the current POSIX admission and family receipt."""
    require(family.get("id") == "libc.pthread-tls", "wrong family for pthread/TLS admission")
    status = family.get("status")
    require(status in ALLOWED_STATUSES, "pthread/TLS admission family status is invalid")
    evidence, _ = evidence_records(
        family.get("native_evidence"), "family[libc.pthread-tls].native_evidence",
        unique_commands=True,
    )
    expected_commands = (
        "./scripts/dev-x86_64.sh libc-atomic",
        "./scripts/dev-x86_64.sh libc-clone-raw",
        "./scripts/dev-x86_64.sh owned-pthread-family --family-execution FILE --output NEW_DIR",
    )
    require(tuple(entry["command"] for entry in evidence) == expected_commands,
            "pthread/TLS native evidence command roster differs")
    expected_scopes = (
        "Source-only native x86 i32 atomic helper instruction/behavior proof; it does not select crabc-libc or complete pthread/TLS parity.",
        "Source-only pinned-musl x86 process-clone machine-boundary proof for SIGCHLD callback/stack/exit behavior; it has no public clone, pthread, or TLS claim.",
        "The installed pthread/TLS component consumes a validated POSIX matrix and replays the exact finite six-static/twelve-dynamic roster. It retains one supplied-product C11/TLS/synchronization composition with pinned-musl comparison plus reused matrix and dynamic-qualification receipts. It is required component evidence only: it does not admit family completion, promotion, or public x86 support.",
    )
    require(tuple(entry["scope"] for entry in evidence) == expected_scopes,
            "pthread/TLS native evidence scope differs")

    if status == "planned":
        require(posix_admission is None or posix_family.get("status") == "foundation-verified",
                "planned pthread/TLS cannot consume an unadmitted POSIX family")
        require("receipt" not in evidence[2],
                "planned pthread/TLS must not attach a component receipt")
        return None

    require(status == "foundation-verified", "pthread/TLS family status is unsupported")
    require(posix_family.get("status") == "foundation-verified" and posix_admission is not None,
            "pthread/TLS foundation requires admitted libc.posix-runtime")
    require(all(entry.get("state") == "verified" for entry in evidence),
            "foundation-verified pthread/TLS requires every native evidence gate")
    receipt_value = evidence[2].get("receipt")
    require(isinstance(receipt_value, str) and receipt_value,
            "foundation-verified pthread/TLS needs its component receipt")
    receipt_path = Path(receipt_value)
    require(not receipt_path.is_absolute() and ".." not in receipt_path.parts,
            "pthread/TLS component receipt must be checkout-relative")
    physical = ROOT / receipt_path
    require(physical.is_file() and not physical.is_symlink() and physical.resolve() == physical
            and physical.is_relative_to(ROOT / ".work"),
            "pthread/TLS component receipt must be a physical checkout .work file")
    try:
        import owned_pthread_family as pthread_family

        admission = pthread_family.validate_receipt(ROOT, physical)
    except (RuntimeError, OSError, ValueError, TypeError) as error:
        raise LedgerError(f"pthread/TLS component receipt rejected: {error}") from error

    require(admission.get("schema") == "crabc.x86_64-owned-pthread-family/v1"
            and admission.get("status") == "installed-behavior-component-verified"
            and admission.get("family") == "libc.pthread-tls"
            and admission.get("component_complete") is True
            and admission.get("family_completion") is False
            and admission.get("promotion_ready") is False
            and admission.get("public_support") is False,
            "pthread/TLS component receipt completion boundary differs")
    inputs = admission.get("inputs")
    posix_inputs = posix_admission.get("inputs")
    require(isinstance(inputs, Mapping) and isinstance(posix_inputs, Mapping)
            and inputs.get("source") == posix_inputs.get("source")
            and inputs.get("family_execution") == posix_inputs.get("family_execution"),
            "pthread/TLS component and POSIX admission must share source and matrix")
    return admission


def pthread_runtime_private_artifact_view(
    family: Mapping[str, Any], admission: Mapping[str, Any] | None
) -> Mapping[str, Any]:
    """Keep verified pthread leaves private after family admission."""
    if family.get("status") == "planned":
        require(admission is None, "planned pthread/TLS cannot have family admission")
        return family
    require(admission is not None, "pthread/TLS leaf ratchets need actual family admission")
    # Each leaf remains deliberately narrower than its owning family. Its
    # planned-status guard is local to that boundary, not a claim that the
    # full installed-product family receipt is absent.
    view = dict(family)
    view["status"] = "planned"
    return view


RESOLVER_FAMILY_COMMANDS = (
    "./scripts/dev-x86_64.sh owned-resolver-network",
    "./scripts/dev-x86_64.sh owned-resolver-cancellation",
    "./scripts/dev-x86_64.sh owned-resolver-family --static-preparation FILE --dynamic-qualification FILE --output NEW_DIR",
)
RESOLVER_FAMILY_SCOPE = (
    "One supplied current static-preparation/dynamic-qualification cohort executes every libc.resolver "
    "behavior component: controlled-network A/AAAA/CNAME, negative and malformed replies, search, "
    "timeout/retry/server failover and UDP/TCP fallback; classic and modern host/service lookup, errors, "
    "result lifetime, threads and fork; public resolver state and alias bodies; cancellation and descriptor "
    "retirement; and the fixed musl protocol table, through static ET_EXEC/static PIE and dynamic PIE/non-PIE "
    "kernel/direct entry. The retained assessment replays every public reader and joins their product roots "
    "to that one cohort. It admits family evidence only: promotion and public x86 support remain separate."
)


def require_resolver_family_admission(
    family: Mapping[str, Any],
    posix_family: Mapping[str, Any],
    posix_admission: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    """Admit libc.resolver only from a complete assessment on the POSIX cohort.

    The component commands remain development and qualification-chain entry
    points. Only the family command's retained assessment names one current
    product cohort for every reader; the admitted POSIX matrix must have used
    exactly the same static-preparation and dynamic-qualification receipts.
    """
    require(family.get("id") == "libc.resolver", "wrong family for resolver admission")
    status = family.get("status")
    require(status in ALLOWED_STATUSES, "resolver admission family status is invalid")
    evidence, _ = evidence_records(
        family.get("native_evidence"), "family[libc.resolver].native_evidence",
        unique_commands=True,
    )
    require(tuple(entry["command"] for entry in evidence) == RESOLVER_FAMILY_COMMANDS,
            "resolver native evidence command roster differs")
    require(evidence[2]["scope"] == RESOLVER_FAMILY_SCOPE, "resolver family evidence scope differs")

    if status == "planned":
        require("receipt" not in evidence[2], "planned libc.resolver must not attach a family assessment")
        return None

    require(posix_family.get("status") == "foundation-verified" and posix_admission is not None,
            "resolver foundation requires admitted libc.posix-runtime")
    require(all(entry.get("state") == "verified" for entry in evidence),
            "foundation-verified libc.resolver requires every native evidence gate")
    receipt_value = evidence[2].get("receipt")
    require(isinstance(receipt_value, str) and receipt_value,
            "foundation-verified libc.resolver needs its family assessment")
    receipt_path = Path(receipt_value)
    require(not receipt_path.is_absolute() and ".." not in receipt_path.parts,
            "resolver family assessment must be checkout-relative")
    physical = ROOT / receipt_path
    require(physical.is_file() and not physical.is_symlink() and physical.resolve() == physical
            and physical.is_relative_to(ROOT / ".work"),
            "resolver family assessment must be a physical checkout .work file")
    try:
        import owned_resolver_family as resolver_family

        admission = resolver_family.admission_facts(ROOT, physical)
    except (RuntimeError, OSError, ValueError, TypeError) as error:
        raise LedgerError(f"resolver family assessment rejected: {error}") from error

    inputs = posix_admission.get("inputs")
    require(isinstance(inputs, Mapping) and inputs.get("source") == admission.get("source"),
            "resolver family and POSIX admission must share current source")
    matrix_identity = inputs.get("family_execution")
    require(isinstance(matrix_identity, Mapping) and isinstance(matrix_identity.get("path"), str),
            "POSIX admission family matrix identity differs")
    matrix_path = ROOT / matrix_identity["path"]
    try:
        matrix_bytes = matrix_path.read_bytes()
        matrix = json.loads(matrix_bytes)
    except (OSError, ValueError) as error:
        raise LedgerError(f"POSIX family matrix is unreadable for resolver admission: {error}") from error
    require(hashlib.sha256(matrix_bytes).hexdigest() == matrix_identity.get("sha256"),
            "POSIX family matrix changed after admission")
    matrix_inputs = matrix.get("inputs") if isinstance(matrix, Mapping) else None
    require(isinstance(matrix_inputs, Mapping), "POSIX family matrix inputs differ")
    for name in ("static_preparation", "dynamic_qualification"):
        resolver_record, posix_record = admission.get(name), matrix_inputs.get(name)
        require(isinstance(resolver_record, Mapping) and isinstance(posix_record, Mapping)
                and resolver_record.get("path") == posix_record.get("path")
                and resolver_record.get("sha256") == posix_record.get("sha256"),
                f"resolver family and POSIX matrix must share the {name} receipt")
    return admission


def resolver_private_artifact_view(
    family: Mapping[str, Any], admission: Mapping[str, Any] | None
) -> Mapping[str, Any]:
    """Keep verified resolver leaves private after family admission."""
    if family.get("status") == "planned":
        require(admission is None, "planned libc.resolver cannot have family admission")
        return family
    require(admission is not None, "resolver leaf ratchets need actual family admission")
    # Each static C leaf stays narrower than the admitted family. Its local
    # planned-status guard rejects leaf promotion, not the family receipt.
    view = dict(family)
    view["status"] = "planned"
    return view


def require_ctype_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep ctype declarations and fast/legacy macros below runtime selection."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == "./scripts/dev-x86_64.sh ctype-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one ctype-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl C/C++",
                "fourteen ordinary ctype declarations",
                "C-only `__isspace` inline",
                "exact `isalpha`/`isdigit`/`islower`/`isupper`/`isprint`/`isgraph`/`isspace`",
                "all C feature profiles",
                "C++-hidden",
                "C-only exact `isascii` macro",
                "`toascii` declaration",
                "exact bitwise `_tolower`/`_toupper`",
                "POSIX/XOPEN/GNU/BSD C-visible",
                "strict-C-hidden",
                "compiler-native C++17",
                "archive linkage",
                "C-locale runtime behavior",
                "header-family completion",
                "public support",
            )
        ),
        "libc.headers-layouts ctype-header-abi evidence must retain its narrow header-only boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "include/ctype.h",
        "compat/x86_64/ctype_header_abi_probe.c",
        "compat/x86_64/ctype_header_abi_probe.cpp",
        "compat/x86_64/run_ctype_header_abi.sh",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts ctype-header-abi source owners omit {owner}",
        )


def require_socket_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep netinet macro evidence separate from socket runtime selection."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == "./scripts/dev-x86_64.sh socket-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one socket-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl C/C++",
                "IPv4/IPv6 address-equality/classification",
                "`__ARE_4_EQUAL`/`IN6_ARE_ADDR_EQUAL`",
                "`IN_CLASSA`/`IN_CLASSB`/`IN_CLASSC`/`IN_CLASSD`/`IN_MULTICAST`/`IN_EXPERIMENTAL`/`IN_BADCLASS`",
                "GNU/BSD `IP_MSFILTER_SIZE`/`GROUP_FILTER_SIZE`",
                "socket membership",
                "packet I/O",
                "socket options",
                "vectored/ancillary messages",
                "address conversion",
                "resolver/netdb",
                "C networking runtime behavior",
            )
        ),
        "libc.headers-layouts socket-header-abi evidence must retain its narrow header-only boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "include/netinet/in.h",
        "compat/x86_64/socket_header_abi_probe.c",
        "compat/x86_64/socket_header_abi_probe.cpp",
        "compat/x86_64/socket_header_ipv6_macro_probe.c",
        "compat/x86_64/run_socket_header_abi.sh",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts socket-header-abi source owners omit {owner}",
        )


def require_tcp_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep TCP declaration/layout evidence below transport-runtime selection."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == "./scripts/dev-x86_64.sh tcp-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one tcp-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl seven-profile C/C++",
                "`<netinet/tcp.h>`",
                "unconditional TCP option/state and netlink vocabulary",
                "GNU/BSD option-parser constants",
                "`tcp_seq`",
                "`struct tcphdr` 20-byte/align-4 legacy layout",
                "GNU-only `tcp_info`",
                "`tcp_md5sig`",
                "`tcp_diag_md5sig`",
                "`tcp_repair_window`",
                "`tcp_zerocopy_receive`",
                "anonymous GNU `tcphdr` aliases",
                "archive linkage",
                "TCP socket-option behavior",
                "TCP transport behavior",
                "socket runtime behavior",
                "installed-header completion",
                "family completion",
                "public x86 support",
            )
        ),
        "libc.headers-layouts tcp-header-abi evidence must retain its narrow header-only boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "include/netinet/tcp.h",
        "compat/x86_64/tcp_header_abi_probe.c",
        "compat/x86_64/tcp_header_abi_probe.cpp",
        "compat/x86_64/run_tcp_header_abi.sh",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts tcp-header-abi source owners omit {owner}",
        )


def require_stddef_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep shared stddef declaration evidence below header completion."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == "./scripts/dev-x86_64.sh stddef-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one stddef-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl seven-profile C/C++",
                "`<stddef.h>`",
                "`_STDDEF_H`",
                "`NULL`",
                "`__NEED_ptrdiff_t`/`__NEED_size_t`/`__NEED_wchar_t`/`__NEED_max_align_t`",
                "`bits/alltypes.h`",
                "LP64 `size_t`/`ptrdiff_t`/`wchar_t`",
                "`max_align_t`",
                "`offsetof`",
                "archive linkage",
                "allocation behavior",
                "installed-header completion",
                "family completion",
                "public x86 support",
            )
        ),
        "libc.headers-layouts stddef-header-abi evidence must retain its narrow header-only boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "include/stddef.h",
        "compat/x86_64/stddef_header_abi_probe.c",
        "compat/x86_64/stddef_header_abi_probe.cpp",
        "compat/x86_64/run_stddef_header_abi.sh",
        "compat/x86_64/tests/test_stddef_header_abi.py",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts stddef-header-abi source owners omit {owner}",
        )


def require_socket_messages_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep ancillary traversal macros inside the bounded message header gate."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command")
        == "./scripts/dev-x86_64.sh socket-messages-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one socket-messages-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl POSIX/GNU/BSD C/C++",
                "exact unconditional `__CMSG_LEN`/`__CMSG_NEXT`/`__MHDR_END`",
                "ancillary traversal helpers",
                "archive linkage",
                "socket runtime behavior",
                "installed-header completion",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts socket-messages-header-abi evidence must retain its narrow header-only boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "include/sys/socket.h",
        "compat/x86_64/socket_messages_header_abi_probe.c",
        "compat/x86_64/socket_messages_header_abi_probe.cpp",
        "compat/x86_64/socket_messages_header_visibility_probe.c",
        "compat/x86_64/run_socket_messages_header_abi.sh",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts socket-messages-header-abi source owners omit {owner}",
        )


def require_inet_address_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep the selected numeric-address declarations below header promotion."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == "./scripts/dev-x86_64.sh inet-address-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one inet-address-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "default/GNU/strict C/C++",
                "<arpa/inet.h>",
                "`inet_pton`/`inet_ntop`/`inet_aton`/`inet_addr`/`inet_ntoa`/`inet_makeaddr`/`inet_lnaof`",
                "`in_addr_t`/`in_port_t`/`struct in_addr`",
                "INET text-buffer constants",
                "archive linkage",
                "address-conversion runtime behavior",
                "DNS/resolver state",
                "netdb",
                "installed-header completion",
                "family completion",
                "public x86 support",
            )
        ),
        "libc.headers-layouts inet-address-header-abi evidence must retain its narrow non-completion boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "compat/x86_64/inet_address_header_abi_probe.c",
        "compat/x86_64/inet_address_header_abi_probe.cpp",
        "compat/x86_64/run_inet_address_header_abi.sh",
        "include/arpa/inet.h",
        "include/stddef.h",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts inet-address-header-abi source owners omit {owner}",
        )


def require_nameser_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep the selected nameserver declaration gate below resolver promotion."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == "./scripts/dev-x86_64.sh nameser-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one nameser-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl C/C++",
                "<resolv.h>",
                "`dn_skipname(const unsigned char *, const unsigned char *)`",
                "`ns_get16(const unsigned char *)`",
                "`ns_get32(const unsigned char *)`",
                "`ns_put16(unsigned, unsigned char *)`",
                "NS_CMPRSFLGS/NS_MAXLABEL/NS_MAXCDNAME/NS_MAXDNAME",
                "exact unconditional `ns_t_qt_p`/`ns_t_mrr_p`/`ns_t_rr_p`/`ns_t_udp_p`/`ns_t_xfr_p`",
                "`NS_NXT_BIT_SET`/`NS_NXT_BIT_CLEAR`/`NS_NXT_BIT_ISSET`",
                "record-classification macros",
                "strict C project-header trace exactly owns",
                "`bits/stdint.h`",
                "`bits/socket.h`",
                "rejects `sys/types.h`",
                "caller-owned DNS wire-name span",
                "caller-owned 16-bit wire-read",
                "caller-owned 32-bit wire-read",
                "caller-owned 16-bit wire-write",
                "resolver state",
                "/etc/resolv.conf",
                "DNS packet I/O",
                "sockets",
                "netdb",
                "archive linkage",
                "installed-header completion",
                "family completion",
                "public x86 support",
            )
        ),
        "libc.headers-layouts nameser-header-abi evidence must retain its narrow non-resolver boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "compat/x86_64/nameser_header_abi_probe.c",
        "compat/x86_64/nameser_header_abi_probe.cpp",
        "compat/x86_64/run_nameser_header_abi.sh",
        *EXPECTED_NAMESER_STRICT_C_TRACE_HEADERS,
    ):
        require(
            owner in owners,
            f"libc.headers-layouts nameser-header-abi source owners omit {owner}",
        )

    runner = (
        ROOT / "compat" / "x86_64" / "run_nameser_header_abi.sh"
    ).read_text(encoding="utf-8")

    def read_readonly_trace_array(name: str) -> tuple[str, ...]:
        """Read this runner's declarative quoted array without evaluating shell."""
        match = re.search(
            rf"(?m)^readonly {re.escape(name)}=\(\n"
            r'(?P<body>(?:[ \t]+"[^"\n]+"[ \t]*\n)*)'
            r"^\)$",
            runner,
        )
        require(
            match is not None,
            f"nameser header runner has malformed {name} declaration",
        )
        assert match is not None
        return tuple(
            re.findall(r'(?m)^[ \t]+"([^"\n]+)"[ \t]*$', match.group("body"))
        )

    expected_project_headers = tuple(
        header.removeprefix("include/")
        for header in EXPECTED_NAMESER_STRICT_C_TRACE_HEADERS
    )
    observed_project_headers = read_readonly_trace_array(
        "STRICT_C_PROJECT_HEADERS"
    )
    require(
        observed_project_headers == expected_project_headers,
        "strict C nameser project-header trace drifted: "
        f"expected {expected_project_headers}, observed {observed_project_headers}",
    )
    observed_forbidden_headers = read_readonly_trace_array(
        "STRICT_C_FORBIDDEN_HEADERS"
    )
    require(
        observed_forbidden_headers == ("sys/types.h",),
        "strict C nameser forbidden-header trace drifted: "
        f"observed {observed_forbidden_headers}",
    )
    for snippet in (
        'fail "strict C probe unexpectedly used project <$header>"',
        "strict C trace project header closure diverges from pinned musl",
    ):
        require(
            snippet in runner,
            f"nameser header runner omits strict C trace assertion {snippet}",
        )


def require_quota_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep the complete quota header below quota syscall and policy selection."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == "./scripts/dev-x86_64.sh quota-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one quota-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl C/C++",
                "<sys/quota.h>",
                "full pinned-musl quota header",
                "exact unconditional `dbtob`/`btodb`/`fs_to_dq_blocks`/`dqoff`",
                "quota constants/masks",
                "legacy `dq_*` aliases",
                "`dqblk`/`dqinfo` LP64 layouts",
                "C/C++ `quotactl` declaration",
                "compile-only",
                "quotactl archive/runtime behavior",
                "quota policy/accounting",
                "filesystem/kernel state",
                "system.kernel-admin",
                "installed-header completion",
                "family completion",
                "public support",
            )
        ),
        "libc.headers-layouts quota-header-abi evidence must retain its narrow header-only boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "include/sys/quota.h",
        "compat/x86_64/quota_header_abi_probe.c",
        "compat/x86_64/quota_header_abi_probe.cpp",
        "compat/x86_64/run_quota_header_abi.sh",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts quota-header-abi source owners omit {owner}",
        )


def require_sched_cpu_macros_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep GNU CPU-set syntax below allocator and scheduler runtime selection."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command")
        == "./scripts/dev-x86_64.sh sched-cpu-macros-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one sched-cpu-macros-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl C/C++",
                "<sched.h>",
                "exact GNU `__CPU_op_S`/`CPU_SET_S`/`CPU_CLR_S`/`CPU_ISSET_S`",
                "`CPU_ALLOC_SIZE`/`CPU_ALLOC`/`CPU_FREE`",
                "generated `__CPU_AND_S`/`__CPU_OR_S`/`__CPU_XOR_S`",
                "`CPU_SETSIZE`",
                "canonical C++ strict visibility",
                "forced-macro-hidden negative selection",
                "archive linkage",
                "allocator runtime behavior",
                "byte-string runtime behavior",
                "scheduler policy/affinity",
                "installed-header completion",
                "family completion",
                "public x86 support",
            )
        ),
        "libc.headers-layouts sched-cpu-macros-header-abi evidence must retain its narrow header-only boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "include/sched.h",
        "compat/x86_64/sched_cpu_macros_header_abi_probe.c",
        "compat/x86_64/sched_cpu_macros_header_abi_probe.cpp",
        "compat/x86_64/run_sched_cpu_macros_header_abi.sh",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts sched-cpu-macros-header-abi source owners omit {owner}",
        )


def require_fanotify_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep fanotify caller-buffer macros below descriptor and watcher selection."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matches = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command") == "./scripts/dev-x86_64.sh fanotify-header-abi"
    ]
    require(
        len(matches) == 1,
        "libc.headers-layouts must retain exactly one fanotify-header-abi evidence command",
    )
    record = matches[0]
    scope = record.get("scope")
    require(
        record.get("state") == "required"
        and isinstance(scope, str)
        and all(
            phrase in scope
            for phrase in (
                "project-first/pinned-musl",
                "seven-profile C/C++",
                "<sys/fanotify.h>",
                "Linux 5.10",
                "`fanotify_event_metadata` LP64 layout",
                "`FAN_EVENT_METADATA_LEN`",
                "exact unconditional `FAN_EVENT_NEXT`/`FAN_EVENT_OK`",
                "C/C++ result types",
                "canonical strict C++ visibility",
                "record traversal macros",
                "archive linkage",
                "fanotify_init/fanotify_mark archive/runtime behavior",
                "descriptor creation",
                "kernel watcher state",
                "watcher policy",
                "installed-header completion",
                "family completion",
                "public x86 support",
            )
        ),
        "libc.headers-layouts fanotify-header-abi evidence must retain its narrow header-only boundary",
    )
    owners = set(
        nonempty_strings(
            family["source_owners"], "family[libc.headers-layouts].source_owners"
        )
    )
    for owner in (
        "include/stddef.h",
        "include/sys/fanotify.h",
        "compat/x86_64/fanotify_header_abi_probe.c",
        "compat/x86_64/fanotify_header_abi_probe.cpp",
        "compat/x86_64/run_fanotify_header_abi.sh",
    ):
        require(
            owner in owners,
            f"libc.headers-layouts fanotify-header-abi source owners omit {owner}",
        )


def evidence_records(
    value: Any, location: str, *, unique_commands: bool = False
) -> tuple[list[Mapping[str, Any]], set[str]]:
    """Validate the common native-evidence record shape."""
    require(isinstance(value, list) and value, f"{location} must be a non-empty array")
    records: list[Mapping[str, Any]] = []
    states: set[str] = set()
    commands: set[str] = set()
    for index, entry in enumerate(value):
        item_location = f"{location}[{index}]"
        require(isinstance(entry, Mapping), f"{item_location} must be a table")
        state = entry.get("state")
        command = entry.get("command")
        scope = entry.get("scope")
        require(state in ALLOWED_EVIDENCE_STATES, f"{item_location}.state is invalid")
        require(isinstance(command, str) and command, f"{item_location}.command is empty")
        require(isinstance(scope, str) and scope, f"{item_location}.scope is empty")
        if unique_commands:
            assert isinstance(command, str)
            require(
                command not in commands,
                f"{item_location}.command duplicates a native evidence command",
            )
            commands.add(command)
        states.add(state)
        records.append(entry)
    return records, states


def require_evidence_state(
    value: Any,
    location: str,
    expected_state: str,
    *,
    unique_commands: bool = False,
) -> tuple[list[Mapping[str, Any]], set[str]]:
    """Require one evidence state without promoting its owning family."""
    require(expected_state in ALLOWED_EVIDENCE_STATES, f"{location} has invalid expected state")
    records, states = evidence_records(value, location, unique_commands=unique_commands)
    require(states == {expected_state}, f"{location} must be entirely {expected_state}")
    return records, states


def require_evidence(
    value: Any, location: str, status: str
) -> tuple[list[Mapping[str, Any]], set[str]]:
    """Validate family evidence without treating its execution as promotion.

    A planned family may contain evidence that has already run as well as
    evidence still required.  Its ``status`` and the family-specific
    completion predicates remain the only promotion boundary.  Once a family
    is ``foundation-verified``, every family evidence record must be verified.
    """
    require(status in ALLOWED_STATUSES, f"{location} has invalid family status")
    records, states = evidence_records(value, location)
    if status == "foundation-verified":
        require(states == {"verified"}, f"{location} must be entirely verified")
    return records, states


def require_lua_source_build_admission(family: Mapping[str, Any]) -> None:
    """Do not admit the source-build family from prose or stale latest pointers."""

    evidence, _states = require_evidence(
        family.get("native_evidence"), "family[consumer.source-build].native_evidence", "foundation-verified"
    )
    require(
        len(evidence) == 1
        and evidence[0].get("command") == "./scripts/dev-x86_64.sh lua-source-build-admission",
        "consumer.source-build requires its canonical Lua admission verifier",
    )
    source_build_root = ROOT / "compat" / "lua"
    if str(source_build_root) not in sys.path:
        sys.path.insert(0, str(source_build_root))
    import source_build_admission

    try:
        source_build_admission.validate()
    except Exception as error:
        raise LedgerError(f"consumer.source-build Lua admission failed: {error}") from error


def require_header_foundation_downstream_evidence(
    value: Any, location: str, status: str
) -> tuple[list[Mapping[str, Any]], set[str]]:
    """Keep downstream C-ABI/runtime gates required after header promotion.

    ``libc.headers-layouts`` earns its foundation status from the checked
    aggregate and its verified artifacts.  Its top-level evidence instead
    names C-ABI/provider/runtime leaves that remain explicitly downstream, so
    treating them as family-completion evidence would overstate the result.
    """

    require(
        status == "foundation-verified",
        "header-foundation downstream evidence requires a verified family",
    )
    return require_evidence_state(value, location, "required")


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
    cache = _verified_artifact_cache.get()
    cache_key = id(value)
    if cache is not None:
        cached = cache.get(cache_key)
        if cached is not None:
            cached_value, cached_status, cached_records = cached
            if cached_value is value and cached_status == status:
                return list(cached_records)
    require(
        status in {"planned", "foundation-verified"},
        f"{location} is allowed only on a planned or foundation-verified family",
    )
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
        require_evidence_state(
            entry["native_evidence"],
            f"{item_location}.native_evidence",
            "verified",
            unique_commands=True,
        )
        require_oracles(entry["oracle"], f"{item_location}.oracle")
        records.append(entry)
    if cache is not None:
        # Cache only after every structural predicate and source-owner path
        # has succeeded, retaining `value` to make the identity key unambiguous.
        cache[cache_key] = (value, status, tuple(records))
    return records


def require_posix_process_abi_admission_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet the selected static qualification inventory below family completion."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[compat.posix-process].verified_artifact",
        family.get("status", ""),
    )
    matching = [
        entry
        for entry in artifacts
        if entry.get("id") == "static-posix-process-abi-admission"
    ]
    require(
        len(matching) == 1,
        "compat.posix-process needs exactly one static-posix-process-abi-admission artifact",
    )
    require(
        family.get("status") == "planned",
        "static-posix-process-abi-admission must not promote compat.posix-process",
    )
    artifact = matching[0]
    description = artifact["description"]
    assert isinstance(description, str)
    for phrase in (
        "still-planned `compat.posix-process`",
        "closed five-case inventory",
        "same-object static `memfd_create` ABI/errno differential",
        "selected process-context archive",
        "bounded process-signal execution",
        "child reaping",
        "two-worker pthread/TLS transaction",
        "fresh process group",
        "kills the whole group on timeout",
        "not a generated report",
        "dynamic x86 `os-test`, `libc-test`, `pthread-stress`, and `signal-process` gates",
        "family completion",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-posix-process-abi-admission description omits {phrase}",
        )
    expected_sources = {
        "compat/x86_64/qualification_posix_abi.json",
        "compat/x86_64/run_qualification_manifest.py",
        "compat/x86_64/run_qualification_posix_abi.py",
        "compat/x86_64/run_libc_same_object_static_c_abi_differential.sh",
        "compat/x86_64/run_same_object_static_c_abi_differential.sh",
        "compat/x86_64/run_libc_process_context.sh",
        "compat/x86_64/run_libc_signal_execution.sh",
        "compat/x86_64/run_libc_child_reaping.sh",
        "compat/x86_64/run_libc_pthread_tls_aggregate.sh",
        "compat/x86_64/tests/test_qualification_manifest.py",
        "compat/x86_64/tests/test_qualification_posix_abi.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/tests/test_runner.py",
        "scripts/dev-x86_64.sh",
    }
    require(
        set(string_list(artifact["source_owners"], "POSIX/ABI admission source owners"))
        == expected_sources,
        "static-posix-process-abi-admission source owners drifted",
    )
    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh qualification-posix-abi-admission"},
        "static-posix-process-abi-admission must use the dedicated native command",
    )

    expected_cases = (
        (
            "same-object-static-c-abi",
            "compat.abi-differential",
            "compat/x86_64/run_libc_same_object_static_c_abi_differential.sh",
            "x86 static C ABI same-object differential: PASS (libc.a; pinned musl 1.2.6)",
            1200,
        ),
        (
            "static-process-context",
            "compat.posix-process",
            "compat/x86_64/run_libc_process_context.sh",
            "x86 static crabc-libc process context: PASS",
            1200,
        ),
        (
            "static-signal-execution",
            "compat.posix-process",
            "compat/x86_64/run_libc_signal_execution.sh",
            "x86 static crabc-libc signal execution: PASS",
            1200,
        ),
        (
            "static-child-reaping",
            "compat.posix-process",
            "compat/x86_64/run_libc_child_reaping.sh",
            "x86 static libc child reaping: PASS",
            1200,
        ),
        (
            "static-pthread-tls-aggregate",
            "compat.posix-process",
            "compat/x86_64/run_libc_pthread_tls_aggregate.sh",
            "x86 static crabc-libc pthread/TLS aggregate: PASS",
            1200,
        ),
    )
    try:
        document = json.loads(
            QUALIFICATION_POSIX_ABI_CONTRACT_PATH.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise LedgerError(f"cannot read POSIX/ABI admission contract: {error}") from error
    require(
        isinstance(document, Mapping)
        and document.get("schema")
        == "crabc.x86_64-qualification-posix-abi-admission/v1"
        and document.get("id") == "qualification-posix-abi-admission"
        and document.get("target") == "Linux/x86-64 little-endian",
        "POSIX/ABI admission contract identity drifted",
    )
    cases = document.get("cases")
    require(isinstance(cases, list), "POSIX/ABI admission cases must be an array")
    actual_cases = tuple(
        (
            entry.get("id"),
            entry.get("family"),
            entry.get("runner"),
            entry.get("expected_stdout_line"),
            entry.get("timeout_seconds"),
        )
        for entry in cases
        if isinstance(entry, Mapping)
    )
    require(
        len(actual_cases) == len(cases) and actual_cases == expected_cases,
        "POSIX/ABI admission case inventory drifted",
    )
    execution = qualification_manifest_runner.manifest.EXECUTION_CONTRACT
    expected_environment = {
        "PATH": execution["rust_bin_directory"] + ":" + qualification_manifest_runner.TRUSTED_PATH,
        "RUSTUP_HOME": execution["rustup_home"],
        "CARGO_HOME": execution["cargo_home"],
        "CRABC_WORK_DIR": execution["work_directory"],
        "TMPDIR": execution["temporary_directory"],
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }
    require(
        qualification_manifest_runner.controlled_environment() == expected_environment,
        "POSIX/ABI admission execution environment drifted",
    )
    aggregate = (
        ROOT / "compat" / "x86_64" / "run_qualification_posix_abi.py"
    ).read_text(encoding="utf-8")
    for phrase in (
        "EXPECTED_CASES",
        "qualification case roster or order drifted",
        "start_new_session=True",
        "os.killpg(process.pid, signal.SIGKILL)",
        "nonempty_lines.count(case.expected_stdout_line) != 1",
        "nonempty_lines[-1] != case.expected_stdout_line",
        "selected artifact transactions; non-promoting",
    ):
        require(phrase in aggregate, f"POSIX/ABI admission runner omits {phrase}")
    dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    require(
        "qualification-posix-abi-admission)" in dispatcher,
        "POSIX/ABI admission dispatcher binding is missing",
    )


def require_memory_sync_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep the artifact-local unconditional msync declaration gate explicit."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matching = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command")
        == "./scripts/dev-x86_64.sh memory-sync-header-abi"
    ]
    require(
        len(matching) == 1,
        "libc.headers-layouts must retain exactly one memory-sync-header-abi evidence command",
    )
    entry = matching[0]
    scope = entry.get("scope")
    require(
        entry.get("state") == "required" and isinstance(scope, str),
        "memory-sync-header-abi evidence must remain required text",
    )
    for phrase in (
        "eight-profile C/C++",
        "`msync(void *, size_t, int)`",
        "MS_ASYNC/MS_INVALIDATE/MS_SYNC=1/2/4",
        "unmangled C++ linkage",
        "archive linkage",
        "runtime behavior",
        "cancellation",
        "installed-header completion",
        "public support",
    ):
        require(
            phrase in scope,
            f"memory-sync-header-abi evidence scope omits {phrase}",
        )


def require_memfd_create_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep the artifact-local GNU memfd declaration gate explicit."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matching = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command")
        == "./scripts/dev-x86_64.sh memfd-create-header-abi"
    ]
    require(
        len(matching) == 1,
        "libc.headers-layouts must retain exactly one memfd-create-header-abi evidence command",
    )
    entry = matching[0]
    scope = entry.get("scope")
    require(
        entry.get("state") == "required" and isinstance(scope, str),
        "memfd-create-header-abi evidence must remain required text",
    )
    for phrase in (
        "eight-profile C/C++",
        "GNU `memfd_create(const char *, unsigned)`",
        "MFD_CLOEXEC/MFD_ALLOW_SEALING/MFD_HUGETLB=1/2/4",
        "GNU visibility",
        "default/strict/POSIX/XOPEN/BSD",
        "macro-free C++",
        "unmangled GNU C++ linkage",
        "archive linkage",
        "runtime behavior",
        "seals/fcntl",
        "installed-header completion",
        "public support",
    ):
        require(
            phrase in scope,
            f"memfd-create-header-abi evidence scope omits {phrase}",
        )


def require_memory_locking_header_evidence(family: Mapping[str, Any]) -> None:
    """Keep the artifact-local declaration gate outside the direct manifest."""
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list),
        "libc.headers-layouts must retain native evidence",
    )
    matching = [
        entry
        for entry in evidence
        if isinstance(entry, Mapping)
        and entry.get("command")
        == "./scripts/dev-x86_64.sh memory-locking-header-abi"
    ]
    require(
        len(matching) == 1,
        "libc.headers-layouts must retain exactly one memory-locking-header-abi evidence command",
    )
    entry = matching[0]
    scope = entry.get("scope")
    require(
        entry.get("state") == "required" and isinstance(scope, str),
        "memory-locking-header-abi evidence must remain required text",
    )
    for phrase in (
        "strict/POSIX/GNU C/C++",
        "`mlock`/`munlock`",
        "`mlock2`/`MLOCK_ONFAULT`",
        "GNU hiding",
        "unmangled C++ linkage",
        "archive linkage",
        "runtime behavior",
        "installed-header completion",
        "public support",
    ):
        require(
            phrase in scope,
            f"memory-locking-header-abi evidence scope omits {phrase}",
        )


STDIO_FILE_ENGINE_CAPABILITIES = (
    "stdio.path-stream",
    "stdio.stream-io",
    "stdio.position-buffering",
    "stdio.format-scan",
)


def require_stdio_installed_file_engine_slice(family: Mapping[str, Any]) -> None:
    """Bind the four FILE capabilities to the installed-engine receipt.

    The slice is credited only by the eight-row installed-header FILE-engine
    receipt, whose reader requires the retained objects to reference every
    frozen symbol of these capabilities. It must not absorb the source-only
    `stdio.fopen64-alias` capability or promote the family.
    """
    slices = require_verified_slices(
        family.get("verified_slice"),
        "family[libc.text-math-locale-stdio].verified_slice",
        str(family.get("status", "")),
        string_list(
            family.get("capabilities"),
            "family[libc.text-math-locale-stdio].capabilities",
            allow_empty=True,
        ),
    )
    matching = [entry for entry in slices if entry.get("id") == "stdio.installed-file-engine"]
    require(
        len(matching) == 1,
        "libc.text-math-locale-stdio must contain exactly one stdio.installed-file-engine slice",
    )
    require(
        family.get("status") == "planned",
        "stdio.installed-file-engine must not promote libc.text-math-locale-stdio",
    )
    selected = matching[0]
    require(
        selected.get("capabilities") == list(STDIO_FILE_ENGINE_CAPABILITIES),
        "stdio.installed-file-engine must select exactly the four FILE engine capabilities",
    )
    commands = [
        entry.get("command")
        for entry in selected.get("native_evidence", [])
        if isinstance(entry, Mapping)
    ]
    require(
        commands == [
            "./scripts/dev-x86_64.sh owned-stdio-file-engine",
            "./scripts/dev-x86_64.sh owned-stdio",
        ],
        "stdio.installed-file-engine must use its two installed-product evidence commands",
    )

    description = selected.get("description")
    require(isinstance(description, str), "stdio.installed-file-engine needs a description")
    for phrase in (
        "still-planned `libc.text-math-locale-stdio`",
        "pinned musl 1.2.6",
        "static ET_EXEC, static PIE, and dynamic PIE/non-PIE kernel/direct entry",
        "every frozen symbol of the four capabilities",
        "`feof`/`ferror`",
        "mid-stream `setvbuf`",
        "exit flush",
        "`stdio.fopen64-alias` macro remains its own slice",
        "family aggregate",
        "promotion",
        "public x86 support",
    ):
        require(phrase in description, f"stdio.installed-file-engine description omits {phrase}")

    owners = set(
        nonempty_strings(selected.get("source_owners"), "stdio.installed-file-engine.source_owners")
    )
    receipt_path = ROOT / "compat" / "x86_64" / "owned_stdio_file_engine_receipt.py"
    specification = importlib.util.spec_from_file_location(
        "parity_ledger_owned_stdio_file_engine_receipt", receipt_path
    )
    require(
        specification is not None and specification.loader is not None,
        "stdio.installed-file-engine cannot load its receipt reader",
    )
    reader = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(reader)
    require(
        tuple(reader.FROZEN_CAPABILITIES) == STDIO_FILE_ENGINE_CAPABILITIES
        and reader.FROZEN_LEDGER == "compat/crabc-rs/coverage.toml"
        and "stdio.frozen-surface" in reader.SCOPE,
        "stdio.installed-file-engine reader must check the same frozen FILE surface",
    )
    for role in reader.SCOPE:
        source = str(reader.ROLES[role]["source"])
        require(source in owners, f"stdio.installed-file-engine source owners omit {source}")
    for owner in (
        "compat/crabc-rs/coverage.toml",
        "libc/src/c_abi/x86_64/owned_static_stdio.rs",
        "compat/x86_64/run_owned_stdio_file_engine.sh",
        "compat/x86_64/owned_stdio_file_engine_receipt.py",
        "compat/x86_64/text-math-locale-stdio-family.toml",
        "compat/x86_64/validate_parity_ledger.py",
    ):
        require(owner in owners, f"stdio.installed-file-engine source owners omit {owner}")

    roster = load_toml(ROOT / "compat" / "x86_64" / "text-math-locale-stdio-family.toml")
    components = roster.get("components")
    engine = components.get("stdio-engine") if isinstance(components, Mapping) else None
    require(
        isinstance(engine, Mapping)
        and engine.get("reader") == "compat/x86_64/owned_stdio_file_engine_receipt.py"
        and set(STDIO_FILE_ENGINE_CAPABILITIES) <= set(engine.get("credits", []))
        and engine.get("rows") == list(reader.SCOPE),
        "stdio.installed-file-engine family roster must credit the engine rows",
    )


def require_math_log2_artifact(family: Mapping[str, Any]) -> None:
    """Keep the closed binary32/binary64 log-two leaf below math parity."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.text-math-locale-stdio].verified_artifact",
        family.get("status", ""),
    )
    require(
        len(artifacts) == 77,
        "libc.text-math-locale-stdio must retain exactly seventy-seven private verified artifacts",
    )
    matching = [entry for entry in artifacts if entry.get("id") == "static-c-math-log2"]
    require(
        len(matching) == 1,
        "libc.text-math-locale-stdio must contain exactly one static-c-math-log2 artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-math-log2 must not promote libc.text-math-locale-stdio",
    )
    artifact = matching[0]
    require(
        "capabilities" not in artifact,
        "static-c-math-log2 must remain a non-capability artifact",
    )
    description = artifact["description"]
    assert isinstance(description, str)
    for symbol in MATH_LOG2_SYMBOLS:
        require(
            f"`{symbol}`" in description,
            f"static-c-math-log2 description omits {symbol}",
        )
    for phrase in (
        "binary32/binary64 logarithm-base-two artifact",
        "GCC 15.2.0 assembly translation",
        "close-to-one reconstruction",
        "subnormal normalization",
        "table reduction",
        "localized data/error closure",
        "requested/observed rounding directions",
        "divide-by-zero/invalid",
        "compiler-builtins",
        "no undefined callable symbols",
        "binary80 `log2l`",
        "fenv API/policy",
        "log/log1p/log10 and exp/expm1 families",
        "`exp2`",
        "special and complex functions",
        "binary80/x87 math",
        "family completion",
        "promotion",
        "public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-math-log2 description omits {phrase}",
        )

    owners = nonempty_strings(
        artifact["source_owners"], "static-c-math-log2.source_owners"
    )
    for owner in (
        "compat/upstreams.toml",
        "docker/Dockerfile.x86_64",
        "libc/Cargo.toml",
        "libc/src/lib.rs",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/fenv.rs",
        "libc/src/c_abi/x86_64/math_log2.rs",
        "libc/src/c_abi/x86_64/math_log2_musl_x86_64.S",
        "compat/x86_64/generate_libc_math_log2.py",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/math_log2_header_abi_probe.cpp",
        "compat/x86_64/libc_math_log2_probe.c",
        "compat/x86_64/libc_math_log2_start.S",
        "compat/x86_64/run_libc_math_log2.sh",
        "compat/x86_64/aarch64_parity_inventory.py",
        "compat/x86_64/aarch64_parity_inventory.json",
        "compat/x86_64/tests/test_aarch64_parity_inventory.py",
        "compat/x86_64/tests/test_runner.py",
        "compat/x86_64/tests/test_parity_ledger.py",
        "compat/x86_64/validate_parity_ledger.py",
        "compat/x86_64/README.md",
        "plan.md",
        "scripts/check_structure.py",
        "scripts/dev-x86_64.sh",
    ):
        require(owner in owners, f"static-c-math-log2 omits {owner}")

    prerequisites = " ".join(
        nonempty_strings(
            artifact["x86_abi_prerequisites"],
            "static-c-math-log2.x86_abi_prerequisites",
        )
    )
    for phrase in (
        "src/math/log2.c",
        "log2f.c",
        "log2_data.c",
        "log2f_data.c",
        "__math_divzero.c",
        "__math_invalidf.c",
        "normalized 1.2.6 source-tree digest",
        "GCC 15.2.0",
        "MIT source closure",
        "-frounding-math",
        "-ffp-contract=off",
        "-fexcess-precision=standard",
        "FLT_EVAL_METHOD=0",
        "xmm0",
        "divsd/mulsd/addsd/subsd",
        "mulss/divss/subss",
        "localized",
        "`log2l`",
        "no undefined callable symbols",
        "existing selected static fegetenv",
        "without selecting fenv API or policy",
    ):
        require(phrase in prerequisites, f"static-c-math-log2 prerequisites omit {phrase}")
    header_prerequisites = " ".join(
        nonempty_strings(
            artifact["x86_header_prerequisites"],
            "static-c-math-log2.x86_header_prerequisites",
        )
    )
    for phrase in ("parenthesized", "C++17", "-mfpmath=387", "unmangled C"):
        require(
            phrase in header_prerequisites,
            f"static-c-math-log2 header prerequisites omit {phrase}",
        )

    evidence = artifact["native_evidence"]
    assert isinstance(evidence, list)
    require(
        {entry["command"] for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-math-log2"},
        "static-c-math-log2 must use the closed libc-math-log2 command",
    )
    scope = evidence[0]["scope"]
    assert isinstance(scope, str)
    for phrase in (
        "216 exact 32-byte records",
        "requested/observed MXCSR direction",
        "eight-source localized data/error closure",
        "__log2_data",
        "divsd/mulsd/addsd/subsd/divss/mulss/subss",
        "compiler-builtins",
        "log2l",
        "public x86 support",
    ):
        require(phrase in scope, f"static-c-math-log2 evidence omits {phrase}")

    static_root = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
    ).read_text(encoding="utf-8")
    require(
        '#[path = "math_log2.rs"]\nmod math_log2;' in static_root,
        "x86 static C ABI must compose the math_log2 leaf",
    )
    leaf = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_log2.rs"
    ).read_text(encoding="utf-8")
    for snippet in (
        "Selected static Linux/x86-64 `log2`/`log2f` C ABI leaf",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
        "src/math/log2.c",
        "src/math/log2f.c",
        "src/math/log2_data.c",
        "src/math/log2f_data.c",
        "localized",
        "-frounding-math",
        "fenv API or policy",
        'include_str!("math_log2_musl_x86_64.S")',
        "public x86 support",
    ):
        require(snippet in leaf, f"math_log2 leaf omits {snippet}")

    generator = (
        ROOT / "compat" / "x86_64" / "generate_libc_math_log2.py"
    ).read_text(encoding="utf-8")
    for snippet in (
        "2ebc86943f5cdac77729695b304a08f6308e7a218f9d484cec5675006b207d88",
        '"src/math/log2.c"',
        '"src/math/log2f.c"',
        '"src/math/log2_data.c"',
        '"src/math/log2f_data.c"',
        '"15.2.0"',
        '"-frounding-math"',
        '"-ffp-contract=off"',
        '"-fexcess-precision=standard"',
        "PRIVATE_SYMBOLS",
        "musl's MIT license",
    ):
        require(snippet in generator, f"math-log2 generator omits {snippet}")
    assembly = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "math_log2_musl_x86_64.S"
    ).read_text(encoding="utf-8")
    require(
        "musl's MIT license" in assembly,
        "generated math-log2 assembly omits musl license provenance",
    )
    for symbol in MATH_LOG2_SYMBOLS:
        require(
            f"\t.globl\t{symbol}\n" in assembly,
            f"generated math-log2 assembly omits {symbol}",
        )
    for private in (
        "crabc_x86_math_log2___log2_data",
        "crabc_x86_math_log2___log2f_data",
        "crabc_x86_math_log2___math_divzero",
        "crabc_x86_math_log2___math_divzerof",
        "crabc_x86_math_log2___math_invalid",
        "crabc_x86_math_log2___math_invalidf",
    ):
        require(
            f"\t.local\t{private}" in assembly,
            f"generated math-log2 assembly does not localize {private}",
        )
    for instruction in ("divsd", "mulsd", "addsd", "subsd", "divss", "mulss", "subss"):
        require(
            instruction in assembly,
            f"generated math-log2 assembly omits {instruction}",
        )

    exports = static_c_abi_export_names(
        ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
    )
    require(exports == sorted(exports), "static C ABI export contract must remain ASCII-sorted")
    for symbol in MATH_LOG2_SYMBOLS:
        require(symbol in exports, f"static C ABI export contract omits {symbol}")

    runner = (ROOT / "compat" / "x86_64" / "run_libc_math_log2.sh").read_text(
        encoding="utf-8"
    )
    for snippet in (
        "-nostdlib -static",
        "--no-undefined",
        "--gc-sections",
        "math_log2_header_abi_probe.cpp",
        "strong crabc-owned",
        "weak compiler-builtins",
        "candidate accidentally retains unselected",
        "candidate retains TLS",
        "__log2_data",
        "divsd mulsd addsd subsd divss mulss subss",
        "log2l log10",
    ):
        require(snippet in runner, f"libc-math-log2 runner omits {snippet}")
    dispatcher = (ROOT / "scripts" / "dev-x86_64.sh").read_text(encoding="utf-8")
    for snippet in (
        "libc-math-log2)",
        "run_libc_math_log2_probe()",
        "/workspace/compat/x86_64/run_libc_math_log2.sh",
    ):
        require(snippet in dispatcher, f"x86 dispatcher omits {snippet}")


def require_uchar_stateful_artifact(family: Mapping[str, Any]) -> None:
    """Ratchet the three-state musl uchar block without capability promotion."""

    artifact_id = "static-c-uchar-stateful"
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.text-math-locale-stdio].verified_artifact",
        family.get("status", ""),
    )
    matching = [entry for entry in artifacts if entry.get("id") == artifact_id]
    require(
        len(matching) == 1,
        "libc.text-math-locale-stdio must contain exactly one static-c-uchar-stateful artifact",
    )
    require(
        family.get("status") == "planned",
        "static-c-uchar-stateful must not promote libc.text-math-locale-stdio",
    )
    artifact = matching[0]
    require(
        "capabilities" not in artifact,
        "static-c-uchar-stateful must remain a private non-capability artifact",
    )

    description = artifact.get("description")
    require(isinstance(description, str), "static-c-uchar-stateful needs a description")
    for phrase in (
        "Pinned musl 1.2.6",
        "c16rtomb",
        "mbrtoc16",
        "mbrtoc32",
        "one-word null state",
        "first-word-only",
        "(size_t)-3",
        "C/POSIX/C.UTF-8",
        "unmangled C linkage",
        "true `-nostdlib -static` closure",
        "unchanged c32rtomb",
        "exact x86 musl branch and retained AArch64 fallback spelling",
        "locale policy or public locale-object APIs",
        "family completion, promotion, and public x86 support",
    ):
        require(
            phrase in description,
            f"static-c-uchar-stateful description omits {phrase}",
        )

    owners = set(
        nonempty_strings(artifact.get("source_owners"), "static-c-uchar-stateful.source_owners")
    )
    for owner in (
        "compat/upstreams.toml",
        "compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv",
        "compat/x86_64/uchar-stateful-provider.toml",
        "libc/src/c_abi/x86_64/static_c_abi.rs",
        "libc/src/c_abi/x86_64/uchar_stateful.rs",
        "libc/src/c_abi/x86_64/locale_multibyte.rs",
        "libc/src/c_abi/x86_64/locale_objects.rs",
        "libc/src/c_abi/x86_64/errno.rs",
        "include/errno.h",
        "include/features.h",
        "include/locale.h",
        "include/uchar.h",
        "include/bits/alltypes.h",
        "compat/x86_64/uchar_stateful_header_abi_probe.c",
        "compat/x86_64/uchar_stateful_header_abi_probe.cpp",
        "compat/x86_64/run_uchar_stateful_header_abi.sh",
        "compat/x86_64/libc_uchar_stateful_probe.c",
        "compat/x86_64/libc_uchar_stateful_start.S",
        "compat/x86_64/run_libc_uchar_stateful.sh",
        "compat/x86_64/static_c_abi_exports.txt",
        "compat/x86_64/parity.toml",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/check_structure.py",
        "scripts/dev-x86_64.sh",
    ):
        require(owner in owners, f"static-c-uchar-stateful source owners omit {owner}")

    abi_prerequisites = "\n".join(
        nonempty_strings(
            artifact.get("x86_abi_prerequisites"),
            "static-c-uchar-stateful.x86_abi_prerequisites",
        )
    )
    for phrase in (
        "rdi/esi/rdx",
        "rdi/rsi/rdx/rcx",
        "8-byte/align-4",
        "c16rtomb.c::c16rtomb",
        "mbrtoc16.c::mbrtoc16",
        "mbrtoc32.c::mbrtoc32",
        "first-word state access",
        "three separate one-u32 null fallbacks",
        "positive pending-low",
        "mbrtowc decoder seam",
        "direct wcrtomb edge",
        "initial-exec-errno closure",
    ):
        require(
            phrase in abi_prerequisites,
            f"static-c-uchar-stateful ABI map omits {phrase}",
        )

    header_prerequisites = "\n".join(
        nonempty_strings(
            artifact.get("x86_header_prerequisites"),
            "static-c-uchar-stateful.x86_header_prerequisites",
        )
    )
    for phrase in (
        "C11/C++17",
        "strict, POSIX.1-2008, X/Open 700, GNU, and BSD",
        "char16_t",
        "char32_t",
        "unmangled C++",
        "mbrtoc16 pending source NULL/n=0/bad-pointer",
        "separate null states",
        "caller second-word preservation",
    ):
        require(
            phrase in header_prerequisites,
            f"static-c-uchar-stateful header map omits {phrase}",
        )

    evidence = artifact.get("native_evidence")
    require(isinstance(evidence, list), "static-c-uchar-stateful native evidence is invalid")
    require(
        {entry.get("command") for entry in evidence}
        == {"./scripts/dev-x86_64.sh libc-uchar-stateful"},
        "static-c-uchar-stateful must use the closed libc-uchar-stateful command",
    )
    scope = evidence[0].get("scope")
    require(isinstance(scope, str), "static-c-uchar-stateful evidence scope is invalid")
    for phrase in (
        "five-profile C11/C++17",
        "one true `-nostdlib -static` candidate",
        "c16rtomb/mbrtoc16/mbrtoc32",
        "mbrtowc decoder seam",
        "direct wcrtomb closure",
        "mbrtoc16 -3 no-read pending-low paths",
        "direct fs initial-TLS errno",
        "does not select c32rtomb",
        "family completion, promotion, or public x86 support",
    ):
        require(phrase in scope, f"static-c-uchar-stateful evidence omits {phrase}")

    manifest_path = ROOT / "compat" / "x86_64" / "uchar-stateful-provider.toml"
    require(manifest_path.is_file(), "uchar stateful work-package manifest is missing")
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    require(
        set(manifest) == {"schema", "target", "platform", "oracle", "work_package"},
        "uchar stateful work-package manifest keys drifted",
    )
    require(
        manifest.get("schema") == "crabc.x86_64-uchar-stateful-provider/v1",
        "uchar stateful work-package schema drifted",
    )
    require(
        manifest.get("target") == EXPECTED_TARGET
        and manifest.get("platform") == "Linux/x86-64 little-endian",
        "uchar stateful work-package target drifted",
    )
    work_package = manifest.get("work_package")
    require(isinstance(work_package, Mapping), "uchar stateful work package is invalid")
    require(
        set(work_package)
        == {
            "target_family",
            "target_capability",
            "target_verified_slice",
            "blocker",
            "prerequisites",
            "dependent_work",
            "musl_source_mapping",
            "source_owners",
            "focused_evidence_command",
            "family_aggregate_command",
            "product_command",
            "negative_scope",
            "expected_transition",
            "evidence",
        },
        "uchar stateful work-package fields drifted",
    )
    require(
        work_package.get("target_family") == "libc.text-math-locale-stdio"
        and work_package.get("target_capability") == "text.wide-multibyte"
        and work_package.get("target_verified_slice") == artifact_id,
        "uchar stateful work-package target ownership drifted",
    )
    require(
        work_package.get("focused_evidence_command")
        == "./scripts/dev-x86_64.sh libc-uchar-stateful",
        "uchar stateful work package must retain the closed focused command",
    )
    for field, phrase in (
        ("blocker", "c16rtomb"),
        ("musl_source_mapping", "c16rtomb.c::c16rtomb"),
        ("negative_scope", "c32rtomb"),
        ("expected_transition", "Generated parity inventories"),
    ):
        value = work_package.get(field)
        require(
            isinstance(value, str) and phrase in value,
            f"uchar stateful work package {field} omits {phrase}",
        )
    for field, phrase in (
        ("prerequisites", "initial-exec errno substrate"),
        ("dependent_work", "integration-owned generated inventory"),
        ("evidence", "true-static behavioral differential"),
    ):
        values = string_list(work_package.get(field), f"uchar stateful work package {field}")
        require(
            any(phrase in value for value in values),
            f"uchar stateful work package {field} omits {phrase}",
        )

    static_root = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
    ).read_text(encoding="utf-8")
    require(
        '#[path = "uchar_stateful.rs"]\nmod uchar_stateful;' in static_root,
        "x86 static C ABI must compose the uchar stateful provider",
    )
    implementation = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "uchar_stateful.rs"
    ).read_text(encoding="utf-8")
    for snippet in (
        "src/multibyte/c16rtomb.c::c16rtomb",
        "src/multibyte/mbrtoc16.c::mbrtoc16",
        "src/multibyte/mbrtoc32.c::mbrtoc32",
        "C16RTOMB_INTERNAL_STATE",
        "MBRTOC16_INTERNAL_STATE",
        "MBRTOC32_INTERNAL_STATE",
        "AtomicU32",
        "mbrtowc_with_selected_state",
        "MB_RET_PENDING_LOW",
        "if source.is_null()",
        "pending.wrapping_add(c16).wrapping_sub(0xdc00)",
        "fn mbrtowc(",
        "fn wcrtomb(",
        "initialized, live, aligned x86 `mbstate_t` storage",
        "Callers serialize use of a shared",
        "need external serialization for one coherent conversion sequence",
    ):
        require(snippet in implementation, f"uchar stateful provider omits {snippet}")
    require(
        "static mut" not in implementation,
        "uchar stateful provider must use atomic null-state storage",
    )
    for symbol in ("c16rtomb", "mbrtoc16", "mbrtoc32"):
        require(
            re.search(
                rf'pub\s+unsafe\s+extern\s+"C"\s+fn\s+{symbol}\s*\(', implementation
            )
            is not None,
            f"uchar stateful provider omits exported {symbol}",
        )
    require(
        "c32rtomb" not in implementation,
        "uchar stateful provider must not absorb the pre-existing c32rtomb adapter",
    )

    exports = static_c_abi_export_names(STATIC_C_ABI_EXPORTS_PATH)
    for symbol in ("c16rtomb", "mbrtoc16", "mbrtoc32"):
        require(symbol in exports, f"static C ABI export contract omits {symbol}")

    header_runner = (
        ROOT / "compat" / "x86_64" / "run_uchar_stateful_header_abi.sh"
    ).read_text(encoding="utf-8")
    for snippet in (
        "C11/C++17",
        "CXX_SYMBOLS=(c16rtomb mbrtoc16 mbrtoc32)",
        "strict posix xopen gnu bsd",
        "-nostdinc",
        "unmangled",
    ):
        require(snippet in header_runner, f"uchar stateful header runner omits {snippet}")
    for probe_name in (
        "uchar_stateful_header_abi_probe.c",
        "uchar_stateful_header_abi_probe.cpp",
    ):
        probe = (ROOT / "compat" / "x86_64" / probe_name).read_text(encoding="utf-8")
        for symbol in ("c16rtomb", "mbrtoc16", "mbrtoc32"):
            require(symbol in probe, f"{probe_name} omits {symbol}")

    runner = (ROOT / "compat" / "x86_64" / "run_libc_uchar_stateful.sh").read_text(
        encoding="utf-8"
    )
    for snippet in (
        "run_uchar_stateful_header_abi.sh",
        "c16rtomb.lo",
        "mbrtoc16.lo",
        "mbrtoc32.lo",
        "reconstructed closure archive",
        "-nostdlib -static",
        "--no-undefined",
        "mbrtowc decoder seam",
        "wcrtomb",
        "initial TLS",
        "newlocale|duplocale|uselocale|freelocale",
        "mimalloc",
    ):
        require(snippet in runner, f"uchar stateful runner omits {snippet}")
    fixture = (ROOT / "compat" / "x86_64" / "libc_uchar_stateful_probe.c").read_text(
        encoding="utf-8"
    )
    for snippet in (
        "C.UTF-8",
        "(size_t)-3",
        "(const char *)1",
        "invalid_c0",
        "invalid_c1",
        "invalid_f5",
        "invalid_80",
        "overlong",
        "encoded_surrogate",
        "beyond_unicode",
        "check_mbrtoc32_split",
        "check_mbrtoc16_split",
        "check_null_states_are_separate",
        "check_c16rtomb_state_machine",
        "__opaque2",
    ):
        require(snippet in fixture, f"uchar stateful fixture omits {snippet}")

    dispatcher = X86_64_DISPATCHER_PATH.read_text(encoding="utf-8")
    for snippet in (
        "uchar-stateful-header-abi)",
        "libc-uchar-stateful)",
        "run_uchar_stateful_header_abi.sh",
        "run_libc_uchar_stateful.sh",
    ):
        require(snippet in dispatcher, f"x86 dispatcher omits {snippet}")


TEXT_COMPONENT_COMMAND = "./scripts/dev-x86_64.sh owned-text-locale-numeric-component"
TEXT_COMPONENT_SLICES = (
    "numeric.parse-float-locale",
    "locale.core",
    "text.wide-multibyte",
    "text.iconv",
)


def require_text_component_slices(family: Mapping[str, Any]) -> None:
    """Bind the four text/locale/numeric capability slices to their component.

    Each selection rests on the installed text/locale/numeric component. The
    ledger may select either capability only while that component's machine
    contract carries rows for it and observes every frozen spelling, either as
    an installed-header ET_REL import or through the separate public/private
    locale-alias workload. A future narrowing of the component therefore fails
    here instead of leaving a stale selected-private claim.
    """
    import owned_text_locale_numeric_component_contract as text_component

    slices = require_verified_slices(
        family.get("verified_slice"),
        "family[libc.text-math-locale-stdio].verified_slice",
        family.get("status", ""),
        list(family.get("capabilities", [])),
    )
    try:
        roster = text_component.load_capability_roster(ROOT)
    except text_component.ContractError as error:
        raise LedgerError(f"text component contract is invalid: {error}") from error
    alias_contract = json.loads(
        (ROOT / "compat" / "x86_64" / "locale_alias_contract.json").read_text(encoding="utf-8")
    )
    alias_proved = set(alias_contract["visible_aliases"].values()) | set(
        alias_contract["reverse_visible_aliases"].values()
    )
    for capability in TEXT_COMPONENT_SLICES:
        matching = [entry for entry in slices if entry.get("id") == capability]
        require(
            len(matching) == 1,
            f"libc.text-math-locale-stdio must contain exactly one {capability} slice",
        )
        selected = matching[0]
        require(
            selected.get("capabilities") == [capability],
            f"{capability} slice must select exactly its capability",
        )
        require(
            family.get("status") == "planned",
            f"{capability} slice must not promote libc.text-math-locale-stdio",
        )
        evidence = selected.get("native_evidence")
        require(
            isinstance(evidence, list)
            and TEXT_COMPONENT_COMMAND in [entry.get("command") for entry in evidence],
            f"{capability} slice must use the installed text/locale/numeric component",
        )
        require(
            any(row_capability == capability for row_capability, _row, _roles in text_component.ROWS),
            f"text component contract has no {capability} row",
        )
        unobserved = sorted(
            symbol
            for symbol in roster[capability]
            if symbol not in text_component.PROVIDER_SYMBOLS and symbol not in alias_proved
        )
        require(
            not unobserved,
            f"text component leaves {capability} spellings unobserved: {', '.join(unobserved)}",
        )
        owners = set(nonempty_strings(selected["source_owners"], f"{capability}.source_owners"))
        for owner in (
            "compat/x86_64/owned_text_locale_numeric_component_contract.py",
            "compat/x86_64/run_owned_text_locale_numeric_component.sh",
            "compat/x86_64/owned_text_locale_differential_probe.c",
        ):
            require(owner in owners, f"{capability} source owners omit {owner}")
        for phrase in ("selected-private", "family completion", "public x86 support"):
            require(phrase in selected["description"], f"{capability} description omits {phrase}")


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


def validate_static_product_contract(
    contract: Mapping[str, Any], families: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Validate the implemented owned-static product without promoting its owner.

    The private owned-static-sysroot artifacts remain evidence for their narrow
    installed vertical.  This separate contract defines the broader product
    gate that must close before ``sysroot.static-tls`` can become complete.
    Its suite roster, coverage map, and receipt boundary are validated by
    ``static_product_contract.py``; only a published live receipt qualifies it.
    """

    require(
        set(contract) == {
            "schema",
            "owner_family",
            "status",
            "static_family_ids",
            "prerequisite_families",
            "product",
            "mode",
            "inspections",
            "reproducibility",
            "extracted_smoke",
            "coverage",
            "suite",
            "qualification",
        },
        "static product contract keys drifted",
    )
    require(
        contract.get("schema") == EXPECTED_STATIC_PRODUCT_SCHEMA,
        "unexpected static product contract schema",
    )
    require(
        contract.get("owner_family") == "sysroot.static-tls",
        "static product owner must be sysroot.static-tls",
    )
    require(
        contract.get("status") == "implemented-unqualified",
        "checked-in static product contract must remain implemented-unqualified",
    )

    static_family_ids = string_list(
        contract.get("static_family_ids"), "static_product.static_family_ids"
    )
    require(
        tuple(static_family_ids) == ("crt.static-pie", "sysroot.static-tls"),
        "static product static-family roster drifted",
    )
    prerequisite_families = string_list(
        contract.get("prerequisite_families"),
        "static_product.prerequisite_families",
    )
    expected_prerequisites = (
        "oracle.musl-toolchain",
        "libc.headers-layouts",
        "libc.posix-runtime",
        "libc.pthread-tls",
        "libc.text-math-locale-stdio",
        "libc.resolver",
        "libc.c-abi-compat",
        "crt.static-pie",
    )
    require(
        tuple(prerequisite_families) == expected_prerequisites,
        "static product prerequisite roster drifted",
    )
    require(
        set(static_family_ids).issubset(families),
        "static product names an unknown static family",
    )
    require(
        set(prerequisite_families).issubset(families),
        "static product names an unknown prerequisite family",
    )
    owner = families["sysroot.static-tls"]
    require_static_tls_family_evidence(owner, families)
    owner_dependencies = string_list(
        owner.get("depends_on"), "family[sysroot.static-tls].depends_on"
    )
    require(
        tuple(owner_dependencies) == expected_prerequisites,
        "sysroot.static-tls must depend on the owned-static product prerequisites",
    )

    def depends_on_dynamic_startup(identifier: str, seen: set[str]) -> bool:
        if identifier in seen:
            return False
        seen.add(identifier)
        dependencies = families[identifier].get("depends_on")
        assert isinstance(dependencies, list)
        for dependency in dependencies:
            assert isinstance(dependency, str)
            if dependency == "crt.dynamic-startup" or depends_on_dynamic_startup(
                dependency, seen
            ):
                return True
        return False

    for identifier in static_family_ids:
        require(
            not depends_on_dynamic_startup(identifier, set()),
            f"static family {identifier} must not depend on crt.dynamic-startup",
        )

    product = contract.get("product")
    require(isinstance(product, Mapping), "static_product.product must be a table")
    require(
        set(product)
        == {
            "target",
            "source",
            "link_interface",
            "required_target_inputs",
            "rejected_ambient_target_inputs",
        },
        "static_product.product keys drifted",
    )
    require(
        product.get("target") == EXPECTED_TARGET,
        "static product target drifted",
    )
    require(
        product.get("source") == "materialized installed crabc x86-64 sysroot",
        "static product must build from the materialized installed sysroot",
    )
    require(
        product.get("link_interface") == "deterministic owned static link interface",
        "static product requires a deterministic owned static link interface",
    )
    require(
        tuple(string_list(product.get("required_target_inputs"), "static_product.product.required_target_inputs"))
        == (
            "installed crabc headers",
            "crt1.o",
            "rcrt1.o",
            "crti.o",
            "crtn.o",
            "libc.a",
            "libcrabc-builtins.a",
            "accepted allocator backend",
            "explicitly admitted application objects",
        ),
        "static product target-input contract drifted",
    )
    require(
        tuple(string_list(product.get("rejected_ambient_target_inputs"), "static_product.product.rejected_ambient_target_inputs"))
        == ("headers", "CRT", "libc", "libgcc", "compiler-rt", "loader"),
        "static product ambient-input rejection contract drifted",
    )

    modes = contract.get("mode")
    require(isinstance(modes, list), "static_product.mode must be an array")
    expected_modes = (
        ("static-et-exec", "ET_EXEC", "crt1.o", "absent"),
        ("static-pie", "ET_DYN", "rcrt1.o", "absent"),
    )
    actual_modes: list[tuple[str, str, str, str]] = []
    for index, mode in enumerate(modes):
        require(isinstance(mode, Mapping), f"static_product.mode[{index}] must be a table")
        require(
            set(mode) == {"id", "elf_type", "crt_object", "interpreter"},
            f"static_product.mode[{index}] keys drifted",
        )
        values = tuple(mode.get(key) for key in ("id", "elf_type", "crt_object", "interpreter"))
        require(
            all(isinstance(value, str) and value for value in values),
            f"static_product.mode[{index}] has an invalid value",
        )
        actual_modes.append(values)  # type: ignore[arg-type]
    require(tuple(actual_modes) == expected_modes, "static product mode contract drifted")

    inspections = contract.get("inspections")
    require(isinstance(inspections, Mapping), "static_product.inspections must be a table")
    require(
        set(inspections) == {"required", "before_execution"},
        "static_product.inspections keys drifted",
    )
    require(
        tuple(string_list(inspections.get("required"), "static_product.inspections.required"))
        == (
            "link trace",
            "link map",
            "ELF headers",
            "dynamic section",
            "relocations",
            "symbol ownership",
            "TLS segments",
            "stack flags",
            "interpreter absence",
        ),
        "static product inspection contract drifted",
    )
    require(
        inspections.get("before_execution")
        == "reject undeclared target inputs before executing the fixture",
        "static product must reject undeclared inputs before execution",
    )

    reproducibility = contract.get("reproducibility")
    require(isinstance(reproducibility, Mapping), "static_product.reproducibility must be a table")
    require(
        dict(reproducibility)
        == {
            "clean_installed_builds": 2,
            "artifact_set": "declared regular-file artifact set",
            "comparison": "byte-for-byte identical",
            "suite": "same declared static smoke suite",
        },
        "static product reproducibility contract drifted",
    )
    extracted_smoke = contract.get("extracted_smoke")
    require(isinstance(extracted_smoke, Mapping), "static_product.extracted_smoke must be a table")
    require(
        dict(extracted_smoke)
        == {
            "source": "one extracted packaged installed sysroot",
            "suite": "same declared static smoke suite",
        },
        "static product extracted-smoke contract drifted",
    )
    coverage = contract.get("coverage")
    require(isinstance(coverage, Mapping), "static_product.coverage must be a table")
    require(set(coverage) == {"required", "evidence"}, "static_product.coverage keys drifted")
    require(
        tuple(string_list(coverage.get("required"), "static_product.coverage.required"))
        == (
            "argument environment auxiliary-vector and program-name publication",
            "Initial TLS errno and high-alignment initialized and zero-filled TLS",
            "allocator allocation alignment reallocation failure and remote-thread ownership",
            "pthread/C11 creation join/detach synchronization once TSD cancellation atfork/fork and exit behavior",
            "stdio creation buffering byte/block/formatted operations positions errors and exit flushing",
            "pathname descriptor directory metadata process signal and time paths",
            "local socket transport and bounded resolver behavior",
            "constructors destructors atexit-class behavior and ordinary/immediate termination",
            "owned compiler helper whose link fails without libcrabc-builtins.a",
        ),
        "static product coverage contract drifted",
    )
    import static_product_contract as static_product

    try:
        suite_report = static_product.validate_contract(contract)
    except static_product.StaticProductError as error:
        raise LedgerError(f"static product suite contract rejected: {error}") from error
    return {
        "owner_family": "sysroot.static-tls",
        "modes": len(actual_modes),
        "coverage_obligations": len(coverage["required"]),
        "suite_cases": suite_report["case_count"],
    }


def require_static_tls_family_evidence(
    family: Mapping[str, Any], families: Mapping[str, Mapping[str, Any]]
) -> None:
    """Bind ``sysroot.static-tls`` to the owned static product gate.

    While planned, the family names the real product runner as required
    evidence. Completion additionally needs a published static product receipt
    for the current clean source and every prerequisite family completed; a
    status edit or a stale receipt is never enough.
    """
    status = family.get("status")
    require(status in ALLOWED_STATUSES, "sysroot.static-tls status is invalid")
    evidence = family.get("native_evidence")
    require(
        isinstance(evidence, list) and len(evidence) == 1 and isinstance(evidence[0], Mapping)
        and set(evidence[0]) == {"state", "command", "scope"}
        and evidence[0].get("command") == "./scripts/dev-x86_64.sh owned-static-sysroot"
        and evidence[0].get("state") == ("required" if status == "planned" else "verified"),
        "sysroot.static-tls must name the owned static product gate as its evidence",
    )
    scope = evidence[0].get("scope")
    require(
        isinstance(scope, str)
        and "compat/x86_64/static-product.toml" in scope
        and "published source-bound receipt" in scope
        and "public x86 support" in scope,
        "sysroot.static-tls evidence scope must name the declared suite and receipt boundary",
    )
    if status == "planned":
        return
    incomplete = [
        dependency
        for dependency in family.get("depends_on", [])
        if families[dependency].get("status") != "foundation-verified"
    ]
    require(not incomplete, f"sysroot.static-tls cannot complete before {', '.join(incomplete)}")
    import static_product_contract as static_product

    try:
        receipt = static_product.load_publication()
    except static_product.StaticProductError as error:
        raise LedgerError(f"sysroot.static-tls publication rejected: {error}") from error
    require(
        receipt is not None,
        "foundation-verified sysroot.static-tls needs a published static product receipt for current clean source",
    )


def require_signal_header_trace_ownership(family: Mapping[str, Any]) -> None:
    """Keep signal/wait/AIO/poll source ownership tied to direct include traces."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    records = {entry["id"]: entry for entry in artifacts}
    # The pthread-owned static-c-thrd-sleep artifact has the same signal leaf,
    # but its exact owners are guarded by require_static_thrd_sleep_artifact.
    signal_ids = (
        "static-c-signal-control",
        "static-c-signal-legacy-aliases",
        "static-c-sysv-signal-helpers",
        "static-c-child-reaping",
        "static-c-wait-extensions",
        "static-c-immediate-termination",
        "static-c-posix-exit",
        "static-c-signal-altstack",
        "static-c-signalfd",
        "static-c-process-signal-execution",
        "static-c-clock-nanosleep",
        "static-c-nanosleep",
        "static-c-usleep",
        "static-c-sleep",
        "static-c-readiness-signal-waits",
        "static-c-event-descriptors",
        "static-c-siginterrupt",
    )
    for artifact_id in signal_ids:
        owners = set(nonempty_strings(records[artifact_id].get("source_owners"), f"{artifact_id}.source_owners"))
        require("include/bits/signal.h" in owners, f"{artifact_id} must own include/bits/signal.h")
    for artifact_id in ("static-c-descriptor-pipeline", "static-c-readiness-signal-waits", "static-c-timerfd"):
        owners = set(nonempty_strings(records[artifact_id].get("source_owners"), f"{artifact_id}.source_owners"))
        require("include/bits/poll.h" in owners, f"{artifact_id} must own include/bits/poll.h")
    for artifact_id in (
        "static-c-sysv-signal-helpers",
        "static-c-signalfd",
        "static-c-clock-nanosleep",
        "static-c-nanosleep",
        "static-c-sleep",
    ):
        owners = set(nonempty_strings(records[artifact_id].get("source_owners"), f"{artifact_id}.source_owners"))
        require("include/sys/types.h" not in owners, f"{artifact_id} must not own transitive include/sys/types.h")
    for runner in ("run_epoll_header_abi.sh", "run_signalfd_header_abi.sh"):
        runner_text = (ROOT / "compat" / "x86_64" / runner).read_text(encoding="utf-8")
        require("signal.h" not in runner_text, f"{runner} must not require transitive signal.h")


def require_unistd_header_trace_ownership(family: Mapping[str, Any]) -> None:
    """Keep direct unistd.h evidence separate from explicit sys/types.h uses."""
    artifacts = require_verified_artifacts(
        family.get("verified_artifact"),
        "family[libc.posix-runtime].verified_artifact",
        family.get("status", ""),
    )
    records = {entry["id"]: entry for entry in artifacts}
    for artifact_id in (
        "static-c-isatty",
        "static-c-ttyname-r",
        "static-c-tcgetpgrp",
        "static-c-tcsetpgrp",
        "static-c-getpass",
        "static-c-confstr",
        "static-c-fpathconf",
        "static-c-pathconf",
        "static-c-sysconf",
        "static-c-syncfs",
        "static-c-explicit-bzero-swab",
    ):
        owners = set(
            nonempty_strings(
                records[artifact_id].get("source_owners"),
                f"{artifact_id}.source_owners",
            )
        )
        require(
            "include/bits/alltypes.h" in owners,
            f"{artifact_id} must own unistd.h's direct bits/alltypes.h request",
        )
        require(
            "include/sys/types.h" not in owners,
            f"{artifact_id} must not own transitive include/sys/types.h",
        )
    for artifact_id in (
        "static-c-sendfile",
        "static-c-copy-file-range",
        "static-c-credential-observation",
        "static-c-linkat",
        "static-c-readlinkat",
        "static-c-unlinkat",
    ):
        owners = set(
            nonempty_strings(
                records[artifact_id].get("source_owners"),
                f"{artifact_id}.source_owners",
            )
        )
        require(
            "include/sys/types.h" in owners,
            f"{artifact_id} must retain its direct fixture include/sys/types.h",
        )


def validate_ledger(
    data: Mapping[str, Any],
    *,
    header_layout_manifest: Mapping[str, Any] | None = None,
    header_layout_foundation_manifest: Mapping[str, Any] | None = None,
    static_product_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate one ledger with no reusable state beyond this invocation."""
    token = _verified_artifact_cache.set({})
    try:
        return _validate_ledger(
            data,
            header_layout_manifest=header_layout_manifest,
            header_layout_foundation_manifest=header_layout_foundation_manifest,
            static_product_contract=static_product_contract,
        )
    finally:
        _verified_artifact_cache.reset(token)


def _validate_ledger(
    data: Mapping[str, Any],
    *,
    header_layout_manifest: Mapping[str, Any] | None = None,
    header_layout_foundation_manifest: Mapping[str, Any] | None = None,
    static_product_contract: Mapping[str, Any] | None = None,
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
    verified_records: dict[str, Mapping[str, Any]] = {}
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
        if identifier == "libc.headers-layouts":
            require_header_foundation_downstream_evidence(
                entry["native_evidence"], f"{location}.native_evidence", status
            )
        else:
            require_evidence(entry["native_evidence"], f"{location}.native_evidence", status)
        if identifier == "consumer.source-build" and status == "foundation-verified":
            require_lua_source_build_admission(entry)
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
            verified_records[slice_id] = slice_entry
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
            verified_records[artifact_id] = artifact_entry
        ids.add(identifier)
        orders.append(order)
        by_id[identifier] = entry
        status_counts[status] += 1

    require(tuple(entry["id"] for entry in families) == EXPECTED_FAMILIES, "family table order must equal promotion dependency order")
    require(orders == sorted(orders) and len(orders) == len(set(orders)), "family order values must be unique and ascending")
    require(ids == set(EXPECTED_FAMILIES), "family coverage does not match promotion roster")
    for identifier, entry in by_id.items():
        if entry["status"] != "foundation-verified":
            continue
        dependencies = entry["depends_on"]
        assert isinstance(dependencies, list)
        for dependency in dependencies:
            require(by_id[dependency]["status"] == "foundation-verified",
                    f"foundation-verified family {identifier} depends on planned {dependency}")

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
    posix_runtime = by_id["libc.posix-runtime"]
    require_posix_native_profile_companions(posix_runtime)
    posix_runtime_admission = require_posix_runtime_family_admission(posix_runtime)
    # The following retained artifacts have explicit ``planned`` ratchets.
    # They remain strict while this family is planned; after, and only after,
    # the full physical admission above, they preserve their leaf boundary
    # without contradicting the admitted family status.
    posix_runtime_leaf = posix_runtime_private_artifact_view(
        posix_runtime, posix_runtime_admission
    )
    require_memory_sync_header_evidence(by_id["libc.headers-layouts"])
    require_memory_locking_header_evidence(by_id["libc.headers-layouts"])
    require_memfd_create_header_evidence(by_id["libc.headers-layouts"])
    require_ctype_header_evidence(by_id["libc.headers-layouts"])
    require_socket_header_evidence(by_id["libc.headers-layouts"])
    require_tcp_header_evidence(by_id["libc.headers-layouts"])
    require_stddef_header_evidence(by_id["libc.headers-layouts"])
    require_socket_messages_header_evidence(by_id["libc.headers-layouts"])
    require_nameser_header_evidence(by_id["libc.headers-layouts"])
    require_quota_header_evidence(by_id["libc.headers-layouts"])
    require_sched_cpu_macros_header_evidence(by_id["libc.headers-layouts"])
    require_fanotify_header_evidence(by_id["libc.headers-layouts"])
    require_inet_address_header_evidence(by_id["libc.headers-layouts"])

    pthread_runtime = by_id["libc.pthread-tls"]
    pthread_admission = require_pthread_runtime_family_admission(
        pthread_runtime, posix_runtime, posix_runtime_admission
    )
    pthread_runtime_leaf = pthread_runtime_private_artifact_view(
        pthread_runtime, pthread_admission
    )
    require_signal_header_trace_ownership(by_id["libc.posix-runtime"])
    require_unistd_header_trace_ownership(by_id["libc.posix-runtime"])
    resolver_family = by_id["libc.resolver"]
    resolver_admission = require_resolver_family_admission(
        resolver_family, posix_runtime, posix_runtime_admission
    )
    resolver_leaf = resolver_private_artifact_view(resolver_family, resolver_admission)
    require_stdio_installed_file_engine_slice(by_id["libc.text-math-locale-stdio"])
    require_math_log2_artifact(by_id["libc.text-math-locale-stdio"])
    require_uchar_stateful_artifact(by_id["libc.text-math-locale-stdio"])
    require_text_component_slices(by_id["libc.text-math-locale-stdio"])
    require_posix_process_abi_admission_artifact(by_id["compat.posix-process"])

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

    feature_archive_report = validate_feature_archive_roster(data, verified_records)

    if static_product_contract is None:
        static_product_contract = load_toml(STATIC_PRODUCT_CONTRACT_PATH)
    static_product_report = validate_static_product_contract(
        static_product_contract, by_id
    )

    dispatch_source = (ROOT / "scripts" / "dev.sh").read_text(encoding="utf-8")
    used_gates = {gate for family in families for gate in family["aarch64_gates"]}
    missing_dispatch = sorted(gate for gate in used_gates if f"    {gate})" not in dispatch_source and f"    {gate}|" not in dispatch_source)
    require(not missing_dispatch, f"AArch64 gate dispatch does not contain: {', '.join(missing_dispatch)}")
    require_aarch64_parity_inventory()

    return {
        "schema": EXPECTED_SCHEMA,
        "family_count": len(families),
        "capability_count": len(baseline_ids),
        "capability_owners": capability_owners,
        "status_counts": status_counts,
        "verified_slice_count": len(verified_slice_ids),
        "verified_artifact_count": len(verified_artifact_ids),
        "feature_archive_count": feature_archive_report["feature_archive_count"],
        "verified_feature_archive_count": feature_archive_report[
            "verified_feature_archive_count"
        ],
        "planned_feature_archive_count": feature_archive_report[
            "planned_feature_archive_count"
        ],
        "static_product": static_product_report,
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
        "header_foundation_sys_io_header_profile_matrix_row_count": header_layout_foundation_report[
            "sys_io_header_profile_matrix_row_count"
        ],
        "header_foundation_epoll_header_profile_matrix_row_count": header_layout_foundation_report[
            "epoll_header_profile_matrix_row_count"
        ],
        "header_foundation_event_descriptors_header_profile_matrix_row_count": header_layout_foundation_report[
            "event_descriptors_header_profile_matrix_row_count"
        ],
        "header_foundation_dirent_header_profile_matrix_row_count": header_layout_foundation_report[
            "dirent_header_profile_matrix_row_count"
        ],
        "header_foundation_stdlib_header_profile_matrix_row_count": header_layout_foundation_report[
            "stdlib_header_profile_matrix_row_count"
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
        "header_foundation_xattr_header_profile_matrix_row_count": header_layout_foundation_report[
            "xattr_header_profile_matrix_row_count"
        ],
        "header_foundation_callable_feature_visibility_matrix_row_count": header_layout_foundation_report[
            "callable_feature_visibility_matrix_row_count"
        ],
        "header_foundation_feature_visibility_matrix_row_count": header_layout_foundation_report[
            "feature_visibility_matrix_row_count"
        ],
        "header_foundation_prototype_layout_matrix_row_count": header_layout_foundation_report[
            "prototype_layout_matrix_row_count"
        ],
        "header_foundation_record_layout_matrix_row_count": header_layout_foundation_report[
            "record_layout_matrix_row_count"
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
