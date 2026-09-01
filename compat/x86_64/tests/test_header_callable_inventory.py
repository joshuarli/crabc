#!/usr/bin/env python3
"""Focused contracts for compiler-derived x86 header callable accounting."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
INVENTORY_PATH = ROOT / "compat" / "x86_64" / "header_callable_inventory.py"
AUDIT_PATH = ROOT / "compat" / "x86_64" / "header_callable_linkage_audit.py"
RUNNER = ROOT / "compat" / "x86_64" / "run_header_callable_linkage_audit.sh"
CHECKED_INVENTORY = ROOT / "compat" / "x86_64" / "header_callable_inventory.json"
DOCKERFILE = ROOT / "docker" / "Dockerfile.x86_64"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INVENTORY = load_module("header_callable_inventory_test", INVENTORY_PATH)
AUDIT = load_module("header_callable_linkage_audit_test", AUDIT_PATH)


class HeaderCallableInventoryTests(unittest.TestCase):
    def test_contract_keeps_the_fixed_profiles_and_no_header_text_parser(self) -> None:
        contract = INVENTORY.load_contract()

        self.assertEqual(
            [profile.identifier for profile in contract.profiles],
            [
                "c11-gnu",
                "cxx17-gnu",
                "c11-strict",
                "c11-posix-2008",
                "c11-xopen-700",
                "c11-bsd",
                "cxx17-strict",
            ],
        )
        self.assertEqual(
            set(contract.oracle_not_applicable),
            {("aio.h", "c11-strict"), ("aio.h", "cxx17-strict")},
        )
        self.assertEqual(
            contract.parity_ledger,
            ROOT / "compat" / "x86_64" / "parity.toml",
        )
        source = INVENTORY_PATH.read_text(encoding="utf-8")
        self.assertIn("-ast-dump=json", source)
        self.assertIn('"-E", "-dD"', source)
        self.assertNotIn("parse_header", source)

    def test_pinned_image_provisions_clang_for_the_canonical_inventory(self) -> None:
        """The checked AST inventory must be reproducible in its declared image."""
        runner = RUNNER.read_text(encoding="utf-8")
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn("for tool in cargo clang ld nm python3 rustup; do", runner)
        self.assertIn("        clang \\", dockerfile)

    def test_ast_function_discovery_distinguishes_archive_external_from_static_inline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "demo.h"
            header.write_text("/* synthetic AST origin */\n", encoding="utf-8")
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "kind": "FunctionDecl",
                        "name": "archive_owner",
                        "loc": {"file": str(header), "line": 4},
                        "type": {"qualType": "int (int)"},
                    },
                    {
                        "kind": "FunctionDecl",
                        "name": "header_local",
                        "storageClass": "static",
                        "inline": True,
                        "loc": {"file": str(header), "line": 8},
                        "type": {"qualType": "int (int)"},
                        "inner": [{"kind": "CompoundStmt", "inner": []}],
                    },
                    {
                        "kind": "FunctionDecl",
                        "name": "builtin_without_header_origin",
                        "loc": {"file": "<built-in>", "line": 1},
                        "type": {"qualType": "void (void)"},
                    },
                ],
            }

            rows = INVENTORY.discover_functions(ast, root)

        self.assertEqual(
            [(row["name"], row["classification"], row["declaring_header"]) for row in rows],
            [("archive_owner", "external", "demo.h"), ("header_local", "inline", "demo.h")],
        )

    def test_preprocessor_records_classify_function_like_and_builtin_macros_without_scanning_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "stdlib.h"
            header.write_text("/* synthetic preprocessor origin */\n", encoding="utf-8")
            records = INVENTORY.discover_macros(
                "\n".join(
                    [
                        f'# 1 "{header}" 1',
                        "#define CALLBACK(value) (value)",
                        "#define alloca __builtin_alloca",
                        '# 1 "<built-in>" 1',
                        "#define HOST_ONLY(value) (value)",
                    ]
                ),
                root,
            )

        self.assertEqual(
            [(record["name"], record["macro_form"], record["declaring_header"]) for record in records],
            [
                ("CALLBACK", "function-like", "stdlib.h"),
                ("alloca", "object-like-builtin", "stdlib.h"),
            ],
        )
        self.assertTrue(all(record["classification"] == "macro" for record in records))

    def test_reference_only_callable_is_an_explicit_missing_classification(self) -> None:
        missing = INVENTORY.missing_candidate_records(
            [
                {
                    "tree": "reference",
                    "profile": "c11-gnu",
                    "classification": "external",
                    "declaration_kind": "function",
                    "declaring_header": "stdlib.h",
                    "line": 12,
                    "name": "reference_only",
                    "visible_from_headers": ["stdlib.h"],
                },
                {
                    "tree": "reference",
                    "profile": "c11-gnu",
                    "classification": "macro",
                    "declaration_kind": "macro",
                    "declaring_header": "stdlib.h",
                    "line": 13,
                    "name": "candidate_macro",
                    "visible_from_headers": ["stdlib.h"],
                },
            ],
            [
                {
                    "tree": "candidate",
                    "profile": "c11-gnu",
                    "classification": "macro",
                    "declaration_kind": "macro",
                    "name": "candidate_macro",
                }
            ],
        )

        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["classification"], "missing")
        self.assertEqual(missing[0]["name"], "reference_only")
        self.assertEqual(missing[0]["reference_classification"], "external")

    def test_checked_inventory_is_a_finite_profile_aware_red_closure_record(self) -> None:
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        self.assertEqual(report["schema"], INVENTORY.SCHEMA)
        self.assertEqual(report["summary"]["pinned_public_header_count"], 183)
        self.assertEqual(report["summary"]["candidate_public_header_count"], 191)
        self.assertFalse(report["summary"]["complete"])
        self.assertEqual(
            set(report["summary"]["callable_classification_counts"]),
            {"external", "inline", "macro", "missing"},
        )
        complement = report["static_export_complement"]["members"]
        self.assertEqual(complement, sorted(complement))
        self.assertEqual(report["summary"]["static_export_complement_count"], len(complement))
        self.assertGreater(len(complement), 0)
        self.assertNotIn("posix_spawnattr_getschedparam", complement)
        self.assertNotIn("posix_spawnattr_setschedparam", complement)
        self.assertNotIn("sched_setscheduler", complement)
        self.assertIn(
            "candidate external callable names are absent from the static export ratchet",
            report["summary"]["incomplete_reasons"],
        )
        partition = report["callable_provider_partition"]
        self.assertEqual(
            partition["kind"],
            "candidate-external-callable-feature-archive-provider-partition",
        )
        provider_counts = report["summary"]["callable_provider_counts"]
        self.assertEqual(
            sum(provider_counts.values()),
            report["summary"]["candidate_external_callable_count"],
        )
        self.assertEqual(
            provider_counts["default_static"] + report["summary"]["static_export_complement_count"],
            report["summary"]["candidate_external_callable_count"],
        )

    def test_checked_inventory_partitions_feature_owned_and_unprovided_callables(self) -> None:
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        partition = report["callable_provider_partition"]
        verified = {
            provider["id"]: set(provider["members"])
            for provider in partition["verified_feature_archives"]
        }
        planned = {
            provider["id"]: set(provider["members"])
            for provider in partition["declared_unverified_feature_archives"]
        }
        unprovided = set(partition["unprovided"]["members"])

        self.assertEqual(
            verified["x86-filesystem-traversal"],
            {"ftw", "nftw"},
        )
        self.assertEqual(verified["x86-scandir"], {"scandir"})
        self.assertEqual(
            verified["x86-legacy-misc"],
            {"encrypt", "fmtmsg", "setkey"},
        )
        self.assertEqual(
            planned["x86-resolver-runtime"],
            {
                "__h_errno_location",
                "__res_state",
                "dn_comp",
                "res_mkquery",
                "res_query",
                "res_querydomain",
                "res_search",
                "res_send",
            },
        )
        self.assertFalse({"ftw", "nftw", "scandir", "fmtmsg", "setkey", "encrypt"} & unprovided)
        self.assertIn("fputws", unprovided)

    def test_netinet_macro_batch_is_present_with_its_exact_feature_split(self) -> None:
        """Keep this header-only reduction separate from archive-callable work."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        unconditional = {
            "__ARE_4_EQUAL",
            "IN6_ARE_ADDR_EQUAL",
            "IN_CLASSA",
            "IN_CLASSB",
            "IN_CLASSC",
            "IN_CLASSD",
            "IN_MULTICAST",
            "IN_EXPERIMENTAL",
            "IN_BADCLASS",
        }
        filter_sizes = {"IP_MSFILTER_SIZE", "GROUP_FILTER_SIZE"}
        all_profiles = {
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        }
        filter_profiles = {"c11-gnu", "cxx17-gnu", "c11-bsd", "cxx17-strict"}
        expected = {
            *( (profile, name) for profile in all_profiles for name in unconditional ),
            *( (profile, name) for profile in filter_profiles for name in filter_sizes ),
        }
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "netinet/in.h"
            and record.get("name") in unconditional | filter_sizes
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "netinet/in.h"
            and record.get("name") in unconditional | filter_sizes
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "netinet/in.h"
            and record.get("name") in unconditional | filter_sizes
        }
        for profile, name in expected:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_ctype_legacy_case_macro_batch_has_its_exact_feature_split(self) -> None:
        """Keep this source-faithful header macro closure outside archive work."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        names = {"_tolower", "_toupper"}
        visible_profiles = {
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        }
        expected = {(profile, name) for profile in visible_profiles for name in names}
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") in names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") in names
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") in names
        }
        for profile, name in expected:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_ctype_isascii_macro_has_its_exact_c_only_feature_split(self) -> None:
        """Keep musl's C-only seven-bit predicate syntax out of runtime work."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        name = "isascii"
        visible_profiles = {
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-xopen-700",
        }
        expected = {(profile, name) for profile in visible_profiles}
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") == name
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") == name
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"]): record["replacement_sha256"]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") == name
        }
        for profile in visible_profiles:
            self.assertEqual(
                replacement_hashes[("candidate", profile)],
                replacement_hashes[("reference", profile)],
                f"isascii replacement differs from pinned musl in {profile}",
            )

    def test_socket_ancillary_helper_macro_batch_is_unconditional(self) -> None:
        """Account for helpers without selecting ancillary socket runtime work."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        names = {"__CMSG_LEN", "__CMSG_NEXT", "__MHDR_END"}
        profiles = {
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        }
        expected = {(profile, name) for profile in profiles for name in names}
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "sys/socket.h"
            and record.get("name") in names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "sys/socket.h"
            and record.get("name") in names
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "sys/socket.h"
            and record.get("name") in names
        }
        for profile, name in expected:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_nameser_record_classification_macro_batch_is_unconditional(self) -> None:
        """Keep DNS record classification syntax out of resolver runtime work."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        names = {
            "NS_NXT_BIT_CLEAR",
            "NS_NXT_BIT_ISSET",
            "NS_NXT_BIT_SET",
            "ns_t_mrr_p",
            "ns_t_qt_p",
            "ns_t_rr_p",
            "ns_t_udp_p",
            "ns_t_xfr_p",
        }
        profiles = {
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        }
        expected = {(profile, name) for profile in profiles for name in names}
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "arpa/nameser.h"
            and record.get("name") in names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "arpa/nameser.h"
            and record.get("name") in names
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "arpa/nameser.h"
            and record.get("name") in names
        }
        for profile, name in expected:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_libintl_format_argument_annotation_is_transient_and_exact(self) -> None:
        """Account for musl's private declaration annotation without a runtime claim."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        names = {"__fa"}
        profiles = {
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        }
        expected = {(profile, name) for profile in profiles for name in names}
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "libintl.h"
            and record.get("name") in names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "libintl.h"
            and record.get("name") in names
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "libintl.h"
            and record.get("name") in names
        }
        for profile, name in expected:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_quota_conversion_macro_batch_is_unconditional(self) -> None:
        """Keep musl's quota-unit syntax outside quota syscall ownership."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        names = {"btodb", "dbtob", "dqoff", "fs_to_dq_blocks"}
        profiles = {
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        }
        expected = {(profile, name) for profile in profiles for name in names}
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "sys/quota.h"
            and record.get("name") in names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "sys/quota.h"
            and record.get("name") in names
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "sys/quota.h"
            and record.get("name") in names
        }
        for profile, name in expected:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_strdupa_macro_stays_exactly_gnu_selected(self) -> None:
        """Keep stack-copy syntax out of allocator and string-runtime ownership."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        names = {"strdupa"}
        profiles = {"c11-gnu", "cxx17-gnu", "cxx17-strict"}
        expected = {(profile, name) for profile in profiles for name in names}
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "string.h"
            and record.get("name") in names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "string.h"
            and record.get("name") in names
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "string.h"
            and record.get("name") in names
        }
        for profile, name in expected:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_sched_cpu_macro_family_is_exactly_gnu_selected(self) -> None:
        """Keep CPU-set construction syntax below scheduler and allocator work."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        macro_names = {
            "CPU_ALLOC",
            "CPU_ALLOC_SIZE",
            "CPU_AND",
            "CPU_AND_S",
            "CPU_CLR",
            "CPU_CLR_S",
            "CPU_EQUAL",
            "CPU_EQUAL_S",
            "CPU_FREE",
            "CPU_ISSET",
            "CPU_ISSET_S",
            "CPU_OR",
            "CPU_OR_S",
            "CPU_SET",
            "CPU_SET_S",
            "CPU_XOR",
            "CPU_XOR_S",
            "CPU_ZERO",
            "CPU_ZERO_S",
            "__CPU_op_S",
            "__CPU_op_func_S",
        }
        inline_names = {"__CPU_AND_S", "__CPU_OR_S", "__CPU_XOR_S"}
        profiles = {"c11-gnu", "cxx17-gnu", "cxx17-strict"}
        expected_macros = {
            (profile, name) for profile in profiles for name in macro_names
        }
        expected_inlines = {
            (profile, name) for profile in profiles for name in inline_names
        }
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate_macros = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "sched.h"
            and record.get("name") in macro_names
        }
        candidate_inlines = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "inline"
            and record.get("declaring_header") == "sched.h"
            and record.get("name") in inline_names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "sched.h"
            and record.get("name") in macro_names | inline_names
        }

        self.assertEqual(candidate_macros, expected_macros)
        self.assertEqual(candidate_inlines, expected_inlines)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "sched.h"
            and record.get("name") in macro_names
        }
        for profile, name in expected_macros:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_fanotify_event_traversal_macros_are_unconditional_and_exact(self) -> None:
        """Keep caller-buffer traversal syntax below fanotify watcher ownership."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        names = {"FAN_EVENT_NEXT", "FAN_EVENT_OK"}
        profiles = {
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        }
        expected = {(profile, name) for profile in profiles for name in names}
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "sys/fanotify.h"
            and record.get("name") in names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "sys/fanotify.h"
            and record.get("name") in names
        }

        self.assertEqual(candidate, expected)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "sys/fanotify.h"
            and record.get("name") in names
        }
        for profile, name in expected:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_ctype_c_fast_path_macro_block_matches_pinned_musl(self) -> None:
        """Keep musl's C-only classification syntax exact and header-local."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        macro_names = {
            "isalpha",
            "isdigit",
            "isgraph",
            "islower",
            "isprint",
            "isspace",
            "isupper",
        }
        inline_names = {"__isspace"}
        profiles = {
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
        }
        expected_macros = {
            (profile, name) for profile in profiles for name in macro_names
        }
        expected_inlines = {
            (profile, name) for profile in profiles for name in inline_names
        }
        callables = report["callables"]
        assert isinstance(callables, list)
        candidate_macros = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") in macro_names
        }
        candidate_inlines = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "inline"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") in inline_names
        }
        missing = {
            (record["profile"], record["name"])
            for record in callables
            if record.get("classification") == "missing"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") in macro_names | inline_names
        }

        self.assertEqual(candidate_macros, expected_macros)
        self.assertEqual(candidate_inlines, expected_inlines)
        self.assertEqual(missing, set())
        replacement_hashes = {
            (record["tree"], record["profile"], record["name"]): record[
                "replacement_sha256"
            ]
            for record in callables
            if record.get("tree") in {"candidate", "reference"}
            and record.get("classification") == "macro"
            and record.get("declaring_header") == "ctype.h"
            and record.get("name") in macro_names
        }
        for profile, name in expected_macros:
            self.assertEqual(
                replacement_hashes[("candidate", profile, name)],
                replacement_hashes[("reference", profile, name)],
                f"{name} replacement differs from pinned musl in {profile}",
            )

    def test_selected_static_external_declarations_match_musl_visibility(self) -> None:
        """Header profile drift must not hide already-selected static ABI owners."""
        with CHECKED_INVENTORY.open(encoding="utf-8") as stream:
            report = json.load(stream)

        all_profiles = {
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        }
        expected_profiles = {
            "ctermid": all_profiles,
            "nl_langinfo_l": all_profiles,
            "strcasecmp_l": all_profiles,
            "strncasecmp_l": all_profiles,
            "setpgrp": {
                "c11-gnu",
                "cxx17-gnu",
                "c11-xopen-700",
                "c11-bsd",
                "cxx17-strict",
            },
        }
        callables = report["callables"]
        assert isinstance(callables, list)

        for name, expected in expected_profiles.items():
            with self.subTest(name=name):
                reference = {
                    record["profile"]
                    for record in callables
                    if record.get("tree") == "reference"
                    and record.get("classification") == "external"
                    and record.get("name") == name
                }
                candidate = {
                    record["profile"]
                    for record in callables
                    if record.get("tree") == "candidate"
                    and record.get("classification") == "external"
                    and record.get("name") == name
                }
                missing = {
                    record["profile"]
                    for record in callables
                    if record.get("classification") == "missing"
                    and record.get("name") == name
                }
                self.assertEqual(reference, expected)
                self.assertEqual(candidate, expected)
                self.assertEqual(missing, set())
                for profile in expected:
                    reference_type = next(
                        record["type"]
                        for record in callables
                        if record.get("tree") == "reference"
                        and record.get("classification") == "external"
                        and record.get("name") == name
                        and record.get("profile") == profile
                    )
                    candidate_type = next(
                        record["type"]
                        for record in callables
                        if record.get("tree") == "candidate"
                        and record.get("classification") == "external"
                        and record.get("name") == name
                        and record.get("profile") == profile
                    )
                    self.assertEqual(candidate_type, reference_type)

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm")), "requires native binutils and C compiler")
    def test_audit_uses_ordinary_archive_extraction_and_reports_finite_complement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "available.c"
            object_path = root / "available.o"
            archive = root / "libcandidate.a"
            exports = root / "exports.txt"
            inventory = root / "inventory.json"
            source.write_text("int available(void) { return 7; }\n", encoding="utf-8")
            subprocess.run(["cc", "-c", str(source), "-o", str(object_path)], check=True)
            subprocess.run(["ar", "rcs", str(archive), str(object_path)], check=True)
            exports.write_text("# ratchet\navailable\n", encoding="utf-8")
            inventory.write_text(
                json.dumps(
                    {
                        "schema": AUDIT.INVENTORY_SCHEMA,
                        "inputs": {
                            "static_c_abi_exports_sha256": hashlib.sha256(exports.read_bytes()).hexdigest(),
                        },
                        "callables": [
                            {
                                "tree": "candidate",
                                "profile": "c11-gnu",
                                "classification": "external",
                                "declaration_kind": "function",
                                "name": "available",
                            },
                            {
                                "tree": "candidate",
                                "profile": "c11-gnu",
                                "classification": "external",
                                "declaration_kind": "function",
                                "name": "not_ratcheted",
                            },
                        ],
                        "callable_provider_partition": {
                            "kind": "candidate-external-callable-feature-archive-provider-partition",
                            "default_static": {"members": ["available"]},
                            "verified_feature_archives": [],
                            "declared_unverified_feature_archives": [],
                            "unprovided": {"members": ["not_ratcheted"]},
                            "replacement_variants": [],
                        },
                    }
                ),
                encoding="utf-8",
            )

            report = AUDIT.audit_inventory_file(inventory, exports, archive)

        self.assertEqual(report["static_export_complement"]["members"], ["not_ratcheted"])
        self.assertEqual(report["archive_extraction"], [
            {
                "detail": "ordinary ld -r extraction defined the requested function",
                "status": "extracted",
                "symbol": "available",
            }
        ])
        self.assertFalse(report["summary"]["complete"])
        self.assertIn("static export complement is nonempty", report["summary"]["incomplete_reasons"])
        self.assertIn(
            "one or more candidate external callables have no declared archive provider",
            report["summary"]["incomplete_reasons"],
        )

    def test_runner_is_an_explicit_red_audit_not_a_dispatcher_or_whole_archive_proxy(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        runner = RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "run_musl_oracle.sh",
            "run_linux_5_10_uapi.sh",
            "header_callable_inventory.py",
            "--check",
            "header_callable_linkage_audit.py",
            "--allow-incomplete",
            "x86 header callable linkage audit: INCOMPLETE",
            "refuses emulation",
        ):
            self.assertIn(phrase, runner)
        self.assertNotIn("scripts/dev-x86_64.sh", runner)

    def test_dispatcher_exposes_the_audit_without_claiming_completion(self) -> None:
        source = DISPATCHER.read_text(encoding="utf-8")

        self.assertIn("header-callable-linkage-audit", source)
        self.assertIn("    header-callable-linkage-audit) ;;", source)
        self.assertIn("run_header_callable_linkage_audit()", source)
        self.assertIn(
            '    header-callable-linkage-audit)\n        [ "$#" -eq 0 ] || fail "header-callable-linkage-audit takes no arguments"',
            source,
        )


if __name__ == "__main__":
    unittest.main()
