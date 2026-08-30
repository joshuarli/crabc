#!/usr/bin/env python3
"""Focused contract tests for the x86 runtime-parity ledger."""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "validate_parity_ledger.py"
SPEC = importlib.util.spec_from_file_location("x86_parity_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)


class X86ParityLedgerTests(unittest.TestCase):
    def data(self) -> dict[str, object]:
        return copy.deepcopy(ledger.load_toml(ledger.LEDGER_PATH))

    def header_manifest(self) -> dict[str, object]:
        return copy.deepcopy(ledger.load_toml(ledger.HEADER_LAYOUT_MANIFEST_PATH))

    def header_foundation_manifest(self) -> dict[str, object]:
        return copy.deepcopy(
            ledger.load_toml(ledger.HEADER_LAYOUT_FOUNDATION_MANIFEST_PATH)
        )

    @staticmethod
    def family(data: dict[str, object], identifier: str) -> dict[str, object]:
        entries = data["family"]
        assert isinstance(entries, list)
        for entry in entries:
            assert isinstance(entry, dict)
            if entry["id"] == identifier:
                return entry
        raise AssertionError(f"missing family: {identifier}")

    def test_checked_in_ledger_is_closed_and_not_a_public_support_claim(self) -> None:
        report = ledger.validate_ledger(self.data())
        self.assertEqual(report["schema"], "crabc.x86_64-runtime-parity/v3")
        self.assertEqual(report["family_count"], 26)
        self.assertEqual(report["status_counts"], {"foundation-verified": 8, "planned": 18})
        self.assertEqual(report["capability_count"], 223)
        self.assertEqual(len(report["capability_owners"]), 223)
        self.assertEqual(report["verified_slice_count"], 28)
        self.assertEqual(report["verified_artifact_count"], 49)
        self.assertEqual(report["header_layout_probe_count"], 37)
        self.assertEqual(report["public_header_inventory_count"], 183)
        self.assertEqual(report["header_foundation_header_count"], 191)
        self.assertEqual(report["header_foundation_pinned_header_count"], 183)
        self.assertEqual(report["header_foundation_project_only_header_count"], 8)
        self.assertEqual(report["header_foundation_uapi_path_count"], 3)
        self.assertEqual(report["header_foundation_uapi_wrapper_matrix_row_count"], 21)
        self.assertEqual(report["header_foundation_ioctl_header_profile_matrix_row_count"], 7)
        self.assertEqual(report["header_foundation_epoll_header_profile_matrix_row_count"], 7)
        self.assertEqual(
            report["header_foundation_timeval_transitive_header_profile_matrix_row_count"],
            35,
        )
        self.assertEqual(
            report["header_foundation_sys_time_direct_header_profile_matrix_row_count"],
            7,
        )
        self.assertEqual(
            report["header_foundation_access_header_profile_matrix_row_count"],
            8,
        )
        self.assertEqual(report["header_foundation_language_profile_count"], 7)
        self.assertEqual(report["header_foundation_profile_obligation_count"], 21)
        self.assertEqual(report["header_foundation_profile_matrix_row_count"], 1337)
        self.assertEqual(report["header_foundation_abi_facet_count"], 18)
        self.assertEqual(report["header_foundation_linkage_owner_count"], 3)
        self.assertGreater(report["header_foundation_static_export_count"], 0)
        self.assertFalse(report["promotion_ready"])
        self.assertFalse(report["public_support"])

    def test_ldso_initial_graph_is_a_planned_private_artifact(self) -> None:
        data = self.data()
        family = self.family(data, "ldso.dynamic-runtime")
        self.assertEqual(family["status"], "planned")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(entry for entry in artifacts if entry["id"] == "ldso-initial-graph")
        assert isinstance(artifact, dict)
        self.assertNotIn("capabilities", artifact)
        self.assertIn("main PIE -> mid.so -> leaf.so", artifact["description"])
        self.assertIn("bounded packed `DT_RELR`", artifact["description"])
        self.assertIn("direct-address and bitmap", artifact["description"])
        self.assertIn("512-record/512-target caps per object", artifact["description"])
        self.assertIn("zero-bit bitmap runs", artifact["description"])
        self.assertIn("`DT_RELA`-only", artifact["description"])
        self.assertIn("main-image DT_INIT/DT_INIT_ARRAY dispatch", artifact["description"])
        self.assertEqual(
            {entry["command"] for entry in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh ldso-initial-graph"},
        )
        self.assertIn("ldso/src/x86_64_initial_graph.rs", artifact["source_owners"])

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "ldso.dynamic-runtime")["verified_artifact"]
        assert isinstance(changed_artifacts, list)
        changed_artifact = next(entry for entry in changed_artifacts if entry["id"] == "ldso-initial-graph")
        assert isinstance(changed_artifact, dict)
        changed_artifact["description"] = "private graph"
        with self.assertRaisesRegex(ledger.LedgerError, "ldso-initial-graph description omits"):
            ledger.validate_ledger(changed)

    def test_header_layout_manifest_is_a_closed_direct_probe_inventory(self) -> None:
        data = self.data()
        manifest = self.header_manifest()
        report = ledger.validate_ledger(data, header_layout_manifest=manifest)
        headers_layouts = self.family(data, "libc.headers-layouts")

        self.assertEqual(report["header_layout_probe_count"], 37)
        self.assertEqual(manifest["schema"], "crabc.x86_64-headers-layouts/v1")
        self.assertEqual(manifest["status"], "planned")
        self.assertEqual(manifest["family"], "libc.headers-layouts")
        self.assertEqual(
            headers_layouts["header_manifest"],
            "compat/x86_64/headers-layouts.toml",
        )
        self.assertIn(
            "compat/x86_64/headers-layouts.toml", headers_layouts["source_owners"]
        )
        self.assertNotIn("include", headers_layouts["source_owners"])

        probes = manifest["probe"]
        assert isinstance(probes, list)
        self.assertEqual(
            [probe["id"] for probe in probes],
            list(ledger.EXPECTED_HEADER_LAYOUT_PROBES),
        )
        socket = next(probe for probe in probes if probe["id"] == "socket")
        assert isinstance(socket, dict)
        self.assertEqual(socket["kind"], "macro-runtime")
        self.assertEqual(
            socket["sources"],
            [
                "compat/x86_64/socket_header_abi_probe.c",
                "compat/x86_64/socket_header_abi_probe.cpp",
                "compat/x86_64/socket_header_ipv6_macro_probe.c",
                "compat/x86_64/run_socket_header_abi.sh",
            ],
        )
        math_complex = next(probe for probe in probes if probe["id"] == "math-complex")
        assert isinstance(math_complex, dict)
        self.assertEqual(math_complex["kind"], "macro-runtime")
        self.assertEqual(
            math_complex["headers"],
            [
                "include/complex.h",
                "include/float.h",
                "include/math.h",
                "include/tgmath.h",
            ],
        )
        self.assertEqual(
            math_complex["sources"],
            [
                "compat/x86_64/math_complex_header_abi_probe.c",
                "compat/x86_64/math_complex_header_abi_probe.cpp",
                "compat/x86_64/run_math_complex_header_abi.sh",
            ],
        )
        ioctl = next(probe for probe in probes if probe["id"] == "ioctl")
        assert isinstance(ioctl, dict)
        self.assertEqual(ioctl["kind"], "compile-only")
        self.assertEqual(ioctl["headers"], ["include/sys/ioctl.h"])
        self.assertEqual(
            ioctl["sources"],
            [
                "compat/x86_64/ioctl_header_abi_probe.c",
                "compat/x86_64/ioctl_header_abi_probe.cpp",
                "compat/x86_64/run_ioctl_header_abi.sh",
            ],
        )
        epoll = next(probe for probe in probes if probe["id"] == "epoll")
        assert isinstance(epoll, dict)
        self.assertEqual(epoll["kind"], "compile-only")
        self.assertEqual(
            epoll["headers"],
            ["include/stddef.h", "include/sys/epoll.h", "include/sys/ioctl.h"],
        )
        self.assertEqual(
            epoll["sources"],
            [
                "compat/x86_64/epoll_header_abi_probe.c",
                "compat/x86_64/epoll_header_abi_probe.cpp",
                "compat/x86_64/run_epoll_header_abi.sh",
            ],
        )
        timeval_transitive = next(
            probe for probe in probes if probe["id"] == "timeval-transitive"
        )
        assert isinstance(timeval_transitive, dict)
        self.assertEqual(timeval_transitive["kind"], "compile-only")
        self.assertEqual(
            timeval_transitive["headers"],
            [
                "include/lastlog.h",
                "include/stddef.h",
                "include/sys/time.h",
                "include/sys/timex.h",
                "include/utmp.h",
                "include/utmpx.h",
            ],
        )
        self.assertEqual(
            timeval_transitive["sources"],
            [
                "compat/x86_64/timeval_transitive_header_abi_probe.c",
                "compat/x86_64/timeval_transitive_header_abi_probe.cpp",
                "compat/x86_64/run_timeval_transitive_header_abi.sh",
            ],
        )
        sys_time_direct = next(probe for probe in probes if probe["id"] == "sys-time-direct")
        assert isinstance(sys_time_direct, dict)
        self.assertEqual(sys_time_direct["kind"], "compile-only")
        self.assertEqual(
            sys_time_direct["headers"],
            ["include/stddef.h", "include/sys/time.h"],
        )
        self.assertEqual(
            sys_time_direct["sources"],
            [
                "compat/x86_64/sys_time_direct_header_abi_probe.c",
                "compat/x86_64/sys_time_direct_header_abi_probe.cpp",
                "compat/x86_64/run_sys_time_direct_header_abi.sh",
            ],
        )
        access_header = next(probe for probe in probes if probe["id"] == "access-header")
        assert isinstance(access_header, dict)
        self.assertEqual(access_header["kind"], "compile-only")
        self.assertEqual(
            access_header["headers"], ["include/fcntl.h", "include/unistd.h"]
        )
        self.assertEqual(
            access_header["sources"],
            [
                "compat/x86_64/access_header_abi_probe.c",
                "compat/x86_64/access_header_abi_probe.cpp",
                "compat/x86_64/run_access_header_abi.sh",
            ],
        )

    def test_header_layout_manifest_rejects_scope_or_probe_drift(self) -> None:
        data = self.data()
        manifest = self.header_manifest()
        manifest["status"] = "foundation-verified"
        with self.assertRaisesRegex(ledger.LedgerError, "must remain planned"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

        data = self.data()
        manifest = self.header_manifest()
        probes = manifest["probe"]
        assert isinstance(probes, list)
        probes.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "probe count drifted"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

        data = self.data()
        manifest = self.header_manifest()
        probes = manifest["probe"]
        assert isinstance(probes, list) and isinstance(probes[0], dict)
        probes[0]["headers"] = ["include/time.h"]
        with self.assertRaisesRegex(ledger.LedgerError, "direct C/C\\+\\+ includes"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

        data = self.data()
        manifest = self.header_manifest()
        probes = manifest["probe"]
        assert isinstance(probes, list) and isinstance(probes[0], dict)
        probes[0]["sources"][-1] = "compat/x86_64/run_time_header_abi.sh"
        with self.assertRaisesRegex(ledger.LedgerError, "sources drifted"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

        data = self.data()
        manifest = self.header_manifest()
        probes = manifest["probe"]
        assert isinstance(probes, list) and isinstance(probes[0], dict)
        probes[0]["command"] = "./scripts/dev-x86_64.sh libc-foundation"
        with self.assertRaisesRegex(ledger.LedgerError, "command drifted"):
            ledger.validate_ledger(data, header_layout_manifest=manifest)

    def test_header_foundation_manifest_accounts_for_all_paths_without_promotion(self) -> None:
        data = self.data()
        manifest = self.header_foundation_manifest()
        report = ledger.validate_ledger(
            data, header_layout_foundation_manifest=manifest
        )
        headers_layouts = self.family(data, "libc.headers-layouts")

        self.assertEqual(
            manifest["schema"], "crabc.x86_64-headers-layouts-foundation/v7"
        )
        self.assertEqual(manifest["status"], "planned")
        self.assertEqual(manifest["family"], "libc.headers-layouts")
        self.assertEqual(
            headers_layouts["header_foundation_manifest"],
            "compat/x86_64/headers-layouts-foundation.toml",
        )
        self.assertIn(
            "compat/x86_64/headers-layouts-foundation.toml",
            headers_layouts["source_owners"],
        )
        self.assertIn("compat/upstreams.toml", headers_layouts["source_owners"])
        self.assertEqual(report["header_foundation_header_count"], 191)
        self.assertEqual(report["header_foundation_profile_matrix_row_count"], 1337)
        self.assertEqual(report["header_foundation_uapi_wrapper_matrix_row_count"], 21)
        self.assertEqual(report["header_foundation_ioctl_header_profile_matrix_row_count"], 7)
        self.assertEqual(report["header_foundation_epoll_header_profile_matrix_row_count"], 7)
        self.assertEqual(
            report["header_foundation_timeval_transitive_header_profile_matrix_row_count"],
            35,
        )
        self.assertEqual(
            report["header_foundation_sys_time_direct_header_profile_matrix_row_count"],
            7,
        )

        classes = manifest["header_class"]
        assert isinstance(classes, list)
        self.assertEqual(
            [entry["id"] for entry in classes],
            [
                "pinned-non-uapi",
                "pinned-uapi-inputs",
                "project-only-extensions",
            ],
        )
        uapi = classes[1]
        project_only = classes[2]
        assert isinstance(uapi, dict) and isinstance(project_only, dict)
        self.assertEqual(uapi["paths"], ["sys/kd.h", "sys/soundcard.h", "sys/vt.h"])
        self.assertEqual(
            project_only["paths"],
            [
                "daemon.h",
                "dn_expand.h",
                "linux/capability.h",
                "lrand48.h",
                "pthread_atfork.h",
                "stdatomic.h",
                "strverscmp.h",
                "sys/module.h",
            ],
        )

        inputs = manifest["uapi_input"]
        assert isinstance(inputs, list) and len(inputs) == 1 and isinstance(inputs[0], dict)
        self.assertEqual(inputs[0]["id"], "linux-5.10-uapi")
        self.assertEqual(inputs[0]["state"], "pinned-verified")
        self.assertEqual(
            inputs[0]["upstream_pin"], "compat/upstreams.toml#linux_5_10_uapi"
        )
        self.assertEqual(inputs[0]["version"], "5.10")
        self.assertEqual(
            inputs[0]["source_sha256"],
            "dcdf99e43e98330d925016985bfbc7b83c66d367b714b2de0cbbfcbf83d8ca43",
        )
        self.assertEqual(inputs[0]["exported_header_count"], 935)
        self.assertEqual(
            inputs[0]["exported_header_manifest_sha256"],
            "00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e",
        )
        self.assertEqual(
            inputs[0]["provenance_verifier"],
            "compat/x86_64/run_linux_5_10_uapi.sh",
        )
        self.assertEqual(
            inputs[0]["paths"], ["linux/kd.h", "linux/soundcard.h", "linux/vt.h"]
        )

        matrix = manifest["uapi_wrapper_matrix"]
        assert isinstance(matrix, dict)
        self.assertEqual(matrix["id"], "linux-5.10-uapi-wrapper-profile-matrix")
        self.assertEqual(matrix["state"], "partial-verified")
        self.assertEqual(matrix["required_result"], "pass")
        self.assertEqual(
            matrix["command"], "./scripts/dev-x86_64.sh uapi-wrapper-matrix"
        )
        self.assertEqual(matrix["header_class"], "pinned-uapi-inputs")
        self.assertEqual(matrix["headers"], ["sys/kd.h", "sys/soundcard.h", "sys/vt.h"])
        self.assertEqual(
            matrix["profiles"],
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
        self.assertEqual(matrix["row_count"], 21)
        rows = matrix["row"]
        assert isinstance(rows, list)
        self.assertEqual(len(rows), 21)
        self.assertEqual(
            [
                (row["header"], row["dependency"], row["profile"])
                for row in rows
                if isinstance(row, dict)
            ],
            [
                (header, dependency, profile)
                for header, dependency in ledger.EXPECTED_PUBLIC_HEADER_UAPI_GAPS.items()
                for profile in ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES
            ],
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in rows
            )
        )
        ioctl_matrix = manifest["ioctl_header_profile_matrix"]
        assert isinstance(ioctl_matrix, dict)
        self.assertEqual(ioctl_matrix["id"], "x86-ioctl-header-profile-matrix")
        self.assertEqual(ioctl_matrix["state"], "partial-verified")
        self.assertEqual(ioctl_matrix["required_result"], "pass")
        self.assertEqual(
            ioctl_matrix["command"], "./scripts/dev-x86_64.sh ioctl-header-abi"
        )
        self.assertEqual(ioctl_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(ioctl_matrix["subject_header"], "sys/ioctl.h")
        self.assertEqual(
            ioctl_matrix["profiles"], list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES)
        )
        self.assertEqual(ioctl_matrix["row_count"], 7)
        ioctl_rows = ioctl_matrix["row"]
        assert isinstance(ioctl_rows, list)
        self.assertEqual(len(ioctl_rows), 7)
        self.assertEqual(
            [row["profile"] for row in ioctl_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in ioctl_rows
            )
        )
        epoll_matrix = manifest["epoll_header_profile_matrix"]
        assert isinstance(epoll_matrix, dict)
        self.assertEqual(epoll_matrix["id"], "x86-epoll-header-profile-matrix")
        self.assertEqual(epoll_matrix["state"], "partial-verified")
        self.assertEqual(epoll_matrix["required_result"], "pass")
        self.assertEqual(
            epoll_matrix["command"], "./scripts/dev-x86_64.sh epoll-header-abi"
        )
        self.assertEqual(epoll_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(epoll_matrix["subject_header"], "sys/epoll.h")
        self.assertEqual(epoll_matrix["direct_macro_header"], "sys/ioctl.h")
        self.assertEqual(
            epoll_matrix["profiles"], list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES)
        )
        self.assertEqual(epoll_matrix["row_count"], 7)
        epoll_rows = epoll_matrix["row"]
        assert isinstance(epoll_rows, list)
        self.assertEqual(len(epoll_rows), 7)
        self.assertEqual(
            [row["profile"] for row in epoll_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in epoll_rows
            )
        )
        timeval_matrix = manifest["timeval_transitive_header_profile_matrix"]
        assert isinstance(timeval_matrix, dict)
        self.assertEqual(
            timeval_matrix["id"], "x86-timeval-transitive-header-profile-matrix"
        )
        self.assertEqual(timeval_matrix["state"], "partial-verified")
        self.assertEqual(timeval_matrix["required_result"], "pass")
        self.assertEqual(
            timeval_matrix["command"],
            "./scripts/dev-x86_64.sh timeval-transitive-header-abi",
        )
        self.assertEqual(timeval_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(
            timeval_matrix["subject_headers"],
            ["sys/time.h", "utmpx.h", "utmp.h", "lastlog.h", "sys/timex.h"],
        )
        self.assertEqual(
            timeval_matrix["sys_time_required_transitive_header"], "sys/select.h"
        )
        self.assertEqual(
            timeval_matrix["profiles"],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertEqual(timeval_matrix["row_count"], 35)
        timeval_rows = timeval_matrix["row"]
        assert isinstance(timeval_rows, list)
        self.assertEqual(len(timeval_rows), 35)
        self.assertEqual(
            [
                (row["header"], row["profile"])
                for row in timeval_rows
                if isinstance(row, dict)
            ],
            [
                (header, profile)
                for header in ledger.EXPECTED_TIMEVAL_TRANSITIVE_HEADER_PROFILE_MATRIX_HEADERS
                for profile in ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES
            ],
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in timeval_rows
            )
        )
        sys_time_direct_matrix = manifest["sys_time_direct_header_profile_matrix"]
        assert isinstance(sys_time_direct_matrix, dict)
        self.assertEqual(
            sys_time_direct_matrix["id"],
            "x86-sys-time-direct-header-profile-matrix",
        )
        self.assertEqual(sys_time_direct_matrix["state"], "partial-verified")
        self.assertEqual(sys_time_direct_matrix["required_result"], "pass")
        self.assertEqual(
            sys_time_direct_matrix["command"],
            "./scripts/dev-x86_64.sh sys-time-direct-header-abi",
        )
        self.assertEqual(sys_time_direct_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(sys_time_direct_matrix["subject_header"], "sys/time.h")
        self.assertEqual(
            sys_time_direct_matrix["profiles"],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertEqual(sys_time_direct_matrix["row_count"], 7)
        sys_time_direct_rows = sys_time_direct_matrix["row"]
        assert isinstance(sys_time_direct_rows, list)
        self.assertEqual(len(sys_time_direct_rows), 7)
        self.assertEqual(
            [row["profile"] for row in sys_time_direct_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_UAPI_WRAPPER_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in sys_time_direct_rows
            )
        )
        access_header_matrix = manifest["access_header_profile_matrix"]
        assert isinstance(access_header_matrix, dict)
        self.assertEqual(
            access_header_matrix["id"], "x86-access-header-profile-matrix"
        )
        self.assertEqual(access_header_matrix["state"], "partial-verified")
        self.assertEqual(access_header_matrix["required_result"], "pass")
        self.assertEqual(
            access_header_matrix["command"], "./scripts/dev-x86_64.sh access-header-abi"
        )
        self.assertEqual(access_header_matrix["header_class"], "pinned-non-uapi")
        self.assertEqual(access_header_matrix["subject_headers"], ["fcntl.h", "unistd.h"])
        self.assertEqual(
            access_header_matrix["profiles"],
            list(ledger.EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertEqual(access_header_matrix["row_count"], 8)
        access_header_rows = access_header_matrix["row"]
        assert isinstance(access_header_rows, list)
        self.assertEqual(len(access_header_rows), 8)
        self.assertEqual(
            [row["profile"] for row in access_header_rows if isinstance(row, dict)],
            list(ledger.EXPECTED_ACCESS_HEADER_PROFILE_MATRIX_PROFILES),
        )
        self.assertTrue(
            all(
                isinstance(row, dict)
                and row["reference"] == "compile-ok"
                and row["candidate"] == "compile-ok"
                and row["applicability"] == "applicable"
                for row in access_header_rows
            )
        )
        completion = manifest["completion"]
        assert isinstance(completion, dict)
        self.assertTrue(completion["uapi_wrapper_profile_matrix_slice"])
        self.assertTrue(completion["ioctl_header_profile_matrix_slice"])
        self.assertTrue(completion["epoll_header_profile_matrix_slice"])
        self.assertTrue(completion["timeval_transitive_header_profile_matrix_slice"])
        self.assertTrue(completion["sys_time_direct_header_profile_matrix_slice"])
        self.assertTrue(completion["access_header_profile_matrix_slice"])
        self.assertFalse(completion["family_promotion"])
        self.assertFalse(completion["public_support"])

        diagnostics = manifest["closure_diagnostic"]
        assert (
            isinstance(diagnostics, list)
            and len(diagnostics) == 1
            and isinstance(diagnostics[0], dict)
        )
        self.assertEqual(diagnostics[0]["id"], "isolated-candidate-header-closure")
        self.assertEqual(diagnostics[0]["state"], "required-live")
        self.assertEqual(diagnostics[0]["required_result"], "pass")
        self.assertEqual(
            diagnostics[0]["command"],
            "./scripts/dev-x86_64.sh candidate-header-closure",
        )
        self.assertEqual(diagnostics[0]["record_count"], 382)
        obligations = manifest["profile_obligation"]
        assert isinstance(obligations, list)
        self.assertEqual(len(obligations), 21)
        current = next(
            obligation
            for obligation in obligations
            if obligation["header_class"] == "pinned-non-uapi"
            and obligation["profile"] == "c11-gnu"
        )
        assert isinstance(current, dict)
        self.assertEqual(current["applicability"], "applicable")
        self.assertEqual(current["state"], "partial-verified")
        self.assertEqual(current["evidence"], ["public-header-c-consumability"])
        uapi_current = next(
            obligation
            for obligation in obligations
            if obligation["header_class"] == "pinned-uapi-inputs"
            and obligation["profile"] == "c11-gnu"
        )
        assert isinstance(uapi_current, dict)
        self.assertEqual(uapi_current["applicability"], "applicable")
        self.assertEqual(uapi_current["state"], "partial-verified")
        self.assertEqual(
            uapi_current["evidence"],
            [
                "pinned-linux-5.10-uapi-input",
                "linux-5.10-uapi-wrapper-profile-matrix",
            ],
        )

        owners = manifest["linkage_owner"]
        assert isinstance(owners, list)
        self.assertEqual(
            [entry["id"] for entry in owners],
            [
                "current-static-c-exports",
                "unlisted-public-callables",
                "noncallable-header-abi",
            ],
        )

    def test_header_foundation_manifest_rejects_false_closure_or_accounting_drift(self) -> None:
        data = self.data()
        manifest = self.header_foundation_manifest()
        completion = manifest["completion"]
        assert isinstance(completion, dict)
        completion["family_promotion"] = True
        with self.assertRaisesRegex(ledger.LedgerError, "completion drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        matrix = manifest["uapi_wrapper_matrix"]
        assert isinstance(matrix, dict)
        rows = matrix["row"]
        assert isinstance(rows, list)
        rows.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "matrix row roster drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        matrix = manifest["uapi_wrapper_matrix"]
        assert isinstance(matrix, dict)
        rows = matrix["row"]
        assert isinstance(rows, list) and isinstance(rows[0], dict)
        rows[0]["dependency"] = "linux/input.h"
        with self.assertRaisesRegex(ledger.LedgerError, "Linux-UAPI dependency drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        matrix = manifest["uapi_wrapper_matrix"]
        assert isinstance(matrix, dict)
        rows = matrix["row"]
        assert isinstance(rows, list) and isinstance(rows[0], dict)
        rows[0]["candidate"] = "incomplete"
        with self.assertRaisesRegex(ledger.LedgerError, "resolved compile-only result"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        ioctl_matrix = manifest["ioctl_header_profile_matrix"]
        assert isinstance(ioctl_matrix, dict)
        ioctl_rows = ioctl_matrix["row"]
        assert isinstance(ioctl_rows, list)
        ioctl_rows.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "ioctl header matrix row roster drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        ioctl_matrix = manifest["ioctl_header_profile_matrix"]
        assert isinstance(ioctl_matrix, dict)
        ioctl_matrix["subject_header"] = "sys/socket.h"
        with self.assertRaisesRegex(ledger.LedgerError, "ioctl header matrix subject header drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        epoll_matrix = manifest["epoll_header_profile_matrix"]
        assert isinstance(epoll_matrix, dict)
        epoll_rows = epoll_matrix["row"]
        assert isinstance(epoll_rows, list)
        epoll_rows.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "epoll header matrix row roster drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        epoll_matrix = manifest["epoll_header_profile_matrix"]
        assert isinstance(epoll_matrix, dict)
        epoll_matrix["direct_macro_header"] = "sys/socket.h"
        with self.assertRaisesRegex(ledger.LedgerError, "direct macro header drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        timeval_matrix = manifest["timeval_transitive_header_profile_matrix"]
        assert isinstance(timeval_matrix, dict)
        timeval_rows = timeval_matrix["row"]
        assert isinstance(timeval_rows, list)
        timeval_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "timeval transitive-header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        timeval_matrix = manifest["timeval_transitive_header_profile_matrix"]
        assert isinstance(timeval_matrix, dict)
        timeval_matrix["sys_time_required_transitive_header"] = "sys/socket.h"
        with self.assertRaisesRegex(
            ledger.LedgerError, "required dependency drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        sys_time_direct_matrix = manifest["sys_time_direct_header_profile_matrix"]
        assert isinstance(sys_time_direct_matrix, dict)
        sys_time_direct_rows = sys_time_direct_matrix["row"]
        assert isinstance(sys_time_direct_rows, list)
        sys_time_direct_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "direct sys/time header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        sys_time_direct_matrix = manifest["sys_time_direct_header_profile_matrix"]
        assert isinstance(sys_time_direct_matrix, dict)
        sys_time_direct_matrix["subject_header"] = "sys/socket.h"
        with self.assertRaisesRegex(
            ledger.LedgerError, "direct sys/time header matrix subject header drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        access_header_matrix = manifest["access_header_profile_matrix"]
        assert isinstance(access_header_matrix, dict)
        access_header_rows = access_header_matrix["row"]
        assert isinstance(access_header_rows, list)
        access_header_rows.pop()
        with self.assertRaisesRegex(
            ledger.LedgerError, "access header matrix row roster drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        access_header_matrix = manifest["access_header_profile_matrix"]
        assert isinstance(access_header_matrix, dict)
        access_header_matrix["subject_headers"] = ["sys/socket.h"]
        with self.assertRaisesRegex(
            ledger.LedgerError, "access header matrix subject headers drifted"
        ):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        uapi_paths = manifest["uapi_path"]
        assert isinstance(uapi_paths, list) and isinstance(uapi_paths[0], dict)
        uapi_paths[0]["dependency"] = "linux/input.h"
        with self.assertRaisesRegex(ledger.LedgerError, "Linux-UAPI dependency"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        inputs = manifest["uapi_input"]
        assert isinstance(inputs, list) and isinstance(inputs[0], dict)
        inputs[0]["upstream_pin"] = "compat/upstreams.toml#musl"
        with self.assertRaisesRegex(ledger.LedgerError, "upstream pin drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        diagnostics = manifest["closure_diagnostic"]
        assert isinstance(diagnostics, list) and isinstance(diagnostics[0], dict)
        diagnostics[0]["required_result"] = "incomplete"
        with self.assertRaisesRegex(ledger.LedgerError, "require a live pass"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        classes = manifest["header_class"]
        assert isinstance(classes, list) and isinstance(classes[2], dict)
        paths = classes[2]["paths"]
        assert isinstance(paths, list)
        paths.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "project-only public header"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        obligations = manifest["profile_obligation"]
        assert isinstance(obligations, list) and isinstance(obligations[1], dict)
        obligations[1]["applicability"] = "applicable"
        with self.assertRaisesRegex(ledger.LedgerError, "applicability drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

        data = self.data()
        manifest = self.header_foundation_manifest()
        owners = manifest["linkage_owner"]
        assert isinstance(owners, list) and isinstance(owners[1], dict)
        owners[1]["family"] = "libc.headers-layouts"
        with self.assertRaisesRegex(ledger.LedgerError, "family drifted"):
            ledger.validate_ledger(data, header_layout_foundation_manifest=manifest)

    def test_public_header_surface_inventory_is_a_checked_partial_artifact(self) -> None:
        """Every pinned public header must be visible before ABI closure is claimed."""

        inventory = ROOT / "compat" / "x86_64" / "public_headers.txt"
        headers = inventory.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(headers), 183)
        self.assertEqual(headers, sorted(headers))
        self.assertEqual(len(headers), len(set(headers)))
        self.assertIn("pthread.h", headers)
        self.assertIn("stdio.h", headers)
        self.assertIn("sys/ucontext.h", headers)
        self.assertIn("sys/vt.h", headers)

        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        artifacts = headers_layouts["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if entry["id"] == "public-header-c-consumability"
        )
        assert isinstance(artifact, dict)
        self.assertEqual(
            {evidence["command"] for evidence in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh public-header-surface"},
        )
        self.assertIn("compat/x86_64/public_headers.txt", artifact["source_owners"])
        self.assertIn(
            "compat/x86_64/run_public_header_surface.sh", artifact["source_owners"]
        )
        self.assertIn(
            "without declaration, layout, linkage, runtime, or public-support parity",
            artifact["description"],
        )
        self.assertIn(
            "legacy runner deliberately omits the image's declared `/opt/linux-5.10-uapi/include` root",
            artifact["description"],
        )

    def test_header_layouts_baseline_is_a_closed_c_and_cxx_artifact(self) -> None:
        data = self.data()
        headers_layouts = self.family(data, "libc.headers-layouts")
        self.assertEqual(headers_layouts["status"], "planned")
        artifacts = headers_layouts["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 3
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-header-layouts-baseline"
        )
        self.assertNotIn("capabilities", artifact)
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
            self.assertIn(owner, artifact["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-header-layouts-baseline"},
        )
        for phrase in (
            "still-planned `libc.headers-layouts`",
            "freestanding C++17 companion",
            "unmangled C entry called from C",
            "no new C export",
            "`include/**` edit",
            "installed-header closure",
            "C++ runtime",
            "complete C ABI",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])

        data = self.data()
        artifacts = self.family(data, "libc.headers-layouts")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-header-layouts-baseline"
        )
        artifact["native_evidence"][0]["command"] = "./scripts/dev-x86_64.sh mman-header-abi"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-header-layouts-baseline command"
        ):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.headers-layouts")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-header-layouts-baseline"
        )
        artifact["description"] = artifact["description"].replace(
            "complete C ABI", "completed C runtime"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "complete C ABI"):
            ledger.validate_ledger(data)

    def test_math_complex_foundation_remains_a_closed_non_capability_artifact(self) -> None:
        data = self.data()
        text_math = self.family(data, "libc.text-math-locale-stdio")
        self.assertEqual(text_math["status"], "planned")
        artifacts = text_math["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 1
        artifact = artifacts[0]
        assert isinstance(artifact, dict)
        self.assertEqual(artifact["id"], "static-c-math-complex-foundation")
        self.assertNotIn("capabilities", artifact)
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
            "compat/x86_64/libc_math_complex_probe.c",
            "compat/x86_64/libc_math_complex_start.S",
            "compat/x86_64/run_libc_math_complex.sh",
        ):
            self.assertIn(owner, artifact["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-math-complex"},
        )
        for phrase in (
            "long-double/complex foundation",
            "__fpclassify",
            "__fpclassifyf",
            "__fpclassifyl",
            "__signbit",
            "__signbitf",
            "__signbitl",
            "cabs/carg/cproj",
            "complex powers and transcendentals",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])

        data = self.data()
        text_math = self.family(data, "libc.text-math-locale-stdio")
        artifacts = text_math["verified_artifact"]
        assert isinstance(artifacts, list) and isinstance(artifacts[0], dict)
        artifacts[0]["description"] = artifacts[0]["description"].replace(
            "public x86 support", "x86 support"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "public x86 support"):
            ledger.validate_ledger(data)

        data = self.data()
        text_math = self.family(data, "libc.text-math-locale-stdio")
        artifacts = text_math["verified_artifact"]
        assert isinstance(artifacts, list) and isinstance(artifacts[0], dict)
        evidence = artifacts[0]["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh libc-fenv"
        with self.assertRaisesRegex(ledger.LedgerError, "closed libc-math-complex command"):
            ledger.validate_ledger(data)

    def test_foundations_remain_narrow_and_source_or_artifact_scoped(self) -> None:
        data = self.data()
        direct = self.family(data, "facade.direct")
        remaining = self.family(data, "facade.record-owning")
        direct_slices = direct["verified_slice"]
        assert isinstance(direct_slices, list)
        direct_slices_by_id = {
            slice_entry["id"]: slice_entry
            for slice_entry in direct_slices
            if isinstance(slice_entry, dict)
        }
        fnmatch_slice = direct_slices_by_id["pattern.fnmatch"]
        glob_slice = direct_slices_by_id["pattern.glob"]
        assert isinstance(fnmatch_slice, dict)
        assert isinstance(glob_slice, dict)
        self.assertEqual(fnmatch_slice["capabilities"], ["pattern.fnmatch"])
        for owner in (
            "crabc-core/src/pattern.rs",
            "crabc-rs/src/pattern_x86_64.rs",
            "crabc-rs/tests/x86_64_fnmatch.rs",
            "crabc-rs/examples/fnmatch_direct_probe.rs",
            "compat/x86_64/verify_fnmatch_direct.sh",
        ):
            self.assertIn(owner, fnmatch_slice["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in fnmatch_slice["native_evidence"]},
            {"./scripts/dev-x86_64.sh facade"},
        )
        self.assertIn("separate alloc-gated", fnmatch_slice["description"])

        self.assertEqual(glob_slice["capabilities"], ["pattern.glob"])
        for owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/pattern.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/src/raw_dir.rs",
            "crabc-rs/src/pattern_x86_64.rs",
            "crabc-rs/tests/x86_64_glob.rs",
            "crabc-rs/examples/glob_direct_probe.rs",
            "compat/x86_64/verify_glob_direct.sh",
        ):
            self.assertIn(owner, glob_slice["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in glob_slice["native_evidence"]},
            {"./scripts/dev-x86_64.sh facade"},
        )
        self.assertIn("explicit `PathArg` root", glob_slice["description"])
        self.assertIn("fixed custom Rust allocator", glob_slice["x86_abi_prerequisites"][0])
        self.assertIn("glob_t", glob_slice["x86_header_prerequisites"][0])
        self.assertIn("pattern.fnmatch", direct["capabilities"])
        self.assertIn("pattern.glob", direct["capabilities"])
        self.assertNotIn("pattern.glob", fnmatch_slice["capabilities"])
        self.assertEqual(self.family(data, "libc.raw-syscall")["status"], "foundation-verified")
        errno_tls = self.family(data, "libc.errno-tls")
        self.assertEqual(errno_tls["status"], "foundation-verified")
        self.assertIn("oracle.musl-toolchain", errno_tls["depends_on"])
        self.assertIn(
            "libc/src/c_abi/x86_64/foundation.rs", errno_tls["source_owners"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/thread_pointer.rs", errno_tls["source_owners"]
        )
        self.assertTrue(
            any("pthread_arch.h::__get_tp" in item for item in errno_tls["x86_abi_prerequisites"])
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-foundation",
            {evidence["command"] for evidence in errno_tls["native_evidence"]},
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-thread-pointer",
            {evidence["command"] for evidence in errno_tls["native_evidence"]},
        )
        posix_runtime = self.family(data, "libc.posix-runtime")
        self.assertEqual(posix_runtime["status"], "planned")
        slices = posix_runtime["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 2
        slices_by_id = {slice_entry["id"]: slice_entry for slice_entry in slices}
        stat_compat = slices_by_id["filesystem.stat-compat"]
        assert isinstance(stat_compat, dict)
        self.assertEqual(stat_compat["id"], "filesystem.stat-compat")
        self.assertEqual(stat_compat["capabilities"], ["filesystem.stat-compat"])
        self.assertIn(
            "libc/src/c_abi/x86_64/stat_compat.rs",
            stat_compat["source_owners"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            stat_compat["source_owners"],
        )
        stat_commands = {
            evidence["command"] for evidence in stat_compat["native_evidence"]
        }
        self.assertEqual(
            stat_commands, {"./scripts/dev-x86_64.sh libc-stat-compat"}
        )
        self.assertIn("freestanding fixture", stat_compat["description"])
        self.assertIn("does not select libc.so", stat_compat["native_evidence"][0]["scope"])
        credentials = slices_by_id["process.credentials"]
        assert isinstance(credentials, dict)
        self.assertEqual(credentials["capabilities"], ["process.credentials"])
        for owner in (
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/credentials.rs",
            "compat/x86_64/libc_credentials_probe.c",
            "compat/x86_64/libc_credentials_start.S",
            "compat/x86_64/run_libc_credentials.sh",
        ):
            self.assertIn(owner, credentials["source_owners"])
        credential_commands = {
            evidence["command"] for evidence in credentials["native_evidence"]
        }
        self.assertEqual(
            credential_commands, {"./scripts/dev-x86_64.sh libc-credentials"}
        )
        self.assertIn("EOPNOTSUPP", credentials["description"])
        self.assertIn(
            "does not select libc.so", credentials["native_evidence"][0]["scope"]
        )
        posix_artifacts = posix_runtime["verified_artifact"]
        assert isinstance(posix_artifacts, list) and len(posix_artifacts) == 34
        artifacts_by_id = {
            artifact["id"]: artifact
            for artifact in posix_artifacts
            if isinstance(artifact, dict)
        }
        signal_control = artifacts_by_id["static-c-signal-control"]
        assert isinstance(signal_control, dict)
        self.assertNotIn("capabilities", signal_control)
        for owner in (
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/signal_foundation.rs",
            "libc/src/c_abi/x86_64/signal_control.rs",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_signal_control_probe.c",
            "compat/x86_64/libc_signal_control_start.S",
            "compat/x86_64/run_libc_signal_control.sh",
        ):
            self.assertIn(owner, signal_control["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in signal_control["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-signal-control"},
        )
        self.assertIn("does not select process.signal", signal_control["description"])
        self.assertIn("partial output writes", signal_control["description"])
        self.assertIn(
            "does not select process.signal", signal_control["native_evidence"][0]["scope"]
        )
        self.assertIn(
            "direct null pending EFAULT",
            signal_control["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/signal_control.rs",
            posix_runtime["source_owners"],
        )
        termios_control = artifacts_by_id["static-c-termios-control"]
        assert isinstance(termios_control, dict)
        self.assertNotIn("capabilities", termios_control)
        for owner in (
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/termios_control.rs",
            "include/termios.h",
            "compat/x86_64/termios_header_abi_probe.c",
            "compat/x86_64/termios_header_abi_probe.cpp",
            "compat/x86_64/run_termios_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_termios_control_probe.c",
            "compat/x86_64/libc_termios_control_start.S",
            "compat/x86_64/run_libc_termios_control.sh",
        ):
            self.assertIn(owner, termios_control["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in termios_control["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-termios-control"},
        )
        self.assertIn("does not select a generic ioctl", termios_control["description"])
        self.assertIn("60-byte", termios_control["description"])
        self.assertIn("byte-preserved public tails", termios_control["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/termios_control.rs",
            posix_runtime["source_owners"],
        )
        process_context = artifacts_by_id["static-c-process-context"]
        assert isinstance(process_context, dict)
        self.assertNotIn("capabilities", process_context)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/process_context.rs",
            "include/unistd.h",
            "include/sys/stat.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_process_context_probe.c",
            "compat/x86_64/libc_process_context_start.S",
            "compat/x86_64/run_libc_process_context.sh",
        ):
            self.assertIn(owner, process_context["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in process_context["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-process-context"},
        )
        self.assertIn("narrower than `process.control`", process_context["description"])
        self.assertIn("does not select C fork", process_context["description"])
        self.assertIn("raw-fork-contained", process_context["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/process_context.rs",
            posix_runtime["source_owners"],
        )
        descriptor_io = artifacts_by_id["static-c-descriptor-io"]
        assert isinstance(descriptor_io, dict)
        self.assertNotIn("capabilities", descriptor_io)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/descriptor_io.rs",
            "include/fcntl.h",
            "include/unistd.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_descriptor_io_probe.c",
            "compat/x86_64/libc_descriptor_io_start.S",
            "compat/x86_64/run_libc_descriptor_io.sh",
        ):
            self.assertIn(owner, descriptor_io["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in descriptor_io["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-descriptor-io"},
        )
        self.assertIn("pwrite", descriptor_io["description"])
        self.assertIn(
            "does not select C open/path, generic fcntl command",
            descriptor_io["description"],
        )
        self.assertIn("EBUSY loops", descriptor_io["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_io.rs",
            posix_runtime["source_owners"],
        )
        descriptor_lifecycle = artifacts_by_id["static-c-descriptor-lifecycle"]
        assert isinstance(descriptor_lifecycle, dict)
        self.assertNotIn("capabilities", descriptor_lifecycle)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/stat_compat.rs",
            "libc/src/c_abi/x86_64/descriptor_entry.rs",
            "libc/src/c_abi/x86_64/descriptor_control.rs",
            "libc/src/c_abi/x86_64/descriptor_io.rs",
            "include/fcntl.h",
            "include/stddef.h",
            "include/sys/stat.h",
            "compat/x86_64/fcntl_header_abi_probe.c",
            "compat/x86_64/run_fcntl_header_abi.sh",
            "compat/x86_64/stat_header_abi_probe.c",
            "compat/x86_64/run_stat_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_descriptor_lifecycle_probe.c",
            "compat/x86_64/libc_descriptor_lifecycle_start.S",
            "compat/x86_64/run_libc_descriptor_lifecycle.sh",
        ):
            self.assertIn(owner, descriptor_lifecycle["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in descriptor_lifecycle["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-descriptor-lifecycle"},
        )
        self.assertIn(
            "descriptor-lifecycle composition", descriptor_lifecycle["description"]
        )
        self.assertIn(
            "does not establish a general C runtime",
            descriptor_lifecycle["description"],
        )
        self.assertIn(
            "fdatasync", descriptor_lifecycle["native_evidence"][0]["scope"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/stat_compat.rs",
            posix_runtime["source_owners"],
        )
        process_resources = artifacts_by_id["static-c-process-resources"]
        assert isinstance(process_resources, dict)
        self.assertNotIn("capabilities", process_resources)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/process_resources.rs",
            "include/sys/resource.h",
            "include/sys/time.h",
            "compat/x86_64/resource_header_abi_probe.c",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_process_resources_probe.c",
            "compat/x86_64/libc_process_resources_start.S",
            "compat/x86_64/run_libc_process_resources.sh",
        ):
            self.assertIn(owner, process_resources["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in process_resources["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-process-resources"},
        )
        self.assertIn("narrower than process-resource capabilities", process_resources["description"])
        self.assertIn("capability-conditional", process_resources["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/process_resources.rs",
            posix_runtime["source_owners"],
        )
        readiness_waits = artifacts_by_id["static-c-readiness-signal-waits"]
        assert isinstance(readiness_waits, dict)
        self.assertNotIn("capabilities", readiness_waits)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/readiness_waits.rs",
            "include/poll.h",
            "include/sys/select.h",
            "compat/x86_64/poll_header_abi_probe.c",
            "compat/x86_64/poll_header_abi_probe.cpp",
            "compat/x86_64/run_poll_header_abi.sh",
            "compat/x86_64/select_header_abi_probe.c",
            "compat/x86_64/select_header_abi_probe.cpp",
            "compat/x86_64/run_select_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_readiness_waits_probe.c",
            "compat/x86_64/libc_readiness_waits_start.S",
            "compat/x86_64/run_libc_readiness_waits.sh",
        ):
            self.assertIn(owner, readiness_waits["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in readiness_waits["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-readiness-waits"},
        )
        self.assertIn("does not select epoll/eventfd", readiness_waits["description"])
        self.assertIn(
            "temporary-mask delivery/restoration",
            readiness_waits["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/readiness_waits.rs",
            posix_runtime["source_owners"],
        )
        socket_transport = artifacts_by_id["static-c-socket-transport"]
        assert isinstance(socket_transport, dict)
        self.assertNotIn("capabilities", socket_transport)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/socket_transport.rs",
            "include/fcntl.h",
            "include/bits/fcntl.h",
            "include/arpa/inet.h",
            "include/netinet/in.h",
            "include/sys/socket.h",
            "compat/x86_64/socket_header_abi_probe.c",
            "compat/x86_64/socket_header_abi_probe.cpp",
            "compat/x86_64/socket_header_ipv6_macro_probe.c",
            "compat/x86_64/run_socket_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_socket_transport_probe.c",
            "compat/x86_64/libc_socket_transport_start.S",
            "compat/x86_64/run_libc_socket_transport.sh",
        ):
            self.assertIn(owner, socket_transport["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in socket_transport["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-socket-transport"},
        )
        self.assertIn("socketpair", socket_transport["description"])
        self.assertIn("cancellation-point machinery", socket_transport["description"])
        self.assertIn("does not select resolver/netdb", socket_transport["description"])
        self.assertIn("cancellation semantics", socket_transport["native_evidence"][0]["scope"])
        self.assertIn("atomic CLOEXEC/NONBLOCK", socket_transport["native_evidence"][0]["scope"])
        self.assertIn("null-output socketpair EFAULT", socket_transport["native_evidence"][0]["scope"])
        self.assertIn(
            "IPv6 address-classification macros",
            socket_transport["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/socket_transport.rs",
            posix_runtime["source_owners"],
        )
        byte_strings = artifacts_by_id["static-c-byte-strings"]
        assert isinstance(byte_strings, dict)
        self.assertNotIn("capabilities", byte_strings)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/byte_strings.rs",
            "include/string.h",
            "include/strings.h",
            "compat/x86_64/byte_strings_header_abi_probe.c",
            "compat/x86_64/byte_strings_header_abi_probe.cpp",
            "compat/x86_64/run_byte_strings_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_byte_strings_probe.c",
            "compat/x86_64/libc_byte_strings_start.S",
            "compat/x86_64/run_libc_byte_strings.sh",
        ):
            self.assertIn(owner, byte_strings["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in byte_strings["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-byte-strings"},
        )
        self.assertIn("public `index` and `rindex` forwarding wrappers", byte_strings["description"])
        self.assertIn("private `__strchrnul`/`__memrchr`", byte_strings["description"])
        self.assertIn("scalar fallback", byte_strings["description"])
        self.assertIn("GNU-gated", byte_strings["x86_header_prerequisites"][0])
        self.assertIn("src/string/index.c", byte_strings["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            posix_runtime["source_owners"],
        )
        random_entropy = artifacts_by_id["static-c-random-entropy"]
        assert isinstance(random_entropy, dict)
        self.assertNotIn("capabilities", random_entropy)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/random_entropy.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/random.h",
            "include/unistd.h",
            "compat/x86_64/random_entropy_header_abi_probe.c",
            "compat/x86_64/random_entropy_header_abi_probe.cpp",
            "compat/x86_64/run_random_entropy_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_random_entropy_probe.c",
            "compat/x86_64/libc_random_entropy_start.S",
            "compat/x86_64/run_libc_random_entropy.sh",
        ):
            self.assertIn(owner, random_entropy["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in random_entropy["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-random-entropy"},
        )
        self.assertIn("pthread cancellation point", random_entropy["description"])
        self.assertIn("disables cancellation", random_entropy["description"])
        self.assertIn("omits pthread cancellation", random_entropy["description"])
        self.assertIn("initial-TLS errno", random_entropy["description"])
        self.assertIn("syscall_cp", random_entropy["x86_abi_prerequisites"][1])
        self.assertIn("disables cancellation", random_entropy["x86_abi_prerequisites"][1])
        memory_search = artifacts_by_id["static-c-memory-search"]
        assert isinstance(memory_search, dict)
        self.assertNotIn("capabilities", memory_search)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/memory_search.rs",
            "include/string.h",
            "compat/x86_64/memory_search_header_abi_probe.c",
            "compat/x86_64/memory_search_header_abi_probe.cpp",
            "compat/x86_64/run_memory_search_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_memory_search_probe.c",
            "compat/x86_64/libc_memory_search_start.S",
            "compat/x86_64/run_libc_memory_search.sh",
        ):
            self.assertIn(owner, memory_search["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in memory_search["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-memory-search"},
        )
        self.assertIn("private `__memrchr` helper", memory_search["description"])
        self.assertIn("stateless", memory_search["description"])
        self.assertIn("allocation-free", memory_search["description"])
        self.assertIn("POSIX/GNU-gated", memory_search["x86_header_prerequisites"][0])
        self.assertIn("src/string/memchr.c", memory_search["oracle"][0]["role"])
        string_copy = artifacts_by_id["static-c-string-copy"]
        assert isinstance(string_copy, dict)
        self.assertNotIn("capabilities", string_copy)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/string_copy.rs",
            "include/string.h",
            "compat/x86_64/string_copy_header_abi_probe.c",
            "compat/x86_64/string_copy_header_abi_probe.cpp",
            "compat/x86_64/run_string_copy_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_string_copy_probe.c",
            "compat/x86_64/libc_string_copy_start.S",
            "compat/x86_64/run_libc_string_copy.sh",
        ):
            self.assertIn(owner, string_copy["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in string_copy["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-string-copy"},
        )
        self.assertIn(
            "private `__stpcpy`/`__stpncpy` helpers", string_copy["description"]
        )
        self.assertIn("stateless", string_copy["description"])
        self.assertIn("allocation-free", string_copy["description"])
        self.assertIn("POSIX/XOPEN/GNU/BSD-gated", string_copy["x86_header_prerequisites"][0])
        self.assertIn("src/string/stpcpy.c", string_copy["oracle"][0]["role"])
        ctype = artifacts_by_id["static-c-ctype"]
        assert isinstance(ctype, dict)
        self.assertNotIn("capabilities", ctype)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/ctype.rs",
            "include/ctype.h",
            "compat/x86_64/ctype_header_abi_probe.c",
            "compat/x86_64/ctype_header_abi_probe.cpp",
            "compat/x86_64/run_ctype_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_ctype_probe.c",
            "compat/x86_64/libc_ctype_start.S",
            "compat/x86_64/run_libc_ctype.sh",
        ):
            self.assertIn(owner, ctype["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in ctype["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-ctype"},
        )
        self.assertIn("fixed-C-locale ctype", ctype["description"])
        self.assertIn("stateless", ctype["description"])
        self.assertIn("allocation-free", ctype["description"])
        self.assertIn("POSIX/XOPEN/GNU/BSD-gated", ctype["x86_header_prerequisites"][0])
        self.assertIn("src/ctype/isalnum.c", ctype["oracle"][0]["role"])
        integer_arithmetic = artifacts_by_id["static-c-integer-arithmetic"]
        assert isinstance(integer_arithmetic, dict)
        self.assertNotIn("capabilities", integer_arithmetic)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/integer_arithmetic.rs",
            "include/stdlib.h",
            "compat/x86_64/integer_arithmetic_header_abi_probe.c",
            "compat/x86_64/integer_arithmetic_header_abi_probe.cpp",
            "compat/x86_64/run_integer_arithmetic_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_integer_arithmetic_probe.c",
            "compat/x86_64/libc_integer_arithmetic_start.S",
            "compat/x86_64/run_libc_integer_arithmetic.sh",
        ):
            self.assertIn(owner, integer_arithmetic["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in integer_arithmetic["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-integer-arithmetic"},
        )
        self.assertIn("integer-arithmetic block", integer_arithmetic["description"])
        self.assertIn("stateless", integer_arithmetic["description"])
        self.assertIn("allocation-free", integer_arithmetic["description"])
        self.assertIn("unconditional", integer_arithmetic["x86_header_prerequisites"][0])
        self.assertIn("src/stdlib/abs.c", integer_arithmetic["oracle"][0]["role"])
        integer_parse = artifacts_by_id["static-c-integer-parse"]
        assert isinstance(integer_parse, dict)
        self.assertNotIn("capabilities", integer_parse)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/integer_parse.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "include/errno.h",
            "include/inttypes.h",
            "include/stdlib.h",
            "compat/x86_64/integer_parse_header_abi_probe.c",
            "compat/x86_64/integer_parse_header_abi_probe.cpp",
            "compat/x86_64/run_integer_parse_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_integer_parse_probe.c",
            "compat/x86_64/libc_integer_parse_start.S",
            "compat/x86_64/run_libc_integer_parse.sh",
        ):
            self.assertIn(owner, integer_parse["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in integer_parse["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-integer-parse"},
        )
        self.assertIn("integer-parsing block", integer_parse["description"])
        self.assertIn("defined-input", integer_parse["description"])
        self.assertIn("allocation-free", integer_parse["description"])
        self.assertIn("unconditional", integer_parse["x86_header_prerequisites"][0])
        self.assertIn("src/internal/intscan.c", integer_parse["oracle"][0]["role"])
        intmax_arithmetic = artifacts_by_id["static-c-intmax-arithmetic"]
        assert isinstance(intmax_arithmetic, dict)
        self.assertNotIn("capabilities", intmax_arithmetic)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/intmax_arithmetic.rs",
            "include/inttypes.h",
            "compat/x86_64/intmax_arithmetic_header_abi_probe.c",
            "compat/x86_64/intmax_arithmetic_header_abi_probe.cpp",
            "compat/x86_64/run_intmax_arithmetic_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_intmax_arithmetic_probe.c",
            "compat/x86_64/libc_intmax_arithmetic_start.S",
            "compat/x86_64/run_libc_intmax_arithmetic.sh",
        ):
            self.assertIn(owner, intmax_arithmetic["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in intmax_arithmetic["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-intmax-arithmetic"},
        )
        self.assertIn("intmax-arithmetic block", intmax_arithmetic["description"])
        self.assertIn("stateless", intmax_arithmetic["description"])
        self.assertIn("allocation-free", intmax_arithmetic["description"])
        self.assertIn("unconditional", intmax_arithmetic["x86_header_prerequisites"][0])
        self.assertIn("src/stdlib/imaxabs.c", intmax_arithmetic["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/intmax_arithmetic.rs",
            posix_runtime["source_owners"],
        )
        credential_observation = artifacts_by_id["static-c-credential-observation"]
        assert isinstance(credential_observation, dict)
        self.assertNotIn("capabilities", credential_observation)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/credential_observation.rs",
            "include/unistd.h",
            "compat/x86_64/credential_observation_header_abi_probe.c",
            "compat/x86_64/credential_observation_header_abi_probe.cpp",
            "compat/x86_64/run_credential_observation_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_credential_observation_probe.c",
            "compat/x86_64/libc_credential_observation_start.S",
            "compat/x86_64/run_libc_credential_observation.sh",
        ):
            self.assertIn(owner, credential_observation["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in credential_observation["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-credential-observation"},
        )
        self.assertIn(
            "credential-observation block", credential_observation["description"]
        )
        self.assertIn("read-only", credential_observation["description"])
        self.assertIn(
            "query-then-fill race", credential_observation["description"]
        )
        self.assertIn("GNU", credential_observation["x86_header_prerequisites"][0])
        self.assertIn(
            "src/unistd/getgroups.c", credential_observation["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/credential_observation.rs",
            posix_runtime["source_owners"],
        )
        child_reaping = artifacts_by_id["static-c-child-reaping"]
        assert isinstance(child_reaping, dict)
        self.assertNotIn("capabilities", child_reaping)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/child_reaping.rs",
            "include/sys/wait.h",
            "compat/x86_64/child_reaping_header_abi_probe.c",
            "compat/x86_64/child_reaping_header_abi_probe.cpp",
            "compat/x86_64/run_child_reaping_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_child_reaping_probe.c",
            "compat/x86_64/libc_child_reaping_start.S",
            "compat/x86_64/run_libc_child_reaping.sh",
        ):
            self.assertIn(owner, child_reaping["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in child_reaping["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-child-reaping"},
        )
        self.assertIn("child-reaping block", child_reaping["description"])
        self.assertIn("WNOHANG", child_reaping["description"])
        self.assertIn("WNOWAIT", child_reaping["description"])
        self.assertIn("cancellation", child_reaping["description"])
        self.assertIn("wait4=61", child_reaping["x86_abi_prerequisites"][0])
        self.assertIn(
            "libc/src/c_abi/x86_64/child_reaping.rs",
            posix_runtime["source_owners"],
        )
        immediate_termination = artifacts_by_id["static-c-immediate-termination"]
        assert isinstance(immediate_termination, dict)
        self.assertNotIn("capabilities", immediate_termination)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/immediate_termination.rs",
            "include/stdlib.h",
            "compat/x86_64/immediate_termination_header_abi_probe.c",
            "compat/x86_64/immediate_termination_header_abi_probe.cpp",
            "compat/x86_64/run_immediate_termination_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_immediate_termination_probe.c",
            "compat/x86_64/libc_immediate_termination_start.S",
            "compat/x86_64/run_libc_immediate_termination.sh",
        ):
            self.assertIn(owner, immediate_termination["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in immediate_termination["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-immediate-termination"},
        )
        self.assertIn(
            "immediate-termination block", immediate_termination["description"]
        )
        self.assertIn("exit_group=231", immediate_termination["description"])
        self.assertIn("quick_exit", immediate_termination["description"])
        self.assertIn(
            "libc/src/c_abi/x86_64/immediate_termination.rs",
            posix_runtime["source_owners"],
        )
        callback_algorithms = artifacts_by_id["static-c-callback-algorithms"]
        assert isinstance(callback_algorithms, dict)
        self.assertNotIn("capabilities", callback_algorithms)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/callback_algorithms.rs",
            "include/stdlib.h",
            "compat/x86_64/callback_algorithms_header_abi_probe.c",
            "compat/x86_64/callback_algorithms_header_abi_probe.cpp",
            "compat/x86_64/run_callback_algorithms_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_callback_algorithms_probe.c",
            "compat/x86_64/libc_callback_algorithms_start.S",
            "compat/x86_64/run_libc_callback_algorithms.sh",
        ):
            self.assertIn(owner, callback_algorithms["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in callback_algorithms["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-callback-algorithms"},
        )
        self.assertIn(
            "callback-algorithms block", callback_algorithms["description"]
        )
        self.assertIn("smoothsort", callback_algorithms["description"])
        self.assertIn("same-address", callback_algorithms["description"])
        self.assertIn("stateless", callback_algorithms["description"])
        self.assertIn("src/stdlib/qsort.c", callback_algorithms["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/callback_algorithms.rs",
            posix_runtime["source_owners"],
        )
        clock_gettime = artifacts_by_id["static-c-clock-gettime"]
        assert isinstance(clock_gettime, dict)
        self.assertNotIn("capabilities", clock_gettime)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/clock_gettime.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/time.h",
            "compat/x86_64/time_header_abi_probe.c",
            "compat/x86_64/time_header_abi_probe.cpp",
            "compat/x86_64/run_time_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_clock_gettime_probe.c",
            "compat/x86_64/libc_clock_gettime_start.S",
            "compat/x86_64/run_libc_clock_gettime.sh",
        ):
            self.assertIn(owner, clock_gettime["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in clock_gettime["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-clock-gettime"},
        )
        for phrase in (
            "POSIX clock_gettime block",
            "-1/errno",
            "initial-TLS errno",
            "vDSO resolver",
            "clock_getres",
            "clock_settime",
        ):
            self.assertIn(phrase, clock_gettime["description"])
        self.assertIn(
            "src/time/clock_gettime.c", clock_gettime["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/clock_gettime.rs",
            posix_runtime["source_owners"],
        )
        system_configuration = artifacts_by_id["static-c-system-configuration"]
        assert isinstance(system_configuration, dict)
        self.assertNotIn("capabilities", system_configuration)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "libc/src/c_abi/x86_64/process_resources.rs",
            "libc/src/c_abi/x86_64/system_configuration.rs",
            "libc/src/regression_stubs.rs",
            "include/unistd.h",
            "include/sys/resource.h",
            "compat/x86_64/unistd_header_abi_probe.c",
            "compat/x86_64/unistd_header_abi_probe.cpp",
            "compat/x86_64/run_unistd_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_system_configuration_probe.c",
            "compat/x86_64/libc_system_configuration_start.S",
            "compat/x86_64/run_libc_system_configuration.sh",
            "tests/fixtures/path_configuration_exports_test.c",
            "tests/path_configuration_exports.rs",
        ):
            self.assertIn(owner, system_configuration["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in system_configuration["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-system-configuration"},
        )
        for phrase in (
            "system-configuration block",
            "path- and fd-independent",
            "corresponding AArch64",
            "focused dynamic fixture",
            "full musl sysconf table",
            "startup-owned auxv/getauxval",
        ):
            self.assertIn(phrase, system_configuration["description"])
        self.assertIn(
            "src/conf/sysconf.c", system_configuration["oracle"][0]["role"]
        )
        self.assertIn(
            "src/conf/fpathconf.c", system_configuration["oracle"][0]["role"]
        )
        self.assertIn(
            "prlimit64=302", system_configuration["x86_abi_prerequisites"][3]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/system_configuration.rs",
            posix_runtime["source_owners"],
        )
        mapping_core = artifacts_by_id["static-c-mman-mapping-core"]
        assert isinstance(mapping_core, dict)
        self.assertNotIn("capabilities", mapping_core)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/memory_mapping.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "include/sys/mman.h",
            "include/bits/mman.h",
            "compat/x86_64/mman_header_abi_probe.c",
            "compat/x86_64/mman_header_abi_probe.cpp",
            "compat/x86_64/run_mman_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_mapping_core_probe.c",
            "compat/x86_64/libc_mapping_core_start.S",
            "compat/x86_64/run_libc_mapping_core.sh",
        ):
            self.assertIn(owner, mapping_core["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in mapping_core["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-mapping-core"},
        )
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
            self.assertIn(phrase, mapping_core["description"])
        self.assertTrue(
            any(
                "mmap=9" in prerequisite
                and "mprotect=10" in prerequisite
                and "munmap=11" in prerequisite
                and "mincore=27" in prerequisite
                and "madvise=28" in prerequisite
                for prerequisite in mapping_core["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "PTRDIFF_MAX" in prerequisite and "EPERM" in prerequisite
                for prerequisite in mapping_core["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "local no-op" in prerequisite and "__vm_wait" in prerequisite
                for prerequisite in mapping_core["x86_abi_prerequisites"]
            )
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/memory_mapping.rs",
            posix_runtime["source_owners"],
        )
        clock_nanosleep = artifacts_by_id["static-c-clock-nanosleep"]
        assert isinstance(clock_nanosleep, dict)
        self.assertNotIn("capabilities", clock_nanosleep)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/clock_nanosleep.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/signal_control.rs",
            "include/time.h",
            "compat/x86_64/time_header_abi_probe.c",
            "compat/x86_64/time_header_abi_probe.cpp",
            "compat/x86_64/run_time_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_clock_nanosleep_probe.c",
            "compat/x86_64/libc_clock_nanosleep_start.S",
            "compat/x86_64/run_libc_clock_nanosleep.sh",
        ):
            self.assertIn(owner, clock_nanosleep["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in clock_nanosleep["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-clock-nanosleep"},
        )
        self.assertIn("positive errno", clock_nanosleep["description"])
        self.assertIn("__syscall_cp", clock_nanosleep["description"])
        self.assertIn("CLOCK_REALTIME", clock_nanosleep["description"])
        self.assertIn(
            "separately selected nanosleep leaf", clock_nanosleep["description"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/clock_nanosleep.rs",
            posix_runtime["source_owners"],
        )
        nanosleep = artifacts_by_id["static-c-nanosleep"]
        assert isinstance(nanosleep, dict)
        self.assertNotIn("capabilities", nanosleep)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/nanosleep.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/signal_control.rs",
            "include/time.h",
            "compat/x86_64/time_header_abi_probe.c",
            "compat/x86_64/time_header_abi_probe.cpp",
            "compat/x86_64/run_time_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_nanosleep_probe.c",
            "compat/x86_64/libc_nanosleep_start.S",
            "compat/x86_64/run_libc_nanosleep.sh",
        ):
            self.assertIn(owner, nanosleep["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in nanosleep["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-nanosleep"},
        )
        for phrase in (
            "POSIX nanosleep block",
            "-1/errno",
            "initial-TLS errno",
            "__syscall_cp",
            "omits cancellation",
        ):
            self.assertIn(phrase, nanosleep["description"])
        self.assertIn(
            "src/time/nanosleep.c", nanosleep["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/nanosleep.rs",
            posix_runtime["source_owners"],
        )
        descriptor_entry = artifacts_by_id["static-c-descriptor-entry"]
        assert isinstance(descriptor_entry, dict)
        self.assertNotIn("capabilities", descriptor_entry)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/descriptor_entry.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "include/fcntl.h",
            "include/bits/fcntl.h",
            "include/sys/stat.h",
            "compat/x86_64/fcntl_header_abi_probe.c",
            "compat/x86_64/fcntl_header_abi_probe.cpp",
            "compat/x86_64/run_fcntl_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_descriptor_entry_probe.c",
            "compat/x86_64/libc_descriptor_entry_start.S",
            "compat/x86_64/run_libc_descriptor_entry.sh",
        ):
            self.assertIn(owner, descriptor_entry["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in descriptor_entry["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-descriptor-entry"},
        )
        self.assertIn("descriptor-entry block", descriptor_entry["description"])
        self.assertIn("O_CLOEXEC", descriptor_entry["description"])
        self.assertIn(
            "does not expand C fcntl beyond", descriptor_entry["description"]
        )
        self.assertIn("src/fcntl/open.c", descriptor_entry["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_entry.rs",
            posix_runtime["source_owners"],
        )
        fcntl_status_control = artifacts_by_id["static-c-fcntl-status-control"]
        assert isinstance(fcntl_status_control, dict)
        self.assertNotIn("capabilities", fcntl_status_control)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/descriptor_control.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "include/fcntl.h",
            "include/bits/fcntl.h",
            "compat/x86_64/fcntl_header_abi_probe.c",
            "compat/x86_64/fcntl_header_abi_probe.cpp",
            "compat/x86_64/run_fcntl_header_abi.sh",
            "compat/x86_64/run_x86_fcntl_status_reference.sh",
            "compat/x86_64/x86_fcntl_status_reference_probe.c",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_fcntl_status_control_probe.c",
            "compat/x86_64/libc_fcntl_status_control_start.S",
            "compat/x86_64/run_libc_fcntl_status_control.sh",
        ):
            self.assertIn(owner, fcntl_status_control["source_owners"])
        self.assertEqual(
            {
                evidence["command"]
                for evidence in fcntl_status_control["native_evidence"]
            },
            {"./scripts/dev-x86_64.sh libc-fcntl-status-control"},
        )
        for phrase in (
            "fcntl status-control block",
            "`F_GETFD`",
            "`F_SETFD`",
            "`F_GETFL`",
            "`F_SETFL`",
            "O_LARGEFILE",
            "-1/EINVAL",
            "does not select generic C fcntl",
        ):
            self.assertIn(phrase, fcntl_status_control["description"])
        self.assertIn(
            "src/fcntl/fcntl.c", fcntl_status_control["oracle"][0]["role"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_control.rs",
            posix_runtime["source_owners"],
        )
        ffs = artifacts_by_id["static-c-ffs"]
        assert isinstance(ffs, dict)
        self.assertNotIn("capabilities", ffs)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/ffs.rs",
            "include/strings.h",
            "compat/x86_64/ffs_header_abi_probe.c",
            "compat/x86_64/ffs_header_abi_probe.cpp",
            "compat/x86_64/run_ffs_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_ffs_probe.c",
            "compat/x86_64/libc_ffs_start.S",
            "compat/x86_64/run_libc_ffs.sh",
        ):
            self.assertIn(owner, ffs["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in ffs["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-ffs"},
        )
        self.assertIn("find-first-set block", ffs["description"])
        self.assertIn("stateless", ffs["description"])
        self.assertIn("allocation-free", ffs["description"])
        self.assertIn("XOPEN/GNU/BSD-gated", ffs["x86_header_prerequisites"][0])
        self.assertIn("src/misc/ffs.c", ffs["oracle"][0]["role"])
        self.assertIn(
            "libc/src/c_abi/x86_64/ffs.rs", posix_runtime["source_owners"]
        )
        system_observation = artifacts_by_id["static-c-system-observation"]
        assert isinstance(system_observation, dict)
        self.assertNotIn("capabilities", system_observation)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/system_observation.rs",
            "include/sys/sysinfo.h",
            "include/sys/utsname.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_system_observation_probe.c",
            "compat/x86_64/libc_system_observation_start.S",
            "compat/x86_64/run_libc_system_observation.sh",
        ):
            self.assertIn(owner, system_observation["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in system_observation["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-system-observation"},
        )
        self.assertIn("112-byte", system_observation["description"])
        self.assertIn("252 compatibility bytes", system_observation["description"])
        self.assertIn(
            "does not select hostname/domain lookup or mutation",
            system_observation["description"],
        )
        self.assertIn(
            "src/misc/uname.c and src/linux/sysinfo.c",
            system_observation["oracle"][0]["role"],
        )
        self.assertIn(
            "sysinfo=99", system_observation["x86_abi_prerequisites"][0]
        )
        self.assertIn(
            "remaining 252-byte public compatibility tail is preserved",
            system_observation["native_evidence"][0]["scope"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/system_observation.rs",
            posix_runtime["source_owners"],
        )
        uts_identity = artifacts_by_id["static-c-uts-identity"]
        assert isinstance(uts_identity, dict)
        self.assertNotIn("capabilities", uts_identity)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/errno.rs",
            "libc/src/c_abi/x86_64/syscall.rs",
            "libc/src/c_abi/x86_64/system_observation.rs",
            "libc/src/c_abi/x86_64/uts_identity.rs",
            "include/errno.h",
            "include/stddef.h",
            "include/sys/syscall.h",
            "include/bits/syscall.h",
            "include/sys/utsname.h",
            "include/unistd.h",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_uts_identity_probe.c",
            "compat/x86_64/libc_uts_identity_start.S",
            "compat/x86_64/run_libc_uts_identity.sh",
        ):
            self.assertIn(owner, uts_identity["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in uts_identity["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-uts-identity"},
        )
        self.assertIn("fresh fixture-local UTS namespace", uts_identity["description"])
        self.assertIn("CAP_SYS_ADMIN", uts_identity["description"])
        self.assertIn(
            "does not select UTS namespace creation, entry, or control",
            uts_identity["description"],
        )
        self.assertIn(
            "src/unistd/gethostname.c, src/linux/sethostname.c, "
            "src/misc/getdomainname.c, and src/misc/setdomainname.c",
            uts_identity["oracle"][0]["role"],
        )
        uts_abi = " ".join(uts_identity["x86_abi_prerequisites"])
        for detail in (
            "uname=63",
            "sethostname=170",
            "setdomainname=171",
            "390-byte align-1",
            "65-byte",
            "rdi/rsi",
            "CAP_SYS_ADMIN",
        ):
            self.assertIn(detail, uts_abi)
        uts_scope = uts_identity["native_evidence"][0]["scope"]
        self.assertIn("unshare --uts --fork", uts_scope)
        self.assertIn("CAP_SYS_ADMIN", uts_scope)
        self.assertIn("container or host identity", uts_scope)
        self.assertIn(
            "libc/src/c_abi/x86_64/uts_identity.rs",
            posix_runtime["source_owners"],
        )
        self.assertEqual(self.family(data, "ldso.relative-relocation")["status"], "foundation-verified")
        static_pie = self.family(data, "crt.static-pie")
        self.assertEqual(static_pie["status"], "foundation-verified")
        for owner in (
            "crt/build_x86_64.py",
            "crt/src/x86_64_startup.rs",
            "libc/src/c_abi/x86_64/static_tls.rs",
            "libc/src/c_abi/x86_64/static_startup.rs",
            "crt/fixtures/static_pie_fixture_x86_64.rs",
            "crt/tests/test_x86_64_static_pie.py",
            "crt/x86_64-static-pie.md",
            "compat/x86_64/run_libc_crt_static_tls.sh",
            "compat/x86_64/README.md",
        ):
            self.assertIn(owner, static_pie["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in static_pie["native_evidence"]},
            {"./crt/run-x86_64.sh static-pie"},
        )
        static_pie_abi = " ".join(static_pie["x86_abi_prerequisites"])
        for detail in (
            "hidden static-link call",
            "R_X86_64_RELATIVE slot",
            "__crabc_x86_static_tls_bootstrap",
            "no-PT_TLS",
            "static-c-crt-initial-tls-handoff",
        ):
            self.assertIn(detail, static_pie_abi)
        static_pie_scope = static_pie["native_evidence"][0]["scope"]
        for detail in ("no-PT_TLS", "test-local", "TLS materialization", "public x86 support"):
            self.assertIn(detail, static_pie_scope)
        headers_layouts = self.family(data, "libc.headers-layouts")
        self.assertEqual(headers_layouts["status"], "planned")
        for owner in (
            "include/arpa/inet.h",
            "include/netinet/in.h",
            "include/sys/socket.h",
            "compat/x86_64/socket_header_abi_probe.c",
            "compat/x86_64/socket_header_abi_probe.cpp",
            "compat/x86_64/socket_header_ipv6_macro_probe.c",
            "compat/x86_64/run_socket_header_abi.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        socket_header_evidence = next(
            evidence
            for evidence in headers_layouts["native_evidence"]
            if evidence["command"] == "./scripts/dev-x86_64.sh socket-header-abi"
        )
        self.assertEqual(socket_header_evidence["state"], "required")
        self.assertIn("IPv6 address-classification", socket_header_evidence["scope"])
        artifacts = headers_layouts["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 3
        bootstrap = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-bootstrap-primitives"
        )
        assert isinstance(bootstrap, dict)
        self.assertEqual(bootstrap["id"], "static-c-bootstrap-primitives")
        self.assertNotIn("capabilities", bootstrap)
        for owner in (
            "libc/src/c_abi/x86_64/memory.rs",
            "libc/src/c_abi/x86_64/fenv.rs",
            "libc/src/c_abi/x86_64/setjmp.rs",
            "compat/x86_64/libc_bootstrap_primitives_probe.c",
            "compat/x86_64/libc_bootstrap_primitives_start.S",
            "compat/x86_64/run_libc_bootstrap_primitives.sh",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, bootstrap["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in bootstrap["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-bootstrap-primitives"},
        )
        self.assertIn("does not select libc.so", bootstrap["native_evidence"][0]["scope"])
        self.assertIn(
            "libc/src/c_abi/x86_64/fenv.rs", headers_layouts["source_owners"]
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/memory.rs", headers_layouts["source_owners"]
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-fenv",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-memory",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/signal_foundation.rs",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-signal-foundation",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "include/termios.h", headers_layouts["source_owners"]
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh termios-header-abi",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        for owner in (
            "include/sys/resource.h",
            "compat/x86_64/resource_header_abi_probe.c",
            "compat/x86_64/resource_header_abi_probe.cpp",
            "compat/x86_64/run_resource_header_abi.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        self.assertIn(
            "./scripts/dev-x86_64.sh resource-header-abi",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        for owner in (
            "include/poll.h",
            "compat/x86_64/poll_header_abi_probe.c",
            "compat/x86_64/poll_header_abi_probe.cpp",
            "compat/x86_64/run_poll_header_abi.sh",
            "include/sys/select.h",
            "compat/x86_64/select_header_abi_probe.c",
            "compat/x86_64/select_header_abi_probe.cpp",
            "compat/x86_64/run_select_header_abi.sh",
            "compat/x86_64/byte_strings_header_abi_probe.c",
            "compat/x86_64/byte_strings_header_abi_probe.cpp",
            "compat/x86_64/run_byte_strings_header_abi.sh",
            "include/inttypes.h",
            "compat/x86_64/integer_parse_header_abi_probe.c",
            "compat/x86_64/integer_parse_header_abi_probe.cpp",
            "compat/x86_64/run_integer_parse_header_abi.sh",
            "compat/x86_64/intmax_arithmetic_header_abi_probe.c",
            "compat/x86_64/intmax_arithmetic_header_abi_probe.cpp",
            "compat/x86_64/run_intmax_arithmetic_header_abi.sh",
            "compat/x86_64/credential_observation_header_abi_probe.c",
            "compat/x86_64/credential_observation_header_abi_probe.cpp",
            "compat/x86_64/run_credential_observation_header_abi.sh",
            "compat/x86_64/immediate_termination_header_abi_probe.c",
            "compat/x86_64/immediate_termination_header_abi_probe.cpp",
            "compat/x86_64/run_immediate_termination_header_abi.sh",
            "compat/x86_64/callback_algorithms_header_abi_probe.c",
            "compat/x86_64/callback_algorithms_header_abi_probe.cpp",
            "compat/x86_64/run_callback_algorithms_header_abi.sh",
            "compat/x86_64/ffs_header_abi_probe.c",
            "compat/x86_64/ffs_header_abi_probe.cpp",
            "compat/x86_64/run_ffs_header_abi.sh",
            "compat/x86_64/memory_search_header_abi_probe.c",
            "compat/x86_64/memory_search_header_abi_probe.cpp",
            "compat/x86_64/run_memory_search_header_abi.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        header_commands = {
            evidence["command"] for evidence in headers_layouts["native_evidence"]
        }
        self.assertIn("./scripts/dev-x86_64.sh poll-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh select-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh byte-strings-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh integer-parse-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh intmax-arithmetic-header-abi", header_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh credential-observation-header-abi",
            header_commands,
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh immediate-termination-header-abi",
            header_commands,
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh callback-algorithms-header-abi",
            header_commands,
        )
        self.assertIn("./scripts/dev-x86_64.sh ffs-header-abi", header_commands)
        self.assertIn("./scripts/dev-x86_64.sh memory-search-header-abi", header_commands)
        self.assertIn(
            "libc/src/c_abi/x86_64/process_context.rs",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/libc_process_context_probe.c",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-process-context",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/descriptor_io.rs",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/libc_descriptor_io_probe.c",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-descriptor-io",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/process_resources.rs",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "compat/x86_64/libc_process_resources_probe.c",
            headers_layouts["source_owners"],
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-process-resources",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        for owner in (
            "libc/src/c_abi/x86_64/readiness_waits.rs",
            "compat/x86_64/libc_readiness_waits_probe.c",
            "compat/x86_64/libc_readiness_waits_start.S",
            "compat/x86_64/run_libc_readiness_waits.sh",
        ):
            self.assertIn(owner, headers_layouts["source_owners"])
        self.assertIn(
            "./scripts/dev-x86_64.sh libc-readiness-waits",
            {evidence["command"] for evidence in headers_layouts["native_evidence"]},
        )
        self.assertEqual(self.family(data, "ldso.dynamic-runtime")["status"], "planned")
        self.assertEqual(self.family(data, "sysroot.owned-artifact")["status"], "planned")
        for capability in (
            "io.readiness-poll",
            "io.readiness-ppoll",
            "event.pause",
            "process.pid-observation",
            "process.identity-triples",
            "process.identity",
            "process.session-observation",
            "process.fs-credentials",
            "process.supplementary-groups",
            "process.pidfd-open",
            "process.resource-limits",
            "process.resource-limits-targeted",
            "process.resource-usage",
            "process.resource-limit-mutation",
            "process.umask",
            "thread.futex-basic",
            "thread.identity",
            "thread.credentials-res",
            "thread.cpu-observation",
            "thread.scheduler-rr-interval",
            "thread.cpu-affinity-observation",
            "thread.cpu-affinity-mutation",
            "io.readiness-epoll",
            "io.readiness",
            "system.load-average",
            "system.name-observation",
            "system.identity-info",
            "memory.mapping-remap",
            "memory.mapping-locking",
            "memory.mapping-sync",
            "memory.advice",
            "memory.residency",
            "filesystem.access-advice",
            "filesystem.readahead",
            "filesystem.memory-file",
            "filesystem.seal-observation",
            "filesystem.seal-mutation",
            "filesystem.cwd",
            "filesystem.path-metadata",
            "filesystem.fd-timestamps",
            "filesystem.directory-relative-timestamps",
            "filesystem.cwd-timestamps",
            "filesystem.symlink-timestamps",
            "filesystem.second-resolution-timestamps",
            "io.file-position",
            "filesystem.global-sync",
            "io.syncfs",
            "io.range-sync",
            "io.status-flags",
            "io.advisory-flock",
            "filesystem.descriptor-transfer",
            "filesystem.descriptor-range-copy",
            "process.fcntl-lock-observation",
            "process.scheduling-priority",
            "process.scheduling-priority-mutation",
            "process.scheduler-priority-bounds",
            "time.realtime-millis",
            "time.timespec-get",
            "time.process-cpu-observation",
            "time.process-accounting",
            "time.interval-timer-query",
            "time.timerfd",
            "time.relative-sleep",
            "time.sleep-aliases",
            "time.clock-sleep",
        ):
            self.assertIn(capability, direct["capabilities"])
            self.assertNotIn(capability, remaining["capabilities"])
        self.assertIn("crabc-rs/tests/futex.rs", direct["source_owners"])
        self.assertIn("crabc-core/src/thread.rs", direct["source_owners"])
        self.assertIn("crabc-core/src/io.rs", direct["source_owners"])
        for source_owner in (
            "crabc-rs/tests/x86_64_posix_fallocate.rs",
            "crabc-rs/tests/x86_64_fallocate.rs",
            "crabc-rs/tests/x86_64_ftruncate.rs",
            "crabc-rs/tests/x86_64_futimens.rs",
            "crabc-rs/tests/x86_64_timestamp_paths.rs",
            "crabc-rs/tests/x86_64_fcntl_flags.rs",
            "crabc-rs/tests/x86_64_flock.rs",
            "crabc-rs/tests/x86_64_sendfile.rs",
            "crabc-rs/tests/x86_64_copy_file_range.rs",
            "crabc-rs/tests/x86_64_epoll.rs",
            "crabc-rs/tests/x86_64_pselect.rs",
            "crabc-rs/tests/x86_64_file_position.rs",
            "crabc-rs/tests/x86_64_sync.rs",
            "crabc-rs/tests/x86_64_syncfs.rs",
            "crabc-rs/tests/x86_64_sync_file_range.rs",
            "crabc-rs/tests/x86_64_memfd.rs",
            "crabc-rs/tests/x86_64_thread_credentials.rs",
            "crabc-rs/tests/x86_64_fs_credentials.rs",
            "crabc-rs/tests/x86_64_getgroups.rs",
            "crabc-rs/tests/x86_64_getitimer.rs",
            "crabc-rs/tests/x86_64_timerfd.rs",
            "crabc-rs/tests/x86_64_getcwd.rs",
            "crabc-rs/tests/x86_64_current_dir_name.rs",
            "crabc-rs/tests/x86_64_clock_nanosleep.rs",
            "crabc-rs/tests/x86_64_sched_rr_interval.rs",
            "crabc-rs/tests/x86_64_sched_affinity.rs",
            "crabc-rs/tests/x86_64_sched_setaffinity.rs",
            "crabc-rs/tests/x86_64_setpriority.rs",
            "crabc-rs/tests/x86_64_rlimit.rs",
            "crabc-rs/tests/x86_64_rlimit_targeted.rs",
            "crabc-rs/tests/x86_64_setrlimit.rs",
            "crabc-rs/tests/x86_64_umask.rs",
            "compat/x86_64/run_x86_ftruncate_reference.sh",
            "compat/x86_64/x86_ftruncate_reference_probe.c",
            "compat/x86_64/run_x86_timestamp_reference.sh",
            "compat/x86_64/x86_timestamp_reference_probe.c",
            "compat/x86_64/run_x86_posix_fallocate_reference.sh",
            "compat/x86_64/x86_posix_fallocate_reference_probe.c",
            "compat/x86_64/run_x86_fallocate_reference.sh",
            "compat/x86_64/x86_fallocate_reference_probe.c",
            "compat/x86_64/run_x86_fcntl_status_reference.sh",
            "compat/x86_64/x86_fcntl_status_reference_probe.c",
            "compat/x86_64/run_x86_flock_reference.sh",
            "compat/x86_64/x86_flock_reference_probe.c",
            "compat/x86_64/run_x86_sendfile_reference.sh",
            "compat/x86_64/x86_sendfile_reference_probe.c",
            "compat/x86_64/run_x86_copy_file_range_reference.sh",
            "compat/x86_64/x86_copy_file_range_reference_probe.c",
            "compat/x86_64/run_x86_epoll_reference.sh",
            "compat/x86_64/x86_epoll_reference_probe.c",
            "compat/x86_64/run_x86_pselect_reference.sh",
            "compat/x86_64/x86_pselect_reference_probe.c",
            "compat/x86_64/run_x86_memfd_reference.sh",
            "compat/x86_64/x86_memfd_reference_probe.c",
            "compat/x86_64/run_x86_file_position_reference.sh",
            "compat/x86_64/x86_file_position_reference_probe.c",
            "compat/x86_64/run_x86_sync_reference.sh",
            "compat/x86_64/x86_sync_reference_probe.c",
            "compat/x86_64/run_x86_syncfs_reference.sh",
            "compat/x86_64/x86_syncfs_reference_probe.c",
            "compat/x86_64/run_x86_sync_file_range_reference.sh",
            "compat/x86_64/x86_sync_file_range_reference_probe.c",
            "compat/x86_64/run_x86_thread_credentials_reference.sh",
            "compat/x86_64/x86_thread_credentials_reference_probe.c",
            "compat/x86_64/run_x86_fs_credentials_reference.sh",
            "compat/x86_64/x86_fs_credentials_reference_probe.c",
            "compat/x86_64/run_x86_getgroups_reference.sh",
            "compat/x86_64/x86_getgroups_reference_probe.c",
            "compat/x86_64/run_x86_getitimer_reference.sh",
            "compat/x86_64/x86_getitimer_reference_probe.c",
            "compat/x86_64/run_x86_timerfd_reference.sh",
            "compat/x86_64/x86_timerfd_reference_probe.c",
            "compat/x86_64/run_x86_getcwd_reference.sh",
            "compat/x86_64/x86_getcwd_reference_probe.c",
            "compat/x86_64/run_x86_clock_nanosleep_reference.sh",
            "compat/x86_64/x86_clock_nanosleep_reference_probe.c",
            "compat/x86_64/run_x86_sched_rr_interval_reference.sh",
            "compat/x86_64/x86_sched_rr_interval_reference_probe.c",
            "compat/x86_64/run_x86_sched_affinity_reference.sh",
            "compat/x86_64/x86_sched_affinity_reference_probe.c",
            "compat/x86_64/run_x86_sched_setaffinity_reference.sh",
            "compat/x86_64/x86_sched_setaffinity_reference_probe.c",
            "compat/x86_64/run_x86_setpriority_reference.sh",
            "compat/x86_64/x86_setpriority_reference_probe.c",
            "compat/x86_64/run_x86_rlimit_reference.sh",
            "compat/x86_64/x86_rlimit_reference_probe.c",
            "compat/x86_64/run_x86_rlimit_targeted_reference.sh",
            "compat/x86_64/x86_rlimit_targeted_reference_probe.c",
            "crabc-rs/tests/x86_64_rusage.rs",
            "compat/x86_64/run_x86_rusage_reference.sh",
            "compat/x86_64/x86_rusage_reference_probe.c",
            "compat/x86_64/run_x86_setrlimit_reference.sh",
            "compat/x86_64/x86_setrlimit_reference_probe.c",
            "compat/x86_64/run_x86_umask_reference.sh",
            "compat/x86_64/x86_umask_reference_probe.c",
            "crabc-rs/tests/x86_64_times.rs",
            "compat/x86_64/run_x86_times_reference.sh",
            "compat/x86_64/x86_times_reference_probe.c",
        ):
            self.assertIn(source_owner, direct["source_owners"])
        direct_commands = {
            evidence["command"] for evidence in direct["native_evidence"]
        }
        facade_evidence = next(
            evidence
            for evidence in direct["native_evidence"]
            if evidence["command"] == "./scripts/dev-x86_64.sh facade"
        )
        self.assertIn("timestamp-mutation family", facade_evidence["scope"])
        self.assertIn(
            "fs::{Timespec, Timestamps, UTIME_NOW, UTIME_OMIT, futimens}",
            facade_evidence["scope"],
        )
        self.assertIn("filesystem.path-core", facade_evidence["scope"])
        self.assertIn(
            "./scripts/dev-x86_64.sh posix-fallocate-reference", direct_commands
        )
        self.assertIn("./scripts/dev-x86_64.sh fallocate-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh ftruncate-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh timestamp-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh memfd-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh file-position-reference", direct_commands
        )
        self.assertIn("./scripts/dev-x86_64.sh sync-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh syncfs-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh sync-file-range-reference", direct_commands
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sync=162")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct syncfs=306")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sync_file_range=277")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct posix_fallocate=285")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct fallocate=285")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct timestamp mutation through utimensat=280")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh thread-credentials-reference",
            direct_commands,
        )
        self.assertIn(
            "./scripts/dev-x86_64.sh fs-credentials-reference",
            direct_commands,
        )
        self.assertIn("./scripts/dev-x86_64.sh getgroups-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh getitimer-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh setitimer-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh timerfd-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh getcwd-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh access-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh fcntl-status-reference", direct_commands
        )
        self.assertIn("./scripts/dev-x86_64.sh flock-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh sendfile-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh copy-file-range-reference", direct_commands
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct flock=73")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sendfile=40")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct copy_file_range=326")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertIn("./scripts/dev-x86_64.sh clock-nanosleep-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh rr-interval-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh sched-affinity-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh sched-affinity-set-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh epoll-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh pselect-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh setpriority-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh rlimit-reference", direct_commands)
        self.assertIn(
            "./scripts/dev-x86_64.sh rlimit-targeted-reference", direct_commands
        )
        self.assertIn("./scripts/dev-x86_64.sh rusage-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh setrlimit-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh umask-reference", direct_commands)
        self.assertIn("./scripts/dev-x86_64.sh times-reference", direct_commands)
        self.assertEqual(remaining["status"], "foundation-verified")
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in remaining["native_evidence"])
        )
        self.assertEqual(
            {evidence["command"] for evidence in remaining["native_evidence"]},
            {"./scripts/dev-x86_64.sh facade-record-owning"},
        )
        verified_slices = remaining["verified_slice"]
        assert isinstance(verified_slices, list)
        self.assertEqual(len(verified_slices), 24)
        slices_by_id = {}
        for slice_entry in verified_slices:
            assert isinstance(slice_entry, dict)
            slices_by_id[slice_entry["id"]] = slice_entry
        self.assertEqual(
            set(slices_by_id),
            {
                "network.interface-device",
                "network.resolver-transport",
                "network.resolver",
                "network.netdb",
                "users.databases",
                "mount.basic",
                "filesystem.path-core",
                "filesystem.xattr",
                "filesystem.directory",
                "filesystem.temporary-objects",
                "filesystem.extended-metadata",
                "filesystem.cwd-canonicalize",
                "ipc.posix-mqueue",
                "ipc.posix-shm",
                "system.inotify",
                "time.civil-calendar",
                "time.advanced-clocks-posix-timers",
                "process.root-change",
                "process.child-ownership",
                "process.thread-kill",
                "memory.mapping",
                "memory.vm",
                "terminal.pty-basic",
                "terminal.session-control",
            },
        )
        family_capabilities = remaining["capabilities"]
        assert isinstance(family_capabilities, list)
        slice_capabilities = {
            capability
            for slice_entry in verified_slices
            for capability in slice_entry["capabilities"]
        }
        self.assertEqual(slice_capabilities, set(family_capabilities))
        root_change = slices_by_id["process.root-change"]
        self.assertEqual(root_change["capabilities"], ["process.root-change"])
        self.assertEqual(
            root_change["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh root-change-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in root_change["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/process.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/process_x86_64.rs",
            "crabc-rs/tests/x86_64_chroot.rs",
            "crabc-rs/examples/process_chroot_direct_probe.rs",
            "compat/x86_64/run_x86_root_change_reference.sh",
            "compat/x86_64/x86_root_change_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, root_change["source_owners"])
        self.assertTrue(
            any(
                "chroot=161" in prerequisite
                for prerequisite in root_change["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "CAP_SYS_CHROOT" in prerequisite and "without changing CWD" in prerequisite
                for prerequisite in root_change["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "pivot_root" in prerequisite
                and "mount or namespace control" in prerequisite
                and "confinement/security framework" in prerequisite
                for prerequisite in root_change["x86_header_prerequisites"]
            )
        )
        self.assertIn("process.root-change", remaining["capabilities"])
        child_ownership = slices_by_id["process.child-ownership"]
        self.assertEqual(child_ownership["capabilities"], ["process.child-ownership"])
        self.assertEqual(
            child_ownership["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh child-ownership-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in child_ownership["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/process.rs",
            "crabc-rs/src/process_x86_64.rs",
            "crabc-rs/tests/x86_64_child_ownership.rs",
            "compat/x86_64/run_x86_child_ownership_reference.sh",
            "compat/x86_64/x86_child_ownership_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, child_ownership["source_owners"])
        self.assertTrue(
            any(
                "clone=56" in prerequisite
                and "execve=59" in prerequisite
                and "wait4=61" in prerequisite
                for prerequisite in child_ownership["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "does not expose generic C fork/vfork/exec" in prerequisite
                and "pthread/atfork/cancellation" in prerequisite
                for prerequisite in child_ownership["x86_header_prerequisites"]
            )
        )
        self.assertIn("process.child-ownership", remaining["capabilities"])
        thread_kill = slices_by_id["process.thread-kill"]
        self.assertEqual(thread_kill["capabilities"], ["process.thread-kill"])
        self.assertEqual(
            thread_kill["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh thread-kill-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in thread_kill["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/process.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/signal.rs",
            "crabc-rs/tests/x86_64_thread_kill.rs",
            "crabc-rs/examples/thread_kill_direct_probe.rs",
            "compat/x86_64/run_x86_thread_kill_reference.sh",
            "compat/x86_64/x86_thread_kill_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, thread_kill["source_owners"])
        self.assertTrue(
            any(
                "tgkill=234" in prerequisite
                and "ESRCH" in prerequisite
                and "EINVAL" in prerequisite
                for prerequisite in thread_kill["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "SYS_tkill=200" in prerequisite
                and "SYS_gettid=186" in prerequisite
                and "pthread_kill uses SYS_tkill" in prerequisite
                for prerequisite in thread_kill["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "generic process/group signaling" in prerequisite
                and "signal masks" in prerequisite
                and "signalfd" in prerequisite
                and "pthread cancellation" in prerequisite
                for prerequisite in thread_kill["x86_header_prerequisites"]
            )
        )
        self.assertIn("process.thread-kill", remaining["capabilities"])
        memory_mapping = slices_by_id["memory.mapping"]
        self.assertEqual(memory_mapping["capabilities"], ["memory.mapping"])
        self.assertEqual(
            memory_mapping["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh mapping-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in memory_mapping["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/mm_x86_64.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/mm_x86_64.rs",
            "crabc-rs/tests/x86_64_memory_mapping.rs",
            "crabc-rs/examples/mapping_direct_probe.rs",
            "compat/x86_64/run_x86_mapping_reference.sh",
            "compat/x86_64/x86_mapping_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, memory_mapping["source_owners"])
        self.assertTrue(
            any(
                "mmap=9" in prerequisite
                and "mprotect=10" in prerequisite
                and "munmap=11" in prerequisite
                for prerequisite in memory_mapping["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "MAP_FIXED=0x10" in prerequisite
                and "MAP_32BIT=0x40" in prerequisite
                and "MAP_ANONYMOUS=0x20" in prerequisite
                for prerequisite in memory_mapping["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "pointer-provenance" in prerequisite
                and "no references survive munmap" in prerequisite
                for prerequisite in memory_mapping["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "only raw SYS_mprotect" in prerequisite
                and "musl 1.2.6 rounds" in prerequisite
                for prerequisite in memory_mapping["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "mremap" in prerequisite
                and "mapping locks/sync/advice/residency" in prerequisite
                and "separate memory.vm/brk/process-wide-lock/legacy-remap boundary" in prerequisite
                and "C mmap/mprotect/munmap API/header/ABI" in prerequisite
                for prerequisite in memory_mapping["x86_header_prerequisites"]
            )
        )
        self.assertIn("memory.mapping", remaining["capabilities"])
        memory_vm = slices_by_id["memory.vm"]
        self.assertEqual(memory_vm["capabilities"], ["memory.vm"])
        self.assertEqual(
            memory_vm["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh memory-vm-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in memory_vm["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/mm_x86_64.rs",
            "crabc-core/src/process.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/mm_x86_64.rs",
            "crabc-rs/src/process_x86_64.rs",
            "crabc-rs/tests/x86_64_memory_vm.rs",
            "crabc-rs/examples/memory_vm_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_memory_vm_reference.sh",
            "compat/x86_64/x86_memory_vm_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, memory_vm["source_owners"])
        self.assertTrue(
            any(
                "brk=12" in prerequisite
                and "mlockall=151" in prerequisite
                and "munlockall=152" in prerequisite
                and "remap_file_pages=216" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "MCL_CURRENT=1" in prerequisite
                and "MCL_FUTURE=2" in prerequisite
                and "MCL_ONFAULT=4" in prerequisite
                and "RLIMIT_MEMLOCK" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "queries with a null pointer" in prerequisite
                and "replays that exact returned pointer only" in prerequisite
                and "never asks Linux to move the break" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "musl 1.2.6 sbrk(0)" in prerequisite
                and "musl brk(current) deliberately returns ENOMEM" in prerequisite
                and "raw break remains unchanged" in prerequisite
                and "not selected Rust behavior" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "anonymous one-page mapping" in prerequisite
                and "direct EINVAL" in prerequisite
                and "file-backed remapping behavior" in prerequisite
                for prerequisite in memory_vm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "C brk/sbrk/mlockall/munlockall/remap_file_pages" in prerequisite
                and "allocator, heap, program-break adjustment" in prerequisite
                and "mremap or fixed maps" in prerequisite
                and "range locks, sync, advice, or residency" in prerequisite
                and "public x86 support" in prerequisite
                for prerequisite in memory_vm["x86_header_prerequisites"]
            )
        )
        self.assertIn("memory.vm", remaining["capabilities"])
        pty_basic = slices_by_id["terminal.pty-basic"]
        self.assertEqual(pty_basic["capabilities"], ["terminal.pty-basic"])
        self.assertEqual(
            pty_basic["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh pty-basic-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in pty_basic["native_evidence"])
        )
        self.assertIn(
            "musl grantpt's no-op success",
            pty_basic["native_evidence"][0]["scope"],
        )
        for source_owner in (
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-core/src/io.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/src/pty_x86_64.rs",
            "crabc-rs/tests/x86_64_pty_basic.rs",
            "crabc-rs/examples/pty_basic_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_pty_basic_reference.sh",
            "compat/x86_64/x86_pty_basic_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, pty_basic["source_owners"])
        self.assertTrue(
            any(
                "openat=257" in prerequisite
                and "ioctl=16" in prerequisite
                and "TIOCGPTN=0x80045430" in prerequisite
                and "TIOCSPTLCK=0x40045431" in prerequisite
                and "TIOCGPTPEER=0x5441" in prerequisite
                for prerequisite in pty_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "PtyPair::open requires RDWR" in prerequisite
                and "explicit O_NOCTTY request" in prerequisite
                and "controlling-terminal or session transition" in prerequisite
                for prerequisite in pty_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "ptsname_into" in prerequisite
                and "short caller storage" in prerequisite
                and "RANGE" in prerequisite
                and "C static buffer" in prerequisite
                for prerequisite in pty_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "openpty" in prerequisite
                and "ioctl_tiocgptpeer" in prerequisite
                and "TIOCSCTTY/setsid/process-session" in prerequisite
                and "termios/tty API" in prerequisite
                and "public x86 support" in prerequisite
                for prerequisite in pty_basic["x86_header_prerequisites"]
            )
        )
        terminal_session_control = slices_by_id["terminal.session-control"]
        self.assertEqual(
            terminal_session_control["capabilities"],
            [
                "terminal.pty-session",
                "terminal.termios-control",
                "terminal.termios-queue",
                "terminal.exclusive-mode",
                "terminal.special-codes",
                "terminal.tty-path",
                "terminal.tty-basic",
            ],
        )
        self.assertEqual(
            terminal_session_control["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh terminal-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in terminal_session_control["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/io.rs",
            "crabc-core/src/process.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/pty_x86_64.rs",
            "crabc-rs/src/termios_x86_64.rs",
            "crabc-rs/tests/x86_64_terminal.rs",
            "crabc-rs/examples/x86_64_terminal_direct_probe.rs",
            "compat/x86_64/run_x86_terminal_reference.sh",
            "compat/x86_64/x86_terminal_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, terminal_session_control["source_owners"])
        self.assertTrue(
            any(
                "36-byte align-4" in prerequisite
                and "60-byte align-4" in prerequisite
                and "NCCS=32" in prerequisite
                for prerequisite in terminal_session_control["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "TIOCSCTTY=0x540e" in prerequisite
                and "TIOCGSID=0x5429" in prerequisite
                and "winsize" in prerequisite
                for prerequisite in terminal_session_control["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "C terminal header/API/ABI" in prerequisite
                and "generic ioctl" in prerequisite
                and "openpty/forkpty/login_tty/vhangup" in prerequisite
                and "public x86 support" in prerequisite
                for prerequisite in terminal_session_control["x86_header_prerequisites"]
            )
        )
        verified_terminal_capabilities = {
            capability
            for slice_entry in slices_by_id.values()
            for capability in slice_entry["capabilities"]
            if capability.startswith("terminal.")
        }
        self.assertEqual(
            verified_terminal_capabilities,
            {
                "terminal.pty-basic",
                "terminal.pty-session",
                "terminal.termios-control",
                "terminal.termios-queue",
                "terminal.exclusive-mode",
                "terminal.special-codes",
                "terminal.tty-path",
                "terminal.tty-basic",
            },
        )
        for capability in (
            "terminal.pty-session",
            "terminal.termios-control",
            "terminal.termios-queue",
            "terminal.exclusive-mode",
            "terminal.special-codes",
            "terminal.tty-path",
            "terminal.tty-basic",
        ):
            self.assertIn(capability, remaining["capabilities"])
            self.assertIn(capability, verified_terminal_capabilities)
        interface_device = slices_by_id["network.interface-device"]
        self.assertEqual(interface_device["id"], "network.interface-device")
        self.assertEqual(
            interface_device["capabilities"],
            [
                "network.interface-addresses",
                "network.interface-index",
                "network.interface-name",
                "network.interface-enumeration",
            ],
        )
        self.assertEqual(
            interface_device["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh interface-device-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in interface_device["native_evidence"])
        )
        for source_owner in (
            "crabc-rs/src/netdevice.rs",
            "crabc-rs/tests/x86_64_interface_device.rs",
            "compat/x86_64/run_x86_interface_device_reference.sh",
            "compat/x86_64/x86_interface_device_reference_probe.c",
        ):
            self.assertIn(source_owner, interface_device["source_owners"])
        resolver_transport = slices_by_id["network.resolver-transport"]
        self.assertEqual(
            resolver_transport["capabilities"], ["network.resolver-transport"]
        )
        self.assertEqual(
            resolver_transport["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh resolver-transport-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in resolver_transport["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/resolver.rs",
            "crabc-core/tests/x86_64_resolver_transport.rs",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, resolver_transport["source_owners"])
        resolver = slices_by_id["network.resolver"]
        self.assertEqual(resolver["capabilities"], ["network.resolver"])
        self.assertEqual(
            resolver["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh resolver-facade-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in resolver["native_evidence"])
        )
        for source_owner in (
            "crabc-rs/src/resolver.rs",
            "crabc-rs/src/netdb.rs",
            "crabc-rs/tests/x86_64_resolver.rs",
            "crabc-rs/examples/resolver_hosts_direct_probe.rs",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, resolver["source_owners"])
        self.assertNotIn("network.netdb", resolver["capabilities"])
        netdb = slices_by_id["network.netdb"]
        self.assertEqual(netdb["capabilities"], ["network.netdb"])
        self.assertEqual(
            netdb["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh netdb-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in netdb["native_evidence"])
        )
        for source_owner in (
            "crabc-rs/src/netdb.rs",
            "crabc-rs/tests/x86_64_netdb.rs",
            "crabc-rs/examples/resolver_direct_probe.rs",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, netdb["source_owners"])
        users_databases = slices_by_id["users.databases"]
        self.assertEqual(users_databases["capabilities"], ["users.databases"])
        self.assertEqual(
            users_databases["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh users-databases-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in users_databases["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/io.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/src/users.rs",
            "crabc-rs/tests/x86_64_users_databases.rs",
            "crabc-rs/examples/users_databases_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_users_databases_reference.sh",
            "compat/x86_64/x86_users_databases_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, users_databases["source_owners"])
        self.assertTrue(
            any(
                "openat=257" in prerequisite
                and "read=0" in prerequisite
                and "close=3" in prerequisite
                and "O_CLOEXEC=0x00080000" in prerequisite
                for prerequisite in users_databases["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "one mebibyte" in prerequisite
                and "not an atomic multi-file transaction" in prerequisite
                for prerequisite in users_databases["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "exactly seven colon fields" in prerequisite
                and "exactly four colon fields" in prerequisite
                and "first-match only" in prerequisite
                for prerequisite in users_databases["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "getpwnam" in prerequisite
                and "getgrnam" in prerequisite
                and "shadow" in prerequisite
                and "utmp/utmpx" in prerequisite
                and "initgroups" in prerequisite
                and "process-global enumeration state" in prerequisite
                and "NSS/provider framework" in prerequisite
                for prerequisite in users_databases["x86_header_prerequisites"]
            )
        )
        self.assertIn("users.databases", remaining["capabilities"])
        mount_basic = slices_by_id["mount.basic"]
        self.assertEqual(mount_basic["capabilities"], ["mount.basic"])
        self.assertEqual(
            mount_basic["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh mount-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in mount_basic["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/mount.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/mount_x86_64.rs",
            "crabc-rs/tests/x86_64_mount.rs",
            "crabc-rs/examples/mount_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_mount_reference.sh",
            "compat/x86_64/x86_mount_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, mount_basic["source_owners"])
        self.assertTrue(
            any(
                "mount=165" in prerequisite
                and "umount2=166" in prerequisite
                and "rdi/rsi/rdx" in prerequisite
                and "r10" in prerequisite
                and "r8" in prerequisite
                for prerequisite in mount_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "unique nonexistent targets" in prerequisite
                and "interior-NUL" in prerequisite
                and "non-mutating" in prerequisite
                and "EPERM" in prerequisite
                and "ENOENT" in prerequisite
                for prerequisite in mount_basic["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "null source/type" in prerequisite
                and "pivot_root" in prerequisite
                and "unshare" in prerequisite
                and "setns" in prerequisite
                and "fsopen" in prerequisite
                and "public x86 support" in prerequisite
                for prerequisite in mount_basic["x86_header_prerequisites"]
            )
        )
        self.assertIn("mount.basic", remaining["capabilities"])
        path_core = slices_by_id["filesystem.path-core"]
        self.assertEqual(path_core["capabilities"], ["filesystem.path-core"])
        self.assertEqual(
            path_core["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh path-core-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in path_core["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_path_lifecycle.rs",
            "crabc-rs/tests/x86_64_namespace.rs",
            "crabc-rs/tests/x86_64_readlink.rs",
            "crabc-rs/examples/path_core_owned_direct_probe.rs",
            "compat/x86_64/run_x86_path_lifecycle_reference.sh",
            "compat/x86_64/run_x86_readlinkat_reference.sh",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, path_core["source_owners"])
        xattr = slices_by_id["filesystem.xattr"]
        self.assertEqual(xattr["capabilities"], ["filesystem.xattr"])
        self.assertEqual(
            xattr["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh xattr-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in xattr["native_evidence"])
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_xattr.rs",
            "crabc-rs/examples/xattr_direct_probe.rs",
            "compat/x86_64/run_x86_xattr_reference.sh",
            "compat/x86_64/x86_xattr_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, xattr["source_owners"])
        directory = slices_by_id["filesystem.directory"]
        self.assertEqual(
            directory["capabilities"],
            [
                "filesystem.directory-stream",
                "filesystem.directory-position",
                "filesystem.raw-directory",
            ],
        )
        self.assertEqual(
            directory["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh directory-reference",
        )
        self.assertTrue(
            all(evidence["state"] == "verified" for evidence in directory["native_evidence"])
        )
        for source_owner in (
            "crabc-rs/src/raw_dir.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_raw_directory.rs",
            "crabc-rs/tests/x86_64_directory.rs",
            "crabc-rs/tests/x86_64_directory_position.rs",
            "crabc-rs/examples/directory_direct_probe.rs",
            "crabc-rs/examples/directory_position_direct_probe.rs",
            "compat/x86_64/run_x86_directory_reference.sh",
            "compat/x86_64/x86_directory_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, directory["source_owners"])
        temporary_objects = slices_by_id["filesystem.temporary-objects"]
        self.assertEqual(
            temporary_objects["capabilities"],
            [
                "filesystem.named-temporary-file",
                "filesystem.anonymous-temporary-file",
                "filesystem.temporary-directory",
            ],
        )
        self.assertEqual(
            temporary_objects["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh temporary-object-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in temporary_objects["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_temporary_objects.rs",
            "crabc-rs/examples/fs_named_tempfile_direct_probe.rs",
            "crabc-rs/examples/fs_tempfile_direct_probe.rs",
            "crabc-rs/examples/fs_tempdir_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_temporary_object_reference.sh",
            "compat/x86_64/x86_temporary_object_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, temporary_objects["source_owners"])
        self.assertTrue(
            any(
                "O_TMPFILE=0x00410000" in prerequisite
                for prerequisite in temporary_objects["x86_abi_prerequisites"]
            )
        )
        extended_metadata = slices_by_id["filesystem.extended-metadata"]
        self.assertEqual(
            extended_metadata["capabilities"], ["filesystem.extended-metadata"]
        )
        self.assertEqual(
            extended_metadata["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh statx-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in extended_metadata["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/tests/x86_64_statx.rs",
            "crabc-rs/examples/statx_direct_probe.rs",
            "compat/x86_64/run_x86_statx_reference.sh",
            "compat/x86_64/x86_statx_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, extended_metadata["source_owners"])
        self.assertTrue(
            any(
                "SYS_statx=332" in prerequisite
                for prerequisite in extended_metadata["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "256-byte align-8" in prerequisite
                for prerequisite in extended_metadata["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "AT_EMPTY_PATH" in prerequisite
                for prerequisite in extended_metadata["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "ENOSYS" in prerequisite and "musl's fstatat fallback" in prerequisite
                for prerequisite in extended_metadata["x86_abi_prerequisites"]
            )
        )
        cwd_canonicalize = slices_by_id["filesystem.cwd-canonicalize"]
        self.assertEqual(
            cwd_canonicalize["capabilities"],
            ["filesystem.canonicalize", "filesystem.cwd-mutation"],
        )
        self.assertEqual(
            cwd_canonicalize["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh cwd-canonicalize-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in cwd_canonicalize["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-core/src/fs.rs",
            "crabc-core/src/process.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/fs_x86_64.rs",
            "crabc-rs/src/process_x86_64.rs",
            "crabc-rs/tests/x86_64_canonicalize.rs",
            "crabc-rs/tests/x86_64_cwd_mutation.rs",
            "crabc-rs/examples/fs_canonicalize_direct_probe.rs",
            "crabc-rs/examples/process_cwd_direct_probe.rs",
            "compat/x86_64/run_x86_cwd_canonicalize_reference.sh",
            "compat/x86_64/x86_cwd_canonicalize_reference_probe.c",
            "scripts/dev-x86_64.sh",
        ):
            self.assertIn(source_owner, cwd_canonicalize["source_owners"])
        self.assertTrue(
            any(
                "getcwd=79" in prerequisite
                and "chdir=80" in prerequisite
                and "fchdir=81" in prerequisite
                for prerequisite in cwd_canonicalize["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "PATH_MAX=4096" in prerequisite and "forty" in prerequisite
                for prerequisite in cwd_canonicalize["x86_abi_prerequisites"]
            )
        )
        self.assertNotIn("process.root-change", cwd_canonicalize["capabilities"])
        self.assertIn("process.root-change", remaining["capabilities"])
        ipc_mqueue = slices_by_id["ipc.posix-mqueue"]
        self.assertEqual(ipc_mqueue["capabilities"], ["ipc"])
        self.assertEqual(
            ipc_mqueue["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh ipc-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in ipc_mqueue["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/ipc.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/ipc.rs",
            "crabc-rs/tests/x86_64_ipc.rs",
            "crabc-rs/examples/ipc_direct_probe.rs",
            "compat/x86_64/run_x86_mqueue_reference.sh",
            "compat/x86_64/x86_mqueue_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, ipc_mqueue["source_owners"])
        self.assertTrue(
            any(
                "mq_open=240" in prerequisite
                and "mq_unlink=241" in prerequisite
                and "mq_timedsend=242" in prerequisite
                and "mq_timedreceive=243" in prerequisite
                and "mq_getsetattr=245" in prerequisite
                for prerequisite in ipc_mqueue["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "mqd_t" in prerequisite
                and "64-byte align-8" in prerequisite
                and "16-byte align-8" in prerequisite
                for prerequisite in ipc_mqueue["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C mq API/header" in prerequisite
                for prerequisite in ipc_mqueue["x86_header_prerequisites"]
            )
        )
        self.assertNotIn("ipc.posix-shm", ipc_mqueue["capabilities"])
        self.assertIn("ipc", remaining["capabilities"])
        self.assertIn("ipc.posix-shm", remaining["capabilities"])
        ipc_shm = slices_by_id["ipc.posix-shm"]
        self.assertEqual(ipc_shm["capabilities"], ["ipc.posix-shm"])
        self.assertEqual(
            ipc_shm["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh shm-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in ipc_shm["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/fs.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/shm.rs",
            "crabc-rs/tests/x86_64_shm.rs",
            "crabc-rs/examples/shm_direct_probe.rs",
            "compat/x86_64/run_x86_shm_reference.sh",
            "compat/x86_64/x86_shm_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, ipc_shm["source_owners"])
        self.assertTrue(
            any(
                "openat=257" in prerequisite
                and "unlinkat=263" in prerequisite
                and "rdi/rsi/rdx/r10" in prerequisite
                for prerequisite in ipc_shm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "NAME_MAX=255" in prerequisite
                and "265-byte" in prerequisite
                and "/dev/shm/<name>" in prerequisite
                for prerequisite in ipc_shm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "O_CLOEXEC" in prerequisite
                and "O_NOFOLLOW" in prerequisite
                and "O_NONBLOCK" in prerequisite
                and "no raw/musl flag equivalence is claimed" in prerequisite
                for prerequisite in ipc_shm["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C shared-memory API/header/ABI" in prerequisite
                and "cancellation mechanics" in prerequisite
                and "mount policy/fallback" in prerequisite
                for prerequisite in ipc_shm["x86_header_prerequisites"]
            )
        )
        self.assertIn("ipc.posix-shm", remaining["capabilities"])
        self.assertNotIn("ipc.posix-shm", direct["capabilities"])
        system_inotify = slices_by_id["system.inotify"]
        self.assertEqual(system_inotify["capabilities"], ["system.inotify"])
        self.assertEqual(
            system_inotify["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh inotify-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in system_inotify["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/inotify.rs",
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-rs/src/lib.rs",
            "crabc-rs/src/system_x86_64.rs",
            "crabc-rs/tests/x86_64_inotify.rs",
            "crabc-rs/examples/inotify_direct_probe.rs",
            "crabc-rs/Cargo.toml",
            "compat/x86_64/run_x86_inotify_reference.sh",
            "compat/x86_64/x86_inotify_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, system_inotify["source_owners"])
        self.assertTrue(
            any(
                "inotify_init1=294" in prerequisite
                and "inotify_add_watch=254" in prerequisite
                and "inotify_rm_watch=255" in prerequisite
                for prerequisite in system_inotify["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "16-byte align-4" in prerequisite
                and "wd i32 at 0" in prerequisite
                and "mask u32 at 4" in prerequisite
                and "cookie u32 at 8" in prerequisite
                and "len u32 at 12" in prerequisite
                and "name at 16" in prerequisite
                for prerequisite in system_inotify["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C inotify API/header/ABI" in prerequisite
                and "legacy inotify_init" in prerequisite
                for prerequisite in system_inotify["x86_header_prerequisites"]
            )
        )
        self.assertIn("system.inotify", remaining["capabilities"])
        self.assertNotIn("system.inotify", direct["capabilities"])
        civil_calendar = slices_by_id["time.civil-calendar"]
        self.assertEqual(
            civil_calendar["capabilities"],
            [
                "time.wall-clock",
                "time.calendar-utc",
                "time.timezone-rules",
                "time.local-calendar",
            ],
        )
        self.assertEqual(
            civil_calendar["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh calendar-time-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in civil_calendar["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/time_x86_64.rs",
            "crabc-core/src/tests.rs",
            "crabc-rs/src/civil_time.rs",
            "crabc-rs/UPSTREAM.md",
            "crabc-rs/src/time_x86_64.rs",
            "crabc-rs/src/timezone.rs",
            "crabc-rs/tests/x86_64_calendar_time.rs",
            "crabc-rs/tests/time.rs",
            "crabc-rs/tests/calendar_utc.rs",
            "crabc-rs/tests/calendar_local.rs",
            "crabc-rs/tests/timezone_rules.rs",
            "crabc-rs/examples/time_direct_probe.rs",
            "crabc-rs/examples/calendar_utc_direct_probe.rs",
            "crabc-rs/examples/calendar_local_direct_probe.rs",
            "compat/x86_64/run_x86_calendar_time_reference.sh",
            "compat/x86_64/x86_calendar_time_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, civil_calendar["source_owners"])
        self.assertTrue(
            any(
                "gettimeofday=96" in prerequisite
                and "16-byte align-8 timeval" in prerequisite
                and "tv_sec" in prerequisite
                and "tv_usec" in prerequisite
                for prerequisite in civil_calendar["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "TZif v1/v2/v3" in prerequisite
                and "neither reads TZ nor loads system zoneinfo" in prerequisite
                for prerequisite in civil_calendar["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "one-way" in prerequisite
                and "no inverse local-to-instant conversion" in prerequisite
                for prerequisite in civil_calendar["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C time API/header/ABI" in prerequisite
                and "libc timezone globals" in prerequisite
                and "inverse mktime-style local conversion" in prerequisite
                for prerequisite in civil_calendar["x86_header_prerequisites"]
            )
        )
        self.assertNotIn("time.clock-query", civil_calendar["capabilities"])
        self.assertNotIn("time.clock-set", civil_calendar["capabilities"])
        self.assertNotIn("time.clock-process-id", civil_calendar["capabilities"])
        self.assertNotIn("time.posix-timers", civil_calendar["capabilities"])
        advanced_time = slices_by_id["time.advanced-clocks-posix-timers"]
        self.assertEqual(
            advanced_time["capabilities"],
            [
                "time.clock-query",
                "time.clock-process-id",
                "time.clock-set",
                "time.posix-timers",
            ],
        )
        self.assertEqual(
            advanced_time["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh advanced-time-reference",
        )
        self.assertTrue(
            all(
                evidence["state"] == "verified"
                for evidence in advanced_time["native_evidence"]
            )
        )
        for source_owner in (
            "crabc-core/src/syscall_x86_64.rs",
            "crabc-core/src/time_x86_64.rs",
            "crabc-core/src/tests.rs",
            "crabc-rs/src/time_x86_64.rs",
            "crabc-rs/tests/x86_64_advanced_time.rs",
            "crabc-rs/examples/time_dynamic_direct_probe.rs",
            "crabc-rs/examples/process_clock_id_direct_probe.rs",
            "crabc-rs/examples/time_settime_direct_probe.rs",
            "crabc-rs/examples/time_timers_direct_probe.rs",
            "compat/x86_64/run_x86_advanced_time_reference.sh",
            "compat/x86_64/x86_advanced_time_reference_probe.c",
            "scripts/dev-x86_64.sh",
            "scripts/check_structure.py",
        ):
            self.assertIn(source_owner, advanced_time["source_owners"])
        self.assertTrue(
            any(
                "clock_settime=227" in prerequisite
                and "clock_gettime=228" in prerequisite
                and "clock_getres=229" in prerequisite
                for prerequisite in advanced_time["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "timer_create=222" in prerequisite
                and "timer_settime=223" in prerequisite
                and "old-value pointer is passed in r10" in prerequisite
                for prerequisite in advanced_time["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "SIGEV_THREAD callback pointers" in prerequisite
                and "TIMER_ABSTIME=1" in prerequisite
                for prerequisite in advanced_time["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                "no x86 C time.h timer_t/sigevent/clock API" in prerequisite
                and "callback runtime" in prerequisite
                for prerequisite in advanced_time["x86_header_prerequisites"]
            )
        )
        self.assertNotIn("process.fs-credentials", remaining["capabilities"])
        self.assertNotIn("process.supplementary-groups", remaining["capabilities"])
        for capability in (
            "memory.vm",
            "memory.mapping",
            "time.wall-clock",
            "time.calendar-utc",
            "time.timezone-rules",
            "time.local-calendar",
            "time.clock-query",
            "time.clock-process-id",
            "time.clock-set",
            "time.posix-timers",
        ):
            self.assertNotIn(capability, direct["capabilities"])
            self.assertIn(capability, remaining["capabilities"])
        self.assertIn("time.process-interval-control", direct["capabilities"])
        self.assertNotIn("time.process-interval-control", remaining["capabilities"])
        self.assertIn("filesystem.posix-allocate-range", direct["capabilities"])
        self.assertNotIn("filesystem.posix-allocate-range", remaining["capabilities"])
        self.assertIn("filesystem.allocate-range", direct["capabilities"])
        self.assertNotIn("filesystem.allocate-range", remaining["capabilities"])
        for capability in (
            "filesystem.fd-timestamps",
            "filesystem.directory-relative-timestamps",
            "filesystem.cwd-timestamps",
            "filesystem.symlink-timestamps",
            "filesystem.second-resolution-timestamps",
        ):
            self.assertIn(capability, direct["capabilities"])
            self.assertNotIn(capability, remaining["capabilities"])
        self.assertNotIn(
            "crabc-rs/tests/x86_64_epoll.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_epoll_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_epoll_reference_probe.c", remaining["source_owners"]
        )
        for source_owner in (
            "crabc-rs/tests/x86_64_posix_fallocate.rs",
            "crabc-rs/tests/x86_64_fallocate.rs",
            "compat/x86_64/run_x86_posix_fallocate_reference.sh",
            "compat/x86_64/x86_posix_fallocate_reference_probe.c",
            "compat/x86_64/run_x86_fallocate_reference.sh",
            "compat/x86_64/x86_fallocate_reference_probe.c",
            "crabc-rs/tests/x86_64_futimens.rs",
            "crabc-rs/tests/x86_64_timestamp_paths.rs",
            "compat/x86_64/run_x86_timestamp_reference.sh",
            "compat/x86_64/x86_timestamp_reference_probe.c",
            "crabc-rs/tests/x86_64_flock.rs",
            "compat/x86_64/run_x86_flock_reference.sh",
            "compat/x86_64/x86_flock_reference_probe.c",
            "crabc-rs/tests/x86_64_sendfile.rs",
            "compat/x86_64/run_x86_sendfile_reference.sh",
            "compat/x86_64/x86_sendfile_reference_probe.c",
            "crabc-rs/tests/x86_64_copy_file_range.rs",
            "compat/x86_64/run_x86_copy_file_range_reference.sh",
            "compat/x86_64/x86_copy_file_range_reference_probe.c",
            "crabc-rs/tests/x86_64_sync.rs",
            "compat/x86_64/run_x86_sync_reference.sh",
            "compat/x86_64/x86_sync_reference_probe.c",
            "crabc-rs/tests/x86_64_syncfs.rs",
            "compat/x86_64/run_x86_syncfs_reference.sh",
            "compat/x86_64/x86_syncfs_reference_probe.c",
            "crabc-rs/tests/x86_64_sync_file_range.rs",
            "compat/x86_64/run_x86_sync_file_range_reference.sh",
            "compat/x86_64/x86_sync_file_range_reference_probe.c",
        ):
            self.assertNotIn(source_owner, remaining["source_owners"])
        self.assertIn("crabc-rs/tests/x86_64_timerfd.rs", direct["source_owners"])
        self.assertNotIn(
            "crabc-rs/tests/x86_64_timerfd.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_pselect.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_rlimit_targeted.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_rlimit_targeted_reference.sh",
            remaining["source_owners"],
        )
        self.assertNotIn(
            "compat/x86_64/x86_rlimit_targeted_reference_probe.c",
            remaining["source_owners"],
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_rusage.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_getgroups.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_getitimer.rs", remaining["source_owners"]
        )
        self.assertIn("crabc-rs/tests/x86_64_setitimer.rs", direct["source_owners"])
        self.assertNotIn(
            "crabc-rs/tests/x86_64_setitimer.rs", remaining["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_clock_nanosleep.rs", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/src/process_x86_64.rs", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_timerfd_reference.sh", direct["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_timerfd_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/x86_timerfd_reference_probe.c", direct["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_timerfd_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_pselect_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_pselect_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_rusage_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_getgroups_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_getitimer_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_setitimer_reference.sh", direct["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_setitimer_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/run_x86_clock_nanosleep_reference.sh",
            remaining["source_owners"],
        )
        self.assertNotIn(
            "compat/x86_64/x86_rusage_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_getgroups_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_getitimer_reference_probe.c", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/x86_setitimer_reference_probe.c", direct["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_setitimer_reference_probe.c", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_clock_nanosleep_reference_probe.c",
            remaining["source_owners"],
        )
        self.assertIn("compat/x86_64/x86_statat_reference_probe.c", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_getcwd.rs", remaining["source_owners"])
        self.assertNotIn(
            "compat/x86_64/run_x86_getcwd_reference.sh", remaining["source_owners"]
        )
        self.assertNotIn(
            "compat/x86_64/x86_getcwd_reference_probe.c", remaining["source_owners"]
        )
        self.assertIn("crabc-core/src/fs.rs", remaining["source_owners"])
        self.assertIn("crabc-rs/src/fs_x86_64.rs", remaining["source_owners"])
        self.assertIn("crabc-rs/tests/x86_64_readlink.rs", remaining["source_owners"])
        self.assertIn("compat/x86_64/run_x86_readlinkat_reference.sh", remaining["source_owners"])
        self.assertIn("compat/x86_64/x86_readlinkat_reference_probe.c", remaining["source_owners"])
        self.assertIn("crabc-core/src/io.rs", remaining["source_owners"])
        self.assertIn("crabc-core/src/syscall_x86_64.rs", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_memfd.rs", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/run_x86_memfd_reference.sh", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/x86_memfd_reference_probe.c", remaining["source_owners"])
        self.assertNotIn("crabc-core/src/thread.rs", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_sched_rr_interval.rs", remaining["source_owners"])
        self.assertNotIn("crabc-rs/src/thread_x86_64.rs", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/run_x86_sched_rr_interval_reference.sh", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/x86_sched_rr_interval_reference_probe.c", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_sched_affinity.rs", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/run_x86_sched_affinity_reference.sh", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/x86_sched_affinity_reference_probe.c", remaining["source_owners"])
        self.assertNotIn("crabc-rs/tests/x86_64_sched_setaffinity.rs", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/run_x86_sched_setaffinity_reference.sh", remaining["source_owners"])
        self.assertNotIn("compat/x86_64/x86_sched_setaffinity_reference_probe.c", remaining["source_owners"])
        self.assertEqual(len(remaining["native_evidence"]), 1)
        self.assertEqual(
            remaining["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh facade-record-owning",
        )
        self.assertIn(
            "exact twenty-four record-owning component runners",
            remaining["native_evidence"][0]["scope"],
        )
        self.assertNotIn("filesystem.path-core", direct["capabilities"])
        self.assertIn("filesystem.path-core", remaining["capabilities"])
        self.assertNotIn("filesystem.xattr", direct["capabilities"])
        self.assertIn("filesystem.xattr", remaining["capabilities"])
        for capability in (
            "filesystem.canonicalize",
            "filesystem.cwd-mutation",
            "process.root-change",
            "process.thread-kill",
        ):
            self.assertNotIn(capability, direct["capabilities"])
            self.assertIn(capability, remaining["capabilities"])
        for capability in (
            "filesystem.access-check",
            "filesystem.directory-relative-access-check",
            "filesystem.effective-access",
        ):
            self.assertIn(capability, direct["capabilities"])
            self.assertNotIn(capability, remaining["capabilities"])
        self.assertIn("filesystem.cwd", direct["capabilities"])
        self.assertNotIn("filesystem.cwd", remaining["capabilities"])
        self.assertIn("filesystem.path-metadata", direct["capabilities"])
        self.assertNotIn("filesystem.path-metadata", remaining["capabilities"])
        self.assertIn(
            "crabc-rs/tests/x86_64_current_dir_name.rs", direct["source_owners"]
        )
        self.assertNotIn(
            "crabc-rs/tests/x86_64_current_dir_name.rs", remaining["source_owners"]
        )
        self.assertEqual(remaining["status"], "foundation-verified")
        self.assertIn("thread.scheduler-rr-interval", direct["capabilities"])
        self.assertNotIn("thread.scheduler-rr-interval", remaining["capabilities"])
        self.assertIn("thread.cpu-affinity-observation", direct["capabilities"])
        self.assertNotIn("thread.cpu-affinity-observation", remaining["capabilities"])
        self.assertIn("thread.cpu-affinity-mutation", direct["capabilities"])
        self.assertNotIn("thread.cpu-affinity-mutation", remaining["capabilities"])
        self.assertIn("io.readiness-epoll", direct["capabilities"])
        self.assertNotIn("io.readiness-epoll", remaining["capabilities"])
        self.assertIn("io.readiness", direct["capabilities"])
        self.assertNotIn("io.readiness", remaining["capabilities"])
        self.assertNotIn("filesystem.access-advice", remaining["capabilities"])
        self.assertNotIn("process.scheduling-priority", remaining["capabilities"])
        self.assertNotIn("process.scheduling-priority-mutation", remaining["capabilities"])
        self.assertIn("process.resource-limits", direct["capabilities"])
        self.assertNotIn("process.resource-limits", remaining["capabilities"])
        self.assertNotIn("process.resource-limit-mutation", remaining["capabilities"])
        self.assertNotIn("process.umask", remaining["capabilities"])
        self.assertIn("process.resource-limits-targeted", direct["capabilities"])
        self.assertNotIn("process.resource-limits-targeted", remaining["capabilities"])
        self.assertIn("process.resource-usage", direct["capabilities"])
        self.assertNotIn("process.resource-usage", remaining["capabilities"])
        self.assertIn("time.process-accounting", direct["capabilities"])
        self.assertNotIn("time.process-accounting", remaining["capabilities"])
        self.assertIn("time.interval-timer-query", direct["capabilities"])
        self.assertNotIn("time.interval-timer-query", remaining["capabilities"])
        self.assertIn("time.clock-sleep", direct["capabilities"])
        self.assertNotIn("time.clock-sleep", remaining["capabilities"])
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct memfd_create=319")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private memory-file/seal")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 typed clock_nanosleep=230")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                "clock_nanosleep" in prerequisite
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sched_getaffinity=204")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct sched_setaffinity=203")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct io readiness")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct timerfd=283/286/287")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private timerfd slice")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private pselect slice")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct targeted getrlimit")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct getcwd=79")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct access/accessat: access=21")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        self.assertTrue(
            any(
                prerequisite.startswith("x86 direct fcntl status flags: fcntl=72")
                for prerequisite in direct["x86_abi_prerequisites"]
            )
        )
        getcwd_evidence = next(
            evidence
            for evidence in direct["native_evidence"]
            if evidence["command"] == "./scripts/dev-x86_64.sh getcwd-reference"
        )
        self.assertIn("get_current_dir_name", getcwd_evidence["scope"])
        self.assertIn("newfstatat=262", getcwd_evidence["scope"])
        self.assertIn("never reads PWD", getcwd_evidence["scope"])
        self.assertFalse(
            any(
                prerequisite.startswith("Private CPU-affinity observation")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private CPU-affinity mutation")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private epoll slice")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private targeted resource-limit-query")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertFalse(
            any(
                prerequisite.startswith("Private getcwd slice")
                for prerequisite in remaining["x86_abi_prerequisites"]
            )
        )
        self.assertIn("process.supplementary-groups", direct["capabilities"])
        self.assertNotIn("process.supplementary-groups", remaining["capabilities"])
        pthread_tls = self.family(data, "libc.pthread-tls")
        self.assertEqual(pthread_tls["status"], "planned")
        self.assertIn("libc/src/c_abi/x86_64/atomic.rs", pthread_tls["source_owners"])
        self.assertIn("libc/src/c_abi/x86_64/clone.rs", pthread_tls["source_owners"])
        self.assertEqual(
            pthread_tls["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-atomic",
        )
        self.assertEqual(
            pthread_tls["native_evidence"][1]["command"],
            "./scripts/dev-x86_64.sh libc-clone-raw",
        )

    def test_pthread_tls_artifacts_are_verified_without_promoting_pthread_parity(
        self,
    ) -> None:
        data = self.data()
        pthread_tls = self.family(data, "libc.pthread-tls")
        self.assertEqual(pthread_tls["status"], "planned")
        artifacts = pthread_tls["verified_artifact"]
        self.assertEqual(len(artifacts), 10)
        by_id = {artifact["id"]: artifact for artifact in artifacts}
        self.assertEqual(
            set(by_id),
            {
                "static-c-initial-tls-v1",
                "static-c-crt-initial-tls-handoff",
                "static-c-pthread-create-join-tls",
                "static-c-pthread-explicit-exit-tls",
                "static-c-pthread-identity",
                "static-c-c11-lifecycle",
                "static-c-pthread-c11-detach",
                "static-c-thrd-sleep",
                "static-c-pthread-normal-mutex",
                "static-c-pthread-cond-private",
            },
        )
        static_tls = by_id["static-c-initial-tls-v1"]
        crt_handoff = by_id["static-c-crt-initial-tls-handoff"]
        normal_return = by_id["static-c-pthread-create-join-tls"]
        explicit_exit = by_id["static-c-pthread-explicit-exit-tls"]
        identity = by_id["static-c-pthread-identity"]
        c11_lifecycle = by_id["static-c-c11-lifecycle"]
        detach = by_id["static-c-pthread-c11-detach"]
        thrd_sleep = by_id["static-c-thrd-sleep"]
        normal_mutex = by_id["static-c-pthread-normal-mutex"]
        private_condition = by_id["static-c-pthread-cond-private"]
        for artifact in artifacts:
            self.assertNotIn("capabilities", artifact)
        for artifact in (normal_return, explicit_exit):
            self.assertEqual(
                artifact["native_evidence"][0]["command"],
                "./scripts/dev-x86_64.sh libc-pthread-create-join-tls",
            )
        for owner in (
            "libc/src/c_abi/x86_64/pthread_create_join.rs",
            "libc/src/c_abi/x86_64/static_tls.rs",
            "compat/x86_64/libc_pthread_create_join_tls_probe.c",
            "compat/x86_64/libc_pthread_create_join_tls_start.S",
            "compat/x86_64/run_libc_pthread_create_join_tls.sh",
            "include/pthread.h",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, normal_return["source_owners"])
            self.assertIn(owner, explicit_exit["source_owners"])
        self.assertIn("null attributes pointer", normal_return["description"])
        self.assertIn("each concurrently live worker", normal_return["description"])
        self.assertIn("pthread_exit", explicit_exit["description"])
        self.assertIn("fixed private 64-slot registry", explicit_exit["description"])
        self.assertIn("Linux gettid", explicit_exit["description"])
        self.assertIn("still-live clear-child-tid word", explicit_exit["description"])
        self.assertIn("candidate-only capacity check", explicit_exit["description"])
        self.assertIn("65th pthread_create", explicit_exit["native_evidence"][0]["scope"])
        self.assertIn("thread.pthread-c11", explicit_exit["description"])
        self.assertIn("public x86 support", explicit_exit["description"])
        self.assertEqual(
            identity["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-pthread-identity",
        )
        for phrase in (
            "still-planned `libc.pthread-tls`",
            "weak same-address",
            "`pthread_self`/`thrd_current`",
            "`pthread_equal`/`thrd_equal`",
            "Variant-II `%fs:0`",
            "canonical one or zero",
            "true/false equality",
            "general pthread runtime",
            "thread.pthread-c11",
            "public x86 support",
        ):
            self.assertIn(phrase, identity["description"])
        for owner in (
            "libc/src/c_abi/x86_64/pthread_identity.rs",
            "libc/src/c_abi/x86_64/pthread_create_join.rs",
            "include/pthread.h",
            "include/threads.h",
            "compat/x86_64/libc_pthread_identity_probe.c",
            "compat/x86_64/libc_pthread_identity_start.S",
            "compat/x86_64/run_libc_pthread_identity.sh",
            "compat/x86_64/run_pthread_c11_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, identity["source_owners"])
        identity_abi = " ".join(identity["x86_abi_prerequisites"])
        for phrase in (
            "__get_tp",
            "__pthread_self",
            "weak function symbols",
            "canonical 0 or 1",
            "CLONE_SETTLS",
            "registry lock",
        ):
            self.assertIn(phrase, identity_abi)
        identity_scope = identity["native_evidence"][0]["scope"]
        for phrase in (
            "Pinned-musl project-header C reference",
            "weak",
            "one address",
            "exactly one for equal and zero for distinct",
            "two concurrently live normal workers",
            "selected explicit-exit worker",
            "parent errno preservation",
            "general pthread/C11-thread behavior",
            "public x86 support",
        ):
            self.assertIn(phrase, identity_scope)
        self.assertEqual(
            c11_lifecycle["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-c11-lifecycle",
        )
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
            self.assertIn(phrase, c11_lifecycle["description"])
        for owner in (
            "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs",
            "libc/src/c_abi/x86_64/pthread_create_join.rs",
            "libc/src/c_abi/x86_64/pthread_identity.rs",
            "include/limits.h",
            "include/pthread.h",
            "include/threads.h",
            "compat/x86_64/libc_c11_lifecycle_probe.c",
            "compat/x86_64/libc_c11_lifecycle_start.S",
            "compat/x86_64/run_libc_c11_lifecycle.sh",
            "compat/x86_64/run_pthread_c11_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, c11_lifecycle["source_owners"])
        c11_abi = " ".join(c11_lifecycle["x86_abi_prerequisites"])
        for phrase in (
            "thrd_create.c",
            "pthread_create.c::start_c11",
            "thrd_join.c",
            "thrd_exit.c",
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
            self.assertIn(phrase, c11_abi)
        c11_scope = c11_lifecycle["native_evidence"][0]["scope"]
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
            self.assertIn(phrase, c11_scope)
        self.assertEqual(
            detach["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-pthread-detach",
        )
        for phrase in (
            "still-planned `libc.pthread-tls`",
            "prompt `pthread_detach`/`thrd_detach`",
            "Joinable",
            "Detached",
            "CLONE_CHILD_CLEARTID",
            "Candidate-only",
            "not musl parity evidence",
            "detached-at-create attributes",
            "general pthread/C11 runtime",
            "thread.pthread-c11",
            "public x86 support",
        ):
            self.assertIn(phrase, detach["description"])
        for owner in (
            "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs",
            "libc/src/c_abi/x86_64/pthread_create_join.rs",
            "include/pthread.h",
            "include/threads.h",
            "compat/x86_64/libc_pthread_detach_probe.c",
            "compat/x86_64/libc_pthread_detach_start.S",
            "compat/x86_64/run_libc_pthread_detach.sh",
            "compat/x86_64/run_libc_static_tls_v1.sh",
            "compat/x86_64/run_libc_pthread_create_join_tls.sh",
            "compat/x86_64/run_libc_c11_lifecycle.sh",
            "compat/x86_64/run_pthread_c11_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, detach["source_owners"])
        detach_abi = " ".join(detach["x86_abi_prerequisites"])
        for phrase in (
            "pthread_detach.c",
            "thrd_detach.c",
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
            self.assertIn(phrase, detach_abi)
        detach_scope = detach["native_evidence"][0]["scope"]
        for phrase in (
            "Pinned-musl project-header C reference",
            "`-nostdlib -static` candidate",
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
            self.assertIn(phrase, detach_scope)
        self.assertEqual(
            thrd_sleep["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-thrd-sleep",
        )
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
            self.assertIn(phrase, thrd_sleep["description"])
        for owner in (
            "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs",
            "libc/src/c_abi/x86_64/clock_nanosleep.rs",
            "include/threads.h",
            "include/time.h",
            "compat/x86_64/libc_thrd_sleep_probe.c",
            "compat/x86_64/libc_thrd_sleep_start.S",
            "compat/x86_64/run_libc_thrd_sleep.sh",
            "compat/x86_64/run_pthread_c11_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, thrd_sleep["source_owners"])
        thrd_sleep_abi = " ".join(thrd_sleep["x86_abi_prerequisites"])
        for phrase in (
            "thrd_sleep.c",
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
            self.assertIn(phrase, thrd_sleep_abi)
        thrd_sleep_scope = thrd_sleep["native_evidence"][0]["scope"]
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
            self.assertIn(phrase, thrd_sleep_scope)
        self.assertEqual(
            normal_mutex["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-pthread-mutex-normal",
        )
        for phrase in (
            "still-planned `libc.pthread-tls`",
            "`PTHREAD_MUTEX_NORMAL`",
            "all-zero 40-byte aligned public record",
            "EBUSY|INT_MIN",
            "private futex",
            "six bounded two-worker rounds",
            "ENOTSUP",
            "recursive/errorcheck/robust/PI/pshared behavior",
            "C11 mtx/once",
            "thread.pthread-c11",
            "public x86 support",
        ):
            self.assertIn(phrase, normal_mutex["description"])
        for owner in (
            "libc/src/c_abi/x86_64/atomic.rs",
            "libc/src/c_abi/x86_64/pthread_mutex.rs",
            "libc/src/c_abi/x86_64/static_tls.rs",
            "libc/src/c_abi/x86_64/pthread_create_join.rs",
            "include/pthread.h",
            "compat/x86_64/libc_pthread_mutex_normal_probe.c",
            "compat/x86_64/libc_pthread_mutex_normal_start.S",
            "compat/x86_64/run_libc_pthread_mutex_normal.sh",
            "compat/x86_64/run_pthread_c11_header_abi.sh",
            "compat/x86_64/run_types_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, normal_mutex["source_owners"])
        normal_mutex_abi = " ".join(normal_mutex["x86_abi_prerequisites"])
        for phrase in (
            "pthread_mutex_init.c",
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
            self.assertIn(phrase, normal_mutex_abi)
        normal_mutex_headers = " ".join(normal_mutex["x86_header_prerequisites"])
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
            self.assertIn(phrase, normal_mutex_headers)
        normal_mutex_scope = normal_mutex["native_evidence"][0]["scope"]
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
            self.assertIn(phrase, normal_mutex_scope)
        self.assertEqual(
            private_condition["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-pthread-cond-private",
        )
        for phrase in (
            "still-planned `libc.pthread-tls`",
            "`pthread_cond_init`/`pthread_cond_destroy`/`pthread_cond_wait`/`pthread_cond_signal`/`pthread_cond_broadcast`",
            "all-zero 48-byte aligned public `pthread_cond_t`",
            "`PTHREAD_MUTEX_NORMAL` 40-byte record",
            "private stack waiter/list/barrier/notify protocol",
            "FIFO requeue handoff",
            "four bounded 64-handoff ping-pong rounds",
            "candidate-only `ENOTSUP` rejection",
            "C11 conditions",
            "thread.pthread-c11",
            "public x86 support",
        ):
            self.assertIn(phrase, private_condition["description"])
        for owner in (
            "libc/src/c_abi/x86_64/atomic.rs",
            "libc/src/c_abi/x86_64/pthread_mutex.rs",
            "libc/src/c_abi/x86_64/pthread_cond.rs",
            "libc/src/c_abi/x86_64/static_tls.rs",
            "libc/src/c_abi/x86_64/pthread_create_join.rs",
            "include/pthread.h",
            "compat/x86_64/libc_pthread_cond_private_probe.c",
            "compat/x86_64/libc_pthread_cond_private_start.S",
            "compat/x86_64/run_libc_pthread_cond_private.sh",
            "compat/x86_64/run_pthread_c11_header_abi.sh",
            "compat/x86_64/run_types_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
        ):
            self.assertIn(owner, private_condition["source_owners"])
        private_condition_abi = " ".join(private_condition["x86_abi_prerequisites"])
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
            self.assertIn(phrase, private_condition_abi)
        private_condition_headers = " ".join(
            private_condition["x86_header_prerequisites"]
        )
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
            self.assertIn(phrase, private_condition_headers)
        private_condition_scope = private_condition["native_evidence"][0]["scope"]
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
            self.assertIn(phrase, private_condition_scope)
        self.assertIn("not pthread/TLS parity", pthread_tls["description"])
        self.assertIn("Static Initial TLS v1", static_tls["description"])
        self.assertIn("AT_PHDR", static_tls["description"])
        self.assertIn("PT_TLS", static_tls["description"])
        self.assertIn("initialized/TBSS/high-alignment", static_tls["description"])
        static_tls_abi = " ".join(static_tls["x86_abi_prerequisites"])
        self.assertIn("ET_EXEC", static_tls_abi)
        self.assertIn("no-PT_PHDR", static_tls_abi)
        self.assertIn(
            "ET_EXEC no-PT_PHDR", static_tls["native_evidence"][0]["scope"]
        )
        self.assertIn(
            "fallback ELF version", static_tls["native_evidence"][0]["scope"]
        )
        self.assertIn(
            "PT_TLS p_filesz", static_tls["native_evidence"][0]["scope"]
        )
        self.assertEqual(
            static_tls["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-static-tls-v1",
        )
        for owner in (
            "libc/src/c_abi/x86_64/static_tls.rs",
            "compat/x86_64/libc_static_tls_v1_probe.c",
            "compat/x86_64/libc_static_tls_v1_peer.c",
            "compat/x86_64/libc_static_tls_v1_start.S",
            "compat/x86_64/run_libc_static_tls_v1.sh",
        ):
            self.assertIn(owner, static_tls["source_owners"])

        self.assertEqual(
            crt_handoff["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-crt-static-tls",
        )
        for phrase in (
            "rcrt1.o",
            "crti.o",
            "crtn.o",
            "__crabc_x86_static_tls_bootstrap",
            "__libc_start_main",
            "preinit, init, main",
            "32-registration",
            "atexit",
            "PT_TLS.p_filesz",
            "public x86 support",
        ):
            self.assertIn(phrase, crt_handoff["description"])
        for owner in (
            "crt/build_x86_64.py",
            "crt/src/x86_64_rcrt1.rs",
            "crt/src/x86_64_startup.rs",
            "crt/src/x86_64_crti.rs",
            "crt/src/x86_64_crtn.rs",
            "libc/src/c_abi/x86_64/static_tls.rs",
            "libc/src/c_abi/x86_64/static_startup.rs",
            "libc/src/c_abi/x86_64/immediate_termination.rs",
            "include/stdlib.h",
            "compat/x86_64/libc_crt_static_tls_probe.c",
            "compat/x86_64/libc_crt_static_tls_peer.c",
            "compat/x86_64/run_libc_crt_static_tls.sh",
        ):
            self.assertIn(owner, crt_handoff["source_owners"])
        crt_scope = crt_handoff["native_evidence"][0]["scope"]
        for phrase in (
            "pinned-musl",
            "explicit reference adaptation",
            "no archive link fails",
            "archive-owned startup",
            "32-registration",
            "PIMBCAF",
            "PT_TLS p_filesz mutation",
            "exit 127",
            "public x86 support",
        ):
            self.assertIn(phrase, crt_scope)

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "libc.pthread-tls")[
            "verified_artifact"
        ]
        changed_static_tls = next(
            artifact
            for artifact in changed_artifacts
            if artifact["id"] == "static-c-initial-tls-v1"
        )
        changed_static_tls["native_evidence"][0]["command"] = "./scripts/dev-x86_64.sh core"
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "static-c-initial-tls-v1 must use the closed libc-static-tls-v1 command",
        ):
            ledger.validate_ledger(changed)

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "libc.pthread-tls")[
            "verified_artifact"
        ]
        changed_identity = next(
            artifact
            for artifact in changed_artifacts
            if artifact["id"] == "static-c-pthread-identity"
        )
        changed_identity["native_evidence"][0]["command"] = "./scripts/dev-x86_64.sh core"
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "static-c-pthread-identity must use the closed libc-pthread-identity command",
        ):
            ledger.validate_ledger(changed)

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "libc.pthread-tls")[
            "verified_artifact"
        ]
        changed_c11_lifecycle = next(
            artifact
            for artifact in changed_artifacts
            if artifact["id"] == "static-c-c11-lifecycle"
        )
        changed_c11_lifecycle["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh core"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "static-c-c11-lifecycle must use the closed libc-c11-lifecycle command",
        ):
            ledger.validate_ledger(changed)

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "libc.pthread-tls")[
            "verified_artifact"
        ]
        changed_detach = next(
            artifact
            for artifact in changed_artifacts
            if artifact["id"] == "static-c-pthread-c11-detach"
        )
        changed_detach["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh core"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "static-c-pthread-c11-detach must use the closed libc-pthread-detach command",
        ):
            ledger.validate_ledger(changed)

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "libc.pthread-tls")[
            "verified_artifact"
        ]
        changed_thrd_sleep = next(
            artifact
            for artifact in changed_artifacts
            if artifact["id"] == "static-c-thrd-sleep"
        )
        changed_thrd_sleep["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh core"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "static-c-thrd-sleep must use the closed libc-thrd-sleep command",
        ):
            ledger.validate_ledger(changed)

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "libc.pthread-tls")[
            "verified_artifact"
        ]
        changed_normal_mutex = next(
            artifact
            for artifact in changed_artifacts
            if artifact["id"] == "static-c-pthread-normal-mutex"
        )
        changed_normal_mutex["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh core"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "static-c-pthread-normal-mutex must use the closed libc-pthread-mutex-normal command",
        ):
            ledger.validate_ledger(changed)

        changed = copy.deepcopy(data)
        changed_artifacts = self.family(changed, "libc.pthread-tls")[
            "verified_artifact"
        ]
        changed_private_condition = next(
            artifact
            for artifact in changed_artifacts
            if artifact["id"] == "static-c-pthread-cond-private"
        )
        changed_private_condition["native_evidence"][0]["command"] = (
            "./scripts/dev-x86_64.sh core"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "static-c-pthread-cond-private must use the closed libc-pthread-cond-private command",
        ):
            ledger.validate_ledger(changed)

    def test_musl_oracle_is_a_native_precondition_not_public_support(self) -> None:
        data = self.data()
        family = self.family(data, "oracle.musl-toolchain")
        self.assertEqual(family["status"], "foundation-verified")
        self.assertEqual(
            family["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh musl-oracle",
        )
        self.assertIn("compat/x86_64/run_musl_oracle.sh", family["source_owners"])
        self.assertIn("docker/x86_64-musl-oracle-gcc", family["source_owners"])

    def test_every_musl_backed_family_depends_on_the_musl_oracle(self) -> None:
        data = self.data()
        for entry in data["family"]:
            assert isinstance(entry, dict)
            if entry["id"] != "oracle.musl-toolchain" and ledger.has_musl_oracle(entry):
                self.assertIn("oracle.musl-toolchain", entry["depends_on"])

        self.family(data, "libc.posix-runtime")["depends_on"].remove("oracle.musl-toolchain")
        with self.assertRaisesRegex(ledger.LedgerError, "must depend on oracle.musl-toolchain"):
            ledger.validate_ledger(data)

    def test_symbols_gate_is_accounted_for_by_the_abi_differential_family(self) -> None:
        data = self.data()
        self.assertIn("symbols", self.family(data, "compat.abi-differential")["aarch64_gates"])

    def test_baseline_capabilities_are_read_from_the_baseline_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.toml"
            path.write_text(
                '[[capability]]\nid = "dynamic.capability"\nkind = "semantic"\n',
                encoding="utf-8",
            )
            self.assertEqual(ledger.baseline_capability_ids(path), {"dynamic.capability"})

    def test_rejects_an_unassigned_baseline_capability(self) -> None:
        data = self.data()
        capabilities = self.family(data, "facade.direct")["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.remove("random.state")
        with self.assertRaisesRegex(ledger.LedgerError, "leaves baseline capabilities unmapped: random.state"):
            ledger.validate_ledger(data)

    def test_rejects_a_duplicate_or_stale_capability_mapping(self) -> None:
        duplicate = self.data()
        self.family(duplicate, "core.architecture")["capabilities"].append("random.state")
        with self.assertRaisesRegex(ledger.LedgerError, "mapped by both"):
            ledger.validate_ledger(duplicate)

        stale = self.data()
        self.family(stale, "core.architecture")["capabilities"].append("obsolete.capability")
        with self.assertRaisesRegex(ledger.LedgerError, "maps stale baseline capabilities: obsolete.capability"):
            ledger.validate_ledger(stale)

    def test_rejects_a_missing_promotion_family(self) -> None:
        data = self.data()
        promotion = data["promotion"]
        assert isinstance(promotion, dict)
        required = promotion["required_families"]
        assert isinstance(required, list)
        required.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "roster drifted"):
            ledger.validate_ledger(data)

    def test_rejects_a_dependency_that_is_not_earlier(self) -> None:
        data = self.data()
        self.family(data, "core.architecture")["depends_on"] = ["performance.release"]
        with self.assertRaisesRegex(ledger.LedgerError, "is not earlier"):
            ledger.validate_ledger(data)

    def test_rejects_a_foundation_misrepresented_as_complete_evidence(self) -> None:
        data = self.data()
        evidence = self.family(data, "libc.raw-syscall")["native_evidence"]
        assert isinstance(evidence, list) and evidence
        assert isinstance(evidence[0], dict)
        evidence[0]["state"] = "required"
        with self.assertRaisesRegex(ledger.LedgerError, "entirely verified"):
            ledger.validate_ledger(data)

    def test_rejects_an_incomplete_or_out_of_family_verified_slice(self) -> None:
        data = self.data()
        remaining = self.family(data, "facade.record-owning")
        slices = remaining["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 24
        interface_device = next(
            slice_entry
            for slice_entry in slices
            if isinstance(slice_entry, dict)
            and slice_entry["id"] == "network.interface-device"
        )
        evidence = interface_device["native_evidence"]
        assert isinstance(evidence, list) and evidence
        assert isinstance(evidence[0], dict)
        evidence[0]["state"] = "required"
        with self.assertRaisesRegex(ledger.LedgerError, "entirely verified"):
            ledger.validate_ledger(data)

        data = self.data()
        remaining = self.family(data, "facade.record-owning")
        slices = remaining["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 24
        interface_device = next(
            slice_entry
            for slice_entry in slices
            if isinstance(slice_entry, dict)
            and slice_entry["id"] == "network.interface-device"
        )
        capabilities = interface_device["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.append("random.state")
        with self.assertRaisesRegex(ledger.LedgerError, "escape the owning family"):
            ledger.validate_ledger(data)

        data = self.data()
        remaining = self.family(data, "facade.record-owning")
        slices = remaining["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 24
        resolver_transport = next(
            slice_entry
            for slice_entry in slices
            if isinstance(slice_entry, dict)
            and slice_entry["id"] == "network.resolver-transport"
        )
        capabilities = resolver_transport["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.append("network.interface-index")
        with self.assertRaisesRegex(ledger.LedgerError, "duplicates a capability"):
            ledger.validate_ledger(data)

        data = self.data()
        remaining = self.family(data, "facade.record-owning")
        slices = remaining["verified_slice"]
        assert isinstance(slices, list) and len(slices) == 24
        interface_device = next(
            slice_entry
            for slice_entry in slices
            if isinstance(slice_entry, dict)
            and slice_entry["id"] == "network.interface-device"
        )
        capabilities = interface_device["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.remove("network.interface-name")
        with self.assertRaisesRegex(
            ledger.LedgerError,
            "must exactly cover the foundation family capabilities; missing: network.interface-name",
        ):
            ledger.validate_ledger(data)

    def test_rejects_capability_or_duplicate_identity_on_an_artifact_only_slice(self) -> None:
        data = self.data()
        headers = self.family(data, "libc.headers-layouts")
        artifacts = headers["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 3
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "public-header-c-consumability"
        )
        assert isinstance(artifact, dict)
        artifact["capabilities"] = ["math.fenv"]
        with self.assertRaisesRegex(ledger.LedgerError, "must not carry capabilities"):
            ledger.validate_ledger(data)

        data = self.data()
        headers = self.family(data, "libc.headers-layouts")
        artifacts = headers["verified_artifact"]
        assert isinstance(artifacts, list) and len(artifacts) == 3
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "public-header-c-consumability"
        )
        assert isinstance(artifact, dict)
        artifact["id"] = "filesystem.stat-compat"
        with self.assertRaisesRegex(ledger.LedgerError, "duplicate verified record id"):
            ledger.validate_ledger(data)

    def test_byte_string_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-byte-strings"
        )
        artifact["description"] = artifact["description"].replace(
            "scalar fallback behavior", "vector fallback behavior"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "scalar fallback"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-byte-strings"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh libc-foundation"
        with self.assertRaisesRegex(ledger.LedgerError, "closed libc-byte-strings command"):
            ledger.validate_ledger(data)

    def test_integer_parse_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-integer-parse"
        )
        artifact["description"] = artifact["description"].replace(
            "invalid-base/no-conversion", "invalid-base-only"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "invalid-base/no-conversion"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-integer-parse"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh libc-intmax-arithmetic"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-integer-parse command"
        ):
            ledger.validate_ledger(data)

    def test_credential_observation_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-credential-observation"
        )
        artifact["description"] = artifact["description"].replace(
            "query-then-fill race", "stable snapshot"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "query-then-fill race"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-credential-observation"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh libc-credentials"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-credential-observation command"
        ):
            ledger.validate_ledger(data)

    def test_immediate_termination_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-immediate-termination"
        )
        artifact["description"] = artifact["description"].replace(
            "exit_group=231", "exit_group=999"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "exit_group=231"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-immediate-termination"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh libc-child-reaping"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-immediate-termination command"
        ):
            ledger.validate_ledger(data)

    def test_callback_algorithms_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-callback-algorithms"
        )
        artifact["description"] = artifact["description"].replace(
            "same-address", "different-address"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "same-address"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-callback-algorithms"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh libc-immediate-termination"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-callback-algorithms command"
        ):
            ledger.validate_ledger(data)

    def test_clock_nanosleep_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-clock-nanosleep"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace(
            "clock_nanosleep=230", "clock_nanosleep=999"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "four-register syscall ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-clock-nanosleep"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh clock-nanosleep-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-clock-nanosleep command"
        ):
            ledger.validate_ledger(data)

    def test_clock_gettime_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-clock-gettime"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace(
            "clock_gettime=228", "clock_gettime=999"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "two-register syscall ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-clock-gettime"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh time-abi-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-clock-gettime command"
        ):
            ledger.validate_ledger(data)

    def test_system_configuration_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-system-configuration"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[3], str)
        prerequisites[3] = prerequisites[3].replace("prlimit64=302", "prlimit64=999")
        with self.assertRaisesRegex(ledger.LedgerError, "prlimit64 four-register ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-system-configuration"
        )
        artifact["description"] = artifact["description"].replace(
            "path- and fd-independent", "filesystem-dependent"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "path- and fd-independent"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-system-configuration"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh system-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-system-configuration command"
        ):
            ledger.validate_ledger(data)

    def test_mapping_core_artifact_keeps_its_closed_static_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-mman-mapping-core"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace("mmap=9", "mmap=8")
        with self.assertRaisesRegex(ledger.LedgerError, "x86 syscall ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-mman-mapping-core"
        )
        artifact["description"] = artifact["description"].replace(
            "planned `libc.posix-runtime`", "completed runtime"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "planned `libc.posix-runtime`"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-mman-mapping-core"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh mapping-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-mapping-core command"
        ):
            ledger.validate_ledger(data)

    def test_signal_execution_artifact_keeps_its_closed_static_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-process-signal-execution"
        )
        self.assertNotIn("capabilities", artifact)
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
        ):
            self.assertIn(owner, artifact["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-signal-execution"},
        )
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
            "planned `libc.posix-runtime`",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])
        prerequisites = artifact["x86_abi_prerequisites"]
        self.assertTrue(
            any(
                "kill=62" in prerequisite
                and "rt_sigprocmask=14" in prerequisite
                and "rt_sigtimedwait=128" in prerequisite
                and "rt_sigqueueinfo=129" in prerequisite
                and "gettid=186" in prerequisite
                and "tkill=200" in prerequisite
                for prerequisite in prerequisites
            )
        )
        self.assertTrue(
            any(
                "0xfffffffc7fffffff" in prerequisite
                and "__block_app_sigs/__restore_sigs" in prerequisite
                for prerequisite in prerequisites
            )
        )

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-process-signal-execution"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace("tkill=200", "tkill=201")
        with self.assertRaisesRegex(ledger.LedgerError, "x86 syscall ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-process-signal-execution"
        )
        artifact["description"] = artifact["description"].replace(
            "planned `libc.posix-runtime`", "completed runtime"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "planned `libc.posix-runtime`"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-process-signal-execution"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh signal-header-abi"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-signal-execution command"
        ):
            ledger.validate_ledger(data)

    def test_nanosleep_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-nanosleep"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace("nanosleep=35", "nanosleep=999")
        with self.assertRaisesRegex(ledger.LedgerError, "two-register syscall ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-nanosleep"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh relative-sleep-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-nanosleep command"
        ):
            ledger.validate_ledger(data)

    def test_descriptor_entry_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-descriptor-entry"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace("open=2", "open=999")
        with self.assertRaisesRegex(ledger.LedgerError, "open/openat register ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-descriptor-entry"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh fcntl-status-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-descriptor-entry command"
        ):
            ledger.validate_ledger(data)

    def test_descriptor_lifecycle_artifact_keeps_its_composition_boundary(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-descriptor-lifecycle"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[1], str)
        prerequisites[1] = prerequisites[1].replace("fstat=5", "fstat=999")
        with self.assertRaisesRegex(ledger.LedgerError, "selected stat ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-descriptor-lifecycle"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh libc-descriptor-io"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-descriptor-lifecycle command"
        ):
            ledger.validate_ledger(data)

    def test_timestamp_updates_artifact_keeps_its_bounded_contract(self) -> None:
        data = self.data()
        family = self.family(data, "libc.posix-runtime")
        self.assertEqual(family["status"], "planned")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-timestamp-updates"
        )
        self.assertNotIn("capabilities", artifact)
        for owner in (
            "libc/src/c_abi/x86_64/timestamp_updates.rs",
            "crt/src/x86_64_rcrt1.rs",
            "include/utime.h",
            "compat/x86_64/utime_header_abi_probe.c",
            "compat/x86_64/run_utime_header_abi.sh",
            "compat/x86_64/static_c_abi_exports.txt",
            "compat/x86_64/libc_timestamp_updates_probe.c",
            "compat/x86_64/run_libc_timestamp_updates.sh",
        ):
            self.assertIn(owner, artifact["source_owners"])
        self.assertEqual(
            {evidence["command"] for evidence in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-timestamp-updates"},
        )
        for phrase in (
            "timestamp-update block",
            "strong `__futimesat`",
            "weak same-address `futimesat`",
            "`UTIME_NOW`",
            "`UTIME_OMIT`",
            "real Rust `rcrt1.o`/`crti.o`/`crtn.o`",
            "does not establish general filesystem policy",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])
        prerequisites = artifact["x86_abi_prerequisites"]
        self.assertTrue(
            any(
                "utimensat=280" in prerequisite
                and "rdi/rsi/rdx/r10" in prerequisite
                and "rcx" in prerequisite
                and "16-byte align-8" in prerequisite
                for prerequisite in prerequisites
            )
        )
        self.assertTrue(
            any(
                "all-UTIME_NOW" in prerequisite
                and "weak same-address" in prerequisite
                and "ENOSYS fallback" in prerequisite
                for prerequisite in prerequisites
            )
        )
        self.assertTrue(
            any(
                "utime header gate" in prerequisite
                and "unmangled C++ linkage" in prerequisite
                and "does not close any installed header family" in prerequisite
                for prerequisite in artifact["x86_header_prerequisites"]
            )
        )
        self.assertIn(
            "weak same-address futimesat",
            artifact["native_evidence"][0]["scope"],
        )

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-timestamp-updates"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace("utimensat=280", "utimensat=281")
        with self.assertRaisesRegex(ledger.LedgerError, "x86 syscall and record ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-timestamp-updates"
        )
        artifact["description"] = artifact["description"].replace(
            "weak same-address `futimesat`", "weak different-address `futimesat`"
        )
        with self.assertRaisesRegex(
            ledger.LedgerError, "weak same-address `futimesat`"
        ):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-timestamp-updates"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh timestamp-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-timestamp-updates command"
        ):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-timestamp-updates"
        )
        artifact["capabilities"] = ["filesystem.fd-timestamps"]
        with self.assertRaisesRegex(
            ledger.LedgerError, "must not carry capabilities; use verified_slice instead"
        ):
            ledger.validate_ledger(data)

    def test_filesystem_access_artifact_keeps_its_closed_mapping_contract(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-filesystem-access"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace("access=21", "access=999")
        with self.assertRaisesRegex(
            ledger.LedgerError, "access real-ID register ABI"
        ):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-filesystem-access"
        )
        artifact["description"] = artifact["description"].replace(
            "same-address", "different-address"
        )
        with self.assertRaisesRegex(ledger.LedgerError, "same-address"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-filesystem-access"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh access-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-access command"
        ):
            ledger.validate_ledger(data)

    def test_fcntl_status_control_artifact_keeps_its_variadic_boundary(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-fcntl-status-control"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace("fcntl=72", "fcntl=999")
        with self.assertRaisesRegex(ledger.LedgerError, "variadic register ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict)
            and entry["id"] == "static-c-fcntl-status-control"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh fcntl-status-reference"
        with self.assertRaisesRegex(
            ledger.LedgerError, "closed libc-fcntl-status-control command"
        ):
            ledger.validate_ledger(data)

    def test_generic_ioctl_artifact_keeps_its_safe_no_vararg_boundary(self) -> None:
        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-generic-ioctl"
        )
        self.assertNotIn("capabilities", artifact)
        for owner in (
            "compat/upstreams.toml",
            "libc/src/c_abi/x86_64/static_c_abi.rs",
            "libc/src/c_abi/x86_64/ioctl.rs",
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
            self.assertIn(owner, artifact["source_owners"])
        self.assertEqual(
            {entry["command"] for entry in artifact["native_evidence"]},
            {"./scripts/dev-x86_64.sh libc-ioctl"},
        )
        for phrase in (
            "generic ioctl block",
            "signed-int variadic `ioctl` entry",
            "`FIOCLEX`",
            "`FIONCLEX`",
            "three-word pointer-or-integer forwarding path",
            "`FIONREAD`",
            "`FIONBIO`",
            "does not establish generic device/request behavior",
            "public x86 support",
        ):
            self.assertIn(phrase, artifact["description"])
        self.assertIn("src/misc/ioctl.c", artifact["oracle"][0]["role"])
        self.assertIn("ioctl", (ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt").read_text(encoding="utf-8").splitlines())
        self.assertIn("libc/src/c_abi/x86_64/ioctl.rs", self.family(data, "libc.posix-runtime")["source_owners"])

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-generic-ioctl"
        )
        prerequisites = artifact["x86_abi_prerequisites"]
        assert isinstance(prerequisites, list) and isinstance(prerequisites[0], str)
        prerequisites[0] = prerequisites[0].replace("ioctl=16", "ioctl=999")
        with self.assertRaisesRegex(ledger.LedgerError, "signed-int SysV/Linux ABI"):
            ledger.validate_ledger(data)

        data = self.data()
        artifacts = self.family(data, "libc.posix-runtime")["verified_artifact"]
        assert isinstance(artifacts, list)
        artifact = next(
            entry
            for entry in artifacts
            if isinstance(entry, dict) and entry["id"] == "static-c-generic-ioctl"
        )
        evidence = artifact["native_evidence"]
        assert isinstance(evidence, list) and isinstance(evidence[0], dict)
        evidence[0]["command"] = "./scripts/dev-x86_64.sh ioctl-reference"
        with self.assertRaisesRegex(ledger.LedgerError, "closed libc-ioctl command"):
            ledger.validate_ledger(data)

    def test_rejects_an_unknown_aarch64_gate(self) -> None:
        data = self.data()
        self.family(data, "facade.direct")["aarch64_gates"] = ["invented-gate"]
        with self.assertRaisesRegex(ledger.LedgerError, "unknown AArch64 gates"):
            ledger.validate_ledger(data)


if __name__ == "__main__":
    unittest.main()
