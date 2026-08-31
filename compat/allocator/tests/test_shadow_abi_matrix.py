#!/usr/bin/env python3
"""Contract-level regressions for the paired native-shadow ABI matrix."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "shadow-abi-matrix/run.py"
SPEC = importlib.util.spec_from_file_location("crabc_shadow_abi_matrix", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class ShadowAbiMatrixContractTests(unittest.TestCase):
    def test_checked_in_contract_has_the_closed_local_trace_and_active_required_nonlocal_cases(self) -> None:
        contract = RUNNER.load_contract()
        self.assertEqual(
            RUNNER.expected_trace(contract),
            [
                "free-null-preserves-errno",
                "malloc-local-content-and-errno",
                "realloc-grow-preserves-prefix-and-errno",
                "realloc-shrink-preserves-prefix-and-errno",
                "realloc-null-zero-result",
                "realloc-zero-result",
                "realloc-failure-preserves-source-and-sets-enomem",
                "free-local-preserves-errno",
            ],
        )
        required = {
            case["id"]: case for case in contract["musl_differential_required_cases"]
        }
        self.assertEqual(
            set(required),
            {"foreign-worker-realloc", "post-owner-exit-realloc"},
        )
        self.assertEqual(
            required["foreign-worker-realloc"]["fixture"]["path"],
            "tests/fixtures/native_mimalloc_shadow_foreign_realloc_test.c",
        )
        self.assertEqual(
            required["foreign-worker-realloc"]["expected"]["stdout"],
            "native mimalloc shadow foreign realloc ok\n",
        )
        self.assertEqual(
            required["post-owner-exit-realloc"]["fixture"]["path"],
            "tests/fixtures/native_mimalloc_owner_exit_realloc_test.c",
        )
        self.assertEqual(
            required["post-owner-exit-realloc"]["expected"]["stdout"],
            "native mimalloc owner exit realloc ok\n",
        )
        self.assertTrue(
            all(case["classification"] == "musl-differential-required" for case in required.values())
        )
        self.assertTrue(all(case["activation"] == "required" for case in required.values()))
        self.assertEqual(
            {case["id"] for case in contract["intentionally_blocked_cases"]},
            {
                "foreign-worker-free-routing",
                "owner-exit-routing-outside-selected-realloc",
                "dso-interposition-and-static-linking",
                "address-reuse-usable-size-and-page-layout",
            },
        )

    def test_trace_parser_accepts_only_the_complete_ordered_semantic_records(self) -> None:
        contract = RUNNER.load_contract()
        expected = RUNNER.expected_trace(contract)
        expected_results = {
            case["id"]: case["expected"]["native-rust-mimalloc-shadow"]
            for case in contract["semantic_cases"]
        }
        stdout = b"".join(
            f"case={case} result={expected_results[case]}\n".encode("ascii") for case in expected
        )
        self.assertEqual(
            RUNNER.parse_trace(stdout, contract),
            [{"id": case, "result": expected_results[case]} for case in expected],
        )
        changed = RUNNER.parse_trace(stdout.replace(b"result=pass", b"result=unknown", 1), contract)
        with self.assertRaisesRegex(RUNNER.MatrixError, "recorded semantics"):
            RUNNER.validate_backend_trace(
                contract,
                RUNNER.backend_contract(contract, "native-rust-mimalloc-shadow"),
                changed,
            )
        with self.assertRaisesRegex(RUNNER.MatrixError, "semantic records"):
            RUNNER.parse_trace(
                b"".join(
                    f"case={case} result=pass\n".encode("ascii")
                    for case in reversed(expected)
                ),
                contract,
            )

    def test_contract_rejects_a_hidden_second_attempt_or_missing_blocker(self) -> None:
        contract = RUNNER.load_contract()
        changed_attempts = copy.deepcopy(contract)
        changed_attempts["execution"]["process_attempts_per_backend"] = 2
        with mock.patch.object(RUNNER, "read_json", return_value=changed_attempts), self.assertRaisesRegex(
            RUNNER.MatrixError, "execution contract drifted"
        ):
            RUNNER.load_contract()

        missing_blocker = copy.deepcopy(contract)
        missing_blocker["intentionally_blocked_cases"].pop()
        with mock.patch.object(RUNNER, "read_json", return_value=missing_blocker), self.assertRaisesRegex(
            RUNNER.MatrixError, "blocked case count drifted"
        ):
            RUNNER.load_contract()

        changed_operations = copy.deepcopy(contract)
        changed_operations["semantic_cases"][0]["operations"] = ["malloc"]
        with mock.patch.object(RUNNER, "read_json", return_value=changed_operations), self.assertRaisesRegex(
            RUNNER.MatrixError, "semantic case operations drifted"
        ):
            RUNNER.load_contract()
        self.assertEqual(RUNNER.parse_dynamic_search_paths(" 0x0 (NEEDED) Shared library: [libc.so]"), [])
        self.assertEqual(
            RUNNER.parse_dynamic_search_paths(" 0x0 (RUNPATH) Library runpath: [/unexpected]"),
            ["/unexpected"],
        )

    def test_nonlocal_realloc_cases_cannot_be_classified_as_intentional_divergences(self) -> None:
        contract = RUNNER.load_contract()
        changed_classification = copy.deepcopy(contract)
        changed_classification["musl_differential_required_cases"][0]["classification"] = "known-red"
        with mock.patch.object(RUNNER, "read_json", return_value=changed_classification), self.assertRaisesRegex(
            RUNNER.MatrixError, "musl differential classification drifted"
        ):
            RUNNER.load_contract()

        hidden_as_blocked = copy.deepcopy(contract)
        hidden_as_blocked["intentionally_blocked_cases"][0]["id"] = "foreign-worker-realloc"
        with mock.patch.object(RUNNER, "read_json", return_value=hidden_as_blocked), self.assertRaisesRegex(
            RUNNER.MatrixError, "blocked case inventory drifted"
        ):
            RUNNER.load_contract()

        changed_output = copy.deepcopy(contract)
        changed_output["musl_differential_required_cases"][1]["expected"]["stdout"] = "accepted\n"
        with mock.patch.object(RUNNER, "read_json", return_value=changed_output), self.assertRaisesRegex(
            RUNNER.MatrixError, "musl differential expected stream drifted"
        ):
            RUNNER.load_contract()

    def test_deferred_nonlocal_cases_block_runtime_acceptance_and_activation_requires_fixture_provenance(self) -> None:
        contract = RUNNER.load_contract()
        deferred = copy.deepcopy(contract)
        for case in deferred["musl_differential_required_cases"]:
            case["activation"] = "deferred"
        with self.assertRaisesRegex(RUNNER.MatrixError, "deferred pending source-faithful siblings"):
            RUNNER.active_musl_differential_cases(deferred)

        activated = copy.deepcopy(contract)
        activated["musl_differential_required_cases"][0]["activation"] = "required"
        original_sha256_file = RUNNER.sha256_file

        def wrong_source_sha256(path: Path) -> str:
            if path == RUNNER.case_fixture_path(activated["musl_differential_required_cases"][0]):
                return "0" * 64
            return original_sha256_file(path)

        with mock.patch.object(RUNNER, "read_json", return_value=activated), mock.patch.object(
            RUNNER, "sha256_file", side_effect=wrong_source_sha256
        ), self.assertRaisesRegex(RUNNER.MatrixError, "fixture provenance drifted"):
            RUNNER.load_contract()

        def source_faithful_sha256(path: Path) -> str:
            for case in activated["musl_differential_required_cases"]:
                fixture = case["fixture"]
                if path == RUNNER.ROOT / fixture["path"]:
                    return fixture["sha256"]
            return original_sha256_file(path)

        for case in activated["musl_differential_required_cases"]:
            case["activation"] = "required"
        with mock.patch.object(RUNNER, "read_json", return_value=activated), mock.patch.object(
            RUNNER, "sha256_file", side_effect=source_faithful_sha256
        ):
            activated_contract = RUNNER.load_contract()
        self.assertEqual(
            [case["id"] for case in RUNNER.active_musl_differential_cases(activated_contract)],
            ["foreign-worker-realloc", "post-owner-exit-realloc"],
        )

    def test_musl_differential_requires_the_expected_oracle_and_selected_streams(self) -> None:
        contract = RUNNER.load_contract()
        case = contract["musl_differential_required_cases"][0]
        expected_stdout = case["expected"]["stdout"].encode("utf-8")
        reference = {
            "kind": "process",
            "status": 0,
            "stdout": RUNNER.bytes_record(expected_stdout),
            "stderr": RUNNER.bytes_record(b""),
        }
        selected = copy.deepcopy(reference)
        result = RUNNER.validate_musl_differential_execution(case, reference, selected)
        self.assertEqual(result["classification"], "musl-differential-required")
        self.assertEqual(result["expected_stdout"], expected_stdout.decode("utf-8"))

        selected["stdout"] = RUNNER.bytes_record(b"different\n")
        with self.assertRaisesRegex(RUNNER.MatrixError, "selected stream diverges"):
            RUNNER.validate_musl_differential_execution(case, reference, selected)

        wrong_reference = copy.deepcopy(reference)
        wrong_reference["stdout"] = RUNNER.bytes_record(b"wrong oracle\n")
        with self.assertRaisesRegex(RUNNER.MatrixError, "oracle stream differs"):
            RUNNER.validate_musl_differential_execution(case, wrong_reference, reference)

    def test_nonlocal_differential_build_commands_select_only_the_case_fixture_and_oracle(self) -> None:
        contract = RUNNER.load_contract()
        case = contract["musl_differential_required_cases"][0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected_root = root / "selected"
            selected_libc = selected_root / "libc.so"
            builtins = root / "sysroot/usr/lib/libcrabc-builtins.a"
            selected_root.mkdir()
            builtins.parent.mkdir(parents=True)
            selected_libc.write_bytes(b"selected")
            builtins.write_bytes(b"builtins")
            selected = RUNNER.musl_differential_selected_link_command(
                case,
                root / "sysroot/bin/crabc-cc",
                selected_libc,
                builtins,
                root / "selected-case",
            )
            self.assertIn(str(RUNNER.case_fixture_path(case)), selected)
            self.assertNotIn(str(RUNNER.FIXTURE_PATH), selected)
            self.assertIn("-nodefaultlibs", selected)
            self.assertIn(RUNNER.SELECTED_LIBC_LINK_FLAG, selected)
            self.assertEqual(RUNNER.link_plan_search_paths(selected), [str(selected_root)])

            oracle = RUNNER.musl_differential_oracle_link_command(
                case, Path("/opt/musl-1.2.6/bin/musl-gcc"), root / "oracle-case"
            )
            self.assertEqual(oracle[0], "/opt/musl-1.2.6/bin/musl-gcc")
            self.assertIn(str(RUNNER.case_fixture_path(case)), oracle)
            self.assertNotIn("-nodefaultlibs", oracle)
            self.assertNotIn(RUNNER.SELECTED_LIBC_LINK_FLAG, oracle)
            self.assertIn("-lc", oracle)

    def test_required_nonlocal_differentials_reject_an_unpinned_musl_environment(self) -> None:
        contract = RUNNER.load_contract()
        with mock.patch.object(RUNNER.shutil, "which", return_value="/opt/musl-1.2.6/bin/musl-gcc"), mock.patch.dict(
            RUNNER.os.environ, {"MUSL_REFERENCE_LIBDIR": "/opt/musl-1.2.6/lib"}, clear=False
        ):
            compiler, library_root = RUNNER.require_pinned_musl_oracle(contract)
        self.assertEqual(compiler, Path("/opt/musl-1.2.6/bin/musl-gcc"))
        self.assertEqual(library_root, Path("/opt/musl-1.2.6/lib"))

        with mock.patch.object(RUNNER.shutil, "which", return_value="/usr/bin/musl-gcc"), mock.patch.dict(
            RUNNER.os.environ, {"MUSL_REFERENCE_LIBDIR": "/usr/lib"}, clear=False
        ), self.assertRaisesRegex(RUNNER.MatrixError, "pinned musl 1.2.6 library root"):
            RUNNER.require_pinned_musl_oracle(contract)

    def test_deferred_nonlocal_requirements_make_run_report_failed_without_runtime_inputs(self) -> None:
        deferred = RUNNER.load_contract()
        for case in deferred["musl_differential_required_cases"]:
            case["activation"] = "deferred"
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "shadow-matrix.json"
            with mock.patch.object(RUNNER, "load_contract", return_value=deferred), mock.patch.object(
                RUNNER, "require_runtime_inputs"
            ) as runtime_inputs:
                self.assertEqual(RUNNER.main(["run", "--report", str(report_path)]), 1)
            runtime_inputs.assert_not_called()
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["first_fact"]["kind"], "first-failure")
        self.assertEqual(report["first_fact"]["stage"], "required-musl-differential")
        self.assertIn("deferred pending source-faithful siblings", report["first_fact"]["message"])
        self.assertEqual(report["musl_differential_cases"], [])

    def test_report_base_carries_blocked_and_active_required_cases_without_turning_them_into_passes(self) -> None:
        contract = RUNNER.load_contract()
        report = RUNNER.report_base(contract)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["semantic_comparisons"], [])
        self.assertEqual(report["intentionally_blocked_cases"], contract["intentionally_blocked_cases"])
        self.assertTrue(all(case["status"] == "blocked" for case in report["intentionally_blocked_cases"]))
        self.assertEqual(
            report["musl_differential_required_cases"], contract["musl_differential_required_cases"]
        )
        self.assertEqual(report["musl_differential_cases"], [])
        self.assertTrue(
            all(case["activation"] == "required" for case in report["musl_differential_required_cases"])
        )

    def test_known_reds_are_recorded_as_differences_not_matching_passes(self) -> None:
        contract = RUNNER.load_contract()
        rows = [case for case in contract["semantic_cases"] if case["comparison"] == "known-red"]
        self.assertEqual(
            [(row["id"], row["expected"]) for row in rows],
            [
                (
                    "realloc-null-zero-result",
                    {
                        "ordinary-c-mimalloc": "freeable-misaligned-preserves-errno",
                        "native-rust-mimalloc-shadow": "freeable-aligned-preserves-errno",
                    },
                ),
                (
                    "realloc-zero-result",
                    {
                        "ordinary-c-mimalloc": "distinct-aligned-preserves-errno",
                        "native-rust-mimalloc-shadow": "distinct-misaligned-preserves-errno",
                    },
                ),
            ],
        )
        self.assertTrue(all("not an accepted" in row["reason"] for row in rows))

    def test_selected_libc_link_plan_rejects_the_sealed_default_libc_shape(self) -> None:
        contract = RUNNER.load_contract()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysroot = root / "sysroot"
            selected_root = root / "selected"
            selected_libc = selected_root / "libc.so"
            builtins = sysroot / RUNNER.OWNED_BUILTINS_RELATIVE_PATH
            selected_root.mkdir()
            builtins.parent.mkdir(parents=True)
            selected_libc.write_bytes(b"selected")
            builtins.write_bytes(b"builtins")
            command = RUNNER.matrix_link_command(
                contract,
                sysroot / "bin/crabc-cc",
                selected_libc,
                builtins,
                root / "matrix",
            )
            self.assertIn("-nodefaultlibs", command)
            self.assertIn(RUNNER.SELECTED_LIBC_LINK_FLAG, command)
            self.assertIn(str(builtins), command)
            self.assertEqual(RUNNER.link_plan_search_paths(command), [str(selected_root)])

            plan = {
                "command": command,
                "default_libraries": [],
                "interpreter": str(RUNNER.CANONICAL_LOADER),
            }
            provenance = RUNNER.audit_selected_link_plan(plan, sysroot, selected_libc, builtins)
            self.assertEqual(provenance["selected_library_root"], str(selected_root.resolve()))
            self.assertEqual(provenance["selected_library_flag"], "-l:libc.so")

            old_driver_shape = copy.deepcopy(plan)
            old_driver_shape["command"] = [
                "clang",
                "-L",
                str(sysroot / "usr/lib"),
                "fixture.c",
                "-lc",
            ]
            old_driver_shape["default_libraries"] = ["-L", str(sysroot / "usr/lib"), "-lc"]
            with self.assertRaisesRegex(RUNNER.MatrixError, "retained default libraries"):
                RUNNER.audit_selected_link_plan(old_driver_shape, sysroot, selected_libc, builtins)

            missing_opt_out = copy.deepcopy(plan)
            missing_opt_out["command"].remove("-nodefaultlibs")
            with self.assertRaisesRegex(RUNNER.MatrixError, "exactly one -nodefaultlibs"):
                RUNNER.audit_selected_link_plan(missing_opt_out, sysroot, selected_libc, builtins)

            trace = {
                "stdout": RUNNER.bytes_record(f"{selected_libc.resolve()}\n".encode("utf-8")),
                "stderr": RUNNER.bytes_record(b""),
            }
            trace_provenance = RUNNER.audit_selected_linker_trace(trace, selected_libc, sysroot)
            self.assertTrue(trace_provenance["selected_libc_seen"])
            contaminated_trace = {
                "stdout": RUNNER.bytes_record(
                    f"{selected_libc.resolve()}\n{(sysroot / 'usr/lib/libc.so').resolve()}\n".encode("utf-8")
                ),
                "stderr": RUNNER.bytes_record(b""),
            }
            with self.assertRaisesRegex(RUNNER.MatrixError, "owned sysroot libc"):
                RUNNER.audit_selected_linker_trace(contaminated_trace, selected_libc, sysroot)

    def test_retained_matching_cargo_fingerprints_do_not_make_artifact_attestation_ambiguous(self) -> None:
        contract = RUNNER.load_contract()
        backend = RUNNER.backend_contract(contract, "native-rust-mimalloc-shadow")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for suffix in ("older", "newer"):
                fingerprint = target / ".fingerprint" / f"crabc-libc-{suffix}" / "lib-c.json"
                fingerprint.parent.mkdir(parents=True)
                fingerprint.write_text(
                    json.dumps({"features": '["default", "native-mimalloc-shadow"]'}),
                    encoding="utf-8",
                )
            matches = RUNNER.matching_cargo_fingerprints(target, backend)
        self.assertEqual(len(matches), 2)
        self.assertTrue(
            all(features == ["default", "native-mimalloc-shadow"] for _, features in matches)
        )


class NativePointerFirstGuardTests(unittest.TestCase):
    @staticmethod
    def dwarf_function(name: str, source_path: str, start: int, end: int) -> str:
        return f'''\
0x00001000:   DW_TAG_subprogram
              DW_AT_low_pc\t(0x{start:016x})
              DW_AT_high_pc\t(0x{end:016x})
              DW_AT_name\t("{name}")
              DW_AT_decl_file\t("{source_path}")
'''

    def test_native_guard_contract_covers_each_public_pointer_first_export(self) -> None:
        contract = RUNNER.load_contract()
        backend = RUNNER.backend_contract(contract, "native-rust-mimalloc-shadow")
        guard = backend["native_pointer_first_guard"]
        self.assertEqual(guard["required_elf_identity"], RUNNER.AARCH64_ELF_IDENTITY)
        self.assertEqual(guard["required_debug_sections"], [".debug_info", ".debug_line"])
        self.assertEqual(guard["forbidden_c_backend_symbol_prefix"], "mi_")
        self.assertEqual(guard["exports"], list(RUNNER.NATIVE_DEBUG_GUARD_EXPORTS))
        self.assertEqual(
            [export["symbol"] for export in guard["exports"]],
            ["free", "realloc", "malloc_usable_size"],
        )

        changed = copy.deepcopy(contract)
        changed["backends"][1]["native_pointer_first_guard"]["exports"][0][
            "pointer_first_dwarf_provenance"
        ] = ["native_free_pointer_first_local"]
        with mock.patch.object(RUNNER, "read_json", return_value=changed), self.assertRaisesRegex(
            RUNNER.MatrixError, "native pointer-first guard drifted"
        ):
            RUNNER.load_contract()

    def test_dwarf_address_resolution_uses_only_the_top_level_subprogram_attributes(self) -> None:
        output = '''\
0x00001000:   DW_TAG_subprogram
              DW_AT_low_pc\t(0x0000000000001000)
              DW_AT_high_pc\t(0x0000000000001010)
              DW_AT_name\t("native_free")
              DW_AT_decl_file\t("/workspace/crabc-mimalloc/src/runtime_lifecycle.rs")
0x00001020:     DW_TAG_inlined_subroutine
                DW_AT_low_pc\t(0x0000000000001004)
                DW_AT_high_pc\t(0x0000000000001008)
                DW_AT_name\t("inlined_helper")
                DW_AT_decl_file\t("/workspace/crabc-mimalloc/src/runtime_lifecycle.rs")
'''
        function = RUNNER.dwarf_function_at_address(output, 0x100C)
        self.assertEqual(
            function,
            {
                "address": 0x100C,
                "end_address": 0x1010,
                "name": "native_free",
                "source_path": "/workspace/crabc-mimalloc/src/runtime_lifecycle.rs",
                "start_address": 0x1000,
            },
        )

    def test_native_export_attestation_accepts_an_opaque_elf_label_only_with_dwarf_dispatch_evidence(self) -> None:
        export = copy.deepcopy(RUNNER.NATIVE_DEBUG_GUARD_EXPORTS[0])
        dynamic_symbols = "   123: 0000000000001000    72 FUNC    GLOBAL DEFAULT   12 free\n"
        decoded_lines = [
            {
                "address": 0x1000,
                "line": 67,
                "source_path": "/workspace/libc/src/allocator_native_mimalloc.rs",
            }
        ]

        def command_record(command: list[str] | tuple[str, ...], **_: object) -> dict[str, object]:
            return {"command": tuple(command)}

        def command_text(record: dict[str, object], _: str) -> str:
            command = record["command"]
            assert isinstance(command, tuple)
            if "--disassemble=free" in command:
                return "    1000:\t94000400 \tbl\t2000 <opaque_dispatch>\n"
            if "--start-address=0x2000" in command:
                return "    2000:\t94000400 \tbl\t3000 <opaque_pointer_first_helper>\n"
            if "--lookup=0x2000" in command:
                return self.dwarf_function(
                    "native_free",
                    "/workspace/crabc-mimalloc/src/runtime_lifecycle.rs",
                    0x2000,
                    0x2010,
                )
            if "--lookup=0x3000" in command:
                return self.dwarf_function(
                    "native_free_pointer_first_local",
                    "/workspace/crabc-mimalloc/src/runtime_lifecycle.rs",
                    0x3000,
                    0x3010,
                )
            if "--name=native_free" in command:
                return 'DW_AT_abstract_origin\t(0x00003000 "native_free_pointer_first_nonlocal")\n'
            self.fail(f"unexpected command: {command}")

        with mock.patch.object(RUNNER, "command_record", side_effect=command_record), mock.patch.object(
            RUNNER, "command_text", side_effect=command_text
        ):
            attestation = RUNNER.native_pointer_first_export_attestation(
                Path("/tmp/libc.so"),
                dynamic_symbols,
                decoded_lines,
                "/tools/objdump",
                "/tools/llvm-dwarfdump",
                export,
                "mi_",
            )

        self.assertEqual(attestation["native_dispatch"]["kind"], "direct-dwarf")
        self.assertEqual(attestation["native_dispatch"]["name"], "native_free")
        self.assertEqual(
            attestation["public_direct_targets"],
            [{"address": "0x2000", "dwarf_name": "native_free"}],
        )
        self.assertEqual(
            attestation["pointer_first_dwarf_provenance"],
            ["native_free_pointer_first_local", "native_free_pointer_first_nonlocal"],
        )

    def test_native_export_attestation_rejects_a_direct_c_mimalloc_transfer(self) -> None:
        export = copy.deepcopy(RUNNER.NATIVE_DEBUG_GUARD_EXPORTS[0])
        dynamic_symbols = "   123: 0000000000001000    72 FUNC    GLOBAL DEFAULT   12 free\n"
        decoded_lines = [
            {
                "address": 0x1000,
                "line": 67,
                "source_path": "/workspace/libc/src/allocator_native_mimalloc.rs",
            }
        ]

        def command_record(command: list[str] | tuple[str, ...], **_: object) -> dict[str, object]:
            return {"command": tuple(command)}

        def command_text(record: dict[str, object], _: str) -> str:
            command = record["command"]
            assert isinstance(command, tuple)
            if "--disassemble=free" in command:
                return "    1000:\t94000400 \tbl\t2000 <mi_free>\n"
            self.fail(f"unexpected command: {command}")

        with mock.patch.object(RUNNER, "command_record", side_effect=command_record), mock.patch.object(
            RUNNER, "command_text", side_effect=command_text
        ), self.assertRaisesRegex(RUNNER.MatrixError, "transfers directly to C mimalloc"):
            RUNNER.native_pointer_first_export_attestation(
                Path("/tmp/libc.so"),
                dynamic_symbols,
                decoded_lines,
                "/tools/objdump",
                "/tools/llvm-dwarfdump",
                export,
                "mi_",
            )

    def test_native_guard_requires_the_selected_artifact_and_rejects_mimalloc_relocations(self) -> None:
        contract = RUNNER.load_contract()
        backend = RUNNER.backend_contract(contract, "native-rust-mimalloc-shadow")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target/debug"
            target.mkdir(parents=True)
            libc = target / "libc.so"
            libc.write_bytes(b"selected native artifact")

            with self.assertRaisesRegex(
                RUNNER.MatrixError, "requires target-dir libc.so"
            ):
                RUNNER.attest_native_pointer_first_guard(
                    root / "different/libc.so", target, backend, []
                )

            def command_record(command: list[str] | tuple[str, ...], **_: object) -> dict[str, object]:
                return {"command": tuple(command)}

            def command_text(record: dict[str, object], _: str) -> str:
                command = record["command"]
                assert isinstance(command, tuple)
                if "--file-header" in command:
                    return '''\
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
'''
                if "--sections" in command:
                    return "  [ 1] .debug_info\n  [ 2] .debug_line\n"
                if "--dyn-syms" in command:
                    return "\n"
                if "--relocs" in command:
                    return "0000000000001000  R_AARCH64_JUMP_SLOT mi_free + 0\n"
                self.fail(f"unexpected command: {command}")

            with mock.patch.object(
                RUNNER.shutil,
                "which",
                side_effect=lambda name: f"/tools/{name}",
            ), mock.patch.object(RUNNER, "command_record", side_effect=command_record), mock.patch.object(
                RUNNER, "command_text", side_effect=command_text
            ), self.assertRaisesRegex(RUNNER.MatrixError, "retains a C mimalloc relocation"):
                RUNNER.attest_native_pointer_first_guard(libc, target, backend, [])


if __name__ == "__main__":
    unittest.main()
