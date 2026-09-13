#!/usr/bin/env python3
"""Focused contracts for the raw native x86 header declaration inventory."""

from __future__ import annotations

import copy
import io
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
INVENTORY_PATH = ROOT / "compat" / "x86_64" / "header_declaration_inventory.py"
TEST_WORK_ROOT = ROOT / ".work" / "x86_64" / "header-declaration-inventory-tests"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INVENTORY = load_module("header_declaration_inventory_test", INVENTORY_PATH)


def temporary_directory() -> tempfile.TemporaryDirectory[str]:
    TEST_WORK_ROOT.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=TEST_WORK_ROOT)


class HeaderDeclarationInventoryTests(unittest.TestCase):
    def test_host_replay_fixture_creates_its_own_work_root(self) -> None:
        """Each retained-input regression must run without an earlier scratch-creating test."""
        with temporary_directory() as temporary:
            isolated = Path(temporary) / "isolated-host-replay-root"
            with patch.object(sys.modules[__name__], "TEST_WORK_ROOT", isolated):
                output, selection = self._host_replay_fixture()
            self.assertTrue(output.is_dir())
            self.assertEqual(selection["candidate_headers"], ["demo.h"])

    def test_ast_occurrences_preserve_redeclarations_and_unknown_linkage(self) -> None:
        """A collapsed fact cannot erase the declarations selection must inspect."""
        with temporary_directory() as temporary:
            header_root = Path(temporary)
            header = header_root / "demo.h"
            header.write_text("/* source fixture */\n", encoding="utf-8")
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "kind": "LinkageSpecDecl",
                        "language": "C",
                        "loc": {"file": str(header), "line": 1},
                        "inner": [
                            {
                                "id": "0xone",
                                "kind": "FunctionDecl",
                                "name": "extern_fn",
                                "loc": {"file": str(header), "line": 2},
                                "storageClass": "extern",
                                "type": {
                                    "qualType": "int (int)",
                                    "desugaredQualType": "int (int)",
                                },
                            },
                            {
                                "id": "0xtwo",
                                "kind": "FunctionDecl",
                                "name": "extern_fn",
                                "previousDecl": "0xone",
                                "loc": {"file": str(header), "line": 3},
                                "storageClass": "extern",
                                "type": {"qualType": "int (int)"},
                            },
                            {
                                "id": "0xthree",
                                "kind": "VarDecl",
                                "name": "extern_value",
                                "loc": {"file": str(header), "line": 4},
                                "storageClass": "extern",
                                "tls": "dynamic",
                                "type": {"qualType": "const int[3]"},
                            },
                        ],
                    },
                    {
                        "id": "0xfour",
                        "kind": "VarDecl",
                        "name": "private_static",
                        "loc": {"file": str(header), "line": 5},
                        "storageClass": "static",
                        "type": {"qualType": "int"},
                        "init": "c",
                    },
                    {
                        "id": "0xfive",
                        "kind": "VarDecl",
                        "name": "cpp_namespace_const",
                        "loc": {"file": str(header), "line": 6},
                        "mangledName": "_ZL19cpp_namespace_const",
                        "type": {"qualType": "const int"},
                    },
                    {
                        "kind": "FunctionDecl",
                        "name": "outer",
                        "loc": {"file": str(header), "line": 7},
                        "type": {"qualType": "void (void)"},
                        "inner": [
                            {
                                "kind": "CompoundStmt",
                                "inner": [
                                    {
                                        "kind": "VarDecl",
                                        "name": "automatic_ignored",
                                        "loc": {"file": str(header), "line": 8},
                                        "type": {"qualType": "int"},
                                    }
                                ],
                            }
                        ],
                    },
                ],
            }
            occurrences = INVENTORY.discover_declaration_occurrences(
                ast,
                header_root=header_root,
                tree="candidate",
                input_header="demo.h",
                profile="cxx17-gnu",
                raw_ast_path="raw/candidate/demo/cxx17-gnu/ast.json",
            )

        self.assertEqual(
            [(item["kind"], item["name"], item["source"]["line"]) for item in occurrences],
            [
                ("function", "extern_fn", 2),
                ("function", "extern_fn", 3),
                ("variable", "extern_value", 4),
                ("variable", "private_static", 5),
                ("variable", "cpp_namespace_const", 6),
                ("function", "outer", 7),
            ],
        )
        first, second, tls, static, unknown, _outer = occurrences
        self.assertEqual(first["linkage_status"], "source-external-declaration")
        self.assertEqual(first["linkage_specifier_languages"], ["C"])
        self.assertEqual(second["previous_declaration"], {"kind": "same-ast", "occurrence_ordinal": 0})
        self.assertEqual(tls["tls_observation"], "dynamic")
        self.assertEqual(static["linkage_status"], "source-static")
        self.assertEqual(static["definition_observation"], "initializer-present")
        self.assertEqual(unknown["linkage_status"], "unresolved-from-json")
        self.assertEqual(unknown["mangled_name_observation"], "_ZL19cpp_namespace_const")
        self.assertEqual(unknown["source"]["origin_resolution"], "physical")
        self.assertNotIn("automatic_ignored", [item["name"] for item in occurrences])

    def test_variable_occurrences_exclude_function_and_record_member_scope(self) -> None:
        with temporary_directory() as temporary:
            root = Path(temporary)
            header = root / "demo.h"
            header.write_text("/* direct */\n", encoding="utf-8")
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "kind": "CXXRecordDecl",
                        "loc": {"file": str(header), "line": 1},
                        "inner": [
                            {
                                "kind": "VarDecl",
                                "name": "member_should_not_be_retained",
                                "loc": {"file": str(header), "line": 2},
                                "storageClass": "static",
                                "type": {"qualType": "int"},
                            },
                            {
                                "kind": "CXXMethodDecl",
                                "loc": {"file": str(header), "line": 3},
                                "inner": [
                                    {
                                        "kind": "CompoundStmt",
                                        "inner": [
                                            {
                                                "kind": "VarDecl",
                                                "name": "local_should_not_be_retained",
                                                "loc": {"file": str(header), "line": 4},
                                                "type": {"qualType": "int"},
                                            }
                                        ],
                                    }
                                ],
                            },
                        ],
                    },
                    {
                        "kind": "VarDecl",
                        "name": "namespace_scope_retained",
                        "loc": {"file": str(header), "line": 5},
                        "storageClass": "extern",
                        "type": {"qualType": "int"},
                    },
                ],
            }
            occurrences = INVENTORY.discover_declaration_occurrences(
                ast,
                header_root=root,
                tree="candidate",
                input_header="demo.h",
                profile="cxx17-gnu",
                raw_ast_path="raw/ast.json",
            )
        self.assertEqual([item["name"] for item in occurrences], ["namespace_scope_retained"])

    def test_compact_location_recovered_to_foreign_header_is_not_relabelled_as_direct_include(self) -> None:
        with temporary_directory() as temporary:
            root = Path(temporary)
            header = root / "demo.h"
            foreign = root.parent / "foreign.h"
            header.write_text("/* direct */\n", encoding="utf-8")
            foreign.write_text("/* foreign */\n", encoding="utf-8")
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "kind": "FunctionDecl",
                        "name": "foreign_anchor",
                        "loc": {"file": str(foreign), "line": 1, "offset": 1, "col": 1, "tokLen": 1},
                        "type": {"qualType": "void (void)"},
                    },
                    {
                        "kind": "FunctionDecl",
                        "name": "compact_foreign",
                        "loc": {"line": 2, "offset": 2, "col": 1, "tokLen": 1},
                        "type": {"qualType": "void (void)"},
                    },
                ],
            }
            occurrences = INVENTORY.discover_declaration_occurrences(
                ast,
                header_root=root,
                tree="candidate",
                input_header="demo.h",
                profile="c11-gnu",
                raw_ast_path="raw/ast.json",
            )
        self.assertEqual(occurrences, [])

    def test_macro_events_keep_redefinitions_and_undefinitions_before_final_view(self) -> None:
        with temporary_directory() as temporary:
            header_root = Path(temporary)
            header = header_root / "demo.h"
            header.write_text("/* source fixture */\n", encoding="utf-8")
            preprocessed = "\n".join(
                [
                    f'# 1 "{header}" 1',
                    "#define FIRST 1",
                    "#define AGAIN(x) (x)",
                    "#undef FIRST",
                    "#define FIRST 2",
                    "#define FIRST 3",
                    '# 1 "<built-in>" 2',
                    "#undef FIRST",
                    "#undef AGAIN",
                ]
            )
            events, active = INVENTORY.discover_macro_events(
                preprocessed,
                header_root=header_root,
                tree="candidate",
                input_header="demo.h",
                profile="c11-gnu",
                raw_preprocessor_path="raw/candidate/demo/c11-gnu/preprocessor.txt",
            )

        self.assertEqual(
            [(event["event"], event["name"], event["ordinal"]) for event in events],
            [
                ("define", "FIRST", 0),
                ("define", "AGAIN", 1),
                ("undef", "FIRST", 2),
                ("define", "FIRST", 3),
                ("define", "FIRST", 4),
            ],
        )
        self.assertEqual(events[1]["form"], "function-like")
        self.assertEqual(active, [])

    def test_mounted_workspace_admits_only_its_own_physical_work_root(self) -> None:
        """A `/workspace` mount has no visible main-checkout `.work/worktrees`."""
        with temporary_directory() as temporary:
            base = Path(temporary)
            mounted = base / "workspace"
            admitted = mounted / ".work"
            evidence = admitted / "x86_64" / "receipt"
            evidence.mkdir(parents=True)
            report = evidence / "report.json"
            self.assertEqual(
                INVENTORY.canonical_checkout_work_root(root=mounted, ancestors=(mounted,)),
                admitted,
            )
            self.assertEqual(
                INVENTORY.evidence_directory_below_work_root(report, admitted),
                evidence,
            )
            outside = base / "outside" / "report.json"
            outside.parent.mkdir(parents=True)
            with self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "escapes admitted"):
                INVENTORY.evidence_directory_below_work_root(outside, admitted)

            symlinked = base / "symlinked-workspace"
            symlinked.mkdir()
            os.symlink(admitted, symlinked / ".work")
            with self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "cannot locate"):
                INVENTORY.canonical_checkout_work_root(root=symlinked, ancestors=(symlinked,))

    def _host_replay_fixture(self) -> tuple[Path, dict[str, object]]:
        TEST_WORK_ROOT.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix="host-replay-", dir=TEST_WORK_ROOT))
        staging = output / "staging"
        project = staging / "project"
        musl = staging / "musl" / "include"
        resource = staging / "resource"
        uapi = staging / "uapi"
        project.mkdir(parents=True)
        musl.mkdir(parents=True)
        resource.mkdir()
        uapi.mkdir()
        header = project / "demo.h"
        header.write_text("extern int host_replay_value;\n#define HOST_REPLAY 1\n", encoding="utf-8")
        reference_header = musl / "demo.h"
        reference_header.write_text(header.read_text(encoding="utf-8"), encoding="utf-8")
        fake_tool = staging / "clang"
        fake_tool.write_text("fixture compiler bytes\n", encoding="utf-8")
        marker_musl = staging / "musl-marker"
        marker_uapi = staging / "uapi-marker"
        marker_musl.write_text(
            "format=crabc-pinned-musl-oracle-v1\n"
            "version=1.2.6\n"
            "source_sha256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a\n"
            "fallback_revision=9fa28ece75d8a2191de7c5bb53bed224c5947417\n"
            "architecture=x86_64\n",
            encoding="utf-8",
        )
        marker_uapi.write_text(
            "format=crabc-linux-uapi-v1\n"
            "version=5.10\n"
            "source_sha256=dcdf99e43e98330d925016985bfbc7b83c66d367b714b2de0cbbfcbf83d8ca43\n"
            "architecture=x86_64\n"
            "install_arch=x86\n"
            "header_count=935\n"
            "header_manifest_sha256=00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e\n",
            encoding="utf-8",
        )
        def snapshot(source: Path, relative: str, original: str):
            return INVENTORY.snapshot_regular_file(output, source, relative, original)
        def text_artifact(relative: str, value: str):
            return INVENTORY.write_text_artifact(output, output / relative, value)
        source_contract_root = staging / "source-contracts"
        source_contracts: dict[str, object] = {}
        source_texts = {
            "compat/x86_64/header_abi_matrix.toml": (
                'public_headers = "compat/x86_64/public_headers.txt"\n'
                "[[oracle_not_applicable]]\n"
                'header = "demo.h"\n'
                'profile = "c11-gnu"\n'
                'reason = "fixture oracle parse failure"\n'
            ),
            "compat/x86_64/header_callable_inventory.toml": (
                "[[profile]]\n"
                'id = "c11-gnu"\n'
                'language = "c"\n'
                'standard = "c11"\n'
                'defines = ["_GNU_SOURCE=1"]\n'
            ),
            "compat/x86_64/public_headers.txt": "demo.h\n",
        }
        for relative in INVENTORY.SOURCE_CONTRACT_FILES:
            source_contract = source_contract_root / relative
            source_contract.parent.mkdir(parents=True, exist_ok=True)
            source_contract.write_text(
                source_texts.get(relative, f"fixture retained source: {relative}\n"),
                encoding="utf-8",
            )
            source_contracts[relative] = snapshot(
                source_contract,
                f"inputs/source-contracts/{relative}",
                relative,
            )
        tool = {
            "executable": snapshot(fake_tool, "inputs/toolchain/clang", "/unavailable/toolchain/clang"),
            "executable_original_path": "/unavailable/toolchain/clang",
            "requested": "clang",
            "resource_include_original_path": "/unavailable/resource/include",
            "resource_query": {
                "argv": ["clang", "-print-resource-dir"],
                "returncode": 0,
                "stdout": text_artifact("inputs/toolchain/clang-resource.stdout.txt", "/unavailable/resource\n"),
                "stderr": text_artifact("inputs/toolchain/clang-resource.stderr.txt", ""),
            },
            "version": {
                "argv": ["clang", "--version"],
                "returncode": 0,
                "stdout": text_artifact("inputs/toolchain/clang-version.stdout.txt", "fixture clang\n"),
                "stderr": text_artifact("inputs/toolchain/clang-version.stderr.txt", ""),
            },
        }
        markers = {
            "pinned-musl": snapshot(marker_musl, "inputs/oracle-markers/pinned-musl", "/unavailable/musl/.crabc-oracle"),
            "linux-uapi": snapshot(marker_uapi, "inputs/oracle-markers/linux-uapi", "/unavailable/uapi/.crabc-linux-uapi"),
        }
        dependency = {
            "classification": "candidate-header-root",
            "key": "candidate-header-root/demo.h",
            "logical_path": "demo.h",
            "original_path_observation": "/unavailable/project/demo.h",
            "snapshot": snapshot(header, "inputs/dependencies/candidate-header-root/demo.h", "/unavailable/project/demo.h"),
        }
        reference_dependency = {
            "classification": "pinned-musl-header-root",
            "key": "pinned-musl-header-root/demo.h",
            "logical_path": "demo.h",
            "original_path_observation": "/unavailable/musl/include/demo.h",
            "snapshot": snapshot(reference_header, "inputs/dependencies/pinned-musl-header-root/demo.h", "/unavailable/musl/include/demo.h"),
        }
        raw = output / "raw" / "candidate" / "demo.h" / "c11-gnu"
        raw.mkdir(parents=True)
        source = raw / "probe.c"
        source.write_text("#include <demo.h>\n", encoding="utf-8")
        probe_source = staging / "probes" / "candidate" / "probe.c"
        probe_source.parent.mkdir(parents=True)
        probe_source.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        probe_original = "/unavailable/probes/candidate/probe.c"
        probe_key = INVENTORY.dependency_key("probe", "probe.c", probe_original)
        probe_dependency = {
            "classification": "probe",
            "key": probe_key,
            "logical_path": "probe.c",
            "original_path_observation": probe_original,
            "snapshot": snapshot(probe_source, f"inputs/dependencies/{probe_key}", probe_original),
        }
        reference_probe_original = "/unavailable/probes/reference/probe.c"
        reference_probe_key = INVENTORY.dependency_key("probe", "probe.c", reference_probe_original)
        reference_probe_source = staging / "reference-probes" / "probe.c"
        reference_probe_source.parent.mkdir(parents=True)
        reference_probe_source.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        reference_probe_dependency = {
            "classification": "probe",
            "key": reference_probe_key,
            "logical_path": "probe.c",
            "original_path_observation": reference_probe_original,
            "snapshot": snapshot(
                reference_probe_source,
                f"inputs/dependencies/{reference_probe_key}",
                reference_probe_original,
            ),
        }
        profile = INVENTORY.callable_inventory.Profile("c11-gnu", "c", "c11", ("_GNU_SOURCE=1",))
        origin_project = Path("/unavailable/project")
        origin_musl = Path("/unavailable/musl/include")
        origin_resource = Path("/unavailable/resource/include")
        origin_uapi = Path("/unavailable/uapi/include")
        origin_probe = Path(probe_original)
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [{
                "id": "0x1",
                "kind": "VarDecl",
                "name": "host_replay_value",
                "loc": {"file": "/unavailable/project/demo.h", "line": 1},
                "storageClass": "extern",
                "type": {"qualType": "int"},
            }],
        }
        preprocessed = (
            '# 1 "/unavailable/probes/candidate/probe.c" 1\n'
            '# 1 "/unavailable/project/demo.h" 1\n'
            "#define HOST_REPLAY 1\n"
        )
        ast_descriptor = INVENTORY.write_text_artifact(output, raw / "ast.json", json.dumps(ast))
        pp_descriptor = INVENTORY.write_text_artifact(output, raw / "preprocessor.txt", preprocessed)
        ast_command = INVENTORY.callable_inventory.compiler_command(
            "clang", profile, origin_project, origin_resource, origin_uapi, origin_probe, ast=True, preprocess=False
        )
        pp_command = INVENTORY.callable_inventory.compiler_command(
            "clang", profile, origin_project, origin_resource, origin_uapi, origin_probe, ast=False, preprocess=True
        )
        artifacts = {
            "source": INVENTORY.artifact_descriptor(output, source),
            "ast_stdout": ast_descriptor,
            "ast_stderr": INVENTORY.write_text_artifact(output, raw / "ast.stderr.txt", ""),
            "ast_command": INVENTORY.write_json_artifact(output, raw / "ast.command.json", ast_command),
            "preprocessor_stdout": pp_descriptor,
            "preprocessor_stderr": INVENTORY.write_text_artifact(output, raw / "preprocessor.stderr.txt", ""),
            "preprocessor_command": INVENTORY.write_json_artifact(output, raw / "preprocessor.command.json", pp_command),
        }
        status = {
            "schema": INVENTORY.RAW_ARTIFACT_SCHEMA,
            "status": "ok",
            "detail": "fixture",
            "ast_returncode": 0,
            "preprocess_returncode": 0,
        }
        artifacts["status"] = INVENTORY.write_json_artifact(output, raw / "status.json", status)
        selection = {
            "candidate_headers": ["demo.h"],
            "candidate_include_tree_sha256": "0" * 64,
            "header_abi_matrix_contract_sha256": source_contracts["compat/x86_64/header_abi_matrix.toml"]["retained"]["sha256"],
            "oracle_not_applicable": [{
                "header": "demo.h",
                "profile": "c11-gnu",
                "reason": "fixture oracle parse failure",
            }],
            "pinned_headers": [],
            "profiles": [{"id": "c11-gnu", "language": "c", "standard": "c11", "defines": ["_GNU_SOURCE=1"]}],
            "public_headers_sha256": source_contracts["compat/x86_64/public_headers.txt"]["retained"]["sha256"],
            "source_contract_sha256": {
                relative: source_contracts[relative]["retained"]["sha256"]
                for relative in INVENTORY.SOURCE_CONTRACT_FILES
            },
        }
        inputs = {
            "collector": {
                "id": INVENTORY.COLLECTOR_ID,
                "raw_ast_json": True,
                "raw_preprocessor_records": True,
                "source_text_parsing": False,
            },
            "collector_source_contracts": source_contracts,
            "compiler": tool,
            "dependency_snapshots": [dependency, probe_dependency],
            "image_id_observation": "crabc-core-evidence@sha256:" + "a" * 64,
            "oracle_markers": markers,
            "origin_roots": {
                "candidate-header-root": str(origin_project),
                "compiler-resource": str(origin_resource),
                "linux-uapi": str(origin_uapi),
                "pinned-musl-header-root": "/unavailable/musl/include",
            },
            "selection_source": selection,
        }
        derived = INVENTORY.derive_raw_records_for_replay(
            ast_json=ast,
            preprocessed=preprocessed,
            header_root=origin_project,
            tree="candidate",
            input_header="demo.h",
            profile="c11-gnu",
            raw_ast_path=artifacts["ast_stdout"]["path"],
            raw_preprocessor_path=artifacts["preprocessor_stdout"]["path"],
            source_language="c",
        )
        job = {
            "artifacts": artifacts,
            "dependencies": sorted([dependency["key"], probe_dependency["key"]]),
            "detail": "fixture",
            "header": "demo.h",
            "ordinal": 0,
            "probe_original_path_observation": str(origin_probe),
            "profile": "c11-gnu",
            "status": "ok",
            "tree": "candidate",
        }
        reference_raw = output / "raw" / "reference" / "demo.h" / "c11-gnu"
        reference_raw.mkdir(parents=True)
        reference_source = reference_raw / "probe.c"
        reference_source.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        reference_artifacts = {
            "source": INVENTORY.artifact_descriptor(output, reference_source),
            "ast_stdout": INVENTORY.write_text_artifact(output, reference_raw / "ast.json", ""),
            "ast_stderr": INVENTORY.write_text_artifact(output, reference_raw / "ast.stderr.txt", "fixture expected parse error\n"),
            "ast_command": INVENTORY.write_json_artifact(
                output,
                reference_raw / "ast.command.json",
                INVENTORY.callable_inventory.compiler_command(
                    "clang", profile, origin_musl, origin_resource, origin_uapi,
                    Path(reference_probe_original), ast=True, preprocess=False,
                ),
            ),
        }
        reference_status = {
            "schema": INVENTORY.RAW_ARTIFACT_SCHEMA,
            "status": "oracle-not-applicable",
            "detail": "fixture oracle parse failure",
            "ast_returncode": 1,
            "preprocess_returncode": None,
        }
        reference_artifacts["status"] = INVENTORY.write_json_artifact(
            output, reference_raw / "status.json", reference_status
        )
        reference_job = {
            "artifacts": reference_artifacts,
            "dependencies": [reference_probe_dependency["key"]],
            "detail": "fixture oracle parse failure",
            "header": "demo.h",
            "ordinal": 1,
            "probe_original_path_observation": reference_probe_original,
            "profile": "c11-gnu",
            "status": "oracle-not-applicable",
            "tree": "reference",
        }
        selection["pinned_headers"] = ["demo.h"]
        inputs["dependency_snapshots"] = [
            dependency,
            probe_dependency,
            reference_dependency,
            reference_probe_dependency,
        ]
        report = INVENTORY.build_report(
            inputs=inputs,
            jobs=[job, reference_job],
            occurrences=derived["occurrences"],
            macro_events=derived["macro_events"],
            final_active_macros=derived["final_active_macros"],
            workers=1,
            timeout_seconds=1.0,
        )
        INVENTORY.write_json(output / "report.json", report)
        shutil.rmtree(staging)
        return output, selection

    def test_host_replay_uses_retained_inputs_without_compiler_or_original_oracle_paths(self) -> None:
        output, selection = self._host_replay_fixture()
        report_path = output / "report.json"
        unavailable = Path("/unavailable")
        self.assertFalse(unavailable.exists())
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY,
            "selection_source_snapshot",
            return_value=(selection, object(), ["demo.h"], []),
        ):
            envelope = INVENTORY.validate_report(report_path)
        self.assertTrue(envelope["current_selecting_source"]["matches_retained"])
        self.assertEqual(envelope["report"]["summary"]["occurrence_count"], 1)

        drifted_selection = copy.deepcopy(selection)
        drifted_selection["candidate_include_tree_sha256"] = "f" * 64
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY,
            "selection_source_snapshot",
            return_value=(drifted_selection, object(), ["demo.h"], ["demo.h"]),
        ):
            historical = INVENTORY.validate_report(report_path)
        self.assertFalse(historical["current_selecting_source"]["matches_retained"])
        self.assertEqual(historical["current_selecting_source"]["differences"][0]["path"], "candidate_include_tree_sha256")

        changed = copy.deepcopy(envelope["report"])
        changed["occurrences"] = []
        INVENTORY.write_json(report_path, changed)
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY,
            "selection_source_snapshot",
            return_value=(selection, object(), ["demo.h"], []),
        ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "occurrences"):
            INVENTORY.validate_report(report_path)

    def test_host_replay_rejects_deleted_and_extra_retained_input_or_raw_files(self) -> None:
        output, selection = self._host_replay_fixture()
        report_path = output / "report.json"
        extra = output / "raw" / "unexpected.txt"
        extra.write_text("not in receipt\n", encoding="utf-8")
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], [])
        ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "raw artifact"):
            INVENTORY.validate_report(report_path)
        extra.unlink()
        report = INVENTORY.load_json_object(report_path, "fixture report")
        retained_marker = report["inputs"]["oracle_markers"]["pinned-musl"]["retained"]["path"]
        (output / retained_marker).unlink()
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], [])
        ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "retained oracle marker"):
            INVENTORY.validate_report(report_path)

    def test_host_replay_binds_raw_stderr_selection_contracts_and_oracle_failure_probe(self) -> None:
        """Every advertised raw artifact and oracle-failure source stays replayable."""
        output, selection = self._host_replay_fixture()
        report_path = output / "report.json"
        report = INVENTORY.load_json_object(report_path, "fixture report")
        ast_stderr = report["jobs"][0]["artifacts"]["ast_stderr"]["path"]
        (output / ast_stderr).write_text("changed only stderr bytes\n", encoding="utf-8")
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], ["demo.h"])
        ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "ast_stderr.*(size|digest)"):
            INVENTORY.validate_report(report_path)

        output, selection = self._host_replay_fixture()
        report_path = output / "report.json"
        report = INVENTORY.load_json_object(report_path, "fixture report")
        report["inputs"]["selection_source"]["header_abi_matrix_contract_sha256"] = "1" * 64
        INVENTORY.write_json(report_path, report)
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], ["demo.h"])
        ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "header ABI matrix contract digest is detached"):
            INVENTORY.validate_report(report_path)

        output, selection = self._host_replay_fixture()
        report_path = output / "report.json"
        report = INVENTORY.load_json_object(report_path, "fixture report")
        oracle_job = report["jobs"][1]
        replacement_probe = "/unavailable/probes/rebound/probe.c"
        oracle_job["probe_original_path_observation"] = replacement_probe
        profile = INVENTORY.callable_inventory.Profile("c11-gnu", "c", "c11", ("_GNU_SOURCE=1",))
        command = INVENTORY.callable_inventory.compiler_command(
            "clang",
            profile,
            Path("/unavailable/musl/include"),
            Path("/unavailable/resource/include"),
            Path("/unavailable/uapi/include"),
            Path(replacement_probe),
            ast=True,
            preprocess=False,
        )
        command_path = output / oracle_job["artifacts"]["ast_command"]["path"]
        INVENTORY.write_json(command_path, command)
        oracle_job["artifacts"]["ast_command"] = INVENTORY.artifact_descriptor(output, command_path)
        INVENTORY.write_json(report_path, report)
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], ["demo.h"])
        ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "exactly one retained probe"):
            INVENTORY.validate_report(report_path)

    def test_host_replay_rejects_self_consistent_fabricated_oracle_markers(self) -> None:
        """Hashes alone cannot promote arbitrary retained markers into either frozen pin."""
        for label, expected in (
            ("pinned-musl", "pinned musl provenance marker"),
            ("linux-uapi", "Linux UAPI provenance marker"),
        ):
            with self.subTest(label=label):
                output, selection = self._host_replay_fixture()
                report_path = output / "report.json"
                report = INVENTORY.load_json_object(report_path, "fixture report")
                marker = report["inputs"]["oracle_markers"][label]
                retained_path = output / marker["retained"]["path"]
                retained_path.write_text("format=fabricated-marker-v1\n", encoding="utf-8")
                digest = INVENTORY.sha256_file(retained_path)
                size = retained_path.stat().st_size
                for identity_name in ("before", "after"):
                    marker[identity_name]["sha256"] = digest
                    marker[identity_name]["size"] = size
                marker["retained"]["sha256"] = digest
                marker["retained"]["size"] = size
                INVENTORY.write_json(report_path, report)
                with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
                    INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], ["demo.h"])
                ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, expected):
                    INVENTORY.validate_report(report_path)

    def test_host_replay_rejects_self_consistent_duplicate_or_nonfinite_raw_ast_json(self) -> None:
        """Raw compiler JSON must retain object and numeric syntax, not Python's lossy parse."""
        for mutation, expected in (
            (
                lambda text: '{"kind":"fabricated",' + text.lstrip()[1:],
                "duplicate JSON key",
            ),
            (
                lambda text: text.rstrip()[:-1] + ',"fabricated_nonfinite":NaN}\n',
                "nonfinite JSON constant",
            ),
            (
                lambda text: text.rstrip()[:-1] + ',"fabricated_overflow":1e9999}\n',
                "nonfinite JSON number",
            ),
            (
                lambda text: text.rstrip()[:-1] + ',"fabricated_overflow":-1e9999}\n',
                "nonfinite JSON number",
            ),
        ):
            with self.subTest(expected=expected):
                output, selection = self._host_replay_fixture()
                report_path = output / "report.json"
                report = INVENTORY.load_json_object(report_path, "fixture report")
                descriptor = report["jobs"][0]["artifacts"]["ast_stdout"]
                raw_path = output / descriptor["path"]
                raw_path.write_text(mutation(raw_path.read_text(encoding="utf-8")), encoding="utf-8")
                descriptor["sha256"] = INVENTORY.sha256_file(raw_path)
                descriptor["size"] = raw_path.stat().st_size
                INVENTORY.write_json(report_path, report)
                with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
                    INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], ["demo.h"])
                ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, expected):
                    INVENTORY.validate_report(report_path)

    def test_host_replay_rejects_duplicate_report_json_keys(self) -> None:
        """A repeated envelope key cannot be accepted just because its final value is valid."""
        output, selection = self._host_replay_fixture()
        report_path = output / "report.json"
        report_text = report_path.read_text(encoding="utf-8")
        self.assertTrue(report_text.startswith("{\n"))
        report_path.write_text(
            '{\n  "schema": "fabricated",\n' + report_text[2:],
            encoding="utf-8",
        )
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], ["demo.h"])
        ), self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "duplicate JSON key"):
            INVENTORY.validate_report(report_path)

    def test_validate_report_cli_emits_historical_source_status_and_rejects_collect_options(self) -> None:
        output, selection = self._host_replay_fixture()
        report_path = output / "report.json"
        stdout = io.StringIO()
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY, "selection_source_snapshot", return_value=(selection, object(), ["demo.h"], ["demo.h"])
        ), redirect_stdout(stdout):
            self.assertEqual(INVENTORY.main(["--validate-report", str(report_path)]), 0)
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(receipt["schema"], INVENTORY.VALIDATION_SCHEMA)
        self.assertEqual(receipt["report"]["path"], str(report_path.resolve()))
        self.assertEqual(receipt["report"]["sha256"], INVENTORY.sha256_file(report_path))
        self.assertTrue(receipt["current_selecting_source"]["matches_retained"])
        self.assertEqual(receipt["report"]["summary"]["occurrence_count"], 1)

        drifted = copy.deepcopy(selection)
        drifted["candidate_include_tree_sha256"] = "f" * 64
        stdout = io.StringIO()
        with patch.object(INVENTORY.subprocess, "run", side_effect=AssertionError("host replay ran compiler")), patch.object(
            INVENTORY, "selection_source_snapshot", return_value=(drifted, object(), ["demo.h"], ["demo.h"])
        ), redirect_stdout(stdout):
            self.assertEqual(INVENTORY.main(["--validate-report", str(report_path)]), 0)
        historical = json.loads(stdout.getvalue())
        self.assertFalse(historical["current_selecting_source"]["matches_retained"])
        self.assertEqual(historical["current_selecting_source"]["differences"][0]["path"], "candidate_include_tree_sha256")

        with self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "--compiler only applies"):
            INVENTORY.main(["--validate-report", str(report_path), "--compiler", "clang"])

    def test_raw_replay_rejects_lost_or_extra_occurrences_and_scalar_type_substitution(self) -> None:
        """Raw evidence is authoritative; an edited derived result cannot pass replay."""
        with temporary_directory() as temporary:
            header_root = Path(temporary)
            header = header_root / "demo.h"
            header.write_text("/* source fixture */\n", encoding="utf-8")
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "id": "0xone",
                        "kind": "VarDecl",
                        "name": "external_value",
                        "loc": {"file": str(header), "line": 1},
                        "storageClass": "extern",
                        "type": {"qualType": "int"},
                    }
                ],
            }
            raw = INVENTORY.derive_raw_records_for_replay(
                ast_json=ast,
                preprocessed=f'# 1 "{header}" 1\n#define DEMO 1\n',
                header_root=header_root,
                tree="candidate",
                input_header="demo.h",
                profile="c11-gnu",
                raw_ast_path="raw/ast.json",
                raw_preprocessor_path="raw/preprocessor.txt",
            )
            INVENTORY.validate_derived_records(raw, raw)
            lost = dict(raw)
            lost["occurrences"] = []
            with self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "occurrences"):
                INVENTORY.validate_derived_records(lost, raw)
            scalar_type_substitution = dict(raw)
            scalar_type_substitution["summary"] = dict(raw["summary"])
            scalar_type_substitution["summary"]["occurrence_count"] = True
            with self.assertRaisesRegex(INVENTORY.HeaderDeclarationInventoryError, "occurrence_count"):
                INVENTORY.validate_derived_records(scalar_type_substitution, raw)



if __name__ == "__main__":
    unittest.main()
