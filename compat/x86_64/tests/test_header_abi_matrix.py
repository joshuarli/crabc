#!/usr/bin/env python3
"""Focused contracts for the native x86 all-header ABI matrix."""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = ROOT / "compat" / "x86_64" / "header_abi_matrix.py"
CHECKED_REPORT = ROOT / "compat" / "x86_64" / "generated" / "header_abi_matrix" / "report.json"
RUNNER = ROOT / "compat" / "x86_64" / "run_header_abi_matrix.sh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MATRIX = load_module("header_abi_matrix_test", MATRIX_PATH)


class HeaderAbiMatrixTests(unittest.TestCase):
    def matrix_test_work_root(self) -> Path:
        """Keep synthetic compiler-collection state inside this checkout."""
        root = ROOT / ".work" / "x86_64" / "header-abi-matrix-tests"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def test_comparator_preserves_matched_missing_and_incompatible_facts(self) -> None:
        candidate = [
            MATRIX.fact("function", "shared", "int (int)"),
            MATRIX.fact("macro", "MODE", "function-like:(value) (value)"),
            MATRIX.fact("record", "candidate_record", "struct:int:first"),
        ]
        reference = [
            MATRIX.fact("function", "shared", "int (int)"),
            MATRIX.fact("macro", "MODE", "function-like:(value) ((value)+1)"),
            MATRIX.fact("typedef", "reference_size", "unsigned long"),
        ]

        comparison = MATRIX.compare_facts(candidate, reference)

        self.assertEqual(comparison["matched_count"], 1)
        self.assertEqual(
            comparison["candidate_only"],
            [
                {
                    "kind": "record",
                    "name": "candidate_record",
                    "signature": "struct:int:first",
                }
            ],
        )
        self.assertEqual(
            comparison["reference_only"],
            [
                {
                    "kind": "typedef",
                    "name": "reference_size",
                    "signature": "unsigned long",
                }
            ],
        )
        self.assertEqual(
            comparison["incompatible"],
            [
                {
                    "candidate_signature": "function-like:(value) (value)",
                    "kind": "macro",
                    "name": "MODE",
                    "reference_signature": "function-like:(value) ((value)+1)",
                }
            ],
        )
        self.assertEqual(comparison["incompatible_count"], 1)

    def test_ast_discovery_uses_only_header_owned_named_abi_facts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "demo.h"
            header.write_text("/* synthetic AST origin */\n", encoding="utf-8")
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "kind": "TypedefDecl",
                        "name": "demo_size",
                        "loc": {"file": str(header), "line": 3},
                        "type": {"qualType": "unsigned long"},
                    },
                    {
                        "kind": "RecordDecl",
                        "name": "demo_record",
                        "tagUsed": "struct",
                        "completeDefinition": True,
                        "loc": {"file": str(header), "line": 5},
                        "inner": [
                            {
                                "kind": "FieldDecl",
                                "name": "first",
                                "type": {"qualType": "int"},
                            },
                            {
                                "kind": "FieldDecl",
                                "name": "second",
                                "type": {"qualType": "long"},
                            },
                        ],
                    },
                    {
                        "kind": "EnumDecl",
                        "name": "demo_mode",
                        "loc": {"file": str(header), "line": 10},
                        "inner": [
                            {"kind": "EnumConstantDecl", "name": "DEMO_A", "value": "1"},
                            {"kind": "EnumConstantDecl", "name": "DEMO_B", "value": "2"},
                        ],
                    },
                    {
                        "kind": "VarDecl",
                        "name": "demo_global",
                        "loc": {"file": str(header), "line": 15},
                        "type": {"qualType": "int"},
                    },
                    {
                        "kind": "FunctionDecl",
                        "name": "demo_function",
                        "loc": {"file": str(header), "line": 17},
                        "type": {"qualType": "int (int)"},
                    },
                    {
                        "kind": "TypedefDecl",
                        "name": "builtin_ignored",
                        "loc": {"file": "<built-in>", "line": 1},
                        "type": {"qualType": "int"},
                    },
                ],
            }

            facts = MATRIX.discover_ast_facts(ast, root)

        self.assertEqual(
            [(fact["kind"], fact["name"]) for fact in facts],
            [
                ("enum", "demo_mode"),
                ("function", "demo_function"),
                ("record", "demo_record"),
                ("typedef", "demo_size"),
                ("variable", "demo_global"),
            ],
        )
        record = next(fact for fact in facts if fact["name"] == "demo_record")
        self.assertEqual(record["signature"], "struct{first:int,second:long}")
        enum = next(fact for fact in facts if fact["name"] == "demo_mode")
        self.assertEqual(enum["signature"], "enum{DEMO_A=1,DEMO_B=2}")

    def test_ast_discovery_retains_compact_ast_declarations_from_the_direct_include(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "demo.h"
            header.write_text("/* synthetic direct include */\n", encoding="utf-8")
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "kind": "TypedefDecl",
                        "name": "demo_anchor",
                        "loc": {"file": str(header), "line": 2},
                        "type": {"qualType": "unsigned long"},
                    },
                    {
                        "kind": "FunctionDecl",
                        "name": "demo_compact_function",
                        # Clang's compact AST can omit the repeated file path
                        # after another declaration from the same direct include.
                        "loc": {"offset": 40, "line": 3, "col": 5},
                        "type": {"qualType": "int (int)"},
                    },
                    {
                        "kind": "TypedefDecl",
                        "name": "builtin_must_not_fall_back",
                        "loc": {},
                        "type": {"qualType": "int"},
                    },
                    {
                        "kind": "TypedefDecl",
                        "name": "explicit_external_must_not_fall_back",
                        "loc": {"file": "<built-in>", "line": 1},
                        "type": {"qualType": "int"},
                    },
                ],
            }

            facts = MATRIX.discover_ast_facts(ast, root, "demo.h")

        self.assertEqual(
            [(fact["kind"], fact["name"], fact["signature"]) for fact in facts],
            [
                ("function", "demo_compact_function", "int (int)"),
                ("typedef", "demo_anchor", "unsigned long"),
            ],
        )

    def test_ast_discovery_retains_cxx_named_records_from_the_direct_include(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "demo.h"
            header.write_text("/* synthetic C++ AST origin */\n", encoding="utf-8")
            ast = {
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "kind": "CXXRecordDecl",
                        "name": "demo_cxx_record",
                        "tagUsed": "struct",
                        "completeDefinition": True,
                        "loc": {"file": str(header), "line": 3},
                        "inner": [
                            {
                                "kind": "FieldDecl",
                                "name": "member",
                                "type": {"qualType": "long"},
                            }
                        ],
                    }
                ],
            }

            facts = MATRIX.discover_ast_facts(ast, root)

        self.assertEqual(
            [(fact["kind"], fact["name"], fact["signature"]) for fact in facts],
            [("record", "demo_cxx_record", "struct{member:long}")],
        )

    def test_record_shapes_retain_compiler_bitfield_widths(self) -> None:
        node = {
            "kind": "RecordDecl",
            "tagUsed": "struct",
            "completeDefinition": True,
            "inner": [
                {
                    "kind": "FieldDecl",
                    "name": "flags",
                    "type": {"qualType": "unsigned int"},
                    "isBitfield": True,
                    "inner": [
                        {"kind": "ConstantExpr", "value": "4"},
                    ],
                }
            ],
        }

        self.assertEqual(MATRIX.record_signature(node), "struct{flags:unsigned int:4}")

    def test_enum_values_follow_the_compiler_constant_expression(self) -> None:
        node = {
            "kind": "EnumDecl",
            "inner": [
                {
                    "kind": "EnumConstantDecl",
                    "name": "DEMO_ZERO",
                    "inner": [{"kind": "ConstantExpr", "value": "0"}],
                },
                {
                    "kind": "EnumConstantDecl",
                    "name": "DEMO_FOUR",
                    "inner": [{"kind": "ConstantExpr", "value": "4"}],
                },
            ],
        }

        self.assertEqual(MATRIX.enum_signature(node), "enum{DEMO_ZERO=0,DEMO_FOUR=4}")

    def test_anonymous_ast_identities_ignore_coordinates_but_retain_each_shape(self) -> None:
        with tempfile.TemporaryDirectory() as project_directory, tempfile.TemporaryDirectory() as musl_directory:
            project_root = Path(project_directory)
            musl_root = Path(musl_directory)

            def anonymous_ast(
                header: Path,
                *,
                line_offset: int = 0,
                first_enum_value: str = "1",
                first_record_member_type: str = "int",
                switch_enum_fields: bool = False,
            ) -> dict[str, object]:
                first_enum_line = 10 + line_offset
                second_enum_line = 14 + line_offset
                first_record_line = 18 + line_offset
                second_record_line = 23 + line_offset

                def location(line: int) -> dict[str, object]:
                    return {"file": str(header), "line": line, "col": 5}

                def compact_location(line: int) -> dict[str, object]:
                    # Clang omits repeated file paths from nested AST nodes.
                    return {"offset": line * 16, "line": line, "col": 5}

                first_enum = f"enum (unnamed at {header}:{first_enum_line}:5)"
                second_enum = f"enum (unnamed at {header}:{second_enum_line}:5)"
                return {
                    "kind": "TranslationUnitDecl",
                    "inner": [
                        {
                            "kind": "RecordDecl",
                            "name": "container",
                            "tagUsed": "struct",
                            "completeDefinition": True,
                            "loc": location(1 + line_offset),
                            "inner": [
                                {
                                    "kind": "EnumDecl",
                                    "loc": compact_location(first_enum_line),
                                    "inner": [
                                        {"kind": "EnumConstantDecl", "name": "FIRST", "value": first_enum_value}
                                    ],
                                },
                                {
                                    "kind": "FieldDecl",
                                    "name": "first_mode",
                                    "type": {"qualType": second_enum if switch_enum_fields else first_enum},
                                },
                                {
                                    "kind": "EnumDecl",
                                    "loc": compact_location(second_enum_line),
                                    "inner": [
                                        {"kind": "EnumConstantDecl", "name": "SECOND", "value": "2"}
                                    ],
                                },
                                {
                                    "kind": "FieldDecl",
                                    "name": "second_mode",
                                    "type": {"qualType": first_enum if switch_enum_fields else second_enum},
                                },
                                {
                                    "kind": "RecordDecl",
                                    "tagUsed": "struct",
                                    "completeDefinition": True,
                                    "loc": compact_location(first_record_line),
                                    "inner": [
                                        {
                                            "kind": "FieldDecl",
                                            "name": "member",
                                            "type": {"qualType": first_record_member_type},
                                        }
                                    ],
                                },
                                {
                                    "kind": "FieldDecl",
                                    "name": "first_record",
                                    "type": {
                                        "qualType": f"struct (unnamed at {header}:{first_record_line}:5)"
                                    },
                                },
                                {
                                    "kind": "RecordDecl",
                                    "tagUsed": "struct",
                                    "completeDefinition": True,
                                    "loc": compact_location(second_record_line),
                                    "inner": [
                                        {
                                            "kind": "FieldDecl",
                                            "name": "member",
                                            "type": {"qualType": "long"},
                                        }
                                    ],
                                },
                                {
                                    "kind": "FieldDecl",
                                    "name": "second_record",
                                    "type": {
                                        "qualType": f"struct (unnamed at {header}:{second_record_line}:5)"
                                    },
                                },
                            ],
                        }
                    ],
                }

            project_header = project_root / "anonymous.h"
            musl_header = musl_root / "anonymous.h"
            project_header.write_text("/* candidate */\n", encoding="utf-8")
            musl_header.write_text("/* reference */\n", encoding="utf-8")

            candidate = MATRIX.discover_ast_facts(anonymous_ast(project_header), project_root)
            moved_reference = MATRIX.discover_ast_facts(
                anonymous_ast(musl_header, line_offset=30), musl_root
            )
            changed_enum = MATRIX.discover_ast_facts(
                anonymous_ast(musl_header, first_enum_value="9"), musl_root
            )
            changed_record = MATRIX.discover_ast_facts(
                anonymous_ast(musl_header, first_record_member_type="long"), musl_root
            )
            switched_fields = MATRIX.discover_ast_facts(
                anonymous_ast(musl_header, switch_enum_fields=True), musl_root
            )

        self.assertEqual(MATRIX.compare_facts(candidate, moved_reference)["incompatible"], [])
        self.assertEqual(MATRIX.compare_facts(candidate, changed_enum)["incompatible_count"], 1)
        self.assertEqual(MATRIX.compare_facts(candidate, changed_record)["incompatible_count"], 1)
        self.assertEqual(MATRIX.compare_facts(candidate, switched_fields)["incompatible_count"], 1)
        container = next(fact for fact in candidate if fact["name"] == "container")
        self.assertIn("enum{FIRST=1}", container["signature"])
        self.assertIn("struct{member:int}", container["signature"])

    def test_real_clang_anonymous_records_retain_nested_and_promoted_members(self) -> None:
        """Keep pinned-Clang's anonymous-record AST facts structural.

        This uses Clang's actual compact locations and its distinct
        ``unnamed struct`` and promoted ``anonymous`` type spellings. Moving
        the declarations is not a source-form difference, while changing a
        deeply nested anonymous member or a promoted anonymous union member
        is one named-record difference.
        """

        def source(*, padding: int = 0, deep_type: str = "int", union_type: str = "int") -> str:
            return (
                "\n" * padding
                + "struct nested_owner {\n"
                + "    struct {\n"
                + "        struct {\n"
                + f"            {deep_type} deep;\n"
                + "        } middle;\n"
                + "    } outer;\n"
                + "};\n\n"
                + "struct promoted_owner {\n"
                + "    union {\n"
                + f"        {union_type} first;\n"
                + "        struct {\n"
                + "            int nested;\n"
                + "        } record;\n"
                + "    };\n"
                + "};\n"
            )

        with tempfile.TemporaryDirectory(
            prefix="anonymous-record-clang-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            root = Path(temporary)
            header = root / "anonymous.h"
            probe = root / "probe.c"
            probe.write_text('#include "anonymous.h"\n', encoding="utf-8")

            def facts_for(**source_arguments: object) -> list[dict[str, str]]:
                header.write_text(source(**source_arguments), encoding="utf-8")
                result = subprocess.run(
                    [
                        "clang",
                        "-x",
                        "c",
                        "-std=c11",
                        "-nostdinc",
                        "-I",
                        str(root),
                        "-Xclang",
                        "-ast-dump=json",
                        "-fsyntax-only",
                        str(probe),
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                ast = json.loads(result.stdout)
                return MATRIX.discover_ast_facts(ast, root, "anonymous.h")

            candidate = facts_for()
            moved_reference = facts_for(padding=11)
            changed_nested = facts_for(deep_type="long")
            changed_promoted = facts_for(union_type="long")

        self.assertEqual(MATRIX.compare_facts(candidate, moved_reference)["incompatible"], [])
        self.assertEqual(MATRIX.compare_facts(candidate, changed_nested)["incompatible_count"], 1)
        self.assertEqual(MATRIX.compare_facts(candidate, changed_promoted)["incompatible_count"], 1)
        promoted = next(fact for fact in candidate if fact["name"] == "promoted_owner")
        self.assertIn("anonymous", promoted["signature"])
        self.assertIn("union", promoted["signature"])

    def test_macro_discovery_keeps_only_the_final_active_definition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "fcntl.h"
            header.write_text("/* synthetic preprocessor origin */\n", encoding="utf-8")
            preprocessed = "\n".join(
                [
                    f'# 1 "{header}"',
                    "#define O_CREAT 64",
                    "#undef O_CREAT",
                    "#define O_CREAT 0100",
                    "",
                ]
            )

            facts = MATRIX.discover_macro_facts(preprocessed, root)

        self.assertEqual(
            facts,
            [MATRIX.fact("macro", "O_CREAT", "object-like: 0100")],
        )

    def test_macro_facts_retain_whitespace_visible_to_stringification(self) -> None:
        """A macro space survives two-stage stringification and is a source fact."""

        with tempfile.TemporaryDirectory(
            prefix="macro-stringification-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            probe = Path(temporary) / "stringification.c"
            probe.write_text(
                "#define STRINGIFY_RAW(value) #value\n"
                "#define STRINGIFY(value) STRINGIFY_RAW(value)\n"
                "#define SPACED ((void *) -1)\n"
                "#define COMPACT ((void *)-1)\n"
                "const char *spaced = STRINGIFY(SPACED);\n"
                "const char *compact = STRINGIFY(COMPACT);\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["clang", "-E", "-P", str(probe)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('const char *spaced = "((void *) -1)";', result.stdout)
        self.assertIn('const char *compact = "((void *)-1)";', result.stdout)
        spaced = MATRIX.macro_definition("#define MAP_FAILED ((void *) -1)")
        compact = MATRIX.macro_definition("#define MAP_FAILED ((void *)-1)")
        self.assertNotEqual(spaced, compact)
        self.assertEqual(spaced, ("MAP_FAILED", "object-like: ((void *) -1)"))
        self.assertEqual(compact, ("MAP_FAILED", "object-like: ((void *)-1)"))

    def test_compiler_collection_digest_binds_headers_profiles_pins_and_oracle(self) -> None:
        """Provider accounting is not a compiler input, unlike these facts."""
        contract = MATRIX.load_contract()
        collector = {"id": "declaration-form-v1"}
        with tempfile.TemporaryDirectory(
            prefix="compiler-collection-input-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            candidate = Path(temporary) / "include"
            shutil.copytree(ROOT / "include", candidate)
            baseline = MATRIX.compiler_collection_input_digest(
                public_headers=contract.public_headers,
                profiles=contract.profiles,
                project_include=candidate,
                oracle_not_applicable=contract.oracle_not_applicable,
                collector=collector,
            )

            source = next(path for path in sorted(candidate.rglob("*.h")) if path.is_file())
            source.write_bytes(source.read_bytes() + b"\n/* collection-input mutation */\n")
            self.assertNotEqual(
                baseline,
                MATRIX.compiler_collection_input_digest(
                    public_headers=contract.public_headers,
                    profiles=contract.profiles,
                    project_include=candidate,
                    oracle_not_applicable=contract.oracle_not_applicable,
                    collector=collector,
                ),
            )

            source.write_bytes(source.read_bytes().replace(b"\n/* collection-input mutation */\n", b""))
            changed_profiles = (
                dataclasses.replace(
                    contract.profiles[0],
                    defines=(*contract.profiles[0].defines, "CRABC_COLLECTION_INPUT_TEST=1"),
                ),
                *contract.profiles[1:],
            )
            self.assertNotEqual(
                baseline,
                MATRIX.compiler_collection_input_digest(
                    public_headers=contract.public_headers,
                    profiles=changed_profiles,
                    project_include=candidate,
                    oracle_not_applicable=contract.oracle_not_applicable,
                    collector=collector,
                ),
            )

            changed_oracle = dict(contract.oracle_not_applicable)
            changed_oracle[("synthetic.h", "c11-gnu")] = "synthetic oracle exception"
            self.assertNotEqual(
                baseline,
                MATRIX.compiler_collection_input_digest(
                    public_headers=contract.public_headers,
                    profiles=contract.profiles,
                    project_include=candidate,
                    oracle_not_applicable=changed_oracle,
                    collector=collector,
                ),
            )

            original_pin = MATRIX.callable_inventory.MUSL_SOURCE_SHA256
            try:
                MATRIX.callable_inventory.MUSL_SOURCE_SHA256 = "0" * 64
                self.assertNotEqual(
                    baseline,
                    MATRIX.compiler_collection_input_digest(
                        public_headers=contract.public_headers,
                        profiles=contract.profiles,
                        project_include=candidate,
                        oracle_not_applicable=contract.oracle_not_applicable,
                        collector=collector,
                    ),
                )
            finally:
                MATRIX.callable_inventory.MUSL_SOURCE_SHA256 = original_pin

    def test_compiler_collection_digest_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compiler-collection-symlink-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            root = Path(temporary) / "include"
            root.mkdir()
            outside = Path(temporary) / "outside.h"
            outside.write_text("/* outside */\n", encoding="utf-8")
            (root / "escaped.h").symlink_to(outside)

            with self.assertRaisesRegex(MATRIX.HeaderAbiMatrixError, "symlink"):
                MATRIX.header_tree_digest(root)

    def test_compiler_collection_digest_rejects_symlinked_parent_root(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compiler-collection-parent-symlink-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            temporary_root = Path(temporary)
            physical_checkout = temporary_root / "physical-checkout"
            include = physical_checkout / "include"
            include.mkdir(parents=True)
            (include / "demo.h").write_text("/* physical input */\n", encoding="utf-8")
            linked_checkout = temporary_root / "linked-checkout"
            linked_checkout.symlink_to(physical_checkout, target_is_directory=True)

            with self.assertRaisesRegex(MATRIX.HeaderAbiMatrixError, "physical"):
                MATRIX.header_tree_digest(linked_checkout / "include")

    def test_collect_tree_uses_bounded_parallel_isolated_workspaces(self) -> None:
        profiles = MATRIX.load_contract().profiles[:2]
        observed_work_dirs: list[Path] = []
        active = 0
        peak_active = 0
        lock = threading.Lock()
        first_pair = threading.Event()

        def fake_compiler_profile(**arguments):
            nonlocal active, peak_active
            work_dir = arguments["work_dir"]
            assert isinstance(work_dir, Path)
            with lock:
                observed_work_dirs.append(work_dir)
                active += 1
                peak_active = max(peak_active, active)
                if active >= 2:
                    first_pair.set()
            work_dir.joinpath("probe.c").write_text(arguments["header"], encoding="utf-8")
            first_pair.wait(timeout=2)
            with lock:
                active -= 1
            return "ok", "synthetic compiler result", []

        original = MATRIX.compiler_profile
        try:
            MATRIX.compiler_profile = fake_compiler_profile
            records = MATRIX.collect_tree(
                tree="candidate",
                compiler="clang",
                profiles=profiles,
                headers=("alpha.h", "beta.h"),
                header_root=ROOT / "include",
                resource_include=ROOT / "include",
                linux_uapi_include=ROOT / "include",
                oracle_not_applicable={},
                workers=2,
            )
        finally:
            MATRIX.compiler_profile = original

        self.assertEqual(peak_active, 2)
        self.assertEqual(len(observed_work_dirs), 4)
        self.assertEqual(len(set(observed_work_dirs)), 4)
        expected_root = ROOT / ".work" / "x86_64" / "header-abi-matrix"
        for work_dir in observed_work_dirs:
            self.assertTrue(work_dir.is_relative_to(expected_root))
            self.assertFalse(work_dir.exists())
        self.assertEqual(set(records), {("alpha.h", profile.identifier) for profile in profiles} | {("beta.h", profile.identifier) for profile in profiles})

    def test_collection_worker_bound_is_explicit(self) -> None:
        self.assertEqual(MATRIX.DEFAULT_COLLECTION_WORKERS, 4)
        self.assertEqual(MATRIX.bounded_collection_workers(1), 1)
        self.assertEqual(MATRIX.bounded_collection_workers(8), 8)
        for invalid in (0, 9, True):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(MATRIX.HeaderAbiMatrixError, "workers"):
                    MATRIX.bounded_collection_workers(invalid)

    def test_collect_tree_retains_failed_job_artifacts(self) -> None:
        expected_root = ROOT / ".work" / "x86_64" / "header-abi-matrix"
        expected_root.mkdir(parents=True, exist_ok=True)
        before = set(expected_root.iterdir())

        def fake_compiler_profile(**arguments):
            work_dir = arguments["work_dir"]
            assert isinstance(work_dir, Path)
            work_dir.joinpath("probe.c").write_text("failed synthetic probe\n", encoding="utf-8")
            return "failed", "synthetic compiler failure", []

        original = MATRIX.compiler_profile
        try:
            MATRIX.compiler_profile = fake_compiler_profile
            diagnostics = io.StringIO()
            with contextlib.redirect_stderr(diagnostics):
                records = MATRIX.collect_tree(
                    tree="candidate",
                    compiler="clang",
                    profiles=MATRIX.load_contract().profiles[:1],
                    headers=("alpha.h",),
                    header_root=ROOT / "include",
                    resource_include=ROOT / "include",
                    linux_uapi_include=ROOT / "include",
                    oracle_not_applicable={},
                    workers=1,
                )
        finally:
            MATRIX.compiler_profile = original

        self.assertEqual(records[("alpha.h", "c11-gnu")]["status"], "failed")
        self.assertEqual(records[("alpha.h", "c11-gnu")]["detail"], "synthetic compiler failure")
        self.assertIn("scratch retained at .work/x86_64/header-abi-matrix/", diagnostics.getvalue())
        created = set(expected_root.iterdir()) - before
        self.assertEqual(len(created), 1)
        workspace = created.pop()
        try:
            self.assertTrue(workspace.is_dir() and not workspace.is_symlink())
            self.assertTrue((workspace / "jobs").is_dir())
            self.assertEqual(
                sorted(path.read_text(encoding="utf-8") for path in workspace.glob("jobs/*/probe.c")),
                ["failed synthetic probe\n"],
            )
        finally:
            shutil.rmtree(workspace)

    def test_compiler_command_timeout_kills_its_process_group(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compiler-command-timeout-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            pid_path = Path(temporary) / "child.pid"
            command = [
                sys.executable,
                "-c",
                (
                    "import pathlib, subprocess, sys, time; "
                    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                    f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); "
                    "time.sleep(60)"
                ),
            ]
            with self.assertRaisesRegex(MATRIX.CompilerCommandTimeout, "timed out"):
                MATRIX.run_compiler_command(command, timeout_seconds=0.75)
            self.assertTrue(pid_path.is_file())
            child_pid = int(pid_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                state_path = Path(f"/proc/{child_pid}/stat")
                if not state_path.exists() or state_path.read_text(encoding="utf-8").split()[2] == "Z":
                    break
                time.sleep(0.02)
            state_path = Path(f"/proc/{child_pid}/stat")
            self.assertTrue(
                not state_path.exists() or state_path.read_text(encoding="utf-8").split()[2] == "Z",
                "timed-out compiler descendant remained live",
            )

    def test_timeout_kills_pipe_holding_descendant_after_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compiler-command-dead-leader-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            pid_path = Path(temporary) / "child.pid"
            job_tmp = Path(temporary) / "job-tmp"
            job_tmp.mkdir()
            command = [
                sys.executable,
                "-c",
                (
                    "import pathlib, subprocess, sys; "
                    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                    f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid))"
                ),
            ]
            outcome: list[BaseException] = []

            def run_command() -> None:
                try:
                    MATRIX.run_compiler_command(
                        command,
                        timeout_seconds=0.2,
                        temporary_directory=job_tmp,
                    )
                except BaseException as error:
                    outcome.append(error)

            worker = threading.Thread(target=run_command)
            worker.start()
            deadline = time.monotonic() + 2
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            try:
                self.assertTrue(pid_path.is_file(), "pipe-holding compiler descendant did not start")
                worker.join(timeout=2)
                if worker.is_alive():
                    os.kill(int(pid_path.read_text(encoding="utf-8")), 9)
                    worker.join(timeout=2)
                    self.fail("timeout did not terminate a pipe-holding compiler descendant")
                self.assertEqual(len(outcome), 1)
                self.assertIsInstance(outcome[0], MATRIX.CompilerCommandTimeout)
            finally:
                if pid_path.exists():
                    try:
                        os.kill(int(pid_path.read_text(encoding="utf-8")), 9)
                    except ProcessLookupError:
                        pass
                worker.join(timeout=2)

    def test_compiler_command_uses_a_job_local_tmpdir_and_rejects_nonfinite_timeout(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compiler-command-tmpdir-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            job_tmp = Path(temporary) / "job-tmp"
            job_tmp.mkdir()
            result = MATRIX.run_compiler_command(
                [sys.executable, "-c", "import os; print(os.environ['TMPDIR'])"],
                timeout_seconds=1,
                temporary_directory=job_tmp,
            )
            self.assertEqual(result.stdout.strip(), str(job_tmp))
            for timeout in (float("inf"), float("nan")):
                with self.subTest(timeout=timeout):
                    with self.assertRaisesRegex(MATRIX.HeaderAbiMatrixError, "timeout"):
                        MATRIX.run_compiler_command(
                            [sys.executable, "-c", "raise SystemExit(0)"],
                            timeout_seconds=timeout,
                            temporary_directory=job_tmp,
                        )

    def test_reference_timeout_cannot_be_reclassified_as_oracle_not_applicable(self) -> None:
        original = MATRIX.run_compiler_command
        expected_root = ROOT / ".work" / "x86_64" / "header-abi-matrix"
        before = set(expected_root.iterdir())
        diagnostics = io.StringIO()

        def timed_out(*_arguments, **_keywords):
            raise MATRIX.CompilerCommandTimeout("synthetic compiler timeout")

        try:
            MATRIX.run_compiler_command = timed_out
            with contextlib.redirect_stderr(diagnostics):
                with self.assertRaisesRegex(MATRIX.HeaderAbiMatrixError, "compiler collection failed"):
                    MATRIX.collect_tree(
                        tree="reference",
                        compiler="clang",
                        profiles=(
                            next(
                                profile
                                for profile in MATRIX.load_contract().profiles
                                if profile.identifier == "c11-strict"
                            ),
                        ),
                        headers=("aio.h",),
                        header_root=ROOT / "include",
                        resource_include=ROOT / "include",
                        linux_uapi_include=ROOT / "include",
                        oracle_not_applicable={("aio.h", "c11-strict"): "known source limitation"},
                        workers=1,
                    )
        finally:
            MATRIX.run_compiler_command = original
            for workspace in set(expected_root.iterdir()) - before:
                if workspace.is_dir() and not workspace.is_symlink():
                    shutil.rmtree(workspace)
        self.assertIn("scratch retained at .work/x86_64/header-abi-matrix/", diagnostics.getvalue())

    def test_compiler_job_cancellation_kills_its_process_group(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compiler-command-cancel-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            pid_path = Path(temporary) / "child.pid"
            command = [
                sys.executable,
                "-c",
                (
                    "import pathlib, subprocess, sys, time; "
                    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                    f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid)); "
                    "time.sleep(60)"
                ),
            ]
            control = MATRIX.CompilerJobControl()
            outcome: list[BaseException] = []

            def run_command() -> None:
                try:
                    MATRIX.run_compiler_command(
                        command,
                        timeout_seconds=30,
                        job_control=control,
                    )
                except BaseException as error:
                    outcome.append(error)

            worker = threading.Thread(target=run_command)
            worker.start()
            deadline = time.monotonic() + 2
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            try:
                self.assertTrue(pid_path.is_file(), "compiler child did not start")
                control.cancel()
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive(), "cancelled compiler worker did not exit")
                self.assertEqual(len(outcome), 1)
                self.assertIsInstance(outcome[0], MATRIX.CompilerJobCancelled)
                child_pid = int(pid_path.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    state_path = Path(f"/proc/{child_pid}/stat")
                    if not state_path.exists() or state_path.read_text(encoding="utf-8").split()[2] == "Z":
                        break
                    time.sleep(0.02)
                state_path = Path(f"/proc/{child_pid}/stat")
                self.assertTrue(
                    not state_path.exists() or state_path.read_text(encoding="utf-8").split()[2] == "Z",
                    "cancelled compiler descendant remained live",
                )
            finally:
                control.cancel()
                worker.join(timeout=3)

    def test_checked_report_ignores_provider_only_inventory_projection(self) -> None:
        """A feature roster/accounting edit must not force Clang recollection."""
        contract = MATRIX.load_contract()
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(
            prefix="provider-projection-",
            dir=self.matrix_test_work_root(),
        ) as temporary:
            provider_only_inventory = Path(temporary) / "header_callable_inventory.json"
            projection = json.loads(contract.callable_inventory.read_text(encoding="utf-8"))
            projection["callable_provider_partition"]["unprovided"] = ["synthetic_provider_only"]
            projection["summary"]["callable_provider_counts"] = {"unprovided": 1}
            provider_only_inventory.write_text(
                json.dumps(projection, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            MATRIX.validate_checked_report(
                checked,
                dataclasses.replace(contract, callable_inventory=provider_only_inventory),
            )

    def test_checked_report_is_a_deterministic_partial_header_abi_record(self) -> None:
        contract = MATRIX.load_contract()
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))

        MATRIX.validate_checked_report(checked, contract)
        self.assertEqual(checked["schema"], MATRIX.SCHEMA)
        self.assertFalse(checked["summary"]["complete"])
        self.assertEqual(checked["summary"]["row_count"], 1337)
        self.assertEqual(checked["scope"]["archive_linkage"], False)
        self.assertEqual(checked["scope"]["runtime"], False)
        self.assertEqual(checked["work_package"]["target_family"], "libc.headers-layouts")
        self.assertEqual(
            checked["work_package"]["target_obligations"],
            ["callable-prototype-layout", "noncallable-header-abi"],
        )
        self.assertIn("generated-x86-prototype-layout-matrix", checked["work_package"]["evidence"])

        runner = RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "header_abi_matrix.py",
            "--check",
            "Pinned musl",
            "Linux 5.10",
            "partial declaration-form inventory",
        ):
            self.assertIn(phrase, runner)

    def test_dirent_and_sys_dir_have_exact_pinned_source_forms(self) -> None:
        """The directory compatibility aliases must not hide a second header form."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        profiles = {
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        }

        rows = [
            row
            for row in checked["rows"]
            if row["header"] in {"dirent.h", "sys/dir.h"}
        ]
        self.assertEqual(
            {(row["header"], row["profile"]) for row in rows},
            {
                (header, profile)
                for header in ("dirent.h", "sys/dir.h")
                for profile in profiles
            },
        )
        for row in rows:
            self.assertEqual(row["comparison"], "matched")
            self.assertEqual(row["difference"]["candidate_only_count"], 0)
            self.assertEqual(row["difference"]["incompatible_count"], 0)
            self.assertEqual(row["difference"]["reference_only_count"], 0)

    def test_spawn_header_matches_pinned_musl_source_forms(self) -> None:
        """Keep POSIX spawn declarations and feature-independent flags exact."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        profiles = {
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        }
        rows = [row for row in checked["rows"] if row["header"] == "spawn.h"]
        self.assertEqual({row["profile"] for row in rows}, profiles)
        for row in rows:
            with self.subTest(profile=row["profile"]):
                self.assertEqual(row["candidate_status"], "ok")
                self.assertEqual(row["reference_status"], "ok")
                self.assertEqual(row["comparison"], "matched")
                self.assertEqual(row["difference"]["candidate_only_count"], 0)
                self.assertEqual(row["difference"]["incompatible_count"], 0)
                self.assertEqual(row["difference"]["reference_only_count"], 0)

    def test_time_header_matches_pinned_musl_source_forms(self) -> None:
        """Keep time feature visibility and declaration forms source-faithful."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        profiles = {
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        }
        rows = [row for row in checked["rows"] if row["header"] == "time.h"]

        self.assertEqual({row["profile"] for row in rows}, profiles)
        for row in rows:
            with self.subTest(profile=row["profile"]):
                self.assertEqual(row["candidate_status"], "ok")
                self.assertEqual(row["reference_status"], "ok")
                self.assertEqual(row["comparison"], "matched")
                self.assertEqual(row["difference"]["candidate_only_count"], 0)
                self.assertEqual(row["difference"]["incompatible_count"], 0)
                self.assertEqual(row["difference"]["reference_only_count"], 0)

    def test_cpio_file_type_literals_match_pinned_musl_source_forms(self) -> None:
        """Keep the historical cpio file-type macro tokens exact across profiles."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        profiles = {
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        }
        names = {"C_ISBLK", "C_ISCHR", "C_ISDIR", "C_ISFIFO"}
        rows = [row for row in checked["rows"] if row["header"] == "cpio.h"]
        self.assertEqual({row["profile"] for row in rows}, profiles)
        for row in rows:
            with self.subTest(profile=row["profile"]):
                difference = row["difference"]
                for field in ("candidate_only", "incompatible", "reference_only"):
                    self.assertEqual(
                        [fact for fact in difference[field] if fact["name"] in names],
                        [],
                        f"cpio.h:{row['profile']} {field} file-type macro facts",
                    )

    def test_fmtmsg_null_macros_match_pinned_musl_source_forms(self) -> None:
        """Keep the historical fmtmsg null macro tokens exact across profiles."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        profiles = {
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        }
        names = {"MM_NULLACT", "MM_NULLLBL", "MM_NULLTAG", "MM_NULLTXT"}
        rows = [row for row in checked["rows"] if row["header"] == "fmtmsg.h"]
        self.assertEqual({row["profile"] for row in rows}, profiles)
        for row in rows:
            with self.subTest(profile=row["profile"]):
                difference = row["difference"]
                for field in ("candidate_only", "incompatible", "reference_only"):
                    self.assertEqual(
                        [fact for fact in difference[field] if fact["name"] in names],
                        [],
                        f"fmtmsg.h:{row['profile']} {field} null macro facts",
                    )

    def test_quota_header_has_no_owned_pinned_musl_fact_differences(self) -> None:
        """Keep quota-header completion distinct from inherited stdint.h differences."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        owned_names = {
            "_LINUX_QUOTA_VERSION",
            "MAX_IQ_TIME",
            "MAX_DQ_TIME",
            "MAXQUOTAS",
            "INITQFNAMES",
            "QUOTAFILENAME",
            "QUOTAGROUP",
            "NR_DQHASH",
            "NR_DQUOTS",
            "dq_bhardlimit",
            "dq_bsoftlimit",
            "dq_curspace",
            "dq_valid",
            "dq_ihardlimit",
            "dq_isoftlimit",
            "dq_curinodes",
            "dq_btime",
            "dq_itime",
            "IIF_BGRACE",
            "IIF_IGRACE",
            "IIF_FLAGS",
            "IIF_ALL",
            "dqinfo",
            "PRJQUOTA",
            "Q_GETNEXTQUOTA",
            "QFMT_SHMEM",
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
        rows = [row for row in checked["rows"] if row["header"] == "sys/quota.h"]
        self.assertEqual({row["profile"] for row in rows}, profiles)
        for row in rows:
            difference = row["difference"]
            differing_names = {
                fact["name"]
                for facts in (
                    difference["candidate_only"],
                    difference["incompatible"],
                    difference["reference_only"],
                )
                for fact in facts
            }
            self.assertFalse(
                owned_names & differing_names,
                f"quota-owned facts drifted in {row['profile']}: "
                f"{sorted(owned_names & differing_names)}",
            )

    def test_gnu_namespace_declarations_keep_cxx_c_linkage(self) -> None:
        """The canonical C++ profiles retain musl's GNU namespace spellings."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        expected = {
            ("sched.h", "cxx17-gnu"),
            ("sched.h", "cxx17-strict"),
            ("pthread.h", "cxx17-gnu"),
            ("pthread.h", "cxx17-strict"),
        }
        rows = [
            row
            for row in checked["rows"]
            if (row["header"], row["profile"]) in expected
        ]
        self.assertEqual(
            {(row["header"], row["profile"]) for row in rows}, expected
        )

        names = {"setns", "unshare"}
        for row in rows:
            difference = row["difference"]
            for field in ("reference_only", "candidate_only", "incompatible"):
                facts = [
                    fact
                    for fact in difference[field]
                    if fact.get("name") in names
                ]
                self.assertEqual(
                    facts,
                    [],
                    f"{row['header']}:{row['profile']} {field} GNU namespace facts",
                )

    def test_statx_gnu_declaration_and_record_facts_match_without_claiming_a_provider(self) -> None:
        """The declaration matrix closes the public surface, not archive linkage."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = ("c11-gnu", "cxx17-gnu", "cxx17-strict")
        names = {
            "statx",
            "statx_timestamp",
            "STATX_TYPE",
            "STATX_MODE",
            "STATX_NLINK",
            "STATX_UID",
            "STATX_GID",
            "STATX_ATIME",
            "STATX_MTIME",
            "STATX_CTIME",
            "STATX_INO",
            "STATX_SIZE",
            "STATX_BLOCKS",
            "STATX_BASIC_STATS",
            "STATX_BTIME",
            "STATX_ALL",
            "STATX_MNT_ID",
            "STATX_DIOALIGN",
            "STATX_MNT_ID_UNIQUE",
            "STATX_SUBVOL",
            "STATX_WRITE_ATOMIC",
            "STATX_ATTR_COMPRESSED",
            "STATX_ATTR_IMMUTABLE",
            "STATX_ATTR_APPEND",
            "STATX_ATTR_NODUMP",
            "STATX_ATTR_ENCRYPTED",
            "STATX_ATTR_AUTOMOUNT",
            "STATX_ATTR_MOUNT_ROOT",
            "STATX_ATTR_VERITY",
            "STATX_ATTR_DAX",
            "STATX_ATTR_WRITE_ATOMIC",
        }

        for header in ("sys/stat.h", "ftw.h"):
            for profile in profiles:
                difference = rows[(header, profile)]["difference"]
                for field in ("candidate_only", "incompatible", "reference_only"):
                    facts = [
                        fact for fact in difference[field] if fact.get("name") in names
                    ]
                    self.assertEqual(
                        facts,
                        [],
                        f"{header}:{profile} {field} statx declaration/layout facts",
                    )

    def test_wordexp_declarations_keep_cxx_c_linkage_without_claiming_a_provider(self) -> None:
        """C++ consumers must retain musl's unmangled wordexp declarations."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        names = {"wordexp", "wordfree"}

        for profile in ("cxx17-gnu", "cxx17-strict"):
            difference = rows[("wordexp.h", profile)]["difference"]
            for field in ("candidate_only", "incompatible", "reference_only"):
                facts = [
                    fact for fact in difference[field] if fact.get("name") in names
                ]
                self.assertEqual(
                    facts,
                    [],
                    f"wordexp.h:{profile} {field} C linkage facts",
                )

    def test_shared_type_headers_keep_musl_type_ownership_boundaries(self) -> None:
        """Shared type requests must not turn adjacent headers into type providers."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("sys/types.h", profile)]
            self.assertEqual(
                row["comparison"],
                "matched",
                f"sys/types.h:{profile} must retain musl's complete type vocabulary",
            )

        public_type_names = {
            "blkcnt_t",
            "blksize_t",
            "clockid_t",
            "dev_t",
            "fsblkcnt_t",
            "fsfilcnt_t",
            "gid_t",
            "id_t",
            "ino_t",
            "key_t",
            "mode_t",
            "nlink_t",
            "off_t",
            "once_flag",
            "pid_t",
            "pthread_attr_t",
            "pthread_barrier_t",
            "pthread_barrierattr_t",
            "pthread_cond_t",
            "pthread_condattr_t",
            "pthread_key_t",
            "pthread_mutex_t",
            "pthread_mutexattr_t",
            "pthread_once_t",
            "pthread_rwlock_t",
            "pthread_rwlockattr_t",
            "pthread_spinlock_t",
            "pthread_t",
            "ssize_t",
            "suseconds_t",
            "thrd_t",
            "timer_t",
            "tss_t",
            "uid_t",
            "useconds_t",
        }

        def is_type_owner_fact(fact):
            name = fact.get("name", "")
            return (
                name in public_type_names
                or name.startswith("__DEFINED_")
                or name.startswith("__NEED_")
                or name
                in {
                    "_PTHREAD_TYPES_DEFINED",
                    "_SYS_TYPES_H",
                    "__pthread",
                }
            )

        for header in ("pthread.h", "threads.h"):
            for profile in profiles:
                difference = rows[(header, profile)]["difference"]
                for field in ("candidate_only", "incompatible", "reference_only"):
                    facts = [
                        fact
                        for fact in difference[field]
                        if is_type_owner_fact(fact)
                    ]
                    self.assertEqual(
                        facts,
                        [],
                        f"{header}:{profile} {field} shared type-owner facts",
                    )

    def test_network_resolver_headers_preserve_their_owned_musl_x86_closure(self) -> None:
        """Keep the shared x86 network/resolver include graph source-faithful.

        These direct consumers share the ``stdint``/socket/IPv4-IPv6 spine.
        Local ABI compatibility is not enough: each must retain musl's selected
        feature visibility, record forms, macro spellings, and C/C++ declarations.

        The all-header ABI matrix reports every declaration inherited by a direct
        include. ``netinet/icmp6.h`` reaches the byte-string headers through its
        musl-owned include path, so that path must retain their selected feature
        visibility and declaration forms as well as the network records. A new
        difference, including an ``in6_addr``, ``ip6_hdr``, ``__res_state``, or
        byte-string source-form regression, must fail this slice immediately.
        The nameser/resolver roots must remain exact through their shared musl
        ``stddef.h`` request boundary.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        headers = (
            "stdint.h",
            "inttypes.h",
            "sys/socket.h",
            "arpa/inet.h",
            "arpa/nameser.h",
            "arpa/nameser_compat.h",
            "netdb.h",
            "resolv.h",
            "netinet/in.h",
            "netinet/tcp.h",
            "netinet/ip.h",
            "netinet/ip6.h",
            "netinet/ip_icmp.h",
            "netinet/igmp.h",
            "netinet/icmp6.h",
        )
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )
        for header in headers:
            for profile in profiles:
                row = rows[(header, profile)]
                self.assertEqual(
                    row["comparison"],
                    "matched",
                    f"{header}:{profile} must retain the complete musl-owned "
                    "network/resolver declaration closure",
                )

        self.assertEqual(len(headers) * len(profiles), 105)

    def test_byte_string_headers_preserve_musl_x86_declaration_forms(self) -> None:
        """Keep direct byte-string declaration forms and feature closure exact.

        The compile-only byte-string gate proves C/C++ spelling, linkage, and
        feature visibility, while this compiler-derived matrix keeps the
        source-significant ``restrict`` forms and GNU/BSD ``strings.h`` include
        closure from silently drifting. ``netinet/icmp6.h`` consumes this same
        public boundary and is covered separately by the network closure test.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        headers = ("string.h", "strings.h")
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for header in headers:
            for profile in profiles:
                self.assertEqual(
                    rows[(header, profile)]["comparison"],
                    "matched",
                    f"{header}:{profile} must retain musl's byte-string "
                    "declaration form and selected feature closure",
                )

        self.assertEqual(len(headers) * len(profiles), 14)

    def test_sys_time_header_preserves_musl_x86_timer_macro_forms(self) -> None:
        """Keep the direct timer/conversion macro replacements exact.

        Musl's GNU/BSD timer helpers and GNU conversion helpers are
        expression-valued comma forms. Their declaration names and feature
        visibility alone are insufficient: a statement-style replacement loses
        valid C and C++ expression contexts, and leaks that source-form debt
        into every direct consumer of sys/time.h.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("sys/time.h", profile)]
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(
                row["comparison"],
                "matched",
                f"sys/time.h:{profile} must retain musl's timer and conversion forms",
            )
            difference = row["difference"]
            self.assertEqual(difference["candidate_only"], [])
            self.assertEqual(difference["candidate_only_count"], 0)
            self.assertEqual(difference["incompatible"], [])
            self.assertEqual(difference["incompatible_count"], 0)
            self.assertEqual(difference["reference_only"], [])
            self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_ifaddrs_header_preserves_musl_x86_record_form_and_feature_context(self) -> None:
        """Keep the direct interface record's selected declaration form exact.

        The anonymous union in struct ifaddrs is a named declaration-form
        relationship. Musl's direct features.h request fixes its selected
        feature context; reshaping the record would recreate source-form debt
        in every C/C++ profile. Blank lines and comments do not alter that
        relationship. This remains header evidence only, not an interface
        discovery provider or runtime claim.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("ifaddrs.h", profile)]
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(
                row["comparison"],
                "matched",
                f"ifaddrs.h:{profile} must retain musl's direct record source form",
            )
            difference = row["difference"]
            self.assertEqual(difference["candidate_only"], [])
            self.assertEqual(difference["candidate_only_count"], 0)
            self.assertEqual(difference["incompatible"], [])
            self.assertEqual(difference["incompatible_count"], 0)
            self.assertEqual(difference["reference_only"], [])
            self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_sys_un_header_preserves_musl_x86_linkage_and_macro_forms(self) -> None:
        """Keep the Unix-socket header's C++ linkage and selected macro exact.

        Musl places its selected strlen declaration in C linkage and exposes
        SUN_LEN as one precise expression form. A local C++ declaration or
        whitespace-altered macro replacement changes compiler-observable
        source forms even though the underlying socket layout is unchanged.
        This is declaration evidence only, not a socket provider or runtime
        claim.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("sys/un.h", profile)]
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(
                row["comparison"],
                "matched",
                f"sys/un.h:{profile} must retain musl's selected source form",
            )
            difference = row["difference"]
            self.assertEqual(difference["candidate_only"], [])
            self.assertEqual(difference["candidate_only_count"], 0)
            self.assertEqual(difference["incompatible"], [])
            self.assertEqual(difference["incompatible_count"], 0)
            self.assertEqual(difference["reference_only"], [])
            self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_glob_header_preserves_musl_x86_c_linkage(self) -> None:
        """Keep glob and globfree unmangled in both C++ profiles.

        The direct glob declarations are source-owned by this header. Their
        pinned-musl C linkage is distinct from runtime provider selection:
        this regression only prevents a local C++ declaration from silently
        changing the compiler-visible callable forms.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("glob.h", profile)]
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(
                row["comparison"],
                "matched",
                f"glob.h:{profile} must preserve musl's C-linkage source form",
            )
            difference = row["difference"]
            self.assertEqual(difference["candidate_only"], [])
            self.assertEqual(difference["candidate_only_count"], 0)
            self.assertEqual(difference["incompatible"], [])
            self.assertEqual(difference["incompatible_count"], 0)
            self.assertEqual(difference["reference_only"], [])
            self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_stdbool_header_preserves_musl_x86_cxx_visibility(self) -> None:
        """Keep C's Boolean macros out of C++ consumers.

        Pinned musl deliberately limits bool, true, and false macro
        definitions to C. The include guard and
        __bool_true_false_are_defined remain visible to C++, but redefining
        its language keywords is a distinct direct-header source-form error.
        This checks declaration visibility only, not runtime behavior.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("stdbool.h", profile)]
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(
                row["comparison"],
                "matched",
                f"stdbool.h:{profile} must retain musl's C/C++ macro boundary",
            )
            difference = row["difference"]
            self.assertEqual(difference["candidate_only"], [])
            self.assertEqual(difference["candidate_only_count"], 0)
            self.assertEqual(difference["incompatible"], [])
            self.assertEqual(difference["incompatible_count"], 0)
            self.assertEqual(difference["reference_only"], [])
            self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_sys_random_header_preserves_musl_x86_type_ownership(self) -> None:
        """Keep the direct random header's narrow type request source-faithful.

        Pinned musl requests only size_t and ssize_t from bits/alltypes.h.
        Pulling the broad sys/types.h umbrella changes every direct
        compiler-visible header closure without selecting a random provider or
        runtime behavior. All feature profiles must retain the narrow direct
        source form.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("sys/random.h", profile)]
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(
                row["comparison"],
                "matched",
                f"sys/random.h:{profile} must retain musl's narrow type closure",
            )
            difference = row["difference"]
            self.assertEqual(difference["candidate_only"], [])
            self.assertEqual(difference["candidate_only_count"], 0)
            self.assertEqual(difference["incompatible"], [])
            self.assertEqual(difference["incompatible_count"], 0)
            self.assertEqual(difference["reference_only"], [])
            self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_sys_xattr_header_preserves_musl_x86_type_ownership(self) -> None:
        """Keep the direct xattr header's type requests source-faithful.

        Pinned musl requests size_t and ssize_t from bits/alltypes.h, then
        marks the public xattr spellings as already owned before any Linux UAPI
        consumer sees them. Pulling broad sys/types.h instead changes every
        direct compiler-visible header closure without selecting an xattr
        provider or runtime behavior. All feature profiles must retain the
        narrow direct source form.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("sys/xattr.h", profile)]
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(
                row["comparison"],
                "matched",
                f"sys/xattr.h:{profile} must retain musl's narrow type closure",
            )
            difference = row["difference"]
            self.assertEqual(difference["candidate_only"], [])
            self.assertEqual(difference["candidate_only_count"], 0)
            self.assertEqual(difference["incompatible"], [])
            self.assertEqual(difference["incompatible_count"], 0)
            self.assertEqual(difference["reference_only"], [])
            self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_sys_times_header_preserves_musl_x86_type_ownership(self) -> None:
        """Keep the direct times header's clock_t request source-faithful.

        Pinned musl requests clock_t from bits/alltypes.h and supplies the
        C++ linkage boundary around its one external declaration. Pulling
        broad sys/types.h leaks unrelated declarations into every direct
        consumer, while losing that linkage boundary changes the C++ source
        form. All feature profiles must retain the narrow direct source form.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for profile in profiles:
            row = rows[("sys/times.h", profile)]
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(
                row["comparison"],
                "matched",
                f"sys/times.h:{profile} must retain musl's narrow type closure",
            )
            difference = row["difference"]
            self.assertEqual(difference["candidate_only"], [])
            self.assertEqual(difference["candidate_only_count"], 0)
            self.assertEqual(difference["incompatible"], [])
            self.assertEqual(difference["incompatible_count"], 0)
            self.assertEqual(difference["reference_only"], [])
            self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_fsuid_and_timex_headers_preserve_musl_x86_type_ownership(self) -> None:
        """Keep the direct identity and time roots out of sys/types.h.

        Pinned musl requests only uid_t/gid_t for sys/fsuid.h and clockid_t
        for sys/timex.h.  Both headers must retain their narrow direct type
        closure through every C/C++ feature profile without claiming the
        GNU/BSD sys/types.h callable umbrella.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        headers = ("sys/fsuid.h", "sys/timex.h")
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for header in headers:
            for profile in profiles:
                row = rows[(header, profile)]
                self.assertEqual(row["candidate_status"], "ok")
                self.assertEqual(row["reference_status"], "ok")
                self.assertEqual(
                    row["comparison"],
                    "matched",
                    f"{header}:{profile} must retain musl's narrow type closure",
                )
                self.assertEqual(
                    row["difference"],
                    {
                        "candidate_only": [],
                        "candidate_only_count": 0,
                        "incompatible": [],
                        "incompatible_count": 0,
                        "matched_count": row["candidate"]["count"],
                        "reference_only": [],
                        "reference_only_count": 0,
                    },
                    f"{header}:{profile} must have no ownership or source-form debt",
                )

        self.assertEqual(len(headers) * len(profiles), 14)

    def test_stdarg_header_preserves_musl_x86_variadic_forms(self) -> None:
        """Keep va_list ownership and its direct err.h consumer source-faithful.

        The selected header owns the va_list request, C++ linkage boundary,
        and macro parameter/replacement forms. err.h includes stdarg.h
        directly, so it must retain those same compiler-visible source forms.
        This is source-form evidence only; separate variadic ABI gates retain
        behavioral evidence for the SysV AMD64 calling convention.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for header in ("stdarg.h", "err.h"):
            for profile in profiles:
                row = rows[(header, profile)]
                self.assertEqual(row["candidate_status"], "ok")
                self.assertEqual(row["reference_status"], "ok")
                self.assertEqual(
                    row["comparison"],
                    "matched",
                    f"{header}:{profile} must retain musl's variadic source forms",
                )
                difference = row["difference"]
                self.assertEqual(difference["candidate_only"], [])
                self.assertEqual(difference["candidate_only_count"], 0)
                self.assertEqual(difference["incompatible"], [])
                self.assertEqual(difference["incompatible_count"], 0)
                self.assertEqual(difference["reference_only"], [])
                self.assertEqual(difference["reference_only_count"], 0)

        self.assertEqual(len(profiles), 7)

    def test_signal_wait_aio_poll_headers_preserve_musl_x86_ownership(self) -> None:
        """Keep the signal/process-control declaration spine source-faithful.

        These direct consumers must request only their own musl types and use
        the private x86 ``bits/signal.h``/``bits/poll.h`` leaves rather than
        inheriting the legacy ``sys/types.h`` umbrella.  The one C11-strict
        ``aio.h`` reference limitation remains explicit: pinned musl embeds an
        incomplete ``struct sigevent`` there, while the candidate closure still
        has to compile the direct consumer.

        ``sys/wait.h`` reaches ``RUSAGE_CHILDREN`` through ``sys/resource.h``.
        The candidate's x86 branch and pinned musl both expose the exact
        object-like replacement ``(-1)`` for the BSD, GNU, and C++ profiles,
        so it is matched evidence rather than reviewed source-form debt.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        headers = ("signal.h", "sys/wait.h", "aio.h", "poll.h")
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for header in headers:
            for profile in profiles:
                row = rows[(header, profile)]
                self.assertEqual(row["candidate_status"], "ok")
                if (header, profile) == ("aio.h", "c11-strict"):
                    self.assertEqual(row["comparison"], "oracle-not-applicable")
                    self.assertEqual(row["reference_status"], "oracle-not-applicable")
                    continue

                self.assertEqual(
                    row["comparison"],
                    "matched",
                    f"{header}:{profile} must retain musl's exact source form",
                )
                self.assertEqual(row["reference_status"], "ok")
                difference = row["difference"]
                self.assertEqual(
                    difference,
                    {
                        "candidate_only": [],
                        "candidate_only_count": 0,
                        "incompatible": [],
                        "incompatible_count": 0,
                        "matched_count": row["candidate"]["count"],
                        "reference_only": [],
                        "reference_only_count": 0,
                    },
                    f"{header}:{profile} source declarations",
                )

        self.assertEqual(len(headers) * len(profiles), 28)

    def test_unistd_and_sendfile_headers_match_musl_x86_ownership(self) -> None:
        """Keep the process/file declaration boundary source-faithful.

        Musl owns the `unistd.h` type requests directly and makes
        `sys/sendfile.h` a small dependent of that header.  Neither public
        root may retain the legacy x86 `sys/types.h`/`stdint.h` umbrella or
        declarations that belong to fcntl, stat, or time headers.
        """
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }
        headers = ("unistd.h", "sys/sendfile.h")
        profiles = (
            "c11-bsd",
            "c11-gnu",
            "c11-posix-2008",
            "c11-strict",
            "c11-xopen-700",
            "cxx17-gnu",
            "cxx17-strict",
        )

        for header in headers:
            for profile in profiles:
                row = rows[(header, profile)]
                self.assertEqual(row["candidate_status"], "ok")
                self.assertEqual(row["reference_status"], "ok")
                self.assertEqual(
                    row["comparison"],
                    "matched",
                    f"{header}:{profile} must retain only musl-owned declarations",
                )
                self.assertEqual(
                    row["difference"],
                    {
                        "candidate_only": [],
                        "candidate_only_count": 0,
                        "incompatible": [],
                        "incompatible_count": 0,
                        "matched_count": row["candidate"]["count"],
                        "reference_only": [],
                        "reference_only_count": 0,
                    },
                    f"{header}:{profile} must have no ownership or source-form debt",
                )

        self.assertEqual(len(headers) * len(profiles), 14)

    def test_stdio_wchar_and_monetary_declarations_match_musl_forms(self) -> None:
        """Header visibility must not promote deferred stream or locale providers."""
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = {
            (row["header"], row["profile"]): row
            for row in checked["rows"]
        }

        profiles = (
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        )

        def assert_no_named_differences(selected_rows, names):
            for row in selected_rows:
                difference = row["difference"]
                for field in ("reference_only", "candidate_only", "incompatible"):
                    facts = [
                        fact
                        for fact in difference[field]
                        if fact.get("name") in names
                    ]
                    self.assertEqual(
                        facts,
                        [],
                        f"{row['header']}:{row['profile']} {field} stdio/locale facts",
                    )

        unlocked_gnu_or_bsd = {
            "clearerr_unlocked",
            "fflush_unlocked",
            "fgetc_unlocked",
            "fputc_unlocked",
            "fread_unlocked",
            "fwrite_unlocked",
            "getw",
            "putw",
        }
        unlocked_gnu_only = {"fgets_unlocked", "fputs_unlocked"}
        stdio_profiles = {
            "c11-bsd": unlocked_gnu_or_bsd,
            "c11-gnu": unlocked_gnu_or_bsd | unlocked_gnu_only,
            "cxx17-gnu": unlocked_gnu_or_bsd | unlocked_gnu_only,
            "cxx17-strict": unlocked_gnu_or_bsd | unlocked_gnu_only,
        }
        for header in ("stdio.h", "stdio_ext.h"):
            assert_no_named_differences(
                [rows[(header, profile)] for profile in stdio_profiles],
                set().union(*stdio_profiles.values()),
            )

        assert_no_named_differences(
            [rows[("wchar.h", profile)] for profile in profiles],
            {"fputws", "fgetws_unlocked", "fputws_unlocked"},
        )
        assert_no_named_differences(
            [rows[("monetary.h", profile)] for profile in profiles],
            {"strfmon_l"},
        )
        assert_no_named_differences(
            [
                rows[("monetary.h", "cxx17-gnu")],
                rows[("monetary.h", "cxx17-strict")],
            ],
            {"strfmon", "strfmon_l"},
        )

    def test_features_header_uses_pinned_musl_include_guard(self) -> None:
        """Keep the public feature-selection prelude's identity aligned with musl."""
        profiles = (
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        )
        source = (ROOT / "include" / "features.h").read_text(encoding="utf-8")
        self.assertTrue(
            source.startswith("#ifndef _FEATURES_H\n#define _FEATURES_H\n"),
            "features.h must use musl's _FEATURES_H include guard",
        )

        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))
        rows = [row for row in checked["rows"] if row["header"] == "features.h"]
        self.assertEqual([row["profile"] for row in rows], list(profiles))
        for row in rows:
            self.assertEqual(row["comparison"], "matched")
            self.assertEqual(row["candidate_status"], "ok")
            self.assertEqual(row["reference_status"], "ok")
            self.assertEqual(row["candidate"], row["reference"])
            self.assertEqual(
                row["difference"],
                {
                    "candidate_only": [],
                    "candidate_only_count": 0,
                    "incompatible": [],
                    "incompatible_count": 0,
                    "matched_count": 4,
                    "reference_only": [],
                    "reference_only_count": 0,
                },
                f"features.h:{row['profile']} must differ from musl in no facts",
            )

    def test_leaf_headers_use_pinned_musl_include_guards(self) -> None:
        """Keep isolated public-header identities out of private guard namespaces."""
        expected_headers = {
            "ar.h": ("_AR_H", (5, 5, 5, 5, 5, 5, 5)),
            "paths.h": ("_PATHS_H", (25, 25, 25, 25, 25, 25, 25)),
            "stdalign.h": ("_STDALIGN_H", (5, 3, 5, 5, 5, 5, 3)),
            "stdc-predef.h": ("_STDC_PREDEF_H", (3, 3, 3, 3, 3, 3, 3)),
            "sysexits.h": ("_SYSEXITS_H", (19, 19, 19, 19, 19, 19, 19)),
        }
        profiles = (
            "c11-gnu",
            "cxx17-gnu",
            "c11-strict",
            "c11-posix-2008",
            "c11-xopen-700",
            "c11-bsd",
            "cxx17-strict",
        )
        checked = json.loads(CHECKED_REPORT.read_text(encoding="utf-8"))

        for header_name, (guard, matched_counts) in expected_headers.items():
            source = (ROOT / "include" / header_name).read_text(encoding="utf-8")
            self.assertTrue(
                source.startswith(f"#ifndef {guard}\n#define {guard}\n"),
                f"{header_name} must use musl's {guard} include guard",
            )
            rows = [
                row for row in checked["rows"] if row["header"] == header_name
            ]
            self.assertEqual([row["profile"] for row in rows], list(profiles))
            for row, matched_count in zip(rows, matched_counts, strict=True):
                self.assertEqual(row["comparison"], "matched")
                self.assertEqual(row["candidate_status"], "ok")
                self.assertEqual(row["reference_status"], "ok")
                self.assertEqual(row["candidate"], row["reference"])
                self.assertEqual(
                    row["difference"],
                    {
                        "candidate_only": [],
                        "candidate_only_count": 0,
                        "incompatible": [],
                        "incompatible_count": 0,
                        "matched_count": matched_count,
                        "reference_only": [],
                        "reference_only_count": 0,
                    },
                    f"{header_name}:{row['profile']} must differ from musl in no facts",
                )

    def test_x86_header_slice_preserves_pinned_musl_guard_forms(self) -> None:
        """Keep the targeted x86 public wrappers and private leaves source-faithful."""
        guarded = {
            "setjmp.h": "_SETJMP_H",
            "stdnoreturn.h": "_STDNORETURN_H",
            "sys/file.h": "_SYS_FILE_H",
            "sys/io.h": "_SYS_IO_H",
            "sys/ptrace.h": "_SYS_PTRACE_H",
            "sys/statfs.h": "_SYS_STATFS_H",
            "sys/syscall.h": "_SYS_SYSCALL_H",
            "utime.h": "_UTIME_H",
        }
        unguarded = {
            "bits/setjmp.h",
            "bits/io.h",
            "sys/kd.h",
            "sys/poll.h",
            "bits/ptrace.h",
            "sys/soundcard.h",
            "bits/statfs.h",
            "sys/vfs.h",
            "sys/vt.h",
            "syscall.h",
        }

        for header_name, guard in guarded.items():
            source = (ROOT / "include" / header_name).read_text(encoding="utf-8")
            with self.subTest(header=header_name):
                self.assertTrue(
                    source.startswith(f"#ifndef {guard}\n#define {guard}\n"),
                    f"{header_name} must use musl's {guard} include guard",
                )

        for header_name in unguarded:
            source = (ROOT / "include" / header_name).read_text(encoding="utf-8")
            with self.subTest(header=header_name):
                self.assertNotRegex(
                    source,
                    r"(?m)^#ifndef\s+",
                    f"{header_name} must preserve musl's unguarded source form",
                )

    def test_x86_macro_forms_preserve_the_paused_aarch64_spellings(self) -> None:
        """Keep x86 source-form repair from changing the frozen AArch64 side."""

        mman = (ROOT / "include" / "sys" / "mman.h").read_text(encoding="utf-8")
        self.assertIn(
            "#if defined(__x86_64__)\n"
            "#define MLOCK_ONFAULT 0x01\n"
            "#else\n"
            "#define MLOCK_ONFAULT 0x01U\n"
            "#endif",
            mman,
        )

        acct = (ROOT / "include" / "sys" / "acct.h").read_text(encoding="utf-8")
        self.assertIn(
            "#if defined(__x86_64__)\n"
            "#define ACCT_BYTEORDER (128*(__BYTE_ORDER==__BIG_ENDIAN))\n"
            "#else\n"
            "#define ACCT_BYTEORDER (128 * (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))\n"
            "#endif",
            acct,
        )


if __name__ == "__main__":
    unittest.main()
