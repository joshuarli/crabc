#!/usr/bin/env python3
"""Focused behavior checks for the native declaration ABI companion."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "native_declaration_abi.py"


def load_module():
    specification = importlib.util.spec_from_file_location("native_declaration_abi_test", MODULE_PATH)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


ABI = load_module()


def observation(name: str, *, definition: str = "extern-declaration-without-initializer") -> dict[str, object]:
    return {
        "name": name,
        "definition_observation": definition,
        "mangled_name_observation": name,
        "source": {
            "declaring_header": "demo.h",
            "include_root": "candidate-header-root",
        },
    }


def group(
    *,
    name: str = "foo",
    profile: str = "cxx17-gnu",
    candidate: list[dict[str, object]] | None = None,
    reference: list[dict[str, object]] | None = None,
    category: str = "reference-backed",
) -> dict[str, object]:
    return {
        "category": category,
        "input_header": "demo.h",
        "profile": profile,
        "name": name,
        "candidate_observations": candidate or [observation(name)],
        "reference_observations": reference if reference is not None else [observation(name)],
    }


class NativeDeclarationAbiTests(unittest.TestCase):
    def _ordinary_job_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, object], dict[str, object], dict[str, object]]:
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        output = Path(temporary.name)
        directory = output / "raw" / "candidate" / "demo.h" / "c11-gnu"
        directory.mkdir(parents=True)
        plan = ABI.linkage_jobs_from_callable_account({"groups": [group(profile="c11-gnu")]})[0]
        source = directory / "source.c"
        source.write_text(ABI.generated_source(plan), encoding="utf-8")
        object_file = directory / "ordinary.o"
        object_file.write_bytes(b"ordinary-object\n")
        symbol_text = """Symbol table '.symtab' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     8 OBJECT  LOCAL  DEFAULT    3 crabc_native_declaration_abi_reference_0
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND foo
"""
        relocation_text = """Relocation section '.rela.data.crabc_native_declaration_abi_reference_0' at offset 0x1 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000200000001 R_X86_64_64       0000000000000000 foo + 0
"""
        profiles = ABI._profile_records()
        collector_output = Path("/workspace") / output.relative_to(ROOT)
        source_collector = collector_output / "raw" / "candidate" / "demo.h" / "c11-gnu" / "source.c"
        object_collector = collector_output / "raw" / "candidate" / "demo.h" / "c11-gnu" / "ordinary.o"
        environment = {
            "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
            "TMPDIR": str(collector_output / "raw" / "candidate" / "demo.h" / "c11-gnu" / "tmp"),
            "TZ": "UTC",
        }
        tools = {
            "clang": {"identity": {"mode": 0o755, "path": "/tools/clang", "sha256": "a" * 64, "size": 1}},
            "readelf": {"identity": {"mode": 0o755, "path": "/tools/readelf", "sha256": "b" * 64, "size": 1}},
        }

        def command(label: str, argv: list[str], stdout: str) -> dict[str, object]:
            command_path = directory / f"{label}.command.json"
            stdout_path = directory / f"{label}.stdout"
            stderr_path = directory / f"{label}.stderr"
            status_path = directory / f"{label}.status.json"
            command_path.write_text(json.dumps(argv) + "\n", encoding="utf-8")
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            status_path.write_text('{"returncode": 0}\n', encoding="utf-8")
            return {
                "argv": argv,
                "command": ABI._artifact_identity(output, command_path, label + " command"),
                "cwd": "/workspace",
                "environment": environment,
                "returncode": 0,
                "status": ABI._artifact_identity(output, status_path, label + " status"),
                "stderr": ABI._artifact_identity(output, stderr_path, label + " stderr"),
                "stdout": ABI._artifact_identity(output, stdout_path, label + " stdout"),
            }

        compile_argv = ABI._compile_argv(
            Path("/tools/clang"), profiles["c11-gnu"], Path("/workspace/include"),
            Path("/tools/resource"), Path("/opt/linux-5.10-uapi/include"), source_collector, object_collector,
        )
        raw = {
            "compile": command("compile", compile_argv, ""),
            "symbols": command("symbols", ["/tools/readelf", "-sW", str(object_collector)], symbol_text),
            "relocations": command("relocations", ["/tools/readelf", "-rW", str(object_collector)], relocation_text),
            "source": ABI._artifact_identity(output, source, "source"),
        }
        observations = ABI.evaluate_object_linkage(plan, ABI.parse_symbol_table(symbol_text), ABI.parse_relocations(relocation_text))
        job = {
            "header": "demo.h", "language": "c", "names": ["foo"],
            "object": ABI._artifact_identity(output, object_file, "object"), "observations": observations,
            "ordinal": 0, "profile": "c11-gnu", "raw": raw, "references": plan["references"], "tree": "candidate",
        }
        return temporary, output, plan, tools, job

    def _tool_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, dict[str, object], dict[str, object]]:
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        output = Path(temporary.name)
        tools_directory = output / "inputs" / "tools"
        tools_directory.mkdir(parents=True)
        collector_output = Path("/workspace") / output.relative_to(ROOT)
        environment = {
            "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
            "TMPDIR": str(collector_output / "inputs" / "tools"), "TZ": "UTC",
        }

        def command(label: str, argv: list[str]) -> dict[str, object]:
            command_path = tools_directory / f"{label}.command.json"
            stdout_path = tools_directory / f"{label}.stdout"
            stderr_path = tools_directory / f"{label}.stderr"
            status_path = tools_directory / f"{label}.status.json"
            command_path.write_text(json.dumps(argv) + "\n", encoding="utf-8")
            stdout_path.write_text("tool-version\n", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            status_path.write_text('{"returncode": 0}\n', encoding="utf-8")
            return {
                "argv": argv,
                "command": ABI._artifact_identity(output, command_path, label + " command"),
                "cwd": "/workspace",
                "environment": environment,
                "returncode": 0,
                "status": ABI._artifact_identity(output, status_path, label + " status"),
                "stderr": ABI._artifact_identity(output, stderr_path, label + " stderr"),
                "stdout": ABI._artifact_identity(output, stdout_path, label + " stdout"),
            }

        resource = tools_directory / "clang-resource" / "stddef.h"
        resource.parent.mkdir(parents=True)
        resource.write_bytes(b"retained resource header\n")
        resource_record = ABI._artifact_identity(output, resource, "resource")
        readelf = tools_directory / "readelf"
        readelf.write_bytes(b"retained readelf\n")
        readelf.chmod(0o755)
        readelf_record = ABI._artifact_identity(output, readelf, "readelf")
        clang_identity = {"mode": 0o755, "path": "/tools/clang", "sha256": "a" * 64, "size": 1}
        header_tools = {
            "clang": {"path": "/tools/clang", "sha256": "a" * 64, "size": 1},
            "resource_headers": [],
            "resource_include": "/tools/resource",
        }
        tools = {
            "clang": {
                "identity": clang_identity,
                "requested": "clang",
                "resource_include": {
                    "path": "/tools/resource",
                    "records": [{
                        "kind": "file", "mode": resource_record["mode"], "path": "stddef.h",
                        "retained": resource_record, "sha256": resource_record["sha256"], "size": resource_record["size"],
                    }],
                },
                "version": command("clang-version", ["/tools/clang", "--version"]),
            },
            "readelf": {
                "identity": {
                    "mode": readelf_record["mode"], "path": "/tools/readelf", "sha256": readelf_record["sha256"],
                    "size": readelf_record["size"], "retained": readelf_record,
                },
                "requested": "readelf",
                "version": command("readelf-version", ["/tools/readelf", "--version"]),
            },
        }
        return temporary, output, collector_output, tools, header_tools

    def test_generated_c_and_cxx_sources_use_the_header_not_synthetic_declarations(self) -> None:
        plans = ABI.linkage_jobs_from_callable_account({"groups": [group(profile="c11-gnu"), group(profile="cxx17-gnu")]})
        self.assertEqual(
            [(item["tree"], item["language"], item["names"]) for item in plans],
            [("candidate", "c", ["foo"]), ("candidate", "cxx", ["foo"]),
             ("reference", "c", ["foo"]), ("reference", "cxx", ["foo"])],
        )
        for plan in plans:
            source = ABI.generated_source(plan)
            self.assertIn("#include <demo.h>", source)
            self.assertIn("&foo", source)
            self.assertNotIn("extern ", source)

    def test_cxx_mangled_reference_is_retained_from_the_object_observation(self) -> None:
        plan = ABI.linkage_jobs_from_callable_account({"groups": [group()]})[0]
        symbols = ABI.parse_symbol_table(
            """Symbol table '.symtab' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     8 OBJECT  LOCAL  DEFAULT    3 crabc_native_declaration_abi_reference_0
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND _Z3foov
"""
        )
        relocations = ABI.parse_relocations(
            """Relocation section '.rela.data.crabc_native_declaration_abi_reference_0' at offset 0x1 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000000000000000  0000000200000001 R_X86_64_64       0000000000000000 _Z3foov + 0
"""
        )
        self.assertEqual(
            ABI.evaluate_object_linkage(plan, symbols, relocations),
            [{
                "category": "reference-backed",
                "expected_symbol": "foo",
                "holder": "crabc_native_declaration_abi_reference_0",
                "observed_symbol": "_Z3foov",
                "relocation_type": "R_X86_64_64",
                "status": "ordinary-linkage-identity-mismatch",
            }],
        )

        symbols[2]["name"] = "foo"
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "relocation"):
            ABI.evaluate_object_linkage(plan, symbols, [])
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "unambiguous retained relocation"):
            ABI.evaluate_object_linkage(
                plan,
                symbols,
                [{
                    "section": ".rela.data.some_other_source_holder",
                    "symbol": "foo",
                    "type": "R_X86_64_64",
                }],
            )
        self.assertEqual(
            ABI.evaluate_object_linkage(
                plan,
                symbols,
                [{
                    "addend": 0,
                    "offset": 0,
                    "section": ".rela.data.crabc_native_declaration_abi_reference_0",
                    "symbol": "foo",
                    "symbol_index": 2,
                    "type": "R_X86_64_64",
                }],
            ),
            [{
                "category": "reference-backed",
                "name": "foo",
                "status": "ordinary-undefined-reference",
                "symbol": "foo",
            }],
        )

    def test_ambiguous_direct_declaration_fails_before_source_generation(self) -> None:
        ambiguous = group(candidate=[observation("foo"), observation("foo")])
        ambiguous["candidate_observations"][1]["mangled_name_observation"] = "_Z3foov"
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "ambiguous"):
            ABI.linkage_jobs_from_callable_account({"groups": [ambiguous]})

    def test_header_defined_case_is_retained_as_a_limit_not_forced_to_undefined(self) -> None:
        plan = ABI.linkage_jobs_from_callable_account(
            {"groups": [group(name="inline_foo", candidate=[observation("inline_foo", definition="function-body-present")], reference=[] , category="candidate-project-extension")]}
        )[0]
        result = ABI.evaluate_object_linkage(
            plan,
            [{"name": "inline_foo", "binding": "LOCAL", "visibility": "DEFAULT", "type": "FUNC", "section": ".text"}],
            [],
        )
        self.assertEqual(result[0]["status"], "header-defined-or-inline")
        self.assertEqual(result[0]["source_definition_observation"], "function-body-present")

    def test_reviewed_native_tgkill_extension_has_a_candidate_object_plan_only(self) -> None:
        extension = group(
            name="tgkill",
            profile="c11-gnu",
            candidate=[observation("tgkill")],
            reference=[],
            category="reviewed-native-extension",
        )
        plans = ABI.linkage_jobs_from_callable_account({"groups": [extension]})
        self.assertEqual(
            plans,
            [{
                "tree": "candidate",
                "header": "demo.h",
                "profile": "c11-gnu",
                "language": "c",
                "names": ["tgkill"],
                "references": [{
                    "category": "reviewed-native-extension",
                    "holder": "crabc_native_declaration_abi_reference_0",
                    "name": "tgkill",
                    "source_definition_observations": ["extern-declaration-without-initializer"],
                    "expected_observation": "ordinary-undefined-reference",
                }],
            }],
        )

    def test_replayed_header_envelope_reuses_the_existing_public_replay(self) -> None:
        """A selection caller can pass its one authenticated header envelope.

        The declaration component still derives its finite plan from the full
        envelope, but it must not reopen the 616MB raw header receipt after
        the selection reader has already replayed it.
        """
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        header_report = Path(temporary.name) / "header-report.json"
        header_report.write_text("{}\n", encoding="utf-8")
        envelope = {
            "current_selecting_source": {"matches_retained": True, "differences": []},
            "report": {},
        }
        account = {
            "selected_callable_declaration_status": "proved-with-explicit-boundaries",
            "groups": [group(profile="c11-gnu")],
        }
        with mock.patch.object(ABI.declaration_inventory, "validate_report") as header_replay, \
             mock.patch.object(ABI, "_header_tool_envelope", return_value={
                 "clang": {"path": "/tools/clang", "sha256": "a" * 64, "size": 1},
                 "resource_headers": [], "resource_include": "/tools/resource",
             }), \
             mock.patch.object(ABI, "_callable_partition", return_value=(
                 ["foo"], {}, [], {"partition": "fixture"},
             )), \
             mock.patch.object(ABI, "_matrix_projection", return_value=(
                 {"schema": "fixture"}, {"matrix": "fixture"},
             )), \
             mock.patch.object(ABI.callable_declarations, "account_declarations", return_value=account):
            derived, plans, _source, tools = ABI.derive_callable_plan(
                header_report,
                header_envelope=envelope,
            )
        header_replay.assert_not_called()
        self.assertEqual(derived, account)
        self.assertEqual(plans[0]["names"], ["foo"])
        self.assertEqual(tools["clang"]["path"], "/tools/clang")

    def test_replayed_header_envelope_rejects_historical_source_drift(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "native-declaration-abi-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        header_report = Path(temporary.name) / "header-report.json"
        header_report.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "historical source drift"):
            ABI.derive_callable_plan(
                header_report,
                header_envelope={
                    "current_selecting_source": {
                        "matches_retained": False,
                        "differences": [{"path": "include/demo.h"}],
                    },
                    "report": {},
                },
            )

    def test_checked_layout_projection_keeps_only_the_two_selected_record_facts(self) -> None:
        report = ABI.read_json_object(ROOT / "compat" / "x86_64" / "generated" / "header_record_layout_matrix" / "report.json", "layout report")
        projection = ABI.project_checked_record_layout(report)
        self.assertEqual([item["record"] for item in projection["records"]], ["_ns_flagdata", "in6_addr"])
        self.assertEqual(projection["limits"]["_ns_flagdata_array_extent"], "not-proved-by-record-layout")
        self.assertEqual(projection["limits"]["FILE"], "opaque-or-incomplete-not-proved")

        changed = copy.deepcopy(report)
        for row in changed["rows"]:
            if row["header"] == "netinet/in.h" and row["profile"] == "c11-gnu":
                for record in row["candidate_records"]:
                    if record["name"] == "in6_addr":
                        record["size"] = 32
        with self.assertRaises(ABI.NativeDeclarationAbiError):
            ABI.project_checked_record_layout(changed)

    def test_pointer_initializer_requires_exact_relocation_and_local_holder(self) -> None:
        temporary, output, plan, _tools, _job = self._ordinary_job_fixture()
        self.addCleanup(temporary.cleanup)
        directory = output / "raw" / "candidate" / "demo.h" / "c11-gnu"
        symbols = ABI.parse_symbol_table((directory / "symbols.stdout").read_text(encoding="utf-8"))
        relocations = ABI.parse_relocations((directory / "relocations.stdout").read_text(encoding="utf-8"))
        self.assertEqual(
            relocations,
            [{
                "addend": 0, "offset": 0, "section": ".rela.data.crabc_native_declaration_abi_reference_0",
                "symbol": "foo", "symbol_index": 2, "type": "R_X86_64_64",
            }],
        )
        self.assertEqual(ABI.evaluate_object_linkage(plan, symbols, relocations)[0]["status"], "ordinary-undefined-reference")
        for field, value, message in (
            ("type", "R_X86_64_NONE", "type"),
            ("addend", 8, "addend"),
            ("offset", 8, "offset"),
            ("symbol_index", 1, "symbol index"),
        ):
            changed = copy.deepcopy(relocations)
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ABI.NativeDeclarationAbiError, message):
                ABI.evaluate_object_linkage(plan, symbols, changed)
        wrong_holder = copy.deepcopy(symbols)
        wrong_holder[1]["size"] = 4
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "holder metadata"):
            ABI.evaluate_object_linkage(plan, wrong_holder, relocations)

    def test_tool_replay_authenticates_header_clang_and_retained_missing_tool_bytes(self) -> None:
        temporary, output, collector_output, tools, header_tools = self._tool_fixture()
        self.addCleanup(temporary.cleanup)
        normalized = ABI._validate_tools(output, tools, collector_output, 1.0, header_tools=header_tools)
        self.assertEqual(normalized["clang"]["identity"]["sha256"], "a" * 64)
        changed_clang = copy.deepcopy(tools)
        changed_clang["clang"]["identity"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "public-header compiler envelope"):
            ABI._validate_tools(output, changed_clang, collector_output, 1.0, header_tools=header_tools)
        changed_resource = copy.deepcopy(tools)
        changed_resource["clang"]["resource_include"]["records"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "resource tree file.*bytes differ"):
            ABI._validate_tools(output, changed_resource, collector_output, 1.0, header_tools=header_tools)
        retained_readelf = output / "inputs" / "tools" / "readelf"
        retained_readelf.write_bytes(b"substituted readelf\n")
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "readelf executable bytes differ"):
            ABI._validate_tools(output, tools, collector_output, 1.0, header_tools=header_tools)

    def test_declared_symbol_table_rows_cannot_be_silently_dropped(self) -> None:
        truncated = """Symbol table '.symtab' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
"""
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "truncated|missing"):
            ABI.parse_symbol_table(truncated)

    def test_retained_object_replay_requires_the_exact_symbol_and_relocation_observation(self) -> None:
        temporary, output, plan, tools, job = self._ordinary_job_fixture()
        self.addCleanup(temporary.cleanup)
        collector_output = Path("/workspace") / output.relative_to(ROOT)
        profiles = ABI._profile_records()
        replayed = ABI._validate_job(
            output, collector_output, job, plan, 0,
            tools=tools, profiles=profiles, resource_include="/tools/resource",
        )
        self.assertEqual(replayed["observations"][0]["symbol"], "foo")

        relocation_stdout = output / job["raw"]["relocations"]["stdout"]["path"]
        relocation_stdout.write_text("There are no relocations in this file.\n", encoding="utf-8")
        job["raw"]["relocations"]["stdout"] = ABI._artifact_identity(output, relocation_stdout, "changed relocation stdout")
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "relocation"):
            ABI._validate_job(
                output, collector_output, job, plan, 0,
                tools=tools, profiles=profiles, resource_include="/tools/resource",
            )

    def test_cli_rejects_repeated_header_input_before_collection(self) -> None:
        with self.assertRaisesRegex(ABI.NativeDeclarationAbiError, "repeated"):
            ABI._parse_cli([
                "--collect", "--header-report", ".work/first.json", "--header-report", ".work/second.json",
                "--output", ".work/x86_64/native-declaration-abi/fresh",
            ])


if __name__ == "__main__":
    unittest.main()
