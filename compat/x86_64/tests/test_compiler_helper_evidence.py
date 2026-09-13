"""Finite reader checks for the native compiler-helper archive receipt."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / "compat/x86_64/compiler_helper_evidence.py"
SPEC = importlib.util.spec_from_file_location("compiler_helper_evidence_test", PATH)
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


class CompilerHelperEvidenceTests(unittest.TestCase):
    def _temporary_work(self, temporary: str) -> Path:
        work = Path(temporary) / "aggregate"
        (work / "raw").mkdir(parents=True)
        for name in EVIDENCE.AGGREGATE_ARTIFACTS:
            path = work / name
            path.write_bytes((name + "\n").encode("ascii"))
        return work

    def _command_events(self, work: Path) -> Path:
        records = []
        for label, expected_status in EVIDENCE.AGGREGATE_COMMANDS:
            stdout, stderr = work / "raw" / (label + ".stdout"), work / "raw" / (label + ".stderr")
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            records.append({
                "label": label,
                "argv": EVIDENCE._expected_command_argv(label, root=ROOT, work=work,
                                                        source_mount=EVIDENCE.SOURCE_MOUNT),
                "status": 1 if expected_status == "nonzero" else expected_status,
                "inputs": EVIDENCE._expected_command_inputs(label, work),
                "stdout": EVIDENCE._work_identity(work, stdout, label + " stdout"),
                "stderr": EVIDENCE._work_identity(work, stderr, label + " stderr"),
            })
        events = work / "commands.json"
        events.write_text(EVIDENCE.canonical_json(records), encoding="utf-8")
        return events

    def test_contract_has_exact_23_unversioned_global_default_functions(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        self.assertEqual(len(contract["helpers"]), 23)
        self.assertEqual(EVIDENCE.helper_names(contract), tuple(sorted(EVIDENCE.helper_names(contract))))
        self.assertEqual(contract["archive"]["placements"], ["static-builtins", "dynamic-builtins"])
        self.assertTrue(all(row["metadata"] == EVIDENCE.HELPER_METADATA for row in contract["helpers"]))

    def test_source_and_contract_are_a_bijection(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        self.assertEqual(EVIDENCE.source_definitions(ROOT), {
            row["name"]: row["rust_signature"] for row in contract["helpers"]
        })

    def test_reader_rejects_extra_helper_wrong_metadata_and_shared_placement(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "helper roster"):
            EVIDENCE.validate_contract({**contract, "helpers": contract["helpers"][:-1]})
        wrong = copy.deepcopy(contract)
        wrong["helpers"][0]["metadata"]["visibility"] = "HIDDEN"
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "metadata"):
            EVIDENCE.validate_contract(wrong)
        wrong = copy.deepcopy(contract)
        wrong["helpers"][0]["metadata"]["version"] = "versioned"
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "version"):
            EVIDENCE.validate_contract(wrong)
        wrong = copy.deepcopy(contract)
        wrong["archive"]["placements"].append("candidate-shared")
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "placements"):
            EVIDENCE.validate_contract(wrong)


    def test_exact_archive_placement_metadata_is_extracted_without_shared_rows(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        rows = []
        sections = []
        for index, name in enumerate(EVIDENCE.helper_names(contract), start=1):
            rows.append({"name": name, "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
                         "version": None, "version_default": False, "section_index": str(index)})
            sections.append({"index": index, "name": ".text." + name, "flags": "AX"})
        member = {"member": "crabc-builtins.o", "member_index": 0, "member_occurrence": 0,
                  "sections": sections, "symbol_tables": [{"name": ".symtab", "rows": rows}]}
        facts = {"target": EVIDENCE.TARGET, "facts": {
            "static-builtins": [copy.deepcopy(member)], "dynamic-builtins": [copy.deepcopy(member)],
        }}
        placements = EVIDENCE.archive_placements_from_elf_facts(facts, contract)
        self.assertEqual(set(placements), {"static-builtins", "dynamic-builtins"})
        self.assertEqual(placements["static-builtins"]["__popcountdi2"], {
            "member": "crabc-builtins.o", "section": ".text.__popcountdi2",
            "metadata": EVIDENCE.HELPER_METADATA,
        })
        malformed = copy.deepcopy(facts)
        malformed["facts"]["dynamic-builtins"][0]["symbol_tables"][0]["rows"][0]["visibility"] = "HIDDEN"
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "metadata"):
            EVIDENCE.archive_placements_from_elf_facts(malformed, contract)
        malformed = copy.deepcopy(facts)
        malformed["facts"]["static-builtins"][0]["symbol_tables"][0]["rows"].append({
            "name": "extra_external", "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
            "version": None, "version_default": False, "section_index": "1",
        })
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "exported function roster"):
            EVIDENCE.archive_placements_from_elf_facts(malformed, contract)

    def test_popcount_join_requires_the_unique_static_import_and_selected_member(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        placement = {"static-builtins": {"__popcountdi2": {
            "member": "crabc-builtins.o", "section": ".text.__popcountdi2",
            "metadata": EVIDENCE.HELPER_METADATA,
        }}}
        facts = {"facts": {"candidate-static": [{
            "member": "application.o", "member_index": 1, "member_occurrence": 0,
            "symbol_tables": [{"name": ".symtab", "rows": [{
                "name": "__popcountdi2", "type": "NOTYPE", "binding": "GLOBAL",
                "visibility": "DEFAULT", "version": None, "version_default": False,
                "section_index": "UND", "row_index": 7,
            }]}],
        }]}}
        joined = EVIDENCE._popcount_import_from_facts(facts, placement)
        self.assertEqual(joined["provider_section"], ".text.__popcountdi2")
        duplicate = copy.deepcopy(facts)
        duplicate["facts"]["candidate-static"].append(copy.deepcopy(duplicate["facts"]["candidate-static"][0]))
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "not unique"):
            EVIDENCE._popcount_import_from_facts(duplicate, placement)

    def test_selection_group_consumes_the_producer_contract_and_never_shared_libc(self) -> None:
        selection = tomllib.loads((ROOT / "compat/x86_64/native-abi-selection.toml").read_text(encoding="utf-8"))
        group = next(row for row in selection["owner_groups"] if row["id"] == "owned-compiler-helper-archive")
        self.assertEqual(group["sources"], ["builtins/src/lib.rs", "builtins/build_x86_64.py", "builtins/x86_64-helper-contract.toml"])
        self.assertEqual(group["artifacts"], ["static-builtins", "dynamic-builtins"])
        self.assertEqual(group["placement_metadata"], {
            "static-builtins": {"binding": "GLOBAL", "visibility": "DEFAULT"},
            "dynamic-builtins": {"binding": "GLOBAL", "visibility": "DEFAULT"},
        })
        self.assertNotIn("candidate-shared", group["artifacts"])

    def test_aggregate_runner_is_checkout_local_and_records_all_commands(self) -> None:
        runner = (ROOT / "builtins/run_x86_64_compiler_helper_aggregate.sh").read_text(encoding="utf-8")
        self.assertIn("CRABC_COMPILER_HELPER_WORK_DIR", runner)
        self.assertNotIn("mktemp", runner)
        self.assertNotIn("/tmp/", runner)
        probe = (ROOT / "builtins/fixtures/x86_64_compiler_helper_aggregate_probe.c").read_text(encoding="utf-8")
        self.assertIn("typedef double _Complex complex_double;", probe)
        self.assertIn("__builtin_complex", probe)
        self.assertIn("__real__ value", probe)
        self.assertNotIn("struct { double real; double imaginary; }", probe)
        for label, _status in EVIDENCE.AGGREGATE_COMMANDS:
            self.assertIn("record_command " + label, runner)
        self.assertIn("validate-aggregate-report", runner)

    def test_command_reader_rejects_argv_substitution_and_wrong_artifact_input(self) -> None:
        test_root = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as temporary:
            work = self._temporary_work(temporary)
            events = self._command_events(work)
            self.assertEqual(len(EVIDENCE._command_events(work, events, root=ROOT,
                                                          source_mount=EVIDENCE.SOURCE_MOUNT)),
                             len(EVIDENCE.AGGREGATE_COMMANDS))
            changed = json.loads(events.read_text(encoding="utf-8"))
            changed[8]["argv"] = ["echo", "not-readelf"]
            events.write_text(EVIDENCE.canonical_json(changed), encoding="utf-8")
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "candidate-header argv"):
                EVIDENCE._command_events(work, events, root=ROOT, source_mount=EVIDENCE.SOURCE_MOUNT)
            changed[8]["argv"] = EVIDENCE._expected_command_argv("candidate-header", root=ROOT, work=work,
                                                                   source_mount=EVIDENCE.SOURCE_MOUNT)
            changed[8]["inputs"][0]["sha256"] = "0" * 64
            events.write_text(EVIDENCE.canonical_json(changed), encoding="utf-8")
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "candidate-header input relationship"):
                EVIDENCE._command_events(work, events, root=ROOT, source_mount=EVIDENCE.SOURCE_MOUNT)

    def test_provenance_binds_the_retained_archive_sha256(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        test_root = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as temporary:
            work = Path(temporary)
            archive = work / "libcrabc-builtins.a"
            archive.write_bytes(b"owned archive bytes\n")
            archive_identity = EVIDENCE._work_identity(work, archive, "archive")
            provenance = {
                "schema": 1, "target": EVIDENCE.TARGET, "scope": "bounded", "source": EVIDENCE.SOURCE.as_posix(),
                "contract": EVIDENCE.CONTRACT.as_posix(), "reproducible": True,
                "archive": {"members": [EVIDENCE.ARCHIVE_MEMBER],
                            "defined_symbols": list(EVIDENCE.helper_names(contract)),
                            "archive_sha256": archive_identity["sha256"], "contract": contract},
            }
            path = work / "libcrabc-builtins.a.provenance.json"
            path.write_text(EVIDENCE.canonical_json(provenance), encoding="utf-8")
            EVIDENCE._provenance(path, contract, archive_identity)
            provenance["archive"]["archive_sha256"] = "0" * 64
            path.write_text(EVIDENCE.canonical_json(provenance), encoding="utf-8")
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "provenance roster"):
                EVIDENCE._provenance(path, contract, archive_identity)

    def test_ordinary_popcount_attachment_rejects_different_cohort_and_toctou(self) -> None:
        test_root = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        test_root.mkdir(parents=True, exist_ok=True)
        expected_inputs = {"source": {"revision": "same"}, "product": {"sha256": "same"}}

        class Ordinary:
            class PublicDataEvidenceError(ValueError):
                pass

            @staticmethod
            def work_file_identity(root: Path, path: Path, _description: str) -> dict[str, object]:
                path = Path(path)
                return {"path": path.relative_to(root).as_posix(), "sha256": EVIDENCE.digest(path),
                        "size": path.stat().st_size}

            @classmethod
            def validate_report(cls, root: Path, path: Path) -> dict[str, object]:
                return {"report": cls.work_file_identity(root, path, "report"), "links": {}}

        original_loader = EVIDENCE._load_companion_modules
        try:
            EVIDENCE._load_companion_modules = lambda: (None, Ordinary)
            with tempfile.TemporaryDirectory(dir=test_root) as temporary:
                work = Path(temporary) / "ordinary"
                work.mkdir()
                links: dict[str, object] = {}
                for mode in ("static", "static-pie"):
                    map_path, trace_path = work / (mode + ".map"), work / (mode + ".trace")
                    map_path.write_text("libcrabc-builtins.a(crabc-builtins.o):(.text.__popcountdi2)\n__popcountdi2\n")
                    trace_path.write_text("libcrabc-builtins.a(crabc-builtins.o)\n")
                    receipt = work / (mode + ".receipt.json")
                    receipt.write_text(EVIDENCE.canonical_json({
                        "map": {"path": map_path.name, "sha256": EVIDENCE.digest(map_path)},
                        "trace": {"path": trace_path.name, "sha256": EVIDENCE.digest(trace_path)},
                    }))
                    links[mode] = {"receipt": {"path": receipt.name}}
                links.update({"dynamic-pie": {}, "dynamic-non-pie": {}})
                report = work / "report.json"
                report.write_text(EVIDENCE.canonical_json({"source_before": expected_inputs,
                                                          "source_after": expected_inputs, "links": links}))
                joined = EVIDENCE._ordinary_popcount_maps(ROOT, report, expected_inputs)
                self.assertEqual(set(joined["static_modes"]), {"static", "static-pie"})
                altered = json.loads(report.read_text(encoding="utf-8"))
                altered["source_after"] = {"other": True}
                report.write_text(EVIDENCE.canonical_json(altered), encoding="utf-8")
                with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "different supplied product cohort"):
                    EVIDENCE._ordinary_popcount_maps(ROOT, report, expected_inputs)

                report.write_text(EVIDENCE.canonical_json({"source_before": expected_inputs,
                                                          "source_after": expected_inputs, "links": links}))

                class MutatingOrdinary(Ordinary):
                    @classmethod
                    def validate_report(cls, root: Path, path: Path) -> dict[str, object]:
                        replay = super().validate_report(root, path)
                        changed = json.loads(Path(path).read_text(encoding="utf-8"))
                        changed["source_after"] = {"changed": True}
                        Path(path).write_text(EVIDENCE.canonical_json(changed), encoding="utf-8")
                        return replay

                EVIDENCE._load_companion_modules = lambda: (None, MutatingOrdinary)
                with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "changed after replay"):
                    EVIDENCE._ordinary_popcount_maps(ROOT, report, expected_inputs)
        finally:
            EVIDENCE._load_companion_modules = original_loader

    def test_writer_then_reader_rejects_mutated_member_and_source(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        source = EVIDENCE.source_binding(ROOT, contract)
        work = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            output = Path(temporary) / "receipt.json"
            report = EVIDENCE.write_fixture_report(output, contract=contract, source=source)
            self.assertEqual(EVIDENCE.validate_fixture_report(output, root=ROOT), report)
            altered = copy.deepcopy(report)
            altered["archive"]["member"] = "other.o"
            output.write_text(EVIDENCE.canonical_json(altered), encoding="utf-8")
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "member"):
                EVIDENCE.validate_fixture_report(output, root=ROOT)
            altered = copy.deepcopy(report)
            altered["source"]["files"][0]["sha256"] = "0" * 64
            output.write_text(EVIDENCE.canonical_json(altered), encoding="utf-8")
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "source"):
                EVIDENCE.validate_fixture_report(output, root=ROOT)
            cli = Path(temporary) / "cli.json"
            self.assertEqual(EVIDENCE.main(["write-fixture-report", "--output", str(cli)]), 0)
            self.assertEqual(EVIDENCE.main(["validate-fixture-report", str(cli)]), 0)


if __name__ == "__main__":
    unittest.main()
