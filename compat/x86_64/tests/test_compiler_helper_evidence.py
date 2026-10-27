"""Finite reader checks for the native compiler-helper archive receipt."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from product_fixture import write_compatibility_provenance

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / "compat/x86_64/compiler_helper_evidence.py"
SPEC = importlib.util.spec_from_file_location("compiler_helper_evidence_test", PATH)
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)


def _helper_elf(path: Path, binding: str, dynamic_binding: str | None = None,
                visibility: int = 0) -> Path:
    strings = b"\0__addoti4\0"
    section_names = ("", ".text.__addoti4", ".symtab", ".dynsym", ".strtab", ".shstrtab")
    section_strings = bytearray(b"\0")
    name_offsets = {}
    for name in section_names[1:]:
        name_offsets[name] = len(section_strings)
        section_strings.extend(name.encode("ascii") + b"\0")
    text_offset = 64
    symtab_offset = text_offset + 4
    dynsym_offset = symtab_offset + 48
    dynsym_size = 24 if dynamic_binding is None else 48
    strings_offset = dynsym_offset + dynsym_size
    section_strings_offset = strings_offset + len(strings)
    sections_offset = (section_strings_offset + len(section_strings) + 7) & ~7

    def symbol_row(symbol_binding: str) -> bytes:
        info = ((1 if symbol_binding == "GLOBAL" else 0) << 4) | 2
        return struct.pack("<IBBHQQ", 1, info, visibility, 1, 0x1000, 4)

    symtab = bytes(24) + symbol_row(binding)
    dynsym = bytes(24) if dynamic_binding is None else bytes(24) + symbol_row(dynamic_binding)
    section_rows = [bytes(64)]
    for name, kind, flags, address, offset, size, link, info, alignment, entry_size in (
        (".text.__addoti4", 1, 6, 0x1000, text_offset, 4, 0, 0, 16, 0),
        (".symtab", 2, 0, 0, symtab_offset, len(symtab), 4, 2 if binding == "LOCAL" else 1, 8, 24),
        (".dynsym", 11, 0, 0, dynsym_offset, len(dynsym), 4,
         2 if dynamic_binding == "LOCAL" else 1, 8, 24),
        (".strtab", 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0),
        (".shstrtab", 3, 0, 0, section_strings_offset, len(section_strings), 0, 0, 1, 0),
    ):
        section_rows.append(struct.pack(
            "<IIQQQQIIQQ", name_offsets[name], kind, flags, address, offset, size,
            link, info, alignment, entry_size,
        ))
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, 62, 1, 0, 0, sections_offset,
                         0, 64, 56, 0, 64, len(section_rows), 5)
    image = bytearray(header)
    image.extend(b"\x90" * 4)
    image.extend(symtab)
    image.extend(dynsym)
    image.extend(strings)
    image.extend(section_strings)
    image.extend(bytes(sections_offset - len(image)))
    image.extend(b"".join(section_rows))
    path.write_bytes(image)
    return path


class CompilerHelperEvidenceTests(unittest.TestCase):
    def test_allocator_popcount_witness_follows_the_product_build_profile(self) -> None:
        self.assertEqual(EVIDENCE.allocator_popcount_witness_for_profile("release"),
                         "mi_bbitmap_try_find_and_clearNC")
        self.assertEqual(EVIDENCE.allocator_popcount_witness_for_profile("debug"), "mi_popcount")
        for profile in (None, True, "unknown"):
            with self.subTest(profile=profile), self.assertRaisesRegex(
                    EVIDENCE.CompilerHelperEvidenceError, "allocator profile"):
                EVIDENCE.allocator_popcount_witness_for_profile(profile)

    def test_combined_product_profile_comes_from_the_embedded_dynamic_manifest(self) -> None:
        import crabc_cc_owned_dynamic as driver

        scratch = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            product = Path(temporary)
            manifest = {"schema": 1, "format": driver.COMBINED_FORMAT}
            embedded_path = product / driver.COMBINED_PRODUCT_MANIFEST
            embedded_path.parent.mkdir(parents=True)
            embedded = {"schema": 1, "format": driver.FORMAT, "build_profile": "release"}
            embedded_path.write_text(EVIDENCE.canonical_json(embedded), encoding="utf-8")

            self.assertEqual(
                EVIDENCE.dynamic_product_profile_from_admitted_manifest(product, manifest), "release"
            )

            embedded["build_profile"] = "unknown"
            embedded_path.write_text(EVIDENCE.canonical_json(embedded), encoding="utf-8")
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "allocator profile"):
                EVIDENCE.dynamic_product_profile_from_admitted_manifest(product, manifest)

    def _debug_dynamic_product(self, root: Path) -> Path:
        product = root / "debug-product"
        files = (
            "bin/crabc-cc-dynamic",
            "share/crabc/crabc_cc_static.py",
            "share/crabc/native_runtime_profile.py",
            "share/crabc/crt.provenance.json",
            "share/crabc/loader.provenance.json",
            "share/crabc/owned_dynamic_receipt.py",
            "share/crabc/owned_dynamic_elf.py",
            "share/crabc/dynamic-product-state.json",
            "share/crabc/libc-shared.provenance.json",
            "usr/include/fixture.h",
            "lib/ld-crabc-x86_64.so.1",
            "usr/lib/crt1.o",
            "usr/lib/Scrt1.o",
            "usr/lib/crti.o",
            "usr/lib/crtn.o",
            "usr/lib/crabc-dynamic-attach.o",
            "usr/lib/libc.so",
            "usr/lib/libcrabc-builtins.a",
        )
        for relative in files:
            path = product / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((relative + "\n").encode())
        for relative in ("bin/crabc-cc-dynamic", "lib/ld-crabc-x86_64.so.1", "usr/lib/libc.so"):
            (product / relative).chmod(0o755)
        write_compatibility_provenance(product, dynamic=True)
        loader_receipt = product / "share/crabc/loader.provenance.json"
        loader = json.loads(loader_receipt.read_text())
        loader["build_profile"] = "debug"
        loader["compiler_command"] = []
        loader_receipt.write_text(json.dumps(loader))
        (product / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        state = {
            "build_profile": "debug",
            "allocator_backend": "native-shadow",
            "allocator_lifecycle_test_audit": False,
            "status": "materialized-unqualified",
        }
        (product / "share/crabc/dynamic-product-state.json").write_text(EVIDENCE.canonical_json(state))
        provenance = {key: state[key] for key in
                      ("build_profile", "allocator_backend", "allocator_lifecycle_test_audit")}
        (product / "share/crabc/libc-shared.provenance.json").write_text(EVIDENCE.canonical_json(provenance))
        payload = {
            path.relative_to(product).as_posix(): EVIDENCE.digest(path)
            for path in sorted(product.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }
        manifest = {
            "schema": 1,
            "format": "crabc-x86-64-owned-dynamic-sysroot-v1",
            "target": EVIDENCE.TARGET,
            "toolchain": "pinned",
            "files": payload,
            "build_profile": "debug",
            "hardening_profile": "compatibility",
            "source_sha256": self._current_source_digest(),
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
        }
        manifest_path = product / "share/crabc/manifest.json"
        manifest_path.write_text(EVIDENCE.canonical_json(manifest))
        return product

    def _current_source_digest(self) -> str:
        module_dir = Path(EVIDENCE.__file__).resolve().parent
        if str(module_dir) not in sys.path:
            sys.path.insert(0, str(module_dir))
        import owned_dynamic_qualification as qualification

        return qualification.source_digest()

    def test_materialized_debug_product_binds_current_source_and_installed_payload(self) -> None:
        scratch = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            product = self._debug_dynamic_product(Path(temporary))
            identity = EVIDENCE.validate_materialized_dynamic_product(ROOT, product)
            self.assertEqual(identity, EVIDENCE.digest(product / "share/crabc/manifest.json"))
            manifest = json.loads((product / "share/crabc/manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(EVIDENCE.dynamic_product_profile_from_admitted_manifest(product, manifest), "debug")

    def test_materialized_debug_product_rejects_stale_source_and_changed_payload(self) -> None:
        scratch = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            product = self._debug_dynamic_product(Path(temporary))
            manifest_path = product / "share/crabc/manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["source_sha256"] = "f" * 64
            manifest_path.write_text(EVIDENCE.canonical_json(manifest))
            with self.assertRaises(EVIDENCE.CompilerHelperEvidenceError) as stale:
                EVIDENCE.validate_materialized_dynamic_product(ROOT, product)
            self.assertIn("source differs", str(stale.exception.__cause__))

            manifest["source_sha256"] = self._current_source_digest()
            manifest_path.write_text(EVIDENCE.canonical_json(manifest))
            (product / "usr/lib/libcrabc-builtins.a").write_bytes(b"changed archive\n")
            with self.assertRaises(EVIDENCE.CompilerHelperEvidenceError) as changed:
                EVIDENCE.validate_materialized_dynamic_product(ROOT, product)
            self.assertIn("payload hash mismatch", str(changed.exception.__cause__))

    def test_complex_edge_differential_keeps_final_elf_and_rejects_tampering(self) -> None:
        if not Path(EVIDENCE.ORACLE_CC).is_file():
            self.skipTest("pinned musl compiler is available only in the native image")
        scratch = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            report = EVIDENCE.collect_complex_edge_differential(work)
            self.assertEqual(report["cases"], 13 ** 4)
            self.assertEqual(EVIDENCE.validate_complex_edge_differential(work / "complex-edge-report.json"), report)
            executable = work / "complex-edge-candidate"
            executable.write_bytes(executable.read_bytes() + b"tampered")
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "complex edge candidate identity"):
                EVIDENCE.validate_complex_edge_differential(work / "complex-edge-report.json")

    def test_supplied_product_runner_rejects_overlap_and_empty_argument_before_writes(self):
        scratch = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        runner = ROOT / EVIDENCE.SHARED_PLACEMENT_RUNNER
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            product = Path(temporary) / "sealed-product"
            product.mkdir()
            marker = product / "sealed-input"
            marker.write_bytes(b"unchanged\n")
            environment = dict(os.environ,
                CRABC_X86_COMPILER_HELPER_IMAGE="crabc-core-evidence@sha256:" + "0" * 64,
                CRABC_COMPILER_HELPER_SHARED_WORK_DIR=str(product / "new-review"))
            result = subprocess.run(["bash", str(runner), str(product)], cwd=ROOT,
                                    env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(sorted(path.relative_to(product).as_posix() for path in product.rglob("*")),
                             ["sealed-input"], result.stderr)
            self.assertEqual(marker.read_bytes(), b"unchanged\n")
            # A missing image stops the legacy empty-argument branch before it
            # can build anything, while the argument contract must reject first.
            environment["CRABC_X86_COMPILER_HELPER_IMAGE"] = ""
            environment["CRABC_COMPILER_HELPER_SHARED_WORK_DIR"] = str(Path(temporary) / "empty-review")
            result = subprocess.run(["bash", str(runner), ""], cwd=ROOT,
                                    env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("supplied dynamic product", result.stderr)
            self.assertFalse((Path(temporary) / "empty-review").exists())

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

    def test_contract_binds_source_unversioned_global_default_functions(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        self.assertEqual(contract["schema"], 2)
        self.assertEqual(set(EVIDENCE.helper_names(contract)), set(EVIDENCE.source_definitions(ROOT)))
        self.assertEqual(EVIDENCE.helper_names(contract), tuple(sorted(EVIDENCE.helper_names(contract))))
        self.assertEqual(contract["archive"]["placements"], ["static-builtins", "dynamic-builtins"])
        self.assertEqual(contract["archive"]["debug_source_core_support"], "localized-in-member")
        self.assertEqual(contract["shared_libc"], EVIDENCE.SHARED_LIBC_METADATA)
        self.assertEqual(contract["dynamic_application"], EVIDENCE.DYNAMIC_APPLICATION_METADATA)
        self.assertTrue(all(row["metadata"] == EVIDENCE.HELPER_METADATA for row in contract["helpers"]))

    def test_source_and_contract_are_a_bijection(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        self.assertEqual(EVIDENCE.source_definitions(ROOT), {
            row["name"]: row["source_definition"] for row in contract["helpers"]
        })

    def test_reader_rejects_extra_helper_wrong_metadata_and_shared_placement(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        wrong = copy.deepcopy(contract)
        wrong["schema"] = 1
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "schema/target"):
            EVIDENCE.validate_contract(wrong)
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
        wrong = copy.deepcopy(contract)
        wrong["archive"]["debug_source_core_support"] = "public-dynamic-symbols"
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "placements"):
            EVIDENCE.validate_contract(wrong)
        wrong = copy.deepcopy(contract)
        wrong["shared_libc"]["dynsym"] = 0
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "shared-libc"):
            EVIDENCE.validate_contract(wrong)
        wrong = copy.deepcopy(contract)
        wrong["dynamic_application"]["helper_dynsym"] = True
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "dynamic-application"):
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

    def test_shared_libc_copy_requires_local_symtab_and_no_dynsym_rows(self) -> None:
        contract = EVIDENCE.load_contract(ROOT)
        full = []
        for index, name in enumerate(EVIDENCE.helper_names(contract), start=1):
            full.append({"name": name, "type": "FUNC", "binding": "LOCAL", "visibility": "HIDDEN",
                         "version": None, "version_default": False, "row_index": index,
                         "section_index": str(index)})
        facts = {"target": EVIDENCE.TARGET, "facts": {"candidate-shared": {
            "sections": [{"index": index, "name": ".text." + name, "flags": "AX"}
                         for index, name in enumerate(EVIDENCE.helper_names(contract), start=1)],
            "symbol_tables": [
                {"name": ".dynsym", "rows": []}, {"name": ".symtab", "rows": full},
            ],
        }}}
        placement = EVIDENCE.shared_libc_placement_from_elf_facts(facts, contract)
        self.assertEqual(set(placement), set(EVIDENCE.helper_names(contract)))
        self.assertEqual(placement["__popcountdi2"], {
            "table": ".symtab", "row_index": EVIDENCE.helper_names(contract).index("__popcountdi2") + 1,
            "section_index": EVIDENCE.helper_names(contract).index("__popcountdi2") + 1,
            "section": ".text.__popcountdi2",
            "metadata": {"type": "FUNC", "binding": "LOCAL", "visibility": "HIDDEN"},
        })
        leaked = copy.deepcopy(facts)
        leaked["facts"]["candidate-shared"]["symbol_tables"][0]["rows"].append(copy.deepcopy(full[0]))
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "leaked"):
            EVIDENCE.shared_libc_placement_from_elf_facts(leaked, contract)
        visible = copy.deepcopy(facts)
        visible["facts"]["candidate-shared"]["symbol_tables"][1]["rows"][0]["visibility"] = "DEFAULT"
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "metadata"):
            EVIDENCE.shared_libc_placement_from_elf_facts(visible, contract)
        for invalid in ("COM", "0", "PRC[0xff00]"):
            malformed = copy.deepcopy(facts)
            malformed["facts"]["candidate-shared"]["symbol_tables"][1]["rows"][0]["section_index"] = invalid
            with self.subTest(section_index=invalid), self.assertRaisesRegex(
                    EVIDENCE.CompilerHelperEvidenceError, "metadata"):
                EVIDENCE.shared_libc_placement_from_elf_facts(malformed, contract)

    def test_shared_runner_requires_physical_work_and_keeps_the_product_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            allowed = root / ".work/x86_64"
            allowed.mkdir(parents=True)
            self.assertEqual(EVIDENCE.checkout_work_directory(root, allowed / "inside"), allowed / "inside")
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "physical checkout .work/x86_64"):
                EVIDENCE.checkout_work_directory(root, allowed / "../outside")
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (allowed / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "physical checkout .work/x86_64"):
                EVIDENCE.checkout_work_directory(root, allowed / "escape/output")
        runner = (ROOT / "builtins/run_x86_64_compiler_helper_shared_placement.sh").read_text(encoding="utf-8")
        self.assertIn("validate-work-dir", runner)
        self.assertIn("product-admission-before", runner)
        self.assertIn("product-admission-after", runner)
        self.assertIn("EXECUTION_ROOT", runner)
        self.assertNotIn('cp "$WORK_DIR/libhelper.so" "$LIBRARY/libhelper.so"', runner)

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

    def test_installed_helper_command_recorder_retains_success_and_failure(self) -> None:
        test_root = ROOT / ".work/x86_64/compiler-helper-command-capture-tests"
        test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as temporary:
            work = Path(temporary)
            (work / "raw").mkdir()
            success = [sys.executable, "-c", "import sys; sys.stdout.write('success stdout' + chr(10)); "
                       "sys.stderr.write('success stderr' + chr(10))"]
            failure = [sys.executable, "-c", "import sys; sys.stdout.write('failure stdout' + chr(10)); "
                       "sys.stderr.write('failure stderr' + chr(10)); sys.exit(7)"]
            script = (
                "import json, sys\n"
                "from pathlib import Path\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "import compiler_helper_evidence as evidence\n"
                "root, work = Path(sys.argv[2]), Path(sys.argv[3])\n"
                "success, failure = json.loads(sys.argv[4]), json.loads(sys.argv[5])\n"
                "evidence._record_installed_helper_command(root, work, 'success', success)\n"
                "print('success-recorded')\n"
                "try:\n"
                "    evidence._record_installed_helper_command(root, work, 'failure', failure)\n"
                "except evidence.CompilerHelperEvidenceError as error:\n"
                "    print(f'failure-raised: {error}')\n"
                "else:\n"
                "    raise SystemExit('nonzero command status was accepted')\n"
            )
            result = subprocess.run(
                [sys.executable, "-B", "-c", script, str(ROOT / "compat/x86_64"), str(ROOT),
                 str(work), json.dumps(success), json.dumps(failure)],
                cwd=ROOT, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )

            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
            self.assertEqual(result.stdout,
                             b"success-recorded\n"
                             b"failure-raised: compiler-helper installed failure failed with 7\n")
            self.assertEqual(result.stderr, b"")
            for label, argv, stdout, stderr, status in (
                ("success", success, b"success stdout\n", b"success stderr\n", "0\n"),
                ("failure", failure, b"failure stdout\n", b"failure stderr\n", "7\n"),
            ):
                self.assertEqual(json.loads((work / "raw" / f"{label}.argv").read_text()), argv)
                self.assertEqual((work / "raw" / f"{label}.stdout").read_bytes(), stdout)
                self.assertEqual((work / "raw" / f"{label}.stderr").read_bytes(), stderr)
                self.assertEqual((work / "raw" / f"{label}.status").read_text(), status)

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

    def test_ambient_link_trace_rejects_crt_objects_without_posix_regex_syntax(self) -> None:
        self.assertTrue(EVIDENCE._ambient_link_input("/tmp/crta.o\n"))
        self.assertTrue(EVIDENCE._ambient_link_input("/opt/toolchain/crt1.o\n"))
        self.assertTrue(EVIDENCE._ambient_link_input("libgcc.a\n"))
        self.assertFalse(EVIDENCE._ambient_link_input("/tmp/crt file.o\n"))
        self.assertFalse(EVIDENCE._ambient_link_input(
            "/workspace/.work/x86_64/crtcompose36/aggregate/aggregate-start.o\n"))
        self.assertTrue(EVIDENCE._ambient_link_input("/opt/toolchain/Scrt1.o\n"))
        self.assertTrue(EVIDENCE._ambient_link_input("/opt/toolchain/rcrt1.o\n"))

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
                "schema": 2, "target": EVIDENCE.TARGET, "scope": "bounded", "source": EVIDENCE.SOURCE.as_posix(),
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

    def test_aggregate_join_binds_source_and_both_installed_archive_roles(self) -> None:
        test_root = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        test_root.mkdir(parents=True, exist_ok=True)
        supplied_source = {"revision": "a" * 40, "content_sha256": "b" * 64}
        aggregate = {"product_source_before": supplied_source, "product_source_after": supplied_source,
                     "artifacts": {"libcrabc-builtins.a": {"sha256": "c" * 64, "size": 101}}}
        installed = {
            "static-builtins": {"path": "/products/static/usr/lib/libcrabc-builtins.a", "sha256": "c" * 64, "size": 101},
            "dynamic-builtins": {"path": "/products/dynamic/usr/lib/libcrabc-builtins.a", "sha256": "c" * 64, "size": 101},
        }
        original_validate = EVIDENCE.validate_aggregate_report
        try:
            EVIDENCE.validate_aggregate_report = lambda _report, *, root: aggregate
            with tempfile.TemporaryDirectory(dir=test_root) as temporary:
                report = Path(temporary) / "report.json"
                report.write_text("{}\n", encoding="utf-8")
                joined = EVIDENCE._aggregate_archive_join(ROOT, report, supplied_source=supplied_source,
                                                          installed_archives=installed)
                self.assertEqual(joined["c_abi_proof"], "aggregate-direct-c-consumer")
                wrong = copy.deepcopy(installed)
                wrong["static-builtins"]["sha256"] = "d" * 64
                with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "static-builtins"):
                    EVIDENCE._aggregate_archive_join(ROOT, report, supplied_source=supplied_source,
                                                     installed_archives=wrong)
                wrong = copy.deepcopy(installed)
                wrong["dynamic-builtins"]["size"] = 102
                with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "dynamic-builtins"):
                    EVIDENCE._aggregate_archive_join(ROOT, report, supplied_source=supplied_source,
                                                     installed_archives=wrong)
                aggregate["product_source_after"] = {"revision": "e" * 40, "content_sha256": "f" * 64}
                with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "source identities"):
                    EVIDENCE._aggregate_archive_join(ROOT, report, supplied_source=supplied_source,
                                                     installed_archives=installed)
        finally:
            EVIDENCE.validate_aggregate_report = original_validate

    def test_ordinary_popcount_attachment_resolves_checkout_receipts_and_relative_maps(self) -> None:
        test_root = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        test_root.mkdir(parents=True, exist_ok=True)
        expected_inputs = {"source": {"revision": "same"}, "product": {"sha256": "same"}}
        _facts, ordinary = EVIDENCE._load_companion_modules()

        class Ordinary:
            PublicDataEvidenceError = ordinary.PublicDataEvidenceError
            work_file_identity = staticmethod(ordinary.work_file_identity)
            resolve_work_identity = staticmethod(ordinary.resolve_work_identity)

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
                    map_path.write_text(
                        "VMA Size Align Out In Symbol\n"
                        "0x2000 4 4 libcrabc-builtins.a(crabc-builtins.o):(.text.__popcountdi2)\n"
                        "0x2000 0 0 __popcountdi2\n")
                    trace_path.write_text("libcrabc-builtins.a(crabc-builtins.o)\n")
                    receipt = work / (mode + ".receipt.json")
                    receipt.write_text(EVIDENCE.canonical_json({
                        "map": {"path": map_path.name, "sha256": EVIDENCE.digest(map_path)},
                        "trace": {"path": trace_path.name, "sha256": EVIDENCE.digest(trace_path)},
                    }))
                    # The report owns checkout-relative identities; the driver
                    # receipt separately owns its adjacent map/trace basenames.
                    links[mode] = {"receipt": ordinary.work_file_identity(ROOT, receipt, "receipt")}
                links.update({"dynamic-pie": {}, "dynamic-non-pie": {}})
                report = work / "report.json"
                report.write_text(EVIDENCE.canonical_json({"source_before": expected_inputs,
                                                          "source_after": expected_inputs, "links": links}))
                joined = EVIDENCE._ordinary_popcount_maps(ROOT, report, expected_inputs)
                self.assertEqual(set(joined["static_modes"]), {"static", "static-pie"})
                static_map = work / "static.map"
                original_map = static_map.read_bytes()
                original_receipt = (work / "static.receipt.json").read_bytes()
                static_map.write_bytes(original_map +
                    b"0x3000 4 4 libc.a(foreign.o):(.text.__popcountdi2)\n")
                changed_receipt = json.loads(original_receipt)
                changed_receipt["map"]["sha256"] = EVIDENCE.digest(static_map)
                (work / "static.receipt.json").write_text(EVIDENCE.canonical_json(changed_receipt))
                links["static"]["receipt"] = ordinary.work_file_identity(
                    ROOT, work / "static.receipt.json", "receipt")
                report.write_text(EVIDENCE.canonical_json({"source_before": expected_inputs,
                                                          "source_after": expected_inputs, "links": links}))
                with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError,
                                            "provider map is ambiguous"):
                    EVIDENCE._ordinary_popcount_maps(ROOT, report, expected_inputs)
                static_map.write_bytes(original_map)
                (work / "static.receipt.json").write_bytes(original_receipt)
                links["static"]["receipt"] = ordinary.work_file_identity(
                    ROOT, work / "static.receipt.json", "receipt")
                report.write_text(EVIDENCE.canonical_json({"source_before": expected_inputs,
                                                          "source_after": expected_inputs, "links": links}))
                for mode in ("static", "static-pie"):
                    # Replay and attachment must still agree on receipt bytes.
                    # Keep the report unchanged while replacing its sealed file.
                    receipt = ROOT / links[mode]["receipt"]["path"]
                    saved = receipt.read_bytes()
                    receipt.write_bytes(saved + b"\n")
                    with self.assertRaisesRegex(ordinary.PublicDataEvidenceError, "receipt bytes differ"):
                        EVIDENCE._ordinary_popcount_maps(ROOT, report, expected_inputs)
                    receipt.write_bytes(saved)
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

    def test_final_direct_call_requires_the_physical_provider_target(self) -> None:
        elf = object.__new__(EVIDENCE.Elf)
        image = bytearray(64)
        call_address, provider = 0x2010, 0x2100
        image[0x10:0x15] = b"\xe8" + (provider - call_address - 5).to_bytes(4, "little", signed=True)
        elf.data = bytes(image)
        elf.programs = [(1, 5, 0, 0x2000, 0, len(image), len(image), 0x1000)]
        source = [{"section": ".text.caller", "offset": 5}]
        placement = {".text.caller": (0x200c, 32)}
        joined = EVIDENCE._final_direct_calls(elf, source, placement, provider)
        self.assertEqual(joined["resolved_calls"][0]["target_address"], provider)
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "foreign provider"):
            EVIDENCE._final_direct_calls(elf, source, placement, provider + 1)
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "no selected call"):
            EVIDENCE._final_direct_calls(elf, source, {}, provider)

    def test_link_map_projection_selects_the_observed_exact_header(self) -> None:
        name = "libcrabc-builtins.a(crabc-builtins.o):(.text.__addoti4)"
        mold = EVIDENCE._link_map_rows([
            "VMA Size Align Out In Symbol",
            f"0x200160 10 16 {name}",
        ])
        lld = EVIDENCE._link_map_rows([
            "VMA LMA Size Align Out In Symbol",
            f"200160 200160 0000a 16 {name}",
        ])
        expected = EVIDENCE._LinkMapRow(0x200160, 10, 16, name)
        self.assertEqual(mold, [expected])
        self.assertEqual(lld, [expected])
        with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "map header"):
            EVIDENCE._link_map_rows(["VMA Size Align Out In", f"0x200160 10 16 {name}"])

    def test_retained_helper_final_binding_tracks_the_validated_linkage(self) -> None:
        scratch = ROOT / ".work/x86_64/compiler-helper-evidence-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            directory = Path(temporary)
            static = EVIDENCE.Elf(_helper_elf(directory / "static", "LOCAL"))
            forged_static_global = EVIDENCE.Elf(_helper_elf(directory / "forged-static-global", "GLOBAL"))
            for mode in ("static", "static-pie"):
                with self.subTest(mode=mode):
                    static_policy = EVIDENCE._helper_final_policy_for_linkage(mode)
                    static_binding = EVIDENCE._helper_final_binding("GLOBAL", static_policy)
                    self.assertEqual(static_binding, "LOCAL")
                    self.assertEqual(
                        EVIDENCE._final_symbol(static, "__addoti4", static_binding)["binding"], "LOCAL"
                    )
                    self.assertEqual(EVIDENCE._helper_final_binding("LOCAL", static_policy), "LOCAL")
                    with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "provider metadata"):
                        EVIDENCE._final_symbol(forged_static_global, "__addoti4", static_binding)

            dynamic = EVIDENCE.Elf(_helper_elf(directory / "dynamic", "LOCAL", visibility=2))
            public = EVIDENCE.Elf(_helper_elf(directory / "public", "GLOBAL"))
            for mode in ("pie", "non-pie"):
                with self.subTest(mode=mode):
                    dynamic_policy = EVIDENCE._helper_final_policy_for_linkage(mode)
                    dynamic_binding = EVIDENCE._helper_final_binding("GLOBAL", dynamic_policy)
                    dynamic_visibility = EVIDENCE._helper_final_visibility("GLOBAL", dynamic_policy)
                    self.assertEqual(dynamic_binding, "LOCAL")
                    self.assertEqual(dynamic_visibility, "HIDDEN")
                    self.assertEqual(
                        EVIDENCE._final_symbol(dynamic, "__addoti4", dynamic_binding,
                                               visibility=dynamic_visibility)["visibility"], "HIDDEN"
                    )
                    self.assertEqual(EVIDENCE._helper_final_binding("LOCAL", dynamic_policy), "LOCAL")
                    self.assertEqual(EVIDENCE._helper_final_visibility("LOCAL", dynamic_policy), "DEFAULT")
                    private_local = EVIDENCE.Elf(_helper_elf(directory / (mode + "-local"), "LOCAL"))
                    self.assertEqual(
                        EVIDENCE._final_symbol(
                            private_local, "__addoti4", "LOCAL",
                            visibility=EVIDENCE._helper_final_visibility("LOCAL", dynamic_policy),
                        )["visibility"], "DEFAULT"
                    )
                    with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "provider metadata"):
                        EVIDENCE._final_symbol(public, "__addoti4", dynamic_binding,
                                               visibility=dynamic_visibility)
            hidden = EVIDENCE.Elf(_helper_elf(directory / "hidden", "LOCAL", visibility=2))
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "provider metadata"):
                EVIDENCE._final_symbol(hidden, "__addoti4", "LOCAL")

            leaked = EVIDENCE.Elf(_helper_elf(directory / "leaked", "LOCAL", "GLOBAL"))
            with self.assertRaisesRegex(EVIDENCE.CompilerHelperEvidenceError, "dynsym"):
                EVIDENCE._require_helpers_absent_from_dynsym(leaked, ("__addoti4",))

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
