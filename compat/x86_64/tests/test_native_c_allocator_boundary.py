#!/usr/bin/env python3
"""Focused installed-product C allocator boundary reader contracts."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/native_c_allocator_boundary.py"
SPEC = importlib.util.spec_from_file_location("native_c_allocator_boundary_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
BOUNDARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BOUNDARY
SPEC.loader.exec_module(BOUNDARY)


class NativeCAllocatorBoundaryHarnessTests(unittest.TestCase):
    def test_contract_declares_the_finite_inverse_c_runtime_import_roster(self) -> None:
        contract = BOUNDARY.load_contract(ROOT)

        self.assertEqual(contract["scope"]["c_runtime_imports"], [
            {"name": "__errno_location", "binding": "GLOBAL"},
            {"name": "abort", "binding": "GLOBAL"},
            {"name": "clock_gettime", "binding": "WEAK"},
            {"name": "fputs", "binding": "GLOBAL"},
            {"name": "free", "binding": "GLOBAL"},
            {"name": "getenv", "binding": "GLOBAL"},
            {"name": "getrusage", "binding": "GLOBAL"},
            {"name": "madvise", "binding": "WEAK"},
            {"name": "memcpy", "binding": "GLOBAL"},
            {"name": "memset", "binding": "GLOBAL"},
            {"name": "mmap", "binding": "WEAK"},
            {"name": "mprotect", "binding": "WEAK"},
            {"name": "munmap", "binding": "WEAK"},
            {"name": "pathconf", "binding": "GLOBAL"},
            {"name": "prctl", "binding": "GLOBAL"},
            {"name": "pthread_key_create", "binding": "WEAK"},
            {"name": "pthread_key_delete", "binding": "WEAK"},
            {"name": "pthread_mutex_destroy", "binding": "GLOBAL"},
            {"name": "pthread_mutex_lock", "binding": "WEAK"},
            {"name": "pthread_mutex_unlock", "binding": "WEAK"},
            {"name": "pthread_setspecific", "binding": "GLOBAL"},
            {"name": "realpath", "binding": "GLOBAL"},
            {"name": "sleep", "binding": "GLOBAL"},
            {"name": "strtol", "binding": "GLOBAL"},
            {"name": "syscall", "binding": "GLOBAL"},
            {"name": "sysconf", "binding": "GLOBAL"},
            {"name": "sysinfo", "binding": "WEAK"},
        ])

    def test_interposition_runner_derives_owned_dynamic_link_receipts(self) -> None:
        runner = (ROOT / "compat/x86_64/run_owned_c_allocation_interposition.sh").read_text(
            encoding="utf-8"
        )

        for mode in ("pie", "non-pie"):
            self.assertIn(f'-o "$work/candidate-$mode"', runner)
        self.assertIn(
            '"$installed/bin/crabc-cc-dynamic" "$candidate_mode" -rdynamic "$work/workload.o"',
            runner,
        )
        self.assertNotIn("--link-receipt", runner)

    def test_startup_observation_binds_the_runner_owned_same_object(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            workload = work / "workload.o"
            workload.write_bytes(b"ELF fixture")
            self.assertEqual(BOUNDARY._startup_workload(work), workload)

    def test_runtime_static_member_links_require_both_authenticated_members(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            static = output / "static"
            library = static / "usr/lib/libc.a"
            library.parent.mkdir(parents=True)
            library.write_bytes(b"archive fixture")
            archive = BOUNDARY.mounted_path(library)
            imports = {
                "static_c_member": {
                    "name": "selected-c-mimalloc.o", "member_index": 1,
                    "member_occurrence": 0, "sha256": "a" * 64,
                },
                "static_rust_root_member": {
                    "name": "native-c-root.rcgu.o", "member_index": 0, "member_occurrence": 0,
                },
            }
            for mode in BOUNDARY.STATIC_MODES:
                receipt = output / f"static-{mode}.crabc-link.json"
                receipt.write_bytes(b"receipt fixture")
                receipt.with_suffix(".trace").write_text(
                    f"{archive}(native-c-root.rcgu.o)\n{archive}(selected-c-mimalloc.o)\n",
                    encoding="utf-8",
                )
                receipt.with_suffix(".map").write_text(
                    f"  {archive}(native-c-root.rcgu.o):(.text.root)\n"
                    f"  {archive}(selected-c-mimalloc.o):(.text.c)\n",
                    encoding="utf-8",
                )
            links = BOUNDARY._runtime_static_member_links(output, output, static, imports)
            self.assertEqual(set(links), set(BOUNDARY.STATIC_MODES))
            self.assertEqual(
                links["static"]["selected_members"]["static_c_member"],
                f"{archive}(selected-c-mimalloc.o)",
            )
            (output / "static-static-pie.crabc-link.trace").write_text(
                f"{archive}(native-c-root.rcgu.o)\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "trace selection"):
                BOUNDARY._runtime_static_member_links(output, output, static, imports)
            (output / "static-static-pie.crabc-link.trace").write_text(
                f"{archive}(native-c-root.rcgu.o)\n{archive}(selected-c-mimalloc.o)\n",
                encoding="utf-8",
            )
            (output / "static-static-pie.crabc-link.map").write_text(
                f"  {archive}(native-c-root.rcgu.o):(.text.root)\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "map selection"):
                BOUNDARY._runtime_static_member_links(output, output, static, imports)

    def test_link_receipt_reader_keeps_the_real_workload_separate_from_its_output(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            work = output / "work"
            work.mkdir()
            workload = work / "workload.o"
            executable = work / "candidate-pie"
            receipt = work / "candidate-pie.crabc-link.json"
            for path in (workload, executable, receipt):
                path.write_bytes(b"fixture")
            validation = {
                "linkage": "pie", "product": "/workspace/.work/x86_64/product",
                "product_format": "crabc-x86-64-owned-dynamic-sysroot-v1",
                "product_manifest_sha256": "b" * 64, "workload_sha256": "c" * 64,
                "executable_sha256": "d" * 64, "receipt_sha256": "e" * 64,
            }
            with (
                mock.patch.object(BOUNDARY.product_evidence, "validate_link", return_value=validation) as validate,
                mock.patch.object(BOUNDARY, "json_object", return_value={"resolved_linker": {"path": "/fixture/ld.lld", "sha256": "a" * 64}}),
                mock.patch.object(BOUNDARY, "physical_file", return_value=Path("/fixture/ld.lld")),
                mock.patch.object(BOUNDARY.inventory, "sha256", return_value="a" * 64),
            ):
                record = BOUNDARY._link(
                    work, output, Path("/fixture/product"), workload, "candidate-pie",
                    "candidate-pie.crabc-link.json", "pie", export_dynamic=True,
                )
            self.assertEqual(validate.call_args.args[:4], (Path("/fixture/product"), workload, executable, receipt))
            self.assertEqual(validate.call_args.kwargs, {"export_dynamic": True})
            self.assertIs(record["export_dynamic"], True)
            self.assertEqual(record["validated"], {key: value for key, value in validation.items() if key != "product"})

    def test_product_epoch_rejects_mixed_static_dynamic_and_facts_sources(self) -> None:
        source = {"revision": "a" * 40, "content_sha256": "b" * 64}
        preparation = {
            "schema": BOUNDARY.static_products.SCHEMA,
            "status": "prepared-unqualified",
            "work": ".work/x86_64/preparation",
            "source": source,
            "source_seals": {},
            "pins": {},
            "products": {},
            "archives": {},
            "steps": {},
        }
        facts = {"collector_execution_source": {**source, "clean": True}}
        state = {"schema": "crabc.x86_64-owned-dynamic-materialization/v1", "source_sha256": source["content_sha256"]}
        self.assertEqual(BOUNDARY._epoch_source(preparation, facts, state), source)
        mismatched_facts = deepcopy(facts)
        mismatched_facts["collector_execution_source"]["content_sha256"] = "0" * 64
        with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "ELF facts source"):
            BOUNDARY._epoch_source(preparation, mismatched_facts, state)
        mismatched_state = deepcopy(state)
        mismatched_state["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "dynamic product source"):
            BOUNDARY._epoch_source(preparation, facts, mismatched_state)
        with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "static preparation fields"):
            BOUNDARY._epoch_source({"source": source}, facts, state)

    def test_lifecycle_binding_rejects_a_private_import_signature_drift(self) -> None:
        lifecycle = (ROOT / "libc/src/c_abi/x86_64/allocator_mimalloc_lifecycle.rs").read_text(encoding="utf-8")
        self.assertEqual(
            BOUNDARY._lifecycle_c_abi(lifecycle)["imports"],
            ["_mi_auto_process_init", "_mi_auto_process_done"],
        )
        with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "lifecycle import declaration"):
            BOUNDARY._lifecycle_c_abi(lifecycle.replace("fn _mi_auto_process_done();", "fn _mi_auto_process_done(value: usize);"))
        with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "callback differs for initialize"):
            BOUNDARY._lifecycle_c_abi(lifecycle.replace("fn initialize()", "fn initialize(value: c_int)"))

    def test_wrapper_product_bindings_reject_a_global_to_weak_row_drift(self) -> None:
        expected = {name: binding for name, (binding, _, _) in BOUNDARY.WRAPPER_C_ABI.items()}
        expected["malloc_usable_size"] = "GLOBAL"
        def row(name: str, binding: str) -> dict[str, object]:
            return {
                "name": name, "raw_name": name, "type": "FUNC", "binding": binding,
                "visibility": "DEFAULT", "section_index": "9", "version": None,
                "version_default": False, "size_bytes": 1,
            }
        static = {"member": "rust.o", "member_occurrence": 0, "symbol_tables": [{"name": ".symtab", "rows": [row(name, binding) for name, binding in expected.items()]}]}
        shared = {"symbol_tables": [
            {"name": ".dynsym", "rows": [row(name, binding) for name, binding in expected.items()]},
            {"name": ".symtab", "rows": [row(name, binding) for name, binding in expected.items()]},
        ]}
        facts = {"facts": {"candidate-static": [static], "candidate-shared": shared}}
        account = {"archive_map": {"static_rust_root_member": "rust.o"}}
        self.assertEqual(BOUNDARY._wrapper_product_bindings(facts, account, expected)["static_member"], "rust.o")
        shared["symbol_tables"][0]["rows"][1]["binding"] = "WEAK"
        with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, r"shared \.dynsym wrapper binding differs for calloc"):
            BOUNDARY._wrapper_product_bindings(facts, account, expected)

    def test_source_binding_rejects_an_abi_parameter_type_drift(self) -> None:
        wrapper = (ROOT / "libc/src/allocator_mimalloc.rs").read_text(encoding="utf-8")
        observation = (ROOT / "libc/src/allocator_observability_mimalloc.rs").read_text(encoding="utf-8")
        with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "signature differs for malloc"):
            BOUNDARY._c_abi_bindings(wrapper.replace("size: SizeT", "size: u32", 1), observation)

    def test_current_wrapper_and_lifecycle_sources_match_the_supplied_b525_epoch(self) -> None:
        resolution = BOUNDARY.source_resolution(ROOT, "b52538c57e07958a1d31ef5321dd5c6e2dedc258")
        self.assertEqual(resolution["product_revision"], "b52538c57e07958a1d31ef5321dd5c6e2dedc258")
        self.assertEqual(set(resolution["runtime_source_sha256"]), set(BOUNDARY.RUNTIME_SOURCES))

    def test_host_replay_uses_the_retained_workspace_link_reader_and_sealed_linker(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            work = output / "work"
            work.mkdir()
            for name in ("workload.o", "candidate-pie", "candidate-pie.crabc-link.json"):
                (work / name).write_bytes(b"fixture")
            validation = {
                "linkage": "pie", "product": "/workspace/.work/x86_64/product",
                "product_format": "crabc-x86-64-owned-dynamic-sysroot-v1",
                "product_manifest_sha256": "b" * 64, "workload_sha256": "c" * 64,
                "executable_sha256": "d" * 64, "receipt_sha256": "e" * 64,
            }
            link = {
                "validated": {key: value for key, value in validation.items() if key != "product"},
                "linker": {"path": "/opt/ld.lld", "sha256": "a" * 64},
                "export_dynamic": False,
                "executable": BOUNDARY.identity(work / "candidate-pie", logical_path="work/candidate-pie"),
                "receipt": BOUNDARY.identity(work / "candidate-pie.crabc-link.json", logical_path="work/candidate-pie.crabc-link.json"),
            }
            with mock.patch.object(BOUNDARY.product_evidence, "validate_retained_link", return_value=validation) as validate:
                BOUNDARY._replay_link(
                    work, output, Path("/fixture/product"), work / "workload.o", "candidate-pie",
                    "candidate-pie.crabc-link.json", "pie", link, export_dynamic=False,
                )
            self.assertEqual(validate.call_args.args[:3], (ROOT, "/workspace", Path("/fixture/product")))
            self.assertEqual(validate.call_args.args[-1], link["linker"])
            self.assertEqual(validate.call_args.kwargs, {"export_dynamic": False})
            changed = deepcopy(link)
            changed["export_dynamic"] = True
            with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "export-dynamic contract differs"):
                BOUNDARY._replay_link(
                    work, output, Path("/fixture/product"), work / "workload.o", "candidate-pie",
                    "candidate-pie.crabc-link.json", "pie", changed, export_dynamic=False,
                )

    def test_fresh_output_rejects_a_symlinked_existing_ancestor_before_creation(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            work = root / ".work/x86_64"
            work.mkdir(parents=True)
            outside = root / "outside"
            (outside / "nested").mkdir(parents=True)
            (work / "alias").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(BOUNDARY, "ROOT", root):
                with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "symlink"):
                    BOUNDARY.fresh_output(work / "alias/nested/output", static_preparation=root / "preparation.json",
                                          static_product=root / "static", dynamic_product=root / "dynamic")
            self.assertFalse((outside / "nested/output").exists())

    def test_collect_rejects_a_supplied_product_outside_the_workspace_before_writing_output(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            work = root / ".work/x86_64"
            work.mkdir(parents=True)
            inputs = work / "inputs"
            inputs.mkdir()
            output = work / "output"
            with mock.patch.object(BOUNDARY, "ROOT", root):
                with self.assertRaisesRegex(BOUNDARY.AllocatorBoundaryError, "static product escapes"):
                    BOUNDARY.collect(
                        static_preparation=inputs / "preparation.json",
                        static_product=root / "outside-static-product",
                        dynamic_product=inputs / "dynamic-product",
                        elf_facts_report=inputs / "facts.json",
                        output=output,
                    )
            self.assertFalse(output.exists())

    def test_contract_and_source_resolution_keep_weak_and_global_allocator_entries_distinct(self) -> None:
        contract = BOUNDARY.load_contract(ROOT)
        self.assertEqual(contract["scope"]["weak_entries"], ["malloc"])
        self.assertEqual(contract["scope"]["global_entries"], [
            "calloc", "realloc", "reallocarray", "free", "aligned_alloc", "posix_memalign", "memalign", "valloc", "malloc_usable_size",
        ])
        resolution = BOUNDARY.source_resolution(ROOT, "b52538c57e07958a1d31ef5321dd5c6e2dedc258")
        self.assertEqual(resolution["c_abi_bindings"]["malloc"], {
            "binding": "WEAK", "signature": "pub unsafe extern \"C\" fn malloc(size: SizeT) -> *mut c_void",
            "callee": "mi_malloc_aligned",
        })
        self.assertEqual(resolution["c_abi_bindings"]["malloc_usable_size"], {
            "binding": "GLOBAL", "signature": "pub unsafe extern \"C\" fn malloc_usable_size(ptr: *mut c_void) -> usize",
            "callee": "mi_usable_size",
        })

    def test_retained_command_identity_uses_workspace_paths_on_host_replay(self) -> None:
        scratch = ROOT / ".work/x86_64/native-c-allocator-boundary-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            work = root / ".work/x86_64"
            work.mkdir(parents=True)
            source = root / "compat/x86_64/runner.sh"
            source.parent.mkdir(parents=True)
            source.write_text("#!/bin/sh\n", encoding="utf-8")
            with mock.patch.object(BOUNDARY, "ROOT", root):
                self.assertEqual(BOUNDARY.mounted_path(source), "/workspace/compat/x86_64/runner.sh")
                self.assertEqual(BOUNDARY.workload_environment(work / "receipt")["TMPDIR"], "/workspace/.work/x86_64/receipt")


if __name__ == "__main__":
    unittest.main()
