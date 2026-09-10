"""Contract tests for the non-promoting installed pthread/TLS family receipt."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import owned_pthread_family as family
import owned_posix_product_evidence as product_evidence


class PthreadFamilyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/test-owned-pthread-family"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / ".work/posix").mkdir(parents=True)
        self.receipt = self.root / ".work/posix/execution.json"
        self.receipt.write_text("{}\n", encoding="utf-8")

    def test_roster_keeps_exactly_the_three_frozen_capabilities_and_named_cross_cut(self) -> None:
        roster = family.load_roster(ROOT / "compat/x86_64/pthread-family.toml")
        self.assertEqual(
            tuple(roster["capabilities"]),
            ("process.atfork-exit-hooks", "thread.pthread-c11", "time.posix-timer-thread-notify"),
        )
        self.assertEqual(roster["cross_cut"], "tls-dtv")
        self.assertTrue(roster["required"])
        self.assertTrue(all(entry["capability"] in roster["capabilities"] for entry in roster["required"]))

    def test_roster_requires_every_declared_behavior_in_its_exact_mode_set(self) -> None:
        source = (ROOT / "compat/x86_64/pthread-family.toml").read_text(encoding="utf-8")
        changed = source.replace(
            '  "primary:static-et-exec", "primary:static-pie", "reproduction:static-et-exec", "reproduction:static-pie", "extracted:static-et-exec", "extracted:static-pie",\n'
            '  "installed:dynamic-pie-kernel",',
            '  "primary:static-et-exec", "reproduction:static-et-exec", "reproduction:static-pie", "extracted:static-et-exec", "extracted:static-pie",\n'
            '  "installed:dynamic-pie-kernel",',
            1,
        )
        roster = self.root / "pthread-family.toml"
        roster.write_text(changed, encoding="utf-8")
        with self.assertRaisesRegex(family.PthreadFamilyError, "required behavior/mode contract"):
            family.load_roster(roster)

    def test_roster_rejects_a_behavior_redirected_to_another_valid_prerequisite(self) -> None:
        source = (ROOT / "compat/x86_64/pthread-family.toml").read_text(encoding="utf-8")
        changed = source.replace(
            'id = "pthread-cond-cancel"\ncapability = "thread.pthread-c11"\nkind = "dynamic-qualification"\ncase = "pthread-cond-cancel"',
            'id = "pthread-cond-cancel"\ncapability = "thread.pthread-c11"\nkind = "dynamic-qualification"\ncase = "pthread-spin"',
            1,
        )
        roster = self.root / "redirected-pthread-family.toml"
        roster.write_text(changed, encoding="utf-8")
        with self.assertRaisesRegex(family.PthreadFamilyError, "required qualification case differs"):
            family.load_roster(roster)

    def test_request_requires_one_relative_physical_posix_execution_receipt(self) -> None:
        request = {
            "schema": family.SCHEMA,
            "family_execution": ".work/posix/execution.json",
        }
        with patch.object(family.family, "validate_receipt", return_value={"fixture": True}) as validate:
            selected = family.validate_request(self.root, request)
        self.assertEqual(selected, self.receipt)
        validate.assert_called_once_with(self.root, self.receipt)

        for bad in (
            {"schema": family.SCHEMA},
            {"schema": family.SCHEMA, "family_execution": "/outside/execution.json"},
            {"schema": family.SCHEMA, "family_execution": ".work/posix/../execution.json"},
            {"schema": family.SCHEMA, "family_execution": ".work/posix/not-execution.json"},
            {"schema": family.SCHEMA, "family_execution": ".work/posix/execution.json", "waive": True},
        ):
            with self.subTest(request=bad), self.assertRaises(family.PthreadFamilyError):
                family.validate_request(self.root, bad)

    def test_component_receipt_cannot_be_complete_when_any_required_mode_is_missing(self) -> None:
        required = {
            "id": "c11-lifecycle-once-tsd",
            "capability": "thread.pthread-c11",
            "modes": ["primary:static-et-exec", "primary:static-pie"],
        }
        with self.assertRaisesRegex(family.PthreadFamilyError, "missing required mode"):
            family.require_complete_cells(required, {"primary:static-et-exec": {"kind": "fixture"}})

    def test_component_receipt_flags_are_explicitly_nonpromoting(self) -> None:
        self.assertEqual(family.NONPROMOTING_FLAGS, {
            "component_complete": True,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        })


if __name__ == "__main__":
    unittest.main()

class PthreadFamilyCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/test-owned-pthread-family-coverage"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / ".work").mkdir()

    def test_matrix_rows_bind_each_named_mode_to_its_immutable_run_receipt(self) -> None:
        entry = {
            "id": "timer", "capability": "time.posix-timer-thread-notify", "kind": "matrix",
            "workload": "posix-timers", "modes": ["primary:static-et-exec", "installed:dynamic-pie-direct"],
            "behavior": "fixture",
        }
        matrix = {
            "runs": {
                "primary": {"posix-timers": {"workload": "posix-timers", "static_product": "primary",
                    "dynamic_product": "installed", "receipt": {"path": ".work/primary.json", "sha256": "a" * 64, "size": 1},
                    "leaf": ".work/primary-leaf", "artifacts": {"raw": "static"}, "observations": {"case": "posix-timers"}}},
            }
        }
        cells = family.matrix_cells(matrix, entry)
        self.assertEqual(set(cells), {"primary:static-et-exec", "installed:dynamic-pie-direct"})
        self.assertEqual(cells["primary:static-et-exec"]["mode"], "static-et-exec")
        self.assertEqual(cells["installed:dynamic-pie-direct"]["product_pair"], "primary")

    def test_matrix_rows_reject_a_missing_product_or_other_workload(self) -> None:
        entry = {"id": "fork", "capability": "process.atfork-exit-hooks", "kind": "matrix",
                 "workload": "fork", "modes": ["installed:dynamic-pie-kernel"], "behavior": "fixture"}
        with self.assertRaisesRegex(family.PthreadFamilyError, "missing matrix workload"):
            family.matrix_cells({"runs": {"primary": {}}}, entry)

    def test_dynamic_case_rows_bind_all_entry_modes_to_each_qualified_case_receipt(self) -> None:
        entry = {"id": "mutex", "capability": "thread.pthread-c11", "kind": "dynamic-qualification",
                 "case": "pthread-mutex", "modes": [
                     "installed:dynamic-pie-kernel", "installed:dynamic-pie-direct",
                     "installed:dynamic-non-pie-kernel", "installed:dynamic-non-pie-direct",
                 ], "behavior": "fixture"}
        path = self.root / ".work/dynamic/qualification-cases/installed/pthread-mutex.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"product": "installed", "case": "pthread-mutex", "log": "fixture.log"}))
        identity = family.family.file_identity(self.root, path)
        qualification = {"work": ".work/dynamic", "cases": {identity["path"]: identity["sha256"]}}
        cells = family.dynamic_qualification_cells(self.root, qualification, entry)
        self.assertEqual(set(cells), set(entry["modes"]))
        self.assertEqual(cells["installed:dynamic-pie-direct"]["case_receipt"], identity)

    def test_dynamic_case_rows_reject_unsealed_case_receipt(self) -> None:
        entry = {"id": "mutex", "capability": "thread.pthread-c11", "kind": "dynamic-qualification",
                 "case": "pthread-mutex", "modes": ["installed:dynamic-pie-kernel"], "behavior": "fixture"}
        with self.assertRaisesRegex(family.PthreadFamilyError, "missing dynamic qualification case"):
            family.dynamic_qualification_cells(self.root, {"work": ".work/missing", "cases": {}}, entry)

    def test_matrix_request_retains_the_native_source_mount_for_relocated_replay(self) -> None:
        request_path = self.root / ".work/matrix/request.json"
        request_path.parent.mkdir(parents=True)
        request = {
            "schema": "fixture", "source_mount": "/workspace",
            "static_preparation": ".work/static.json", "dynamic_qualification": ".work/dynamic.json",
        }
        request_path.write_text(json.dumps(request), encoding="utf-8")
        inputs = {"source": {"fixture": "source"}, "oracle": {"fixture": "oracle"}}
        products = {
            "static": self.root / ".work/products/static",
            "dynamic": self.root / ".work/products/dynamic",
        }
        for product in products.values():
            product.mkdir(parents=True)
        matrix = {"request": family.family.file_identity(self.root, request_path), "inputs": inputs}
        with patch.object(family.family, "input_products", return_value=(inputs, products)):
            selected, _, selected_products = family.matrix_request(self.root, matrix)
        self.assertEqual(selected, request)
        self.assertEqual(
            family.composition_command(
                self.root, selected_products,
                {"runner": "compat/x86_64/run_owned_pthread_family_composition.sh"},
                selected["source_mount"],
            ),
            ["bash", "/workspace/compat/x86_64/run_owned_pthread_family_composition.sh", "--static-sysroot",
             "/workspace/.work/products/static", "/workspace/.work/products/dynamic"],
        )
        with patch.object(family.family, "input_products", return_value=({"source": {}}, products)):
            with self.assertRaisesRegex(family.PthreadFamilyError, "POSIX matrix inputs changed"):
                family.matrix_request(self.root, matrix)

    def test_static_link_receipts_use_the_driver_required_work_relative_paths(self) -> None:
        leaf = self.root / ".work/composition"
        static = self.root / ".work/products/static"
        dynamic = self.root / ".work/products/dynamic"
        leaf.mkdir(parents=True)
        static.mkdir(parents=True)
        dynamic.mkdir(parents=True)
        expected = family._expected_commands(
            self.root, leaf, static, dynamic,
            {"source": "compat/x86_64/owned_pthread_family_composition.c"}, "/workspace",
        )
        self.assertEqual(expected["static-link"][3], "static.crabc-link.json")
        self.assertEqual(expected["static-pie-link"][3], "static-pie.crabc-link.json")

    def test_link_binding_rejects_a_swapped_sealed_receipt_before_accepting_a_shape_match(self) -> None:
        leaf = self.root / ".work/composition"
        leaf.mkdir(parents=True)
        static = self.root / ".work/products/static"
        dynamic = self.root / ".work/products/dynamic"
        static.mkdir(parents=True)
        dynamic.mkdir(parents=True)
        (leaf / "workload.o").write_bytes(b"one canonical object")
        links = {}
        for name, (linkage, executable_name, receipt_name, validated_name, product_kind) in family.LINKS.items():
            (leaf / executable_name).write_bytes((name + " executable").encode())
            (leaf / receipt_name).write_bytes((name + " receipt").encode())
            product = static if product_kind == "static" else dynamic
            observed = {
                "linkage": linkage, "product": str(product), "product_format": "fixture",
                "product_manifest_sha256": "a" * 64, "workload_sha256": "b" * 64,
                "executable_sha256": "c" * 64, "receipt_sha256": "d" * 64,
            }
            retained = dict(observed)
            retained["product"] = "/workspace/" + product.relative_to(self.root).as_posix()
            (leaf / validated_name).write_text(json.dumps(retained), encoding="utf-8")
            links[name] = {
                "linkage": linkage,
                "executable": family.family.file_identity(self.root, leaf / executable_name),
                "receipt": family.family.file_identity(self.root, leaf / receipt_name),
                "validated": family.family.file_identity(self.root, leaf / validated_name),
            }

        def sealed_link(root, source_mount, product, workload, executable, receipt, linkage, linker):
            return {
                "linkage": linkage, "product": str(product), "product_format": "fixture",
                "product_manifest_sha256": "a" * 64, "workload_sha256": "b" * 64,
                "executable_sha256": "c" * 64, "receipt_sha256": "d" * 64,
            }

        tools = {"linker": {"path": "/opt/native-tools/ld.lld", "sha256": "e" * 64}}
        with patch.object(product_evidence, "validate_retained_link", side_effect=sealed_link) as validate:
            family._validate_link(self.root, leaf, links, static, dynamic, "/workspace", tools)
        self.assertEqual([call.args[2] for call in validate.call_args_list], [static, static, dynamic, dynamic])

        swapped = copy.deepcopy(links)
        swapped["static"]["receipt"] = links["static-pie"]["receipt"]
        with patch.object(product_evidence, "validate_retained_link", side_effect=sealed_link):
            with self.assertRaisesRegex(family.PthreadFamilyError, "composition static receipt path differs"):
                family._validate_link(self.root, leaf, swapped, static, dynamic, "/workspace", tools)

    def test_composition_oracle_must_match_the_validated_matrix_oracle(self) -> None:
        oracle = {
            "compiler_wrapper_sha256": "a" * 64,
            "runtime_sha256": "b" * 64,
            "files": {"source_manifest": "c" * 64},
        }
        report = {
            "compiler": {"path": "/usr/local/bin/crabc-x86_64-musl-gcc", "sha256": "a" * 64, "size": 1},
            "runtime": {"path": "/opt/musl-1.2.6/lib/libc.so", "sha256": "b" * 64, "size": 2},
            "pin": {"path": "/opt/musl-1.2.6/.crabc-oracle", "sha256": "c" * 64, "size": 3},
        }
        tools = {"oracle": dict(report["compiler"])}
        family._validate_oracle(report, oracle, tools)
        report["runtime"]["sha256"] = "d" * 64
        with self.assertRaisesRegex(family.PthreadFamilyError, "pinned oracle identity differs"):
            family._validate_oracle(report, oracle, tools)

    def test_tool_roster_rejects_a_malformed_or_swapped_native_tool(self) -> None:
        static = self.root / ".work/products/static"
        dynamic = self.root / ".work/products/dynamic"
        for path in (static / "bin/crabc-cc", dynamic / "bin/crabc-cc-dynamic"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(path.name.encode())
        def identity(path: Path) -> dict[str, object]:
            value = family.family.file_identity(self.root, path)
            return {"path": "/workspace/" + value["path"], "sha256": value["sha256"], "size": value["size"]}
        tools = {
            "oracle": {"path": "/usr/local/bin/crabc-x86_64-musl-gcc", "sha256": "a" * 64, "size": 1},
            "static_driver": identity(static / "bin/crabc-cc"),
            "dynamic_driver": identity(dynamic / "bin/crabc-cc-dynamic"),
            "compiler": {"path": "/opt/native-tools/gcc", "sha256": "b" * 64, "size": 2},
            "linker": {"path": "/opt/native-tools/ld.lld", "sha256": "c" * 64, "size": 3},
        }
        family._tool_roster(self.root, tools, static, dynamic, "/workspace")
        malformed = copy.deepcopy(tools)
        malformed["linker"]["size"] = True
        with self.assertRaisesRegex(family.PthreadFamilyError, "tool identity is malformed"):
            family._tool_roster(self.root, malformed, static, dynamic, "/workspace")
        swapped = copy.deepcopy(tools)
        swapped["static_driver"] = dict(swapped["dynamic_driver"])
        with self.assertRaisesRegex(family.PthreadFamilyError, "installed driver seal"):
            family._tool_roster(self.root, swapped, static, dynamic, "/workspace")

    def _execution_copy_fixture(self, name: str) -> tuple[Path, Path]:
        """Build one synthetic sealed product and the root that would execute it."""

        product = self.root / ".work" / (name + "-product")
        payload = tuple(product_evidence.DYNAMIC_REQUIRED)
        for relative in payload:
            path = product / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(relative.encode())
        (product / "usr/include").mkdir(parents=True)
        (product / "bin/crabc-cc-dynamic").chmod(0o755)
        (product / "lib/ld-crabc-x86_64.so.1").chmod(0o755)
        (product / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        files = {
            path.relative_to(product).as_posix(): family.family.digest(path)
            for path in sorted(product.rglob("*")) if path.is_file() and not path.is_symlink()
        }
        manifest = {
            "schema": 1, "format": product_evidence.DYNAMIC_PRODUCT_FORMAT,
            "target": product_evidence.TARGET, "files": files,
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
        }
        manifest_path = product / "share/crabc/manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        leaf = self.root / ".work" / (name + "-leaf")
        leaf.mkdir()
        for linkage in ("pie", "non-pie"):
            (leaf / ("dynamic-" + linkage)).write_bytes(("consumer-" + linkage).encode())
        execution = leaf / "dynamic-root"
        shutil.copytree(product, execution, symlinks=True)
        for linkage in ("pie", "non-pie"):
            shutil.copyfile(leaf / ("dynamic-" + linkage), execution / ("consumer-" + linkage))
        return product, leaf

    def test_execution_root_reconstructs_exact_product_and_two_consumers(self) -> None:
        for name, mutation, pattern in (
            ("good", None, None),
            ("swapped-runtime", lambda root: (root / "usr/lib/libc.so").write_bytes(b"foreign runtime"), "copy differs"),
            ("swapped-consumer", lambda root: (root / "consumer-pie").write_bytes(b"wrong consumer"), "copy differs"),
            ("extra-entry", lambda root: (root / "extra").write_bytes(b"undeclared"), "file roster"),
        ):
            with self.subTest(name=name):
                product, leaf = self._execution_copy_fixture(name)
                execution = leaf / "dynamic-root"
                if mutation is not None:
                    mutation(execution)
                    with self.assertRaisesRegex(family.PthreadFamilyError, pattern):
                        family._validate_execution_root(self.root, leaf, product)
                else:
                    record = family._validate_execution_root(self.root, leaf, product)
                    self.assertEqual(record["root"], execution.relative_to(self.root).as_posix())
