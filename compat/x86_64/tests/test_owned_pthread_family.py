"""Contract tests for the non-promoting installed pthread/TLS family receipt."""

from __future__ import annotations

import copy
from contextlib import ExitStack
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
import owned_dynamic_qualification as dynamic_qualification


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
            selected, matrix = family.validate_request(self.root, request)
        self.assertEqual(selected, self.receipt)
        self.assertEqual(matrix, {"fixture": True})
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

    def _collection_fixture(self) -> tuple[Path, Path, dict[str, object], Path]:
        roster = self.root / "compat/x86_64/pthread-family.toml"
        roster.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "compat/x86_64/pthread-family.toml", roster)
        matrix_path = self.root / ".work/posix/execution.json"
        matrix_path.parent.mkdir(parents=True)
        matrix_path.write_text("{}\n", encoding="utf-8")
        matrix = {
            "schema": family.family.SCHEMA,
            "status": "workload-matrix-verified",
            "family": "libc.posix-runtime",
            "native_aggregate_complete": False,
            "family_completion": False,
            "public_support": False,
            "request": {"fixture": "request"},
            "inputs": {
                "source": {"fixture": "source"},
                "oracle": {"fixture": "oracle"},
                "dynamic_qualification": {"fixture": "dynamic"},
            },
        }
        work = self.root / ".work/collection"
        work.mkdir()
        (work / "request.json").write_text(json.dumps({
            "schema": family.SCHEMA,
            "family_execution": ".work/posix/execution.json",
        }), encoding="utf-8")
        return work, matrix_path, matrix, roster

    def _collect_with_mocked_prerequisites(self, work: Path, matrix_path: Path,
                                           matrix: dict[str, object], roster: Path) -> dict[str, object]:
        loaded_roster = family.load_roster
        phase = type("FixturePhase", (), {
            "matrix": matrix,
            "matrix_identity": family.family.file_identity(self.root, matrix_path),
            "dynamic_qualification": {},
            "require_output_disjoint": staticmethod(lambda _work: None),
            "require_current": staticmethod(lambda _root: None),
        })()

        def fixture_cells(*arguments: object) -> dict[str, dict[str, str]]:
            required = arguments[-1]
            return {mode: {"kind": "fixture"} for mode in required["modes"]}

        with patch.object(family, "ROSTER_PATH", roster), \
                patch.object(family, "load_roster", side_effect=lambda: loaded_roster(roster)), \
                patch.object(family, "_validated_phase_inputs", return_value=phase), \
                patch.object(family, "matrix_cells", side_effect=fixture_cells), \
                patch.object(family, "dynamic_qualification_cells", side_effect=fixture_cells), \
                patch.object(family, "composition_cells", side_effect=fixture_cells):
            return family.collect(self.root, work)

    def test_collection_seals_a_tracked_roster_outside_mutable_evidence(self) -> None:
        work, matrix_path, matrix, roster = self._collection_fixture()
        record = self._collect_with_mocked_prerequisites(work, matrix_path, matrix, roster)
        self.assertEqual(record["roster"], {
            "path": "compat/x86_64/pthread-family.toml",
            "sha256": family.family.digest(roster),
            "size": roster.stat().st_size,
        })

    def test_collection_rejects_a_symlink_or_external_roster(self) -> None:
        work, matrix_path, matrix, roster = self._collection_fixture()
        symlink = self.root / "compat/x86_64/pthread-family-link.toml"
        symlink.symlink_to(roster)
        external = self.root.parent / (self.root.name + "-external-roster.toml")
        shutil.copyfile(roster, external)
        self.addCleanup(lambda: external.unlink(missing_ok=True))
        for name, candidate in (("symlink", symlink), ("external", external)):
            with self.subTest(name=name), self.assertRaisesRegex(family.PthreadFamilyError,
                                                                  "physical checkout file"):
                self._collect_with_mocked_prerequisites(work, matrix_path, matrix, candidate)

    def test_composition_command_retains_the_native_source_mount_for_relocated_replay(self) -> None:
        products = {
            "static": self.root / ".work/products/static",
            "dynamic": self.root / ".work/products/dynamic",
        }
        for product in products.values():
            product.mkdir(parents=True)
        self.assertEqual(
            family.composition_command(
                self.root, products,
                {"runner": "compat/x86_64/run_owned_pthread_family_composition.sh"},
                "/workspace",
            ),
            ["bash", "/workspace/compat/x86_64/run_owned_pthread_family_composition.sh", "--static-sysroot",
             "/workspace/.work/products/static", "/workspace/.work/products/dynamic"],
        )

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
        # The copied execution-root reader validates the supplied dynamic
        # product through the common installed link-input contract.  libc.so
        # is executable there, just as it is in a materialized product.
        (product / "usr/lib/libc.so").chmod(0o755)
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


class PthreadPhaseInputTests(unittest.TestCase):
    """Exercise one coordinator phase against retained, physical input trees.

    The POSIX matrix validator is deliberately represented by one narrow
    external-owner seam. Everything after that boundary—the sealed request,
    product paths, source/oracle checks, snapshots, collection, and the
    composition subprocess—uses the real coordinator code and fixture files.
    """

    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/test-owned-pthread-phase-inputs"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / ".work").mkdir()
        self.source_marker = self.root / "source-marker"
        self.source_marker.write_text("source before phase\n", encoding="utf-8")
        self.source = {"revision": "1" * 40, "content_sha256": family.family.digest(self.source_marker)}
        self.roster_path = self.root / "compat/x86_64/pthread-family.toml"
        self.roster_path.parent.mkdir(parents=True)
        self.roster_path.write_text("phase fixture roster\n", encoding="utf-8")
        self.static_work = self.root / ".work/static"
        self.dynamic_work = self.root / ".work/dynamic"
        self.posix_work = self.root / ".work/posix"
        for directory in (self.static_work, self.dynamic_work, self.posix_work):
            directory.mkdir()
        self.static_preparation = self.static_work / "preparation.json"
        self.dynamic_qualification = self.dynamic_work / "qualification.json"
        self.static_preparation.write_text("{}\n", encoding="utf-8")

        static_paths = family.family.static_products.product_paths(self.static_work)
        for label, product in static_paths.items():
            (product / "share/crabc").mkdir(parents=True)
            (product / "payload").write_text(f"static {label}\n", encoding="utf-8")
            (product / "share/crabc/manifest.json").write_text(
                json.dumps({"product": label}), encoding="utf-8")
        self.static_payload = static_paths["primary"] / "payload"

        dynamic_paths = {}
        for product in dynamic_qualification.PRODUCTS:
            path = self.dynamic_work / product
            (path / "share/crabc").mkdir(parents=True)
            (path / "payload").write_text(f"dynamic {product}\n", encoding="utf-8")
            (path / "share/crabc/manifest.json").write_text(
                json.dumps({"product": product}), encoding="utf-8")
            dynamic_paths[product] = path

        # Offline receipt phases must revalidate these retained oracle bytes
        # without touching a native image's /opt or /usr/local oracle paths.
        self.unavailable_oracle_files = {
            name: self.root / ".unavailable-live-oracle" / name
            for name in dynamic_qualification.ORACLE_FILES
        }
        pins = self.root / "compat/upstreams.toml"
        pins.parent.mkdir(exist_ok=True)
        pins.write_text(
            "[musl]\nversion = \"1.2.6\"\nsha256 = \"fixture-source\"\nfallback_revision = \"fixture-revision\"\n",
            encoding="utf-8",
        )
        wrapper = self.root / "docker/x86_64-musl-oracle-gcc"
        wrapper.parent.mkdir(exist_ok=True)
        wrapper.write_bytes(b"fixture musl compiler wrapper\n")
        retained_oracle = self.dynamic_work / "qualification-oracle"
        retained_oracle.mkdir()
        (retained_oracle / "runtime").write_bytes(b"fixture musl runtime\n")
        (retained_oracle / "compiler_wrapper").write_bytes(wrapper.read_bytes())
        (retained_oracle / "specs").write_bytes(b"fixture musl specs\n")
        (retained_oracle / "source_manifest").write_text(
            "format=crabc-pinned-musl-oracle-v1\nversion=1.2.6\n"
            "source_sha256=fixture-source\nfallback_revision=fixture-revision\narchitecture=x86_64\n",
            encoding="utf-8",
        )
        (retained_oracle / "specs_manifest").write_text(
            f"{family.family.digest(retained_oracle / 'specs')}  /opt/musl-1.2.6/lib/musl-gcc.specs\n",
            encoding="utf-8",
        )
        self.retained_oracle_runtime = retained_oracle / "runtime"
        oracle_files = {
            name: family.family.digest(retained_oracle / name)
            for name in dynamic_qualification.ORACLE_FILES
        }
        self.oracle = {
            "version": "musl-1.2.6",
            "runtime_sha256": oracle_files["runtime"],
            "compiler_wrapper_sha256": oracle_files["compiler_wrapper"],
            "pins_sha256": family.family.digest(pins),
            "files": oracle_files,
        }

        # Dynamic validation reaches this retained leaf through the sealed case
        # record, even though the leaf is not below dynamic_work.
        external_leaf = self.root / ".work/external-dynamic-case-artifacts"
        external_leaf.mkdir()
        self.external_dynamic_artifact = external_leaf / "payload"
        self.external_dynamic_artifact.write_text("retained external dynamic leaf\n", encoding="utf-8")
        case_path = self.dynamic_work / "qualification-cases/installed/fixture.json"
        case_path.parent.mkdir(parents=True)
        case_path.write_text(json.dumps({
            "artifacts": {external_leaf.relative_to(self.root).as_posix(): {}},
        }), encoding="utf-8")
        self.dynamic_qualification.write_text(json.dumps({
            "work": self.dynamic_work.relative_to(self.root).as_posix(),
            "cases": {case_path.relative_to(self.root).as_posix(): family.family.digest(case_path)},
        }), encoding="utf-8")
        (self.dynamic_work / "qualification-prepare.json").write_text(
            json.dumps({"oracle": self.oracle}), encoding="utf-8")

        self.posix_request = self.posix_work / "request.json"
        self.posix_request.write_text(json.dumps({
            "schema": family.family.SCHEMA,
            "source_mount": "/workspace",
            "static_preparation": self.static_preparation.relative_to(self.root).as_posix(),
            "dynamic_qualification": self.dynamic_qualification.relative_to(self.root).as_posix(),
        }), encoding="utf-8")
        inputs = {
            "static_preparation": family.family.file_identity(self.root, self.static_preparation),
            "dynamic_qualification": family.family.file_identity(self.root, self.dynamic_qualification),
            "source": self.source,
            "static_products": {
                label: family.family.file_identity(self.root, product / "share/crabc/manifest.json")
                for label, product in static_paths.items()
            },
            "dynamic_products": {
                label: {
                    "path": dynamic_paths[dynamic_product].relative_to(self.root).as_posix(),
                    "manifest_sha256": family.family.digest(
                        dynamic_paths[dynamic_product] / "share/crabc/manifest.json"),
                }
                for label, dynamic_product in family.family.PAIRS.items()
            },
            "dynamic_work": self.dynamic_work.relative_to(self.root).as_posix(),
            "oracle": self.oracle,
        }
        self.matrix = {
            "schema": family.family.SCHEMA,
            "status": "workload-matrix-verified",
            "family": "libc.posix-runtime",
            "native_aggregate_complete": False,
            "family_completion": False,
            "public_support": False,
            "request": family.family.file_identity(self.root, self.posix_request),
            "inputs": inputs,
            "runs": {
                "primary": {
                    "fixture": {
                        "workload": "fixture", "static_product": "primary",
                        "dynamic_product": "installed",
                        "receipt": {"path": ".work/posix/fixture.json", "sha256": "a" * 64, "size": 1},
                        "leaf": ".work/posix/fixture-leaf", "artifacts": {}, "observations": {},
                    },
                },
            },
        }
        self.matrix_path = self.posix_work / "execution.json"
        self.matrix_path.write_text(json.dumps(self.matrix), encoding="utf-8")
        self.work = self.root / ".work/pthread"
        self.work.mkdir()
        (self.work / "request.json").write_text(json.dumps({
            "schema": family.SCHEMA,
            "family_execution": self.matrix_path.relative_to(self.root).as_posix(),
        }), encoding="utf-8")

    @staticmethod
    def _matrix_roster() -> dict[str, object]:
        return {"required": [{
            "id": "fixture-matrix", "capability": "thread.pthread-c11", "kind": "matrix",
            "workload": "fixture", "modes": ["primary:static-et-exec"], "behavior": "fixture",
        }]}

    @staticmethod
    def _composition_roster() -> dict[str, object]:
        return {"required": [{
            "id": "fixture-composition", "capability": "thread.pthread-c11", "kind": "composition",
            "modes": ["primary:static-et-exec"], "behavior": "fixture",
            "runner": "compat/x86_64/phase-mutator.py", "source": "compat/x86_64/fixture.c",
        }]}

    def _phase_patches(self, roster: dict[str, object], calls: list[Path], *, forbid_input_products: bool,
                       source_identity: object = None, before_validator_return: object = None,
                       allow_live_oracle: bool = False) -> ExitStack:
        stack = ExitStack()

        def validate_matrix(root: Path, path: Path) -> dict[str, object]:
            self.assertEqual(root, self.root)
            self.assertEqual(path, self.matrix_path)
            calls.append(path)
            matrix = family.family.read(path)
            if before_validator_return is not None:
                before_validator_return()
            return matrix

        stack.enter_context(patch.object(family, "ROSTER_PATH", self.roster_path))
        stack.enter_context(patch.object(family, "load_roster", return_value=roster))
        stack.enter_context(patch.object(family.family, "validate_receipt", side_effect=validate_matrix))
        if source_identity is None:
            source_identity = lambda _root: self.source
        stack.enter_context(patch.object(family.family.static_products, "source_identity", side_effect=source_identity))
        stack.enter_context(patch.object(dynamic_qualification, "ROOT", self.root))
        stack.enter_context(patch.object(dynamic_qualification, "ORACLE_FILES", self.unavailable_oracle_files))
        if allow_live_oracle:
            stack.enter_context(patch.object(dynamic_qualification, "require_live_oracle"))
        if forbid_input_products:
            stack.enter_context(patch.object(
                family.family, "input_products",
                side_effect=AssertionError("pthread phase replayed the complete POSIX input validator"),
            ))
        else:
            products = {
                label: {
                    "static": family.family.static_products.product_paths(self.static_work)[label],
                    "dynamic": self.dynamic_work / dynamic_product,
                }
                for label, dynamic_product in family.family.PAIRS.items()
            }
            stack.enter_context(patch.object(family.family, "input_products", return_value=(self.matrix["inputs"], products)))
        return stack

    def test_offline_collect_and_standalone_validation_use_retained_oracle_and_one_complete_prerequisite_phase(self) -> None:
        calls: list[Path] = []
        with self._phase_patches(self._matrix_roster(), calls, forbid_input_products=True):
            record = family.collect(self.root, self.work)
            self.assertEqual(len(calls), 1)
            receipt = self.work / "receipt.json"
            receipt.write_text(json.dumps(record), encoding="utf-8")
            family.validate_receipt(self.root, receipt)
            self.assertEqual(len(calls), 2)
            family.collect(self.root, self.work)
            self.assertEqual(len(calls), 3)

    def test_collect_rejects_a_retained_product_mutation_at_the_phase_end(self) -> None:
        calls: list[Path] = []
        original_matrix_cells = family.matrix_cells

        def mutate_after_mapping(matrix: dict[str, object], required: dict[str, object]) -> dict[str, dict[str, object]]:
            result = original_matrix_cells(matrix, required)
            self.static_payload.write_text("mutated after validation\n", encoding="utf-8")
            return result

        with self._phase_patches(self._matrix_roster(), calls, forbid_input_products=False), \
                patch.object(family, "matrix_cells", side_effect=mutate_after_mapping):
            with self.assertRaisesRegex(family.PthreadFamilyError, "static preparation evidence changed"):
                family.collect(self.root, self.work)
        self.assertEqual(len(calls), 1)

    def test_offline_collect_rejects_a_retained_oracle_mutation_without_live_oracle_paths(self) -> None:
        calls: list[Path] = []
        original_matrix_cells = family.matrix_cells

        def mutate_after_mapping(matrix: dict[str, object], required: dict[str, object]) -> dict[str, dict[str, object]]:
            result = original_matrix_cells(matrix, required)
            self.retained_oracle_runtime.write_bytes(b"mutated retained oracle runtime\n")
            return result

        with self._phase_patches(self._matrix_roster(), calls, forbid_input_products=True), \
                patch.object(family, "matrix_cells", side_effect=mutate_after_mapping):
            with self.assertRaisesRegex(dynamic_qualification.QualificationError,
                                        "oracle retained file identity differs"):
                family.collect(self.root, self.work)
        self.assertEqual(len(calls), 1)

    def test_collect_rejects_an_external_dynamic_case_artifact_mutation_at_the_phase_end(self) -> None:
        calls: list[Path] = []
        original_matrix_cells = family.matrix_cells

        def mutate_after_mapping(matrix: dict[str, object], required: dict[str, object]) -> dict[str, dict[str, object]]:
            result = original_matrix_cells(matrix, required)
            self.external_dynamic_artifact.write_text("mutated external dynamic leaf\n", encoding="utf-8")
            return result

        with self._phase_patches(self._matrix_roster(), calls, forbid_input_products=True), \
                patch.object(family, "matrix_cells", side_effect=mutate_after_mapping):
            with self.assertRaisesRegex(family.PthreadFamilyError,
                                        "dynamic case artifact evidence.*changed"):
                family.collect(self.root, self.work)
        self.assertEqual(len(calls), 1)

    def test_collect_rejects_a_nonmanifest_product_change_after_full_validation(self) -> None:
        calls: list[Path] = []

        def mutate_after_validation() -> None:
            self.static_payload.write_text("changed after full validation\n", encoding="utf-8")

        with self._phase_patches(self._matrix_roster(), calls, forbid_input_products=True,
                                 before_validator_return=mutate_after_validation):
            with self.assertRaisesRegex(family.PthreadFamilyError,
                                        "static preparation evidence changed during POSIX validation"):
                family.collect(self.root, self.work)
        self.assertEqual(len(calls), 1)

    def test_collect_rejects_a_source_change_at_the_phase_end(self) -> None:
        calls: list[Path] = []
        original_matrix_cells = family.matrix_cells

        def current_source(_root: Path) -> dict[str, str]:
            return {"revision": "1" * 40, "content_sha256": family.family.digest(self.source_marker)}

        def mutate_after_mapping(matrix: dict[str, object], required: dict[str, object]) -> dict[str, dict[str, object]]:
            result = original_matrix_cells(matrix, required)
            self.source_marker.write_text("source after phase admission\n", encoding="utf-8")
            return result

        with self._phase_patches(self._matrix_roster(), calls, forbid_input_products=True,
                                 source_identity=current_source), \
                patch.object(family, "matrix_cells", side_effect=mutate_after_mapping):
            with self.assertRaisesRegex(family.family.ExecutionError, "POSIX matrix product source changed"):
                family.collect(self.root, self.work)
        self.assertEqual(len(calls), 1)

    def test_execute_uses_a_fresh_collection_context_then_standalone_validation_uses_another(self) -> None:
        calls: list[Path] = []
        output = self.root / ".work/pthread-execute-success"

        def command(_root: Path, _products: dict[str, Path], _roster: dict[str, object],
                    _source_mount: str) -> list[str]:
            return [sys.executable, "-c", "pass"]

        def fixture_cells(*arguments: object) -> dict[str, dict[str, str]]:
            required = arguments[-1]
            return {mode: {"kind": "fixture"} for mode in required["modes"]}

        with self._phase_patches(self._composition_roster(), calls, forbid_input_products=True,
                                 allow_live_oracle=True), \
                patch.object(family, "composition_command", side_effect=command), \
                patch.object(family, "composition_cells", side_effect=fixture_cells):
            receipt = family.execute(self.root, self.matrix_path, output, jobs=1)
            self.assertEqual(len(calls), 2)
            family.validate_receipt(self.root, receipt)
            self.assertEqual(len(calls), 3)

    def test_execute_rejects_a_product_mutated_by_the_composition_subprocess_before_collection(self) -> None:
        calls: list[Path] = []
        output = self.root / ".work/pthread-execute"
        mutator = self.root / "compat/x86_64/phase-mutator.py"
        mutator.parent.mkdir(parents=True, exist_ok=True)
        mutator.write_text(
            "from pathlib import Path\nimport sys\nPath(sys.argv[1], 'payload').write_text('changed by composition\\n')\n",
            encoding="utf-8",
        )

        def command(_root: Path, products: dict[str, Path], _roster: dict[str, object], _source_mount: str) -> list[str]:
            return [sys.executable, str(mutator), str(products["static"])]

        with self._phase_patches(self._composition_roster(), calls, forbid_input_products=False,
                                 allow_live_oracle=True), \
                patch.object(family, "composition_command", side_effect=command), \
                patch.object(family, "collect", side_effect=AssertionError("collection must not run after an input mutation")):
            with self.assertRaisesRegex(family.PthreadFamilyError, "static preparation evidence changed"):
                family.execute(self.root, self.matrix_path, output, jobs=1)
        self.assertEqual(len(calls), 1)
