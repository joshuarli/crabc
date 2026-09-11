#!/usr/bin/env python3
"""Focused rejection checks for the installed synthetic-loader component."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "compat" / "ldso" / "run_x86.py"


def runner():
    spec = importlib.util.spec_from_file_location("owned_loader_synthetic", SOURCE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def qualification():
    directory = str(ROOT / "compat" / "x86_64")
    if directory not in sys.path:
        sys.path.insert(0, directory)
    import owned_dynamic_qualification
    return owned_dynamic_qualification


class OwnedLoaderSyntheticTests(unittest.TestCase):
    def test_normal_exit_with_orphan_retains_observation_before_rejection(self) -> None:
        module = runner()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            work = pathlib.Path(directory)
            pid_path = work / "orphan.pid"
            program = """\
import os
import pathlib
import sys
import time
child = os.fork()
if child == 0:
    os.setsid()
    os.close(1)
    os.close(2)
    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
while not pathlib.Path(sys.argv[1]).exists():
    time.sleep(0.01)
print('parent observation', flush=True)
"""
            with self.assertRaisesRegex(module.LoaderSyntheticError, "descendant boundary"):
                module.Recorder(work, 2).run(
                    "normal-orphan", [sys.executable, "-c", program, pid_path], cwd=work
                )
            self.assertFalse(pathlib.Path(f"/proc/{int(pid_path.read_text())}").exists())
            self.assertEqual((work / "raw/0001-normal-orphan.stdout").read_bytes(), b"parent observation\n")
            observation = json.loads((work / "raw/0001-normal-orphan.json").read_text())
            self.assertEqual(observation["returncode"], 0)
            self.assertFalse(observation["timed_out"])

    def test_recorder_children_disable_core_dumps(self) -> None:
        module = runner()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            work = pathlib.Path(directory)
            result = module.Recorder(work, 2).run(
                "core-limit", [sys.executable, "-c", "import resource; print(resource.getrlimit(resource.RLIMIT_CORE))"],
                cwd=work,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"(0, 0)\n")
            self.assertFalse(result.timed_out)

    def test_recorder_timeout_reaps_a_session_escaping_descendant(self) -> None:
        """A timed-out fixture cannot leave a private session alive."""
        module = runner()
        scratch = ROOT / ".work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            work = pathlib.Path(directory)
            pid_path = work / "escaped.pid"
            program = """\
import os
import pathlib
import sys
import time

child = os.fork()
if child == 0:
    os.setsid()
    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
    while True:
        time.sleep(1)
while not pathlib.Path(sys.argv[1]).exists():
    time.sleep(0.01)
time.sleep(30)
"""
            result = module.Recorder(work, 0.2).run(
                "session-escape", [sys.executable, "-c", program, pid_path], cwd=work
            )
            self.assertTrue(result.timed_out)
            deadline = time.monotonic() + 2
            child = int(pid_path.read_text())
            try:
                while pathlib.Path(f"/proc/{child}").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(pathlib.Path(f"/proc/{child}").exists())
            finally:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_standard_case_seals_roots_after_runtime_observations(self) -> None:
        module = runner()
        oracle_root = pathlib.Path("/private/work/oracle-root")
        candidate_root = pathlib.Path("/private/work/candidate-root")
        observed = False

        def compare(*_args, **_kwargs):
            nonlocal observed
            observed = True
            return {"oracle": {}, "candidate": {}, "candidate_direct": {}}

        def seal(root):
            self.assertTrue(observed)
            return {"root": str(root)}

        with (
            mock.patch.object(module, "copy_root"),
            mock.patch.object(module, "build_arm", side_effect=[
                (pathlib.Path("/private/oracle"), {}),
                (pathlib.Path("/private/candidate"), {}),
            ]),
            mock.patch.object(module, "compare_standard", side_effect=compare),
            mock.patch.object(module, "tree_seal", side_effect=seal),
        ):
            result = module.case_standard("main-handle", pathlib.Path("/private/work"),
                                          pathlib.Path("/private/product"), object(), object())
        self.assertEqual(result["execution_roots"], {"oracle": {"root": str(oracle_root)},
                                                       "candidate": {"root": str(candidate_root)}})

    def test_roster_is_the_complete_frozen_loader_set(self) -> None:
        module = runner()
        self.assertEqual(
            tuple(module.CASES),
            (
                "nested-needed", "nested-dlopen", "search-path", "dso-origin",
                "initial-tls", "dlerror", "hash-formats", "hash-many", "relro",
                "auxv", "legacy-lifecycle", "lookup-scope", "visibility",
                "constructor-order", "main-handle", "lifecycle", "preload", "aslr",
                "dynamic-tls", "relocations", "weak-strong",
            ),
        )

    def test_selection_and_timeout_inputs_are_bounded_before_work_creation(self) -> None:
        module = runner()
        self.assertEqual(module.checked_selection(None), module.CASES)
        subset = module.checked_selection(("auxv",))
        self.assertEqual(subset, ("auxv",))
        self.assertTrue(module.selected_passed({"auxv": {"status": "pass"}}))
        self.assertFalse(module.exact_component_selection(subset))
        self.assertTrue(module.exact_component_selection(module.CASES))
        for selection in ((), ("auxv", "auxv"), ("not-a-case",)):
            with self.subTest(selection=selection), self.assertRaises(module.LoaderSyntheticError):
                module.checked_selection(selection)
        for value in (0.0, -1.0, math.inf, -math.inf, math.nan):
            with self.subTest(timeout=value), self.assertRaises(module.LoaderSyntheticError):
                module.checked_timeout(value)

    def test_installed_driver_linker_identity_seals_selected_physical_lld(self) -> None:
        module = runner()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            root = pathlib.Path(directory)
            linker = root / "ld.lld"
            linker.write_bytes(b"pinned linker bytes\n")
            linker.chmod(0o755)
            shared = SimpleNamespace(linker=lambda: str(linker))
            with mock.patch.object(module, "installed_driver_shared", return_value=shared):
                self.assertEqual(module.producer_linker_seal(root), {
                    "path": str(linker), "sha256": module.sha256(linker),
                })
            linker.write_bytes(b"replaced linker bytes\n")
            with mock.patch.object(module, "installed_driver_shared", return_value=shared):
                self.assertNotEqual(module.producer_linker_seal(root)["sha256"],
                                    hashlib.sha256(b"pinned linker bytes\n").hexdigest())

    def test_hash_formats_seals_both_direct_oracle_shared_outputs(self) -> None:
        module = runner()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            work = pathlib.Path(directory)

            class Recorder:
                def checked(self, name, argv, *, cwd):
                    if "-o" in argv:
                        output = pathlib.Path(argv[argv.index("-o") + 1])
                        output.parent.mkdir(parents=True, exist_ok=True)
                        output.write_bytes(name.encode())
                    tags = b"(GNU_HASH)" if name.endswith("gnu") else b"(HASH)"
                    return module.ProcessResult(tuple(map(str, argv)), 0, tags, b"", False)

            class Builder:
                def __init__(self):
                    self.links = []
                    self.role_index = 0

                def role(self, source, *defines):
                    output = work / f"role-{self.role_index}.o"
                    self.role_index += 1
                    output.write_bytes(str(source).encode())
                    return output

                def shared(self, arm, root, name, object_file, *, hash_style="sysv", runpath="/usr/lib"):
                    output = root / "usr/lib" / name
                    output.write_bytes((arm + name).encode())
                    return output

                def executable(self, arm, root, name, object_file, **kwargs):
                    output = root / name
                    output.write_bytes((arm + name).encode())
                    return output

            def stage(_product, target, *, candidate):
                (target / "usr/lib").mkdir(parents=True)

            builder = Builder()
            with mock.patch.object(module, "copy_root", side_effect=stage), \
                 mock.patch.object(module, "compare_standard", return_value={"oracle": {}, "candidate": {}, "candidate_direct": {}}):
                module.case_hash_formats(work, work / "product", Recorder(), builder)
            self.assertEqual([(entry["arm"], entry["kind"], pathlib.Path(entry["output"]).name)
                              for entry in builder.links],
                             [("oracle", "shared", "libhash_gnu.so"),
                              ("oracle", "shared", "libhash_sysv.so")])
            self.assertEqual([entry["output_sha256"] for entry in builder.links],
                             [module.sha256(work / "oracle-root/usr/lib/libhash_gnu.so"),
                              module.sha256(work / "oracle-root/usr/lib/libhash_sysv.so")])

    def test_invalid_product_is_rejected_before_checkout_work_is_created(self) -> None:
        module = runner()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            root = pathlib.Path(directory)
            missing = root / "missing-product"
            with mock.patch.object(module, "ROOT", root), self.assertRaises(module.LoaderSyntheticError):
                module.preflight(missing, None, 20.0)
            self.assertFalse((root / ".work").exists())

    def test_checkout_scratch_rejects_a_symlink_before_mkdir(self) -> None:
        module = runner()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            root = pathlib.Path(directory)
            outside = root / "outside"
            outside.mkdir()
            (root / ".work").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(module.LoaderSyntheticError):
                module.checked_scratch_directory(root)

    def test_catalogue_evidence_line_names_only_the_retained_directory(self) -> None:
        module = runner()
        catalogue = qualification()
        scratch = ROOT / ".work" / "test-owned-loader-synthetic-catalogue"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            leaf = pathlib.Path(directory)
            receipt = leaf / "report.json"
            receipt.write_text("{}\n")
            log = leaf / "runner.log"
            log.write_text("\n".join(module.summary_lines(False, leaf, receipt)) + "\n")
            self.assertEqual(catalogue.leaf_evidence_directories(log, str(ROOT)), {leaf})

    def test_wrapper_refuses_to_build_without_a_supplied_product(self) -> None:
        scratch = ROOT / ".work"
        scratch.mkdir(exist_ok=True)
        result = subprocess.run(
            [ROOT / "compat/x86_64/run_owned_loader_synthetic.sh"],
            env={"PATH": "/usr/bin:/bin", "TMPDIR": str(scratch)},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"usage:", result.stderr)

    def test_exact_observation_rejects_stream_or_status_changes(self) -> None:
        module = runner()
        good = module.ProcessResult(("/consumer",), 0, b"nested=42\n", b"", False)
        self.assertTrue(module.same_observation(good, good))
        self.assertFalse(module.same_observation(good, module.ProcessResult(("/consumer",), 1, b"nested=42\n", b"", False)))
        self.assertFalse(module.same_observation(good, module.ProcessResult(("/consumer",), 0, b"nested=42\n", b"loader\n", False)))

    def test_aslr_only_normalizes_the_required_base_relation(self) -> None:
        module = runner()
        first = module.ProcessResult(("/consumer",), 0, b"aslr=7 main=0x1000 dso=0x2000\n", b"", False)
        second = module.ProcessResult(("/consumer",), 0, b"aslr=7 main=0x3000 dso=0x4000\n", b"", False)
        self.assertTrue(module.valid_aslr_pair((first, second)))
        self.assertFalse(module.valid_aslr_pair((first, first)))
        self.assertFalse(module.valid_aslr_pair((first, module.ProcessResult(("/consumer",), 0, b"aslr=7\n", b"", False))))

    def test_lifecycle_keeps_markers_then_uses_exact_musl_stream(self) -> None:
        module = runner()
        observed = module.ProcessResult(("/consumer",), 0, b"ctor\nlifecycle=73\ndtor\nafter-close\nreopened=73\n", b"", False)
        self.assertTrue(module.valid_lifecycle_stream(observed))
        self.assertFalse(module.valid_lifecycle_stream(module.ProcessResult(("/consumer",), 0, b"ctor\nlifecycle=73\n", b"", False)))

    def test_rejects_a_symlinked_supplied_product_before_resolution(self) -> None:
        module = runner()
        scratch = ROOT / ".work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            base = pathlib.Path(directory)
            real = base / "real"
            real.mkdir()
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(module.LoaderSyntheticError):
                module.checked_product_directory(alias)

    def test_x86_relocation_contract_requires_each_frozen_class(self) -> None:
        module = runner()
        required = {"R_X86_64_RELATIVE", "R_X86_64_64", "R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"}
        self.assertTrue(module.has_required_relocations(required))
        self.assertFalse(module.has_required_relocations(required - {"R_X86_64_64"}))

    def test_x86_relocation_adapter_keeps_the_original_and_local_classes_distinct(self) -> None:
        module = runner()
        original = {"R_X86_64_64", "R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"}
        self.assertTrue(module.valid_x86_relocation_fixture(original, {"R_X86_64_RELATIVE"}))
        self.assertFalse(module.valid_x86_relocation_fixture(original, set()))
        self.assertFalse(module.valid_x86_relocation_fixture(original - {"R_X86_64_64"}, {"R_X86_64_RELATIVE"}))


if __name__ == "__main__":
    unittest.main()
