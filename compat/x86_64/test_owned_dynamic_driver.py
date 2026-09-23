"""Boundary regressions for the materialized shared-product driver."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import tempfile
import subprocess
import tomllib
import sys
import unittest
from unittest.mock import patch

import crabc_cc_owned_dynamic as driver
import owned_dynamic_package as package
import owned_posix_product_evidence as product_evidence
import io
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import build_x86_64_owned_dynamic_sysroot as producer

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PINNED_TOOLCHAIN = tomllib.loads((REPOSITORY_ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]


class InstalledDynamicDriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dynamic-driver-test.", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "installed"
        self.root.mkdir()
        for relative in driver.REQUIRED:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"owned test payload")
        (self.root / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")
        (self.root / "share/crabc").mkdir(parents=True, exist_ok=True)
        self.manifest = {"schema": 1, "format": driver.FORMAT, "target": driver.shared.TARGET,
                         "toolchain": PINNED_TOOLCHAIN,
                         "files": {relative: hashlib.sha256(b"owned test payload").hexdigest()
                                   for relative in driver.REQUIRED}, "symlinks": driver.ALIASES}
        self.write_manifest()

    def write_manifest(self):
        (self.root / "share/crabc/manifest.json").write_text(json.dumps(self.manifest))

    @staticmethod
    def _run_native(command: list[str]) -> None:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode:
            raise AssertionError(
                f"native fixture command failed: {command[0]}\n{completed.stdout}{completed.stderr}"
            )

    def _installed_native_driver_fixture(self) -> Path:
        """Materialize the smallest physical installed product for an ELF graph.

        This is deliberately not a mocked driver test. The fixture has a
        minimal owned-looking CRT/libc payload solely so the copied installed
        driver can compile and link a leaf, a root, and an executable through
        its normal fixed commands. The executable is inspected, not run.
        """

        root = Path(self.temporary.name) / "native-installed"
        library = root / "usr/lib"
        library.mkdir(parents=True)
        (root / "usr/include").mkdir(parents=True)
        (root / "share/crabc").mkdir(parents=True)
        (root / "bin").mkdir()
        (root / "lib").mkdir()
        for source, relative in (
            (Path(driver.__file__), "bin/crabc-cc-dynamic"),
            (Path(driver.shared.__file__), "share/crabc/crabc_cc_static.py"),
            (Path(driver.receipt_contract.__file__), "share/crabc/owned_dynamic_receipt.py"),
        ):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        (root / "bin/crabc-cc-dynamic").chmod(0o755)

        fixture = root / "fixture.s"
        fixture.write_text(".text\n.globl _start\n_start:\n  ret\n")
        empty = root / "empty.s"
        empty.write_text(".text\n")
        for source, output in ((fixture, "Scrt1.o"), (fixture, "crt1.o"),
                               (empty, "crti.o"), (empty, "crtn.o"),
                               (empty, "crabc-dynamic-attach.o"), (empty, "empty.o")):
            self._run_native(["/usr/bin/gcc", "-c", "-fPIC", str(source), "-o", str(library / output)])
        (root / "share/crabc/manifest.json").write_text(json.dumps({"toolchain": PINNED_TOOLCHAIN}))
        self._run_native([
            driver.shared.linker(root), "-shared", "--hash-style=sysv", "-soname", "libc.so",
            str(library / "empty.o"), "-o", str(library / "libc.so"),
        ])
        self._run_native(["/usr/bin/ar", "rcs", str(library / "libcrabc-builtins.a"), str(library / "empty.o")])
        (root / "lib/ld-crabc-x86_64.so.1").write_bytes(b"fixture interpreter\n")
        (root / "lib/ld-musl-x86_64.so.1").symlink_to("ld-crabc-x86_64.so.1")

        files = {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
            and path != root / "share/crabc/manifest.json"
        }
        (root / "share/crabc/manifest.json").write_text(json.dumps({
            "schema": 1, "format": driver.FORMAT, "target": driver.shared.TARGET,
            "toolchain": PINNED_TOOLCHAIN, "files": files, "symlinks": driver.ALIASES,
        }))
        return root

    @staticmethod
    def _receipt_value_failure(message: str) -> None:
        raise ValueError(message)

    def test_transitive_application_dso_closure_keeps_leaf_out_of_executable_link(self):
        """Schema 3 proves root -> leaf without flattening the executable link."""

        root = self._installed_native_driver_fixture()
        command = [sys.executable, str(root / "bin/crabc-cc-dynamic")]
        work = Path(self.temporary.name) / "native-work"
        work.mkdir()
        leaf_source = work / "leaf.c"
        extra_source = work / "extra.c"
        root_source = work / "root.c"
        main_source = work / "main.c"
        leaf = work / "libleaf.so"
        extra = work / "libextra.so"
        root_dso = work / "libroot.so"
        main_object = work / "main.o"
        executable = work / "main"
        leaf_source.write_text("int leaf(void) { return 7; }\n")
        extra_source.write_text("int extra(void) { return 11; }\n")
        root_source.write_text("extern int leaf(void); int root(void) { return leaf(); }\n")
        main_source.write_text("extern int root(void); int main(void) { return root(); }\n")

        for arguments in (
            ["--dynamic-shared-object", str(leaf_source), "-o", str(leaf)],
            ["--dynamic-shared-object", str(extra_source), "-o", str(extra)],
            ["--dynamic-shared-object", "--application-dso", str(leaf), str(root_source), "-o", str(root_dso)],
            ["--dynamic-pie", "-c", str(main_source), "-o", str(main_object)],
            ["--dynamic-pie", "--application-dso", str(root_dso),
             "--transitive-application-dso", str(leaf), str(main_object), "-o", str(executable)],
        ):
            completed = subprocess.run([*command, *arguments], capture_output=True, text=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)

        receipt_path = Path(str(executable) + ".crabc-link.json")
        receipt = json.loads(receipt_path.read_text())
        root_receipt = json.loads(Path(str(root_dso) + ".crabc-link.json").read_text())
        self.assertEqual(root_receipt["schema"], 2)
        self.assertEqual(set(root_receipt), driver.RECEIPT_V2_FIELDS)
        self.assertEqual(root_receipt["application_dsos"], {leaf.name: hashlib.sha256(leaf.read_bytes()).hexdigest()})
        self.assertEqual(root_receipt["link_command"].count(str(leaf)), 1)
        self.assertEqual(root_receipt["link_trace"].count(str(leaf)), 1)
        contract = driver.receipt_contract.validate(
            receipt, format=driver.FORMAT, label="native closure receipt",
            fail=self._receipt_value_failure, allow_application_dso_closure=True,
        )
        self.assertEqual(contract.schema, 3)
        self.assertEqual(driver.elf_needed(root_dso, work), [leaf.name, "libc.so"])
        self.assertEqual(driver.elf_needed(executable, work), [root_dso.name, "libc.so"])
        self.assertEqual(
            receipt["application_dso_roles"], {root_dso.name: "direct", leaf.name: "transitive"}
        )
        self.assertEqual(
            receipt["application_dso_needed"],
            {root_dso.name: [leaf.name, "libc.so"], leaf.name: ["libc.so"]},
        )
        self.assertEqual(receipt["link_command"].count(str(root_dso)), 1)
        self.assertEqual(receipt["link_trace"].count(str(root_dso)), 1)
        self.assertNotIn("--as-needed", receipt["link_command"])
        self.assertNotIn(str(leaf), receipt["link_command"])
        self.assertNotIn(str(leaf), receipt["link_trace"])

        missing = subprocess.run(
            [*command, "--dynamic-pie", "--application-dso", str(root_dso),
             "--transitive-application-dso", str(extra), str(main_object),
             "-o", str(work / "missing-closure")],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("undeclared transitive dependency", missing.stderr)

        unexpected = subprocess.run(
            [*command, "--dynamic-pie", "--application-dso", str(root_dso),
             "--transitive-application-dso", str(leaf),
             "--transitive-application-dso", str(extra), str(main_object),
             "-o", str(work / "unexpected-closure")],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(unexpected.returncode, 0)
        self.assertIn("unreachable", unexpected.stderr)

        duplicate = subprocess.run(
            [*command, "--dynamic-pie", "--application-dso", str(root_dso),
             "--transitive-application-dso", str(leaf),
             "--transitive-application-dso", str(leaf), str(main_object),
             "-o", str(work / "duplicate-closure")],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("duplicate application SONAME", duplicate.stderr)

        leaf.write_bytes(leaf.read_bytes() + b"changed after sidecar\n")
        changed = subprocess.run(
            [*command, "--dynamic-pie", "--application-dso", str(root_dso),
             "--transitive-application-dso", str(leaf), str(main_object), "-o", str(work / "changed-closure")],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("closure receipt", changed.stderr)

        forged = json.loads(json.dumps(receipt))
        forged["application_dso_roles"][leaf.name] = "direct"
        with self.assertRaisesRegex(ValueError, "role"):
            driver.receipt_contract.validate(
                forged, format=driver.FORMAT, label="forged native closure receipt",
                fail=self._receipt_value_failure, allow_application_dso_closure=True,
            )

    def test_transitive_closure_preserves_exact_lazy_dso_runtime_import_exceptions(self):
        """A receipt-declared lazy import is allowed; an accidental one is not."""

        path = Path(self.temporary.name) / "liblate.so"
        admitted = driver.ApplicationDso(
            path, path.name, (), "direct", runtime_imports=frozenset({"late_import"})
        )
        accidental = driver.ApplicationDso(path, path.name, (), "direct")

        def symbols(candidate, temporary, *, object_symbols=False):
            if candidate.name == "liblate.so":
                return set(), {"late_import"}
            return set(), set()

        with patch.object(driver, "dynamic_symbols", side_effect=symbols):
            self.assertEqual(
                driver.validate_closure_runtime_imports(
                    {path.name: admitted}, Path(self.temporary.name), self.root / "usr/lib"
                ),
                set(),
            )
            with self.assertRaisesRegex(driver.shared.DriverError, "runtime imports"):
                driver.validate_closure_runtime_imports(
                    {path.name: accidental}, Path(self.temporary.name), self.root / "usr/lib"
                )

    def test_exact_payload_accepts_only_canonical_relative_alias(self):
        driver.validate(self.root)
        alias = self.root / "lib/ld-musl-x86_64.so.1"
        alias.unlink()
        alias.symlink_to("/lib/ld-crabc-x86_64.so.1")
        with self.assertRaisesRegex(driver.shared.DriverError, "roster"):
            driver.validate(self.root)

    def test_dynamic_non_pie_plan_selects_owned_crt1_and_et_exec_linkage(self):
        output = io.StringIO()
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch("sys.stdout", output):
            driver.execute(self.root, ["--dynamic-non-pie", "--print-link-plan"])
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["mode"], "exec")
        self.assertIn(str(self.root / "usr/lib/crt1.o"), plan["linker"])
        self.assertNotIn(str(self.root / "usr/lib/Scrt1.o"), plan["linker"])
        self.assertNotIn("-pie", plan["linker"])
        self.assertIn("--dynamic-linker", plan["linker"])

    def test_search_path_plan_records_explicit_application_policy(self):
        output = io.StringIO()
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch("sys.stdout", output):
            driver.execute(self.root, ["--dynamic-pie", "--application-runpath", "/app/lib:$ORIGIN/plugins", "--print-link-plan"])
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["application_runpath"], "/app/lib:$ORIGIN/plugins")
        self.assertIn("/app/lib:$ORIGIN/plugins", plan["linker"])

    def _dynamic_receipt(self, *search_arguments):
        """Generate a receipt through the driver while replacing only external tools."""

        workload = Path(self.temporary.name) / "workload.o"
        output = Path(self.temporary.name) / "consumer"
        linker = Path(self.temporary.name) / "ld.lld"
        workload.write_bytes(b"owned workload object")
        linker.write_bytes(b"owned linker")
        linker.chmod(0o755)

        def link(command, temporary):
            self.assertIn("--trace", command)
            linked_output = Path(command[command.index("-o") + 1])
            self.assertEqual(linked_output, output)
            linked_output.write_bytes(b"owned dynamic executable")
            library = self.root / "usr/lib"
            trace = [
                library / "crti.o", library / "libc.so", library / "crtn.o",
                library / "Scrt1.o", library / "crabc-dynamic-attach.o", workload,
                library / "libcrabc-builtins.a",
            ]
            return "\n".join(str(path) for path in trace)

        with patch.object(driver.shared, "linker", return_value=str(linker)), \
             patch.object(driver.shared, "require_x86_64_relocatable_object", return_value=workload), \
             patch.object(driver, "dynamic_symbols", return_value=(set(), set())), \
             patch.object(driver, "run", side_effect=link):
            driver.execute(self.root, ["--dynamic-pie", *search_arguments, str(workload), "-o", str(output)])
        return workload, output, Path(str(output) + ".crabc-link.json")

    def test_link_evidence_retention_is_opt_in_and_rejects_ambiguous_values_before_tools(self):
        """Only the registry's exact opt-in retains compiler-created inputs."""

        source = Path(self.temporary.name) / "retained-source.c"
        source.write_text("int main(void) { return 0; }\n")

        for value in ("", "0", "true", "retain"):
            with self.subTest(value=value), patch.dict(os.environ, {driver.RETAIN_LINK_EVIDENCE_ENV: value}), \
                 patch.object(driver, "run") as run:
                with self.assertRaisesRegex(driver.shared.DriverError, "retain link evidence"):
                    driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(Path(self.temporary.name) / "invalid")])
                run.assert_not_called()

        def link_with(retain: bool) -> tuple[Path, Path]:
            output = Path(self.temporary.name) / ("retained" if retain else "ordinary")
            linker = Path(self.temporary.name) / "ld.lld"
            linker.write_bytes(b"owned linker")
            linker.chmod(0o755)
            objects: list[Path] = []

            def run(command, temporary):
                if command[0] == "/owned/gcc":
                    compiled = Path(command[command.index("-o") + 1])
                    compiled.write_bytes(b"compiler-created object")
                    objects.append(compiled)
                    return ""
                linked = Path(command[command.index("-o") + 1])
                linked.write_bytes(b"owned dynamic executable")
                library = self.root / "usr/lib"
                return "\n".join(str(path) for path in (
                    library / "crti.o", library / "libc.so", library / "crtn.o",
                    library / "Scrt1.o", library / "crabc-dynamic-attach.o", objects[0],
                    library / "libcrabc-builtins.a",
                ))

            environment = {driver.RETAIN_LINK_EVIDENCE_ENV: "1"} if retain else {}
            with patch.dict(os.environ, environment, clear=not retain), \
                 patch.object(driver.shared, "linker", return_value=str(linker)), \
                 patch.object(driver.shared, "compiler", return_value="/owned/gcc"), \
                 patch.object(driver, "dynamic_symbols", return_value=(set(), set())), \
                 patch.object(driver, "run", side_effect=run):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(output)])
            self.assertEqual(len(objects), 1)
            return output, objects[0]

        ordinary_output, ordinary = link_with(False)
        self.assertFalse(ordinary.exists())
        ordinary_receipt = json.loads(Path(str(ordinary_output) + ".crabc-link.json").read_text())
        self.assertEqual(ordinary_receipt["input_receipts"][5]["path"], str(ordinary))
        retained_output, retained = link_with(True)
        self.assertTrue(retained.is_file())
        self.assertTrue(retained.parent.name.startswith("crabc-dynamic-link."))
        self.assertEqual(retained.read_bytes(), b"compiler-created object")
        retained_receipt = json.loads(Path(str(retained_output) + ".crabc-link.json").read_text())
        self.assertEqual(retained_receipt["input_receipts"][5], {
            "path": str(retained), "sha256": hashlib.sha256(retained.read_bytes()).hexdigest(),
        })

    def test_current_driver_receipt_is_schema_two_and_current_posix_reader_accepts_default(self):
        workload, output, receipt_path = self._dynamic_receipt()
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["schema"], 2)
        self.assertEqual(set(receipt), driver.RECEIPT_V2_FIELDS)
        self.assertEqual(
            (receipt["application_search_kind"], receipt["application_runpath"],
             receipt["application_rpath"], receipt["application_hash_style"]),
            ("runpath", "/usr/lib", None, "sysv"),
        )
        product_evidence._validate_dynamic_receipt(
            self.root, workload, output, receipt_path, "pie", self.root / "share/crabc/manifest.json"
        )

    def test_rpath_receipt_has_no_runpath_field_and_default_workload_reader_rejects_it(self):
        workload, output, receipt_path = self._dynamic_receipt("--application-rpath", "/legacy")
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["schema"], 2)
        self.assertEqual(
            (receipt["application_search_kind"], receipt["application_runpath"],
             receipt["application_rpath"], receipt["application_hash_style"]),
            ("rpath", None, "/legacy", "sysv"),
        )
        with self.assertRaises(product_evidence.ProductEvidenceError):
            product_evidence._validate_dynamic_receipt(
                self.root, workload, output, receipt_path, "pie", self.root / "share/crabc/manifest.json"
            )

    def test_non_sysv_receipt_is_rejected_by_a_sysv_default_workload_reader(self):
        workload, output, receipt_path = self._dynamic_receipt("--application-hash-style", "gnu")
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt["application_hash_style"], "gnu")
        with self.assertRaises(product_evidence.ProductEvidenceError):
            product_evidence._validate_dynamic_receipt(
                self.root, workload, output, receipt_path, "pie", self.root / "share/crabc/manifest.json"
            )

    def test_hash_style_is_a_sealed_link_choice_not_a_raw_linker_flag(self):
        for style in ("sysv", "gnu", "both"):
            with self.subTest(style=style):
                output = io.StringIO()
                with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch("sys.stdout", output):
                    driver.execute(self.root, ["--dynamic-shared-object", "--application-hash-style", style, "--print-link-plan"])
                plan = json.loads(output.getvalue())
                self.assertEqual(plan["application_hash_style"], style)
                self.assertIn("--hash-style=" + style, plan["linker"])
                self.assertEqual(sum(item.startswith("--hash-style=") for item in plan["linker"]), 1)
        source = Path(self.temporary.name) / "consumer.c"
        source.write_text("int value;\n")
        with patch.object(driver, "run") as run:
            with self.assertRaisesRegex(driver.shared.DriverError, "hash style"):
                driver.execute(self.root, ["--dynamic-pie", "--application-hash-style", "gnu", "-c", str(source)])
            run.assert_not_called()

    def test_main_only_rpath_is_mutually_exclusive_with_runpath(self):
        output = io.StringIO()
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch("sys.stdout", output):
            driver.execute(self.root, ["--dynamic-pie", "--application-rpath", "/legacy", "--print-link-plan"])
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["application_search_kind"], "rpath")
        self.assertIsNone(plan["application_runpath"])
        self.assertEqual(plan["application_rpath"], "/legacy")
        self.assertIn("--disable-new-dtags", plan["linker"])
        self.assertNotIn("--enable-new-dtags", plan["linker"])
        source = Path(self.temporary.name) / "consumer.c"
        source.write_text("int value;\n")
        for arguments in (
            ["--dynamic-shared-object", "--application-rpath", "/legacy", "--print-link-plan"],
            ["--dynamic-pie", "--application-rpath", "/legacy", "--application-runpath", "/new", "--print-link-plan"],
            ["--dynamic-pie", "--application-rpath", "/legacy", "-c", str(source)],
        ):
            with self.subTest(arguments=arguments), patch.object(driver, "run") as run:
                with self.assertRaises(driver.shared.DriverError):
                    driver.execute(self.root, arguments)
                run.assert_not_called()

    def test_search_path_rejects_invalid_or_ambiguous_options_before_tools(self):
        for options in (["--application-runpath"], ["--application-runpath", ""],
                        ["--application-runpath", "/a", "--application-runpath", "/b"],
                        ["--application-runpath", "x" * 4096],
                        ["--application-runpath", "/a", "-c", "input.c"]):
            with self.subTest(options=options), patch.object(driver, "run") as run:
                with self.assertRaises(driver.shared.DriverError):
                    driver.execute(self.root, ["--dynamic-pie", *options])
                run.assert_not_called()

    def test_versioned_application_dso_names_reach_the_normal_dso_contract(self):
        """Lua's upstream shared library name is an application DSO, not a runtime escape."""

        accepted = (
            "liblua.so",
            "liblua.so.5",
            "liblua.so.5.4",
            "liblua.so.5.4.8",
        )
        rejected = (
            "liblua.so.",
            "liblua.so.5beta",
            "liblua.so.5.4-beta",
            "liblua.so.5/4",
        )
        for name in accepted:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    driver.shared.DriverError, "link plan accepts no application inputs"
                ):
                    driver.execute(
                        self.root,
                        [
                            "--dynamic-pie",
                            "--application-dso",
                            str(Path(self.temporary.name) / name),
                            "--print-link-plan",
                        ],
                    )
        for name in rejected:
            with self.subTest(name=name):
                with self.assertRaisesRegex(driver.shared.DriverError, "unowned application DSO"):
                    driver.execute(
                        self.root,
                        [
                            "--dynamic-pie",
                            "--application-dso",
                            str(Path(self.temporary.name) / name),
                            "--print-link-plan",
                        ],
                    )

    def test_reserved_runtime_names_cannot_be_application_dso_declarations(self):
        """Runtime identities cannot become direct or validation-only application nodes."""

        for option in ("--application-dso", "--transitive-application-dso"):
            for name in ("libc.so", "ld-crabc-x86_64.so.1", "ld-musl-x86_64.so.1"):
                with self.subTest(option=option, name=name), patch.object(driver, "run") as run:
                    with self.assertRaisesRegex(driver.shared.DriverError, "reserved application DSO"):
                        driver.execute(
                            self.root,
                            [
                                "--dynamic-pie", option, str(Path(self.temporary.name) / name),
                                "--print-link-plan",
                            ],
                        )
                    run.assert_not_called()

    def test_application_search_receipt_binds_the_actual_elf_and_runpath(self):
        path = Path(self.temporary.name) / "plugin.so"
        elf = bytearray(64)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        elf[16:18] = (3).to_bytes(2, "little")
        elf[18:20] = (62).to_bytes(2, "little")
        path.write_bytes(elf)
        receipt = Path(str(path) + ".crabc-link.json")
        legacy = {
            "schema": 1, "format": driver.FORMAT, "mode": "shared", "binding": "now",
            "runtime_imports": [], "application_runpath": "/app/lib", "output_path": str(path.resolve()),
            "output_sha256": driver.shared.sha256_file(path), "manifest_sha256": "0" * 64,
            "application_dsos": {}, "owned_runtime_inputs": [], "input_receipts": [],
            "resolved_linker": {"path": "/owned/ld.lld", "sha256": "0" * 64}, "link_command": [],
            "link_trace": [], "campaign_complete": False,
        }
        valid = {**legacy, "schema": 2, "application_search_kind": "runpath",
                 "application_rpath": None, "application_hash_style": "gnu"}
        dynamic = "(SONAME) [plugin.so]\n(RUNPATH) [/app/lib]\n"
        rpath = {**valid, "application_search_kind": "rpath", "application_runpath": None,
                 "application_rpath": "/app/lib"}
        hybrid = {**legacy, "application_search_kind": "runpath"}
        for record in ([], {**valid, "application_runpath": "/wrong"},
                       {**valid, "output_sha256": "0" * 64}, rpath, hybrid, legacy, valid):
            receipt.write_text(json.dumps(record))
            with self.subTest(record=record), patch.object(driver, "run", side_effect=["", dynamic]):
                if record in (legacy, valid):
                    self.assertEqual(driver.dso_metadata(path, Path(self.temporary.name)), ("plugin.so", []))
                else:
                    with self.assertRaises(driver.shared.DriverError):
                        driver.dso_metadata(path, Path(self.temporary.name))

        # Moving an ELF and an unchanged sidecar does not transfer the path
        # declaration. The basename and all file bytes deliberately match.
        copied = Path(self.temporary.name) / "moved" / path.name
        copied.parent.mkdir()
        copied.write_bytes(path.read_bytes())
        Path(str(copied) + ".crabc-link.json").write_bytes(receipt.read_bytes())
        with patch.object(driver, "run", side_effect=["", dynamic]):
            with self.assertRaises(driver.shared.DriverError):
                driver.dso_metadata(copied, Path(self.temporary.name))

    def test_deferred_binding_plan_requires_exact_shared_runtime_imports(self):
        output = io.StringIO()
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch("sys.stdout", output):
            driver.execute(self.root, ["--dynamic-shared-object", "--binding", "lazy",
                                      "--runtime-import", "future_function", "--print-link-plan"])
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["binding"], "lazy")
        self.assertEqual(plan["runtime_imports"], ["future_function"])
        self.assertIn("lazy", plan["linker"])
        self.assertNotIn("now", plan["linker"])
        for arguments in (["--dynamic-pie", "--runtime-import", "future_function"],
                          ["--dynamic-shared-object", "--binding", "invalid"],
                          ["--dynamic-shared-object", "--runtime-import", "bad@VERSION"],
                          ["--dynamic-shared-object", "--runtime-import", "future_function"]):
            with self.subTest(arguments=arguments), patch.object(driver, "run") as run:
                with self.assertRaises(driver.shared.DriverError):
                    driver.execute(self.root, [*arguments, "--print-link-plan"])
                run.assert_not_called()

    def test_deferred_import_contract_rejects_accidental_or_unused_names_before_link(self):
        source = Path(self.temporary.name) / "plugin.c"
        source.write_text("extern int future_function(void); int run(void) { return future_function(); }\n")
        for required in ({"future_function", "accidental_import"}, set()):
            output = Path(self.temporary.name) / "plugin.so"
            def symbols(path, temporary, *, object_symbols=False):
                return (set(), required) if path.name == "source-0.o" else (set(), set())
            with self.subTest(required=required), patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver.shared, "compiler", return_value="/owned/gcc"), patch.object(driver, "dynamic_symbols", side_effect=symbols), patch.object(driver, "run", return_value="") as run:
                with self.assertRaisesRegex(driver.shared.DriverError, "exact unresolved"):
                    driver.execute(self.root, ["--dynamic-shared-object", "--binding", "lazy",
                        "--runtime-import", "future_function", str(source), "-o", str(output)])
                self.assertEqual([call.args[0][0] for call in run.call_args_list], ["/owned/gcc"])
                self.assertFalse(output.exists())
                self.assertFalse(Path(str(output) + ".crabc-link.json").exists())

    def test_installed_driver_import_does_not_mutate_payload_without_python_environment(self):
        for relative, source in (("bin/crabc-cc-dynamic", Path(driver.__file__)),
                                 ("share/crabc/crabc_cc_static.py", Path(driver.shared.__file__)),
                                 ("share/crabc/owned_dynamic_receipt.py", Path(driver.receipt_contract.__file__))):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            self.manifest["files"][relative] = driver.shared.sha256_file(destination)
        self.write_manifest()
        environment = dict(os.environ)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        result = subprocess.run([sys.executable, str(self.root / "bin/crabc-cc-dynamic")],
                                env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("select --dynamic-pie", result.stderr)
        self.assertEqual(list(self.root.rglob("__pycache__")), [])
        driver.validate(self.root)

    def test_tampered_missing_and_undeclared_payloads_fail(self):
        libc = self.root / "usr/lib/libc.so"
        libc.write_bytes(b"foreign")
        with self.assertRaisesRegex(driver.shared.DriverError, "hash mismatch"):
            driver.validate(self.root)
        libc.unlink()
        with self.assertRaisesRegex(driver.shared.DriverError, "roster"):
            driver.validate(self.root)
        libc.write_bytes(b"owned test payload")
        (self.root / "usr/lib/libforeign.so").write_bytes(b"foreign")
        with self.assertRaisesRegex(driver.shared.DriverError, "roster"):
            driver.validate(self.root)

    def test_runtime_injection_rejected_before_tool_execution(self):
        for flag in ("-L/usr/lib", "-lc", "-Wl,-rpath,/foreign", "-I/usr/include",
                     "-static", "-fPIC", "--dynamic-non-pie", "-shared"):
            with self.subTest(flag=flag), patch.object(driver, "run") as run:
                with self.assertRaises(driver.shared.DriverError):
                    driver.execute(self.root, ["--dynamic-pie", flag, "input.c"])
                run.assert_not_called()

    def test_compile_only_dependency_file_is_a_sealed_header_diagnostic(self):
        """A source consumer may retain headers without opening include controls."""

        source = Path(self.temporary.name) / "headers.c"
        source.write_text("#include <stdio.h>\nint value;\n")
        output = Path(self.temporary.name) / "headers.o"
        dependency = Path(self.temporary.name) / "headers.d"
        with patch.object(driver.shared, "compiler", return_value="/owned/gcc"), \
             patch.object(driver, "run", return_value="") as run:
            driver.execute(
                self.root,
                [
                    "--dynamic-shared-object",
                    "--application-dependency-file",
                    str(dependency),
                    "-c",
                    str(source),
                    "-o",
                    str(output),
                ],
            )
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/owned/gcc")
        self.assertEqual(command[command.index("-MF") + 1], str(dependency))
        self.assertIn("-MD", command)
        self.assertIn("-nostdinc", command)
        self.assertIn(str(self.root / "usr/include"), command)

    def test_native_compile_only_dependency_file_names_the_installed_header(self):
        """The real fixed compiler emits the sealed dependency file for one source."""

        header = self.root / "usr/include/owned.h"
        header.parent.mkdir(parents=True)
        header.write_text("#define OWNED_HEADER_VALUE 1\n")
        self.manifest["files"][header.relative_to(self.root).as_posix()] = hashlib.sha256(
            header.read_bytes()
        ).hexdigest()
        self.write_manifest()
        source = Path(self.temporary.name) / "headers.c"
        source.write_text("#include <owned.h>\nint value = OWNED_HEADER_VALUE;\n")
        output = Path(self.temporary.name) / "headers.o"
        dependency = Path(self.temporary.name) / "headers.d"

        driver.execute(
            self.root,
            [
                "--dynamic-shared-object",
                "--application-dependency-file",
                str(dependency),
                "-c",
                str(source),
                "-o",
                str(output),
            ],
        )

        self.assertTrue(output.is_file())
        recorded = dependency.read_text(encoding="utf-8")
        self.assertIn(str(source), recorded)
        self.assertIn(str(header), recorded)

    def test_dependency_file_is_rejected_for_a_link(self):
        source = Path(self.temporary.name) / "headers.c"
        source.write_text("int value;\n")
        dependency = Path(self.temporary.name) / "headers.d"
        with patch.object(driver, "run") as run:
            with self.assertRaisesRegex(driver.shared.DriverError, "compile-only"):
                driver.execute(
                    self.root,
                    [
                        "--dynamic-pie",
                        "--application-dependency-file",
                        str(dependency),
                        str(source),
                    ],
                )
            run.assert_not_called()

    def test_quote_include_and_rounding_mode_are_explicit_application_inputs(self):
        """The native libc-test source closure needs only quoted local headers.

        The owned driver must continue to reject ordinary ``-I`` injection.
        This deliberately narrow option affects quoted includes only, while
        angle-bracket headers continue to come from the installed product's
        fixed ``-isystem`` directory.
        """

        source_root = Path(self.temporary.name) / "source-root"
        include = source_root / "common"
        include.mkdir(parents=True)
        (include / "local.h").write_text("#define LOCAL_VALUE 7\n")
        source = source_root / "consumer.c"
        source.write_text('#include "local.h"\nint value = LOCAL_VALUE;\n')
        output = Path(self.temporary.name) / "consumer.o"
        with patch.object(driver, "run", return_value="") as run:
            driver.execute(
                self.root,
                [
                    "--dynamic-pie",
                    "--application-quote-include-dir",
                    str(include),
                    "-frounding-math",
                    "-c",
                    str(source),
                    "-o",
                    str(output),
                ],
            )
        command = run.call_args.args[0]
        self.assertIn("-iquote", command)
        self.assertEqual(command[command.index("-iquote") + 1], str(include.resolve()))
        self.assertIn("-frounding-math", command)
        self.assertIn("-nostdinc", command)
        self.assertIn(str(self.root / "usr/include"), command)

    def test_quote_include_cannot_name_a_symlink_or_installed_header_tree(self):
        source = Path(self.temporary.name) / "consumer.c"
        source.write_text("int value;\n")
        external = Path(self.temporary.name) / "external"
        external.mkdir()
        link = Path(self.temporary.name) / "external-link"
        link.symlink_to(external)
        for include in (link, self.root / "usr/include"):
            with self.subTest(include=include), patch.object(driver, "run") as run:
                with self.assertRaisesRegex(driver.shared.DriverError, "quote include"):
                    driver.execute(
                        self.root,
                        [
                            "--dynamic-pie",
                            "--application-quote-include-dir",
                            str(include),
                            "-c",
                            str(source),
                            "-o",
                            str(Path(self.temporary.name) / f"{include.name}.o"),
                        ],
                    )
                run.assert_not_called()

    def test_rdynamic_is_an_executable_only_export_contract(self):
        output = io.StringIO()
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch("sys.stdout", output):
            driver.execute(self.root, ["--dynamic-pie", "-rdynamic", "--print-link-plan"])
        plan = json.loads(output.getvalue())
        self.assertIn("--export-dynamic", plan["linker"])

        source = Path(self.temporary.name) / "consumer.c"
        source.write_text("int main(void) { return 0; }\n")
        for arguments in (
            ["--dynamic-shared-object", "-rdynamic", "--print-link-plan"],
            ["--dynamic-pie", "-rdynamic", "-c", str(source)],
        ):
            with self.subTest(arguments=arguments), patch.object(driver, "run") as run:
                with self.assertRaisesRegex(driver.shared.DriverError, "-rdynamic"):
                    driver.execute(self.root, arguments)
                run.assert_not_called()

    def test_pthread_reaches_both_source_translation_commands(self):
        source = Path(self.temporary.name) / "threaded.c"
        source.write_text("#ifndef _REENTRANT\n#error pthread compilation missing\n#endif\nint value;\n")
        output = Path(self.temporary.name) / "threaded.o"
        arguments = ["-pthread", "-c", str(source), "-o", str(output)]
        invocation = driver.shared.parse_invocation(arguments)
        with patch.object(driver.shared, "run_checked") as run:
            driver.shared.compile_source(
                self.root, invocation.mode, source, output, invocation.compiler_flags,
            )
        self.assertIn("-pthread", run.call_args.args[0])
        with patch.object(driver, "run", return_value="") as run:
            driver.execute(self.root, ["--dynamic-pie", *arguments])
        self.assertIn("-pthread", run.call_args.args[0])

    def test_pthread_does_not_admit_library_or_runtime_flag_injection(self):
        for flag in ("-lpthread", "-pthread=foreign", "-pthreads", "-Wl,-lpthread"):
            with self.subTest(flag=flag), patch.object(driver, "run") as run:
                with self.assertRaises(driver.shared.DriverError):
                    driver.execute(self.root, ["--dynamic-pie", "-pthread", flag, "input.c"])
                run.assert_not_called()

    def test_debug_translation_forces_uncompressed_dwarf_for_both_driver_layers(self):
        """The pinned LLD cannot consume the image's default compressed DWARF."""

        source = Path(self.temporary.name) / "consumer.c"
        source.write_text("int value;\n")
        static = driver.shared.parse_invocation(["-g", "-c", str(source), "-o", str(Path(self.temporary.name) / "static.o")])
        self.assertEqual(static.compiler_flags, ("-g", "-gz=none"))
        no_debug = driver.shared.parse_invocation(["-c", str(source), "-o", str(Path(self.temporary.name) / "plain.o")])
        self.assertNotIn("-gz=none", no_debug.compiler_flags)
        disabled_debug = driver.shared.parse_invocation(["-g", "-g0", "-c", str(source), "-o", str(Path(self.temporary.name) / "disabled.o")])
        self.assertEqual(disabled_debug.compiler_flags, ("-g", "-g0"))
        reenabled_debug = driver.shared.parse_invocation(["-g0", "-g", "-c", str(source), "-o", str(Path(self.temporary.name) / "reenabled.o")])
        self.assertEqual(reenabled_debug.compiler_flags, ("-g0", "-g", "-gz=none"))

        output = Path(self.temporary.name) / "dynamic.o"
        with patch.object(driver.shared, "compiler", return_value="/owned/gcc"), patch.object(driver, "run", return_value="") as run:
            driver.execute(self.root, ["--dynamic-pie", "-g", "-c", str(source), "-o", str(output)])
        compiler_command = run.call_args.args[0]
        self.assertEqual(compiler_command.count("-g"), 1)
        self.assertEqual(compiler_command.count("-gz=none"), 1)
        self.assertLess(compiler_command.index("-g"), compiler_command.index("-gz=none"))

    def test_compressed_debug_requests_are_rejected_before_translation(self):
        source = Path(self.temporary.name) / "consumer.c"
        source.write_text("int value;\n")
        for flag in ("-gz", "-gz=zlib", "-gz=zstd", "-gz=zlib-gnu"):
            with self.subTest(flag=flag):
                with self.assertRaisesRegex(driver.shared.DriverError, "compressed debug"):
                    driver.shared.parse_invocation(["-g", flag, "-c", str(source), "-o", str(Path(self.temporary.name) / "out.o")])
                with patch.object(driver, "run") as run:
                    with self.assertRaisesRegex(driver.shared.DriverError, "compressed debug"):
                        driver.execute(self.root, ["--dynamic-pie", "-g", flag, "-c", str(source), "-o", str(Path(self.temporary.name) / "out.o")])
                    run.assert_not_called()

    def test_install_output_cannot_be_modified(self):
        source = Path(self.temporary.name) / "input.c"
        source.write_text("int main(void) { return 0; }\n")
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver, "run") as run:
            with self.assertRaisesRegex(driver.shared.DriverError, "installed sysroot"):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(self.root / "consumer")])
            run.assert_not_called()

    def test_output_cannot_overwrite_application_source(self):
        source = Path(self.temporary.name) / "input.c"
        source.write_text("int main(void) { return 0; }\n")
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver, "run") as run:
            with self.assertRaisesRegex(driver.shared.DriverError, "collides"):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(source)])
            run.assert_not_called()

    def test_existing_receipt_regular_symlink_and_hardlink_reject_before_tools_and_preserve_bytes(self):
        source = Path(self.temporary.name) / "source.c"
        source.write_text("int main(void) { return 0; }\n")
        for kind in ("regular", "symlink", "hardlink"):
            output = Path(self.temporary.name) / kind
            receipt = Path(str(output) + ".crabc-link.json")
            original = Path(self.temporary.name) / (kind + ".original")
            original.write_bytes(b"old receipt bytes")
            if kind == "regular": receipt.write_bytes(b"old receipt bytes")
            elif kind == "symlink": receipt.symlink_to(original)
            else: os.link(original, receipt)
            with self.subTest(kind=kind), patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver.shared, "compiler", return_value="/owned/gcc"), patch.object(driver, "run", side_effect=driver.shared.DriverError("tool was called")) as run:
                with self.assertRaises(driver.shared.DriverError):
                    driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(output)])
                run.assert_not_called()
                self.assertEqual(receipt.read_bytes(), b"old receipt bytes")
                self.assertEqual(original.read_bytes(), b"old receipt bytes")
                self.assertFalse(output.exists())

    def test_failed_translation_releases_only_its_new_receipt_reservation(self):
        source = Path(self.temporary.name) / "source.c"
        source.write_text("invalid")
        output = Path(self.temporary.name) / "consumer"
        receipt = Path(str(output) + ".crabc-link.json")
        def fail(command, temporary):
            self.assertTrue(receipt.is_file(), "receipt must be reserved before compiler execution")
            self.assertEqual(receipt.read_bytes(), b"")
            raise driver.shared.DriverError("isolated translation failure")
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver.shared, "compiler", return_value="/owned/gcc"), patch.object(driver, "run", side_effect=fail):
            with self.assertRaisesRegex(driver.shared.DriverError, "isolated translation failure"):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(output)])
        self.assertFalse(receipt.exists())

    def test_failed_link_does_not_remove_a_competing_receipt_inode(self):
        source = Path(self.temporary.name) / "source.c"
        source.write_text("int main(void) { return 0; }\n")
        output = Path(self.temporary.name) / "consumer"
        receipt = Path(str(output) + ".crabc-link.json")
        def fail_link(command, temporary):
            self.assertEqual(receipt.read_bytes(), b"")
            if command[0] == "/owned/gcc": return ""
            receipt.unlink()
            receipt.write_bytes(b"competing receipt")
            raise driver.shared.DriverError("isolated link failure")
        with patch.object(driver.shared, "linker", return_value="/owned/ld.lld"), patch.object(driver.shared, "compiler", return_value="/owned/gcc"), patch.object(driver, "dynamic_symbols", return_value=(set(), set())), patch.object(driver, "run", side_effect=fail_link):
            with self.assertRaisesRegex(driver.shared.DriverError, "isolated link failure"):
                driver.execute(self.root, ["--dynamic-pie", str(source), "-o", str(output)])
        self.assertEqual(receipt.read_bytes(), b"competing receipt")

    def test_receipt_replacement_is_rejected_before_publication(self):
        path = Path(self.temporary.name) / "receipt"
        with self.assertRaisesRegex(driver.shared.DriverError, "identity changed"):
            with driver.reserve_receipt(path) as publish:
                path.unlink()
                path.write_bytes(b"other publisher")
                publish("new receipt")
        self.assertEqual(path.read_bytes(), b"other publisher")

    def test_package_is_deterministic_and_extracted_payload_is_identical(self):
        one = Path(self.temporary.name) / "one.tar"
        two = Path(self.temporary.name) / "two.tar"
        extracted = Path(self.temporary.name) / "extracted"
        package.package(self.root, one)
        package.package(self.root, two)
        self.assertEqual(one.read_bytes(), two.read_bytes())
        package.extract(one, extracted)
        self.assertEqual(driver.validate(self.root), driver.validate(extracted))

    def test_package_path_escape_and_duplicate_rejected_before_output_creation(self):
        for name in ("../escape", "/escape", "duplicate"):
            with self.subTest(name=name):
                archive_path = Path(self.temporary.name) / "malformed.tar"
                with tarfile.open(archive_path, "w") as archive:
                    entry = tarfile.TarInfo(name)
                    entry.size = 1
                    archive.addfile(entry, io.BytesIO(b"x"))
                    if name == "duplicate": archive.addfile(entry, io.BytesIO(b"x"))
                output = Path(self.temporary.name) / "rejected"
                with self.assertRaises(driver.shared.DriverError):
                    package.extract(archive_path, output)
                self.assertFalse(output.exists())

    def test_package_nonobject_manifest_is_clean_error_before_output_creation(self):
        for value in ([], None, "manifest", 7, True):
            with self.subTest(value=value):
                archive_path = Path(self.temporary.name) / "bad-manifest.tar"
                payload = json.dumps(value).encode()
                with tarfile.open(archive_path, "w") as archive:
                    entry = tarfile.TarInfo("share/crabc/manifest.json")
                    entry.size = len(payload)
                    archive.addfile(entry, io.BytesIO(payload))
                output = Path(self.temporary.name) / "rejected"
                with self.assertRaises(driver.shared.DriverError):
                    package.extract(archive_path, output)
                self.assertFalse(output.exists())

    def test_producer_failure_keeps_partial_payload_private(self):
        output = Path(self.temporary.name) / "produced"
        def fail(staged, build, *, allocator_backend, lifecycle_test_audit):
            self.assertEqual(allocator_backend, "accepted-c")
            self.assertFalse(lifecycle_test_audit)
            staged.mkdir()
            (staged / "partial-libc.so").write_bytes(b"partial")
            self.assertFalse(output.exists())
            raise producer.common.BuildError("isolated loader build failure")
        with patch.object(producer, "build_staged_payload", side_effect=fail, create=True), patch.object(producer.common, "resolve_pinned_producer_tools", side_effect=AssertionError("private staged payload owner required")):
            with self.assertRaisesRegex(producer.common.BuildError, "isolated loader build failure"):
                producer.build(output)
        self.assertFalse(output.exists())
        self.assertEqual((output.parent / (output.name + ".build") / "installed/partial-libc.so").read_bytes(), b"partial")

    def test_shared_libc_link_keeps_musl_exceptions_and_errno_private_alias(self):
        """The shared libc link keeps both finite policies separate."""

        dynamic_list = producer.shared_libc_dynamic_list()
        self.assertEqual(
            dynamic_list["source"],
            {
                "path": "libc/src/c_abi/x86_64/owned_dynamic.list",
                "sha256": producer.MUSL_1_2_6_DYNAMIC_LIST_SHA256,
                "mode": 0o644,
            },
        )
        self.assertEqual(dynamic_list["data_symbols"], list(producer.MUSL_1_2_6_DYNAMIC_LIST_DATA_SYMBOLS))
        self.assertEqual(
            dynamic_list["allocation_entrypoints"],
            list(producer.MUSL_1_2_6_DYNAMIC_LIST_ALLOCATION_ENTRYPOINTS),
        )
        self.assertIn("optind", dynamic_list["data_symbols"])
        self.assertNotIn("malloc", dynamic_list["data_symbols"])
        self.assertIn("malloc_usable_size", dynamic_list["allocation_entrypoints"])

        private_stage = Path(self.temporary.name) / "errno-private"
        private_stage.mkdir()
        private_aliases = producer.shared_libc_errno_private_aliases(private_stage)
        self.assertEqual(
            private_aliases["source"],
            {
                "path": "libc/src/c_abi/x86_64/owned_errno_private_aliases.list",
                "sha256": producer.ERRNO_PRIVATE_ALIAS_LIST_SHA256,
                "mode": 0o644,
            },
        )
        self.assertEqual(private_aliases["members"], ["___errno_location"])
        self.assertEqual(private_aliases["member_count"], 1)
        self.assertEqual(private_aliases["linker_policy"], "exact-local-symbols")

        command = producer.shared_libc_link_command(
            Path("/pinned/ld.lld"), producer.SHARED_LIBC_DYNAMIC_LIST,
            Path("/private/mimalloc-hidden.exports"), Path("/private/errno-private.exports"),
            Path("/private/objects"),
            ("one.o", "two.o"), Path("/private/libcrabc-builtins.a"), Path("/private/usr/lib"),
        )
        self.assertEqual(command, [
            "/pinned/ld.lld", "-shared", "--hash-style=sysv", "-soname", "libc.so",
            "--dynamic-list=" + str(producer.SHARED_LIBC_DYNAMIC_LIST),
            "--version-script=/private/mimalloc-hidden.exports",
            "--version-script=/private/errno-private.exports",
            "--exclude-libs=libcrabc-builtins.a",
            "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text",
            "/private/objects/one.o", "/private/objects/two.o", "/private/libcrabc-builtins.a",
            "-o", "/private/usr/lib/libc.so",
        ])
        self.assertNotIn("-Bsymbolic", command)
        self.assertNotIn("-Bsymbolic-functions", command)

    def test_shared_libc_keeps_the_bounded_helper_archive_local(self):
        """The installed archive remains public; only its libc.so copy is private."""

        command = producer.shared_libc_link_command(
            Path("/pinned/ld.lld"), producer.SHARED_LIBC_DYNAMIC_LIST,
            Path("/private/mimalloc-hidden.exports"), Path("/private/errno-private.exports"),
            Path("/private/objects"),
            ("one.o",), Path("/private/libcrabc-builtins.a"), Path("/private/usr/lib"),
        )
        self.assertIn("--exclude-libs=libcrabc-builtins.a", command)

    def test_shared_helper_policy_rejects_numeric_dynsym_boolean(self):
        contract = Path(self.temporary.name) / "helper-contract.toml"
        lines = producer.COMPILER_HELPER_CONTRACT.read_text(encoding="utf-8").replace(
            "dynsym = false", "dynsym = 0"
        )
        contract.write_text(lines, encoding="utf-8")
        with patch.object(producer, "COMPILER_HELPER_CONTRACT", contract), patch.object(
            producer, "_source_file_identity", return_value={"path": "builtins/x86_64-helper-contract.toml", "sha256": "0" * 64, "mode": 0o644}
        ):
            with self.assertRaisesRegex(producer.common.BuildError, "shared-libc placement"):
                producer.shared_libc_compiler_helper_archive_policy()

    def test_producer_final_validation_failure_and_competing_publication_preserve_destination(self):
        for failure in ("invalid-payload", "competing-publication"):
            with self.subTest(failure=failure):
                output = Path(self.temporary.name) / failure
                def finish(staged, build, *, allocator_backend, lifecycle_test_audit):
                    self.assertEqual(allocator_backend, "accepted-c")
                    self.assertFalse(lifecycle_test_audit)
                    staged.mkdir()
                    (staged / "payload").write_bytes(b"private candidate")
                    if failure == "competing-publication":
                        output.mkdir()
                        (output / "competitor").write_bytes(b"other publisher")
                validator = (None if failure == "competing-publication" else driver.shared.DriverError("invalid payload"))
                with patch.object(producer, "build_staged_payload", side_effect=finish, create=True), patch.object(driver, "validate", side_effect=validator), patch.object(producer.common, "resolve_pinned_producer_tools", side_effect=AssertionError("private staged payload owner required")):
                    with self.assertRaises(producer.common.BuildError):
                        producer.build(output)
                if failure == "competing-publication":
                    self.assertEqual((output / "competitor").read_bytes(), b"other publisher")
                    self.assertEqual(list(output.iterdir()), [output / "competitor"])
                else:
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
