#!/usr/bin/env python3
"""Focused contracts for selected x86 callable-provider archive linkage."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE_DIR = ROOT / "compat" / "x86_64"
AUDIT_PATH = SOURCE_DIR / "header_callable_provider_linkage_audit.py"
ROSTER_PATH = SOURCE_DIR / "feature_archive_roster.py"
RUNNER = SOURCE_DIR / "run_header_callable_provider_linkage_audit.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ROSTER = load_module("feature_archive_roster_provider_audit_test", ROSTER_PATH)
AUDIT = load_module("header_callable_provider_linkage_audit_test", AUDIT_PATH)


class SuppliedPlannedProfileTests(unittest.TestCase):
    @unittest.skipUnless(all(shutil.which(t) for t in ("cc", "clang", "ar", "readelf")), "requires native compiler tools")
    def test_binding_receipt_rejects_crossed_source_and_changed_raw_application(self):
        import header_callable_inventory as inventory_module
        import owned_posix_product_evidence as product_evidence
        import owned_posix_static_products as products
        anchor = json.loads((ROOT / "compat/x86_64/owned_resolver_network_image_inputs.json").read_text())
        linker = next(p for p in anchor["files"] if p.endswith("/gcc-ld/ld.lld"))
        if not Path(linker).is_file():
            self.skipTest("requires the pinned native image linker")
        work = ROOT / ".work/x86_64/planned-provider-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            contract_dir = root / "compat/x86_64"
            contract_dir.mkdir(parents=True)
            (contract_dir / "owned_resolver_network_image_inputs.json").write_text(json.dumps(anchor))
            (root / ".gitignore").write_text(".work/\n")
            for args in (["init", "-q"], ["add", "."], ["-c", "user.name=T", "-c", "user.email=t@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture"]):
                subprocess.run(["git", *args], cwd=root, check=True)
            source = products.source_identity(root)
            product = root / ".work/product"
            for directory in (product / "usr/include", product / "usr/lib", product / "share/crabc", product / "bin"):
                directory.mkdir(parents=True)
            (product / "usr/include/demo.h").write_text("int owner(void);\n")
            archive = HeaderCallableProviderLinkageAuditTests.archive(product / "usr/lib", "libc",
                'int owner(void) { return 1; }\n'
                '__asm__(".global _start\\n_start: call main; mov %eax,%edi; mov $60,%eax; syscall");\n')
            archive.rename(product / "usr/lib/libc.a")
            archive = product / "usr/lib/libc.a"
            manifest = product / "share/crabc/manifest.json"
            manifest.write_text(json.dumps({"source_sha256": source["content_sha256"]}))
            driver = product / "bin/crabc-cc"
            driver.write_text("#!/usr/bin/python3\n" +
                "import sys, subprocess, json\nfrom pathlib import Path\nargs=sys.argv[1:]\n" +
                "if '-c' in args: raise SystemExit(subprocess.run(['cc',*args]).returncode)\n" +
                "i=args.index('--link-receipt'); receipt=Path(args[i+1]); del args[i:i+2]\n" +
                f"status=subprocess.run([{linker!r},'-static','-e','_start',*args,{str(archive)!r}]).returncode\n" +
                f"receipt.write_text(json.dumps({{'resolved_linker': {{'path': {linker!r}, 'sha256': {anchor['files'][linker]['sha256']!r}}}}}))\n" +
                "receipt.with_suffix('.map').write_text('fixture map\\n'); receipt.with_suffix('.trace').write_text('fixture trace\\n')\n" +
                "raise SystemExit(status)\n")
            driver.chmod(0o755)
            profile = ROSTER.FeatureArchive(identifier="x86-fixture", state="planned", evidence_record=None,
                runner="fixture", dispatch_command=None, baseline_features=(), enabled_features=("x86-fixture",),
                additive_callables=("owner",), replacement_callables=(), aliases=())
            inventory_path = root / ".work/inventory.json"
            inventory_path.write_text(json.dumps({"schema": AUDIT.INVENTORY_SCHEMA, "profiles": [{"id": "c11-gnu", "language": "c", "standard": "c11", "defines": []}],
                "callables": [{"tree": "candidate", "classification": "external", "declaration_kind": "function",
                    "name": "owner", "profile": "c11-gnu", "declaring_header": "demo.h", "type": "int (void)"}],
                "callable_provider_partition": {"declared_unverified_feature_archives": [{"id": "x86-fixture", "members": ["owner"]}], "unprovided": {"members": ["missing"]}}}))
            output = root / ".work/output"
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {"CRABC_X86_HEADER_DECLARATION_IMAGE_ID": "crabc-core-evidence@" + anchor["image"]}), \
                     patch.object(AUDIT, "ROOT", root), patch.object(AUDIT, "INVENTORY_PATH", inventory_path), \
                     patch.object(AUDIT, "load_feature_archive_roster", return_value=(profile,)), \
                     patch.object(inventory_module, "load_contract", return_value=None), \
                     patch.object(inventory_module, "refresh_provider_accounting", side_effect=lambda r, _: r), \
                     patch.object(product_evidence, "_validate_static_product", return_value=(manifest, {})), \
                     patch.object(product_evidence, "validate_retained_link", return_value={}), \
                     patch("crabc_cc_static.linker", return_value=linker):
                    path = AUDIT.audit_supplied_planned_profile(product_root=product, profile=profile.identifier, output=output)
                    report = json.loads((output / "bindings.json").read_text())
                    self.assertFalse(report["full_callable_closure"])
                    self.assertFalse(report["family_admission"])
                    self.assertEqual(report["provider_partition"]["unprovided"]["members"], ["missing"])
                    self.assertEqual(AUDIT.audit_supplied_planned_profile(product_root=product, profile=profile.identifier, output=output, replay=True), path)
                    with (output / "application.o").open("ab") as stream:
                        stream.write(b"changed")
                    with self.assertRaisesRegex(AUDIT.ProviderLinkageAuditError, "raw artifact changed"):
                        AUDIT.audit_supplied_planned_profile(product_root=product, profile=profile.identifier, output=output, read=True)
                    manifest.write_text(json.dumps({"source_sha256": "0" * 64}))
                    with self.assertRaisesRegex(AUDIT.ProviderLinkageAuditError, "executing source differ"):
                        AUDIT.audit_supplied_planned_profile(product_root=product, profile=profile.identifier, output=root / ".work/crossed")
                    self.assertFalse((root / ".work/crossed").exists())
                    manifest.write_text(json.dumps({"source_sha256": source["content_sha256"]}))
                    previous = path.read_bytes()
                    real_run = subprocess.run
                    def changing_source(argv, **kwargs):
                        result = real_run(argv, **kwargs)
                        if str(argv[0]).endswith("/changed-during/bindings"):
                            (root / ".gitignore").write_text(".work/\n# changed\n")
                        return result
                    with patch.object(AUDIT.subprocess, "run", side_effect=changing_source):
                        with self.assertRaisesRegex(products.PreparationError, "clean committed source"):
                            AUDIT.audit_supplied_planned_profile(product_root=product, profile=profile.identifier,
                                output=root / ".work/changed-during")
                    self.assertEqual(path.read_bytes(), previous)
            finally:
                os.chdir(old_cwd)


class PlannedDeclarationCompilerTests(unittest.TestCase):
    def test_timed_out_command_retains_raw_diagnostic_bytes(self):
        work = ROOT / ".work/x86_64/planned-provider-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            output = Path(temporary)
            error = subprocess.TimeoutExpired(["compiler"], 120, output=b"raw\xff", stderr=b"error\xfe")
            with patch.object(AUDIT.subprocess, "run", side_effect=error):
                with self.assertRaises(AUDIT.ProviderLinkageAuditError):
                    AUDIT._planned_command(output, "compiler", ["compiler"])
            self.assertEqual((output / "compiler.stdout").read_bytes(), b"raw\xff")
            self.assertEqual((output / "compiler.stderr").read_bytes(), b"error\xfe")
            self.assertTrue(json.loads((output / "compiler.status.json").read_text())["timeout"])

    @unittest.skipUnless(all(shutil.which(t) for t in ("cc", "ar", "readelf")), "requires native ELF tools")
    def test_planned_binding_rejects_missing_nonfunction_and_changed_weak_owner(self):
        work = ROOT / ".work/x86_64/planned-provider-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            archive = HeaderCallableProviderLinkageAuditTests.archive(root, "owner", "int owner(void) { return 1; }\n")
            for name, source in (("good", "int owner(void) { return 1; }\n"),
                                 ("weak", "__attribute__((weak)) int owner(void) { return 1; }\n"),
                                 ("data", "int owner;\n"), ("absent", "int other(void) { return 1; }\n")):
                target = HeaderCallableProviderLinkageAuditTests.archive(root, name, source)
                if name == "good":
                    result = AUDIT.planned_binding_definitions(archive, target, ("owner",), ())
                    self.assertIn("owner", result)
                else:
                    with self.assertRaises(AUDIT.ProviderLinkageAuditError):
                        AUDIT.planned_binding_definitions(archive, target, ("owner",), ())

    @unittest.skipUnless(all(shutil.which(t) for t in ("cc", "ar", "readelf")), "requires native ELF tools")
    def test_planned_alias_retains_weak_same_address_target(self):
        work = ROOT / ".work/x86_64/planned-provider-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            body = "int target(void) { return 1; } int other(void) { return 2; }\n"
            alias = ROSTER.ArchiveAlias(name="alias_name", target="target", binding="weak-same-address")
            good = HeaderCallableProviderLinkageAuditTests.archive(root, "good_alias", body +
                'extern __typeof(target) alias_name __attribute__((weak, alias("target")));\n')
            bad = HeaderCallableProviderLinkageAuditTests.archive(root, "wrong_alias", body +
                'extern __typeof(other) alias_name __attribute__((weak, alias("other")));\n')
            AUDIT.planned_binding_definitions(good, good, ("target",), (alias,))
            with self.assertRaisesRegex(AUDIT.ProviderLinkageAuditError, "weak alias"):
                AUDIT.planned_binding_definitions(good, bad, ("target",), (alias,))

    @unittest.skipUnless(shutil.which("clang") and shutil.which("nm"), "requires native Clang and nm")
    def test_selected_cxx_only_declaration_retains_ordinary_c_linkage(self):
        work = ROOT / ".work/x86_64/planned-provider-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            headers = root / "include"
            headers.mkdir()
            (headers / "demo.h").write_text(
                "int c_owner(int);\n#ifdef __cplusplus\n"
                'extern "C" int cxx_only(int);\n#endif\n')
            profiles = [{"id": "c11-gnu", "language": "c", "standard": "c11", "defines": []},
                        {"id": "cxx17-gnu", "language": "cxx", "standard": "c++17", "defines": []}]
            inventory = {"profiles": profiles, "callables": [
                {"tree": "candidate", "classification": "external", "declaration_kind": "function",
                 "name": name, "profile": profile, "declaring_header": "demo.h", "type": "int (int)"}
                for name, profile in (("c_owner", "c11-gnu"), ("cxx_only", "cxx17-gnu"))]}
            objects, jobs, products, cases = AUDIT.compile_planned_declarations(
                inventory, ("c_owner", "cxx_only"), headers, root / "output")
            self.assertEqual({j["profile"]["language"] for j in jobs}, {"c", "cxx"})
            imports = "".join(subprocess.check_output(["nm", "-u", str(obj)], text=True) for obj in objects)
            self.assertIn(" U c_owner", imports)
            self.assertIn(" U cxx_only", imports)
            self.assertNotIn("_Z", imports)
            self.assertTrue(products)
            self.assertTrue(all(status == 0 for _, status, _ in cases))
            (headers / "demo.h").write_text("int c_owner(double);\n")
            with self.assertRaisesRegex(AUDIT.ProviderLinkageAuditError, "declaration"):
                AUDIT.compile_planned_declarations(inventory, ("c_owner",), headers, root / "changed")


class HeaderCallableProviderLinkageAuditTests(unittest.TestCase):
    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm", "readelf")),
        "requires native binutils and C compiler",
    )
    def test_selected_feature_provider_extracts_without_closing_unprovided_complement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            default_archive = self.archive(
                root,
                "default",
                "int default_owner(void) { return 1; }\n"
                "int replacement(void) { return 2; }\n",
            )
            baseline_archive = self.archive(
                root,
                "baseline",
                "int default_owner(void) { return 1; }\n"
                "int replacement(void) { return 2; }\n",
            )
            enabled_archive = self.archive(
                root,
                "enabled",
                "int default_owner(void) { return 1; }\n"
                "int replacement(void) { return 3; }\n"
                "int feature_additive(void) { return 4; }\n"
                "int alias_target(void) { return 5; }\n"
                "int abi_only_strong(void) { return 6; }\n"
                "extern __typeof(alias_target) feature_alias "
                "__attribute__((weak, alias(\"alias_target\")));\n",
            )
            feature = ROSTER.FeatureArchive(
                identifier="x86-demo",
                state="verified",
                evidence_record="demo-provider-linkage",
                runner="compat/x86_64/run_demo_provider_linkage.sh",
                dispatch_command="demo-provider-linkage",
                baseline_features=(),
                enabled_features=("x86-demo",),
                additive_callables=("feature_additive",),
                replacement_callables=("replacement",),
                aliases=(
                    ROSTER.ArchiveAlias(
                        name="feature_alias",
                        target="alias_target",
                        binding="weak-same-address",
                    ),
                ),
                abi_only_callables=("abi_only_strong",),
            )
            inventory = {
                "schema": AUDIT.INVENTORY_SCHEMA,
                "callables": [
                    self.callable("default_owner"),
                    self.callable("replacement"),
                    self.callable("feature_additive"),
                    self.callable("unprovided"),
                ],
                "callable_provider_partition": {
                    "kind": "candidate-external-callable-feature-archive-provider-partition",
                    "default_static": {"members": ["default_owner", "replacement"]},
                    "verified_feature_archives": [
                        {
                            "aliases": [
                                {
                                    "binding": "weak-same-address",
                                    "name": "feature_alias",
                                    "target": "alias_target",
                                },
                            ],
                            "evidence_record": "demo-provider-linkage",
                            "id": "x86-demo",
                            "members": ["feature_additive"],
                            "runner": "compat/x86_64/run_demo_provider_linkage.sh",
                            "state": "verified",
                        },
                    ],
                    "declared_unverified_feature_archives": [],
                    "unprovided": {"members": ["unprovided"]},
                    "replacement_variants": [
                        {
                            "id": "x86-demo",
                            "members": ["replacement"],
                            "state": "verified",
                        },
                    ],
                },
            }

            report = AUDIT.audit_provider_closure(
                inventory=inventory,
                static_exports=("default_owner", "replacement"),
                default_archive=default_archive,
                roster=(feature,),
                profile_archives={
                    "x86-demo": {
                        "baseline": baseline_archive,
                        "enabled": enabled_archive,
                    },
                },
            )

        self.assertTrue(
            report["summary"]["selected_provider_closure_complete"],
            report["summary"]["incomplete_reasons"],
        )
        self.assertFalse(report["summary"]["complete"])
        self.assertEqual(report["summary"]["unprovided_callable_count"], 1)
        self.assertEqual(report["external_callable_count"], 4)
        self.assertFalse(report["scope"]["header_declarations_proved_for_abi_only_callables"])
        self.assertEqual(
            report["selected_abi_only_callables"],
            {
                "kind": "selected-non-header-feature-callables",
                "members": ["abi_only_strong"],
            },
        )
        self.assertEqual(report["summary"]["selected_abi_only_callable_count"], 1)
        self.assertEqual(
            [entry["symbol"] for entry in report["default_static"]["extraction"]],
            ["default_owner", "replacement"],
        )
        profile = report["feature_profiles"][0]
        self.assertEqual(profile["id"], "x86-demo")
        self.assertEqual(
            profile["candidate_external_delta"],
            ["feature_additive"],
        )
        self.assertEqual(
            profile["archive_callable_delta"],
            ["abi_only_strong", "feature_additive", "feature_alias"],
        )
        self.assertEqual(profile["abi_only_callables"], ["abi_only_strong"])
        self.assertEqual(profile["baseline_abi_only_callables"], [])
        self.assertEqual(profile["enabled_abi_only_callables"], ["abi_only_strong"])
        self.assertEqual(
            [entry["symbol"] for entry in profile["abi_only_extraction"]],
            ["abi_only_strong"],
        )
        self.assertEqual(profile["abi_only_extraction"][0]["status"], "extracted")
        self.assertEqual(profile["abi_only_extraction"][0]["definitions"][0]["binding"], "GLOBAL")
        self.assertEqual(profile["abi_only_extraction"][0]["definitions"][0]["type"], "FUNC")
        self.assertEqual(
            [entry["symbol"] for entry in profile["additive_extraction"]],
            ["feature_additive"],
        )
        self.assertEqual(
            [entry["symbol"] for entry in profile["replacement_extraction"]],
            ["replacement"],
        )
        self.assertEqual(profile["aliases"][0]["status"], "verified")

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm", "readelf")),
        "requires native binutils and C compiler",
    )
    def test_abi_only_extraction_retains_a_weak_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.archive(
                Path(temporary),
                "weak-abi-only",
                "__attribute__((weak)) int abi_only_weak(void) { return 1; }\n",
            )
            work_dir = Path(temporary) / "extract"
            work_dir.mkdir()
            record = AUDIT.abi_only_record(
                archive,
                "abi_only_weak",
                "ld",
                "nm",
                "readelf",
                work_dir,
            )

        self.assertEqual(record["status"], "extracted")
        self.assertIn("global-or-weak function provider", record["detail"])
        self.assertEqual(record["definitions"][0]["binding"], "WEAK")
        self.assertEqual(record["definitions"][0]["type"], "FUNC")

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm", "readelf")),
        "requires native binutils and C compiler",
    )
    def test_abi_only_extraction_rejects_an_object_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.archive(
                Path(temporary),
                "object-abi-only",
                "int abi_only_object = 1;\n",
            )
            work_dir = Path(temporary) / "extract"
            work_dir.mkdir()
            record = AUDIT.abi_only_record(
                archive,
                "abi_only_object",
                "ld",
                "nm",
                "readelf",
                work_dir,
            )

        self.assertEqual(record["status"], "not-extracted")
        self.assertIn("ordinary archive extraction did not define", record["detail"])

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm", "readelf")),
        "requires native binutils and C compiler",
    )
    def test_abi_only_baseline_surface_includes_only_selected_ancestors(self) -> None:
        """A dependent profile inherits an ABI-only provider without owning it."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            default_archive = self.archive(
                root,
                "default-abi-only",
                "int default_owner(void) { return 1; }\n",
            )
            kernel_enabled = self.archive(
                root,
                "kernel-enabled",
                "int default_owner(void) { return 1; }\n"
                "int arch_prctl(void) { return 2; }\n",
            )
            owned_baseline = self.archive(
                root,
                "owned-baseline",
                "int default_owner(void) { return 1; }\n"
                "int arch_prctl(void) { return 2; }\n",
            )
            owned_enabled = self.archive(
                root,
                "owned-enabled",
                "int default_owner(void) { return 1; }\n"
                "int arch_prctl(void) { return 2; }\n"
                "int __xmknod(void) { return 3; }\n"
                "int __xmknodat(void) { return 4; }\n",
            )
            kernel = ROSTER.FeatureArchive(
                identifier="x86-kernel-admin",
                state="verified",
                evidence_record="kernel-admin",
                runner="compat/x86_64/run_libc_kernel_admin.sh",
                dispatch_command="libc-kernel-admin",
                baseline_features=(),
                enabled_features=("x86-kernel-admin",),
                additive_callables=(),
                replacement_callables=(),
                aliases=(),
                abi_only_callables=("arch_prctl",),
            )
            owned = ROSTER.FeatureArchive(
                identifier="x86-owned-static-runtime",
                state="verified",
                evidence_record="owned-static-runtime",
                runner="compat/x86_64/run_owned_static_sysroot.sh",
                dispatch_command="owned-static-runtime",
                baseline_features=("x86-kernel-admin",),
                enabled_features=("x86-owned-static-runtime",),
                additive_callables=(),
                replacement_callables=(),
                aliases=(),
                abi_only_callables=("__xmknod", "__xmknodat"),
            )
            inventory = {
                "schema": AUDIT.INVENTORY_SCHEMA,
                "callables": [self.callable("default_owner")],
                "callable_provider_partition": {
                    "kind": "candidate-external-callable-feature-archive-provider-partition",
                    "default_static": {"members": ["default_owner"]},
                    "verified_feature_archives": [
                        {
                            "aliases": [],
                            "evidence_record": "kernel-admin",
                            "id": "x86-kernel-admin",
                            "members": [],
                            "runner": "compat/x86_64/run_libc_kernel_admin.sh",
                            "state": "verified",
                        },
                        {
                            "aliases": [],
                            "evidence_record": "owned-static-runtime",
                            "id": "x86-owned-static-runtime",
                            "members": [],
                            "runner": "compat/x86_64/run_owned_static_sysroot.sh",
                            "state": "verified",
                        },
                    ],
                    "declared_unverified_feature_archives": [],
                    "unprovided": {"members": []},
                    "replacement_variants": [],
                },
            }

            report = AUDIT.audit_provider_closure(
                inventory=inventory,
                static_exports=("default_owner",),
                default_archive=default_archive,
                roster=(kernel, owned),
                profile_archives={
                    "x86-kernel-admin": {
                        "baseline": default_archive,
                        "enabled": kernel_enabled,
                    },
                    "x86-owned-static-runtime": {
                        "baseline": owned_baseline,
                        "enabled": owned_enabled,
                    },
                },
            )

        self.assertTrue(report["summary"]["selected_provider_closure_complete"])
        self.assertTrue(report["summary"]["complete"])
        profiles = {row["id"]: row for row in report["feature_profiles"]}
        self.assertEqual(profiles["x86-kernel-admin"]["baseline_abi_only_callables"], [])
        self.assertEqual(
            profiles["x86-kernel-admin"]["enabled_abi_only_callables"],
            ["arch_prctl"],
        )
        self.assertEqual(
            profiles["x86-owned-static-runtime"]["abi_only_callables"],
            ["__xmknod", "__xmknodat"],
        )
        self.assertEqual(
            profiles["x86-owned-static-runtime"]["baseline_abi_only_callables"],
            ["arch_prctl"],
        )
        self.assertEqual(
            profiles["x86-owned-static-runtime"]["enabled_abi_only_callables"],
            ["__xmknod", "__xmknodat", "arch_prctl"],
        )
        self.assertEqual(
            [entry["symbol"] for entry in profiles["x86-owned-static-runtime"]["abi_only_extraction"]],
            ["__xmknod", "__xmknodat"],
        )
        self.assertEqual(
            report["selected_abi_only_callables"]["members"],
            ["__xmknod", "__xmknodat", "arch_prctl"],
        )
        self.assertEqual(report["summary"]["selected_abi_only_callable_count"], 3)

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm")),
        "requires native binutils and C compiler",
    )
    def test_topology_only_profile_retains_its_rejected_direct_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self.archive(
                root,
                "default",
                "int default_owner(void) { return 1; }\n",
            )
            feature = ROSTER.FeatureArchive(
                identifier=AUDIT.TOPOLOGY_ONLY_PROFILE,
                state="verified",
                evidence_record="crypt-allocator-composition",
                runner="compat/x86_64/run_libc_crypt_allocator_composition.sh",
                dispatch_command="libc-crypt-allocator-composition",
                baseline_features=AUDIT.TOPOLOGY_ONLY_BASELINE,
                enabled_features=(AUDIT.TOPOLOGY_ONLY_PROFILE,),
                additive_callables=(),
                replacement_callables=(),
                aliases=(),
            )
            inventory = {
                "schema": AUDIT.INVENTORY_SCHEMA,
                "callables": [self.callable("default_owner"), self.callable("unprovided")],
                "callable_provider_partition": {
                    "kind": "candidate-external-callable-feature-archive-provider-partition",
                    "default_static": {"members": ["default_owner"]},
                    "verified_feature_archives": [
                        {
                            "aliases": [],
                            "evidence_record": "crypt-allocator-composition",
                            "id": AUDIT.TOPOLOGY_ONLY_PROFILE,
                            "members": [],
                            "runner": "compat/x86_64/run_libc_crypt_allocator_composition.sh",
                            "state": "verified",
                        },
                    ],
                    "declared_unverified_feature_archives": [],
                    "unprovided": {"members": ["unprovided"]},
                    "replacement_variants": [],
                },
            }

            report = AUDIT.audit_provider_closure(
                inventory=inventory,
                static_exports=("default_owner",),
                default_archive=archive,
                roster=(feature,),
                profile_archives={
                    AUDIT.TOPOLOGY_ONLY_PROFILE: {"enabled": archive},
                },
            )

        self.assertTrue(report["summary"]["selected_provider_closure_complete"])
        self.assertFalse(report["summary"]["complete"])
        self.assertEqual(report["summary"]["topology_only_profile_count"], 1)
        self.assertEqual(
            report["feature_profiles"][0]["mode"],
            "topology-only-dedicated-evidence",
        )

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm")),
        "requires native binutils and C compiler",
    )
    def test_failed_default_extraction_blocks_selected_provider_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self.archive(
                root,
                "missing-owner",
                "int unrelated(void) { return 1; }\n",
            )
            inventory = {
                "schema": AUDIT.INVENTORY_SCHEMA,
                "callables": [self.callable("default_owner")],
                "callable_provider_partition": {
                    "kind": "candidate-external-callable-feature-archive-provider-partition",
                    "default_static": {"members": ["default_owner"]},
                    "verified_feature_archives": [],
                    "declared_unverified_feature_archives": [],
                    "unprovided": {"members": []},
                    "replacement_variants": [],
                },
            }

            report = AUDIT.audit_provider_closure(
                inventory=inventory,
                static_exports=("default_owner",),
                default_archive=archive,
                roster=(),
                profile_archives={},
            )

        self.assertFalse(report["summary"]["selected_provider_closure_complete"])
        self.assertFalse(report["summary"]["complete"])
        self.assertIn(
            "default static default_owner did not extract ordinarily",
            report["summary"]["incomplete_reasons"],
        )

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm", "readelf")),
        "requires native binutils and C compiler",
    )
    def test_text_section_object_cannot_supply_a_declared_function(self) -> None:
        from header_callable_linkage_audit import extract_one

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self.archive(
                root,
                "object-in-text",
                'int default_owner __attribute__((section(".text"))) = 1;\n',
            )
            symbols = subprocess.check_output(
                ["nm", "--defined-only", "--format=posix", str(archive)], text=True
            )
            self.assertIn("default_owner T ", symbols)
            details = subprocess.check_output(
                ["readelf", "--symbols", "--wide", str(archive)], text=True
            )
            self.assertIn("OBJECT", details)
            for name, extract in (
                ("default", lambda: extract_one(archive, "default_owner", "ld", "nm", root)),
                ("selected", lambda: AUDIT.extract_symbol(archive, ("default_owner",), "ld", "nm", root)[0]),
            ):
                with self.subTest(audit=name):
                    self.assertNotEqual(extract()["status"], "extracted")

    def test_unverified_replacement_variant_remains_an_inventory_fact(self) -> None:
        verified = ROSTER.FeatureArchive(
            identifier="x86-verified-replacement",
            state="verified",
            evidence_record="verified-replacement",
            runner="compat/x86_64/run_verified_replacement.sh",
            dispatch_command="verified-replacement",
            baseline_features=(),
            enabled_features=("x86-verified-replacement",),
            additive_callables=(),
            replacement_callables=("verified_replacement",),
            aliases=(),
        )
        planned = ROSTER.FeatureArchive(
            identifier="x86-planned-replacement",
            state="planned",
            evidence_record=None,
            runner="compat/x86_64/run_planned_replacement.sh",
            dispatch_command="planned-replacement",
            baseline_features=(),
            enabled_features=("x86-planned-replacement",),
            additive_callables=(),
            replacement_callables=("planned_replacement",),
            aliases=(),
        )
        partition = {
            "verified_feature_archives": [{"id": verified.identifier}],
            "replacement_variants": [
                {"id": planned.identifier},
                {"id": verified.identifier},
            ],
        }

        verified_rows, replacement_rows = AUDIT.feature_rows(
            partition, (verified, planned)
        )

        self.assertEqual(set(verified_rows), {verified.identifier})
        self.assertEqual(
            set(replacement_rows), {planned.identifier, verified.identifier}
        )

    def test_runner_reuses_one_invocation_baseline_archives_by_feature_set(self) -> None:
        """Equal baseline feature sets must not cause duplicate archive builds."""

        work_root = ROOT / ".work" / "x86_64" / "provider-linkage-audit-tests"
        work_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="baseline-reuse-",
            dir=work_root,
        ) as temporary:
            root = Path(temporary)

            def execute_orchestration(label: str, runner: str) -> list[str]:
                prelude, marker, entry = runner.partition('[ "$#" -eq 0 ] || fail "usage: $0"')
                self.assertTrue(marker, f"{label} runner has no executable entry boundary")
                _, change_directory, after_directory = entry.partition('cd "$ROOT_DIR"\n')
                self.assertTrue(change_directory, f"{label} runner has no orchestration directory boundary")
                body, audit, _ = after_directory.partition('python3 "$AUDIT" \\')
                self.assertTrue(audit, f"{label} runner has no audit boundary")
                mock_bin = root / f"{label}-bin"
                mock_bin.mkdir()
                capture = root / f"{label}-trace.txt"
                mock_python = mock_bin / "python3"
                mock_python.write_text(
                    "#!/bin/bash\n"
                    "printf 'roster\\n' >>\"$CAPTURE\"\n"
                    "cat >/dev/null\n"
                    "printf '%s\\t%s\\n' x86-alpha ''\n"
                    "printf '%s\\t%s\\n' x86-beta ''\n"
                    "printf '%s\\t%s\\n' x86-gamma x86-shared\n"
                    "printf '%s\\t%s\\n' x86-delta x86-shared\n"
                    "printf '%s\\t%s\\n' x86-epsilon x86-distinct\n"
                    "printf '%s\\t%s\\n' x86-crypt-allocator-composition x86-allocator-runtime,x86-crypt\n",
                    encoding="utf-8",
                )
                mock_bash = mock_bin / "bash"
                mock_bash.write_text(
                    "#!/bin/bash\n"
                    "printf 'topology\\n' >>\"$CAPTURE\"\n",
                    encoding="utf-8",
                )
                mock_python.chmod(0o755)
                mock_bash.chmod(0o755)
                harness = root / f"{label}.sh"
                harness.write_text(
                    prelude
                    + r"""

work_dir="$1"
capture="$2"
default_target="$work_dir/default"
default_archive="$default_target/$TARGET/debug/libc.a"

build_archive() {
    local target_dir="$1"
    local feature_request="$2"
    mkdir -p "$target_dir/$TARGET/debug"
    : >"$target_dir/$TARGET/debug/libc.a"
    printf 'build\t%s\t%s\n' "$(basename "$target_dir")" "$feature_request" >>"$capture"
}

"""
                    + body
                    + r"""
printf 'baseline-args\t%s\n' "${baseline_args[*]}" >>"$capture"
printf 'enabled-args\t%s\n' "${enabled_args[*]}" >>"$capture"
""",
                    encoding="utf-8",
                )
                environment = dict(
                    os.environ,
                    CAPTURE=str(capture),
                    PATH=f"{mock_bin}{os.pathsep}{os.environ['PATH']}",
                )
                completed = subprocess.run(
                    ["/bin/bash", str(harness), str(root / f"{label}-work"), str(capture)],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                return capture.read_text(encoding="utf-8").splitlines()

            current_records = execute_orchestration("current", RUNNER.read_text(encoding="utf-8"))

        current_builds = [record for record in current_records if record.startswith("build\t")]
        self.assertEqual(
            current_builds,
            [
                "build\tdefault\t",
                "build\tx86-alpha-enabled\tx86-alpha",
                "build\tx86-beta-enabled\tx86-beta",
                "build\tx86-gamma-enabled\tx86-gamma",
                "build\tx86-gamma-baseline\tx86-shared",
                "build\tx86-delta-enabled\tx86-delta",
                "build\tx86-epsilon-enabled\tx86-epsilon",
                "build\tx86-epsilon-baseline\tx86-distinct",
                "build\tx86-crypt-allocator-composition-enabled\tx86-crypt-allocator-composition",
            ],
        )
        self.assertEqual(len(current_builds), 9)
        self.assertEqual(sum(record.endswith("\t") for record in current_builds), 1)
        self.assertEqual(current_records.count("roster"), 1)
        self.assertEqual(current_records.count("topology"), 1)

        def archive(directory: str) -> str:
            return str(
                root
                / "current-work"
                / directory
                / "x86_64-unknown-linux-musl"
                / "debug"
                / "libc.a"
            )

        expected_baseline_args = "baseline-args\t" + " ".join(
            (
                f"--profile-baseline x86-alpha={archive('default')}",
                f"--profile-baseline x86-beta={archive('default')}",
                f"--profile-baseline x86-gamma={archive('x86-gamma-baseline')}",
                f"--profile-baseline x86-delta={archive('x86-gamma-baseline')}",
                f"--profile-baseline x86-epsilon={archive('x86-epsilon-baseline')}",
            )
        )
        expected_enabled_args = "enabled-args\t" + " ".join(
            f"--profile-enabled {identifier}={archive(directory)}"
            for identifier, directory in (
                ("x86-alpha", "x86-alpha-enabled"),
                ("x86-beta", "x86-beta-enabled"),
                ("x86-gamma", "x86-gamma-enabled"),
                ("x86-delta", "x86-delta-enabled"),
                ("x86-epsilon", "x86-epsilon-enabled"),
                (
                    "x86-crypt-allocator-composition",
                    "x86-crypt-allocator-composition-enabled",
                ),
            )
        )
        self.assertEqual(current_records[-2:], [expected_baseline_args, expected_enabled_args])

    def test_runner_and_dispatcher_keep_the_provider_audit_non_promoting(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(AUDIT_PATH.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        runner = RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "header_callable_provider_linkage_audit.py",
            "feature_archive_roster.py",
            "ordinary archive extraction",
            "selected provider closure",
            "unprovided complement",
            "family_promotion",
            "full_callable_closure",
            "public_support",
            "uses_whole_archive",
        ):
            self.assertIn(phrase, runner)
        self.assertNotIn("scripts/dev-x86_64.sh", runner)
        self.assertNotIn("--whole-archive", runner)

        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn("header-callable-provider-linkage-audit", dispatcher)
        self.assertIn("    header-callable-provider-linkage-audit) ;;", dispatcher)
        self.assertIn("run_header_callable_provider_linkage_audit()", dispatcher)

    @staticmethod
    def archive(root: Path, name: str, source: str) -> Path:
        source_path = root / f"{name}.c"
        object_path = root / f"{name}.o"
        archive_path = root / f"lib{name}.a"
        source_path.write_text(source, encoding="utf-8")
        subprocess.run(["cc", "-c", str(source_path), "-o", str(object_path)], check=True)
        subprocess.run(["ar", "rcs", str(archive_path), str(object_path)], check=True)
        return archive_path

    @staticmethod
    def callable(name: str) -> dict[str, str]:
        return {
            "tree": "candidate",
            "profile": "c11-gnu",
            "classification": "external",
            "declaration_kind": "function",
            "name": name,
        }


if __name__ == "__main__":
    unittest.main()
