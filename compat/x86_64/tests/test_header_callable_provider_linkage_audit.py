#!/usr/bin/env python3
"""Focused contracts for selected x86 callable-provider archive linkage."""

from __future__ import annotations

import importlib.util
import json
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
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


class HeaderCallableProviderLinkageAuditTests(unittest.TestCase):
    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("cc", "ar", "ld", "nm")),
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
        self.assertEqual(
            [entry["symbol"] for entry in report["default_static"]["extraction"]],
            ["default_owner", "replacement"],
        )
        profile = report["feature_profiles"][0]
        self.assertEqual(profile["id"], "x86-demo")
        self.assertEqual(
            profile["candidate_external_delta"],
            ["feature_additive", "feature_alias"],
        )
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
