"""Focused selector joins for the finite native C allocator boundary receipt."""
from __future__ import annotations

import contextlib
import copy
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import native_abi_selection as selection


class NativeCAllocatorBoundaryAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        common_checkout = mock.patch.object(selection, "_common_checkout", return_value=ROOT)
        common_checkout.start()
        self.addCleanup(common_checkout.stop)

        parent = ROOT / ".work/x86_64/native-c-allocator-boundary-attachment-tests"
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.static = self.work / "static"
        self.dynamic = self.work / "dynamic"
        for directory in (self.static, self.dynamic):
            directory.mkdir()
        self._write(self.static / "share/crabc/manifest.json", b"static manifest\n")
        self._write(self.static / "share/crabc/libc-static.provenance.json", b"static provenance\n")
        self._write(self.static / "bin/crabc-cc", b"static driver\n")
        self._write(self.static / "usr/lib/libc.a", b"static libc\n")
        self._write(self.dynamic / "share/crabc/manifest.json", b"dynamic manifest\n")
        self._write(self.dynamic / "share/crabc/dynamic-product-state.json", b"dynamic state\n")
        self._write(self.dynamic / "share/crabc/libc-shared.provenance.json", b"dynamic provenance\n")
        self._write(self.dynamic / "share/crabc/loader.provenance.json", b"loader provenance\n")
        self._write(self.dynamic / "bin/crabc-cc-dynamic", b"dynamic driver\n")
        self._write(self.dynamic / "usr/lib/libc.so", b"dynamic libc\n")
        self._write(self.dynamic / "lib/ld-crabc-x86_64.so.1", b"dynamic loader\n")
        self.base = self._write(self.work / "base-inventory.json", b"base\n")
        self.elf = self._write(self.work / "elf-facts.json", b"elf\n")
        self.preparation = self._write(self.work / "preparation.json", b"preparation\n")
        self.report_path = self._write(self.work / "allocator-boundary-report.json", b"{}\n")
        self.paths = {
            "measurement_checkout": ROOT,
            "base_inventory": self.base,
            "elf_report": self.elf,
            "static_preparation": self.preparation,
            "static_product": self.static,
            "dynamic_product": self.dynamic,
        }
        self.source = {
            "revision": "a" * 40,
            "content_sha256": "b" * 64,
            "clean": True,
        }
        self.measurement = {
            "candidate_build": {
                "revision": self.source["revision"],
                "source_content_sha256": self.source["content_sha256"],
            },
            "reports": {
                name: selection.file_identity(self.paths[name])
                for name in ("elf_report", "base_inventory", "static_preparation")
            },
        }
        current = selection._runtime_attachment_identities(self.paths)
        self.current = {
            **current,
            "static_provenance": selection.file_identity(
                self.static / "share/crabc/libc-static.provenance.json"
            ),
        }
        self.facts = {
            "artifacts": {
                "candidate-static": {"identity": self.current["static_libc"]},
                "candidate-shared": {"identity": self.current["dynamic_libc"]},
                "candidate-loader": {"identity": self.current["dynamic_loader"]},
            },
        }
        self.names = tuple(
            selection.native_c_allocator_boundary.load_contract()["scope"]["rust_c_imports"]
        )
        self.runtime_roles = dict(selection.native_c_allocator_boundary.C_RUNTIME_IMPORTS)
        self.producer_account = self._producer_account()
        self.fixed_c_companion = {"account": copy.deepcopy(self.producer_account)}

    def _write(self, path: Path, data: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def _producer_account(self) -> dict[str, object]:
        imports = []
        for name in self.names:
            imports.append({
                "name": name,
                "static_rust_import": {
                    "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT",
                    "section_index": "UND",
                },
                "static_c_provider": {
                    "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
                    "definition": "defined", "section_index": "7", "size_bytes": 1,
                },
                "shared_c_final_provider": {
                    "type": "FUNC", "binding": "LOCAL", "visibility": "DEFAULT",
                    "definition": "defined", "section_index": "9", "size_bytes": 1,
                },
            })
        return {
            "schema": selection.producer_metadata.SCHEMA,
            "target": selection.TARGET,
            "status": "component-pass-not-qualification",
            "status_flags": {
                "family_completion": False,
                "promotion_ready": False,
                "public_support": False,
            },
            "scope": {
                "member_count": 424,
                "metadata_buckets": {
                    "strong-functions": 419,
                    "weak-null-fallback": 1,
                    "data-objects": 3,
                    "initial-exec-tls": 1,
                },
                "rust_root_c_imports": len(self.names),
                "shared_dynsym_private_names": "absent",
            },
            "archive_map": {
                "static_c_member": "selected-c-mimalloc.o",
                "static_c_member_sha256": "d" * 64,
                "static_rust_root_member": "native-c-root.rcgu.o",
                "shared_rust_root_member": "native-c-shared.rcgu.o",
                "shared_c_member_sha256": "d" * 64,
            },
            "rust_root_c_import_joins": imports,
        }

    def _runtime_import_bindings(self) -> dict[str, object]:
        def provider(name: str, binding: str) -> dict[str, object]:
            return {
                "name": name, "raw_name": name, "type": "FUNC", "binding": binding,
                "visibility": "DEFAULT", "section_index": "7", "size_bytes": 1,
                "value": "0000000000000000", "version": None, "version_default": False,
            }

        def imported(name: str) -> dict[str, object]:
            return {
                "name": name, "raw_name": name, "type": "NOTYPE", "binding": "GLOBAL",
                "visibility": "DEFAULT", "section_index": "UND", "size_bytes": 0,
                "value": "0000000000000000", "version": None, "version_default": False,
            }

        return {
            "static_c_member": {
                "name": "selected-c-mimalloc.o", "member_index": 1,
                "member_occurrence": 0, "sha256": "d" * 64,
            },
            "static_rust_root_member": {
                "name": "native-c-root.rcgu.o", "member_index": 0, "member_occurrence": 0,
            },
            "shared_rust_root_member": "native-c-shared.rcgu.o",
            "shared_c_member_sha256": "d" * 64,
            "imports": [
                {
                    "name": name, "binding": binding,
                    "static_c_import": imported(name),
                    "static_rust_provider": provider(name, binding),
                    "shared_dynsym_provider": provider(name, binding),
                    "shared_symtab_provider": provider(name, binding),
                }
                for name, binding in self.runtime_roles.items()
            ],
        }

    def _runtime_static_links(self, runtime: dict[str, object]) -> dict[str, object]:
        archive = "/workspace/" + (self.static / "usr/lib/libc.a").relative_to(ROOT).as_posix()
        selected = {
            "static_c_member": f"{archive}({runtime['static_c_member']['name']})",
            "static_rust_root_member": f"{archive}({runtime['static_rust_root_member']['name']})",
        }
        map_path = self._write(self.work / "static.map", b"map\n")
        trace_path = self._write(self.work / "static.trace", b"trace\n")
        return {
            mode: {
                "map": selection.file_identity(map_path),
                "trace": selection.file_identity(trace_path),
                "selected_members": copy.deepcopy(selected),
            }
            for mode in ("static", "static-pie")
        }

    def boundary_report(self) -> dict[str, object]:
        source_without_clean = {
            "revision": self.source["revision"],
            "content_sha256": self.source["content_sha256"],
        }
        runtime = self._runtime_import_bindings()
        return {
            "schema": selection.native_c_allocator_boundary.SCHEMA,
            "target": selection.native_c_allocator_boundary.TARGET,
            "status": {
                "family_completion": False,
                "promotion": False,
                "public_support": False,
            },
            "collector_source": copy.deepcopy(self.source),
            "component_sources": selection.native_c_allocator_boundary.source_records(ROOT),
            "inputs": {
                "product_source": source_without_clean,
                "source_resolution": {
                    "product_revision": self.source["revision"],
                    "runtime_source_sha256": {
                        name: "c" * 64
                        for name in selection.native_c_allocator_boundary.RUNTIME_SOURCES
                    },
                    "c_abi_bindings": {
                        name: {}
                        for name in (
                            set(selection.native_c_allocator_boundary.WRAPPER_C_ABI)
                            | {"malloc_usable_size"}
                        )
                    },
                    "lifecycle_c_abi": {},
                },
                "static_preparation": copy.deepcopy(
                    self.measurement["reports"]["static_preparation"]
                ),
                "static": {
                    "product": "/inputs/static-product",
                    "manifest": copy.deepcopy(self.current["static_manifest"]),
                    "libc": copy.deepcopy(self.current["static_libc"]),
                    "provenance": copy.deepcopy(self.current["static_provenance"]),
                },
                "dynamic": {
                    "product": "/inputs/dynamic-product",
                    "manifest": copy.deepcopy(self.current["dynamic_manifest"]),
                    "state": copy.deepcopy(self.current["dynamic_state"]),
                    "libc": copy.deepcopy(self.current["dynamic_libc"]),
                    "provenance": copy.deepcopy(
                        self.current["dynamic_shared_provenance"]
                    ),
                },
                "elf_facts": copy.deepcopy(self.measurement["reports"]["elf_report"]),
                "producer_account": copy.deepcopy(self.producer_account),
                "c_runtime_import_bindings": runtime,
                "wrapper_product_bindings": {
                    "static_member": "native-c-root.rcgu.o",
                    "static": {
                        name: {}
                        for name in selection.native_c_allocator_boundary.wrapper_roles(
                            selection.native_c_allocator_boundary.load_contract()
                        )
                    },
                    "shared": {
                        table: {
                            name: {}
                            for name in selection.native_c_allocator_boundary.wrapper_roles(
                                selection.native_c_allocator_boundary.load_contract()
                            )
                        }
                        for table in (".dynsym", ".symtab")
                    },
                },
            },
            "startup": {
                "command": {}, "work": "startup", "observation": {
                    "c_runtime_static_links": self._runtime_static_links(runtime),
                },
            },
            "interposition": {
                "command": {}, "work": "interposition", "observation": {},
            },
        }

    def accounting(self) -> dict[str, object]:
        identities, occurrences, placement_joins, blockers = [], [], [], []
        for name in self.names:
            identity = selection.identity(name)
            identities.append({
                "identity": identity,
                "selection": {
                    "disposition": "private-provider",
                    "owner": selection.FIXED_C_PRODUCER_OWNER,
                    "group": selection.FIXED_C_PRODUCER_GROUP,
                },
                "unresolved": [selection.ORDINARY_IMPORT_REASON],
            })
            blockers.append({
                "code": "identity-unresolved",
                "identity": copy.deepcopy(identity),
                "reason": selection.ORDINARY_IMPORT_REASON,
            })
            index = len(occurrences)
            occurrences.append({
                "index": index,
                "artifact_key": "candidate-static",
                "table": ".symtab",
                "role": "import",
                "member_name": "native-c-root.rcgu.o",
                "member_index": 4,
                "member_occurrence": 0,
                "row": {
                    "name": name,
                    "raw_name": name,
                    "version": None,
                    "version_default": False,
                    "row_index": index,
                    "type": "NOTYPE",
                    "binding": "GLOBAL",
                    "visibility": "DEFAULT",
                    "section_index": "UND",
                    "size_bytes": 0,
                    "value": "0000000000000000",
                },
                "accounting": {
                    "disposition": "private-provider",
                    "owner": selection.FIXED_C_PRODUCER_OWNER,
                    "scope": "candidate-static",
                },
            })
            for artifact_key, metadata in (
                ("candidate-static", {
                    "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
                }),
                ("candidate-shared", {
                    "type": "FUNC", "binding": "LOCAL", "visibility": "DEFAULT",
                }),
            ):
                placement_joins.append({
                    "identity": copy.deepcopy(identity),
                    "artifact_key": artifact_key,
                    "expected_metadata": metadata,
                    "placement_observed": True,
                    "definition_count": 1,
                    "occurrence_indices": [index],
                    "metadata_differences": [{"occurrence_index": index, "fields": []}],
                })
        return {
            "identities": identities,
            "occurrences": occurrences,
            "placement_joins": placement_joins,
            "blockers": blockers,
        }

    def runtime_accounting(self) -> dict[str, object]:
        identities, occurrences, placement_joins, blockers = [], [], [], []
        for name, binding in self.runtime_roles.items():
            identity = selection.identity(name)
            unresolved = [selection.ORDINARY_IMPORT_REASON]
            if name in {"memcpy", "memset"}:
                unresolved.insert(0, "candidate definition placement is not selected: candidate-loader")
            identities.append({
                "identity": identity,
                "selection": {
                    "disposition": "public-provider",
                    "owner": "checked-header-provider-routing",
                },
                "unresolved": unresolved,
            })
            for reason in unresolved:
                blockers.append({
                    "code": "identity-unresolved", "identity": copy.deepcopy(identity), "reason": reason,
                })

            def add(artifact: str, table: str, role: str, member: str | None,
                    member_index: int | None, row: dict[str, object]) -> None:
                index = len(occurrences)
                occurrences.append({
                    "index": index, "artifact_key": artifact, "table": table, "role": role,
                    "member_name": member, "member_index": member_index, "member_occurrence": 0 if member else None,
                    "row": {**row, "row_index": index},
                    "accounting": {
                        "disposition": "public-provider", "owner": "checked-header-provider-routing",
                        "scope": artifact,
                    },
                })

            add("candidate-static", ".symtab", "import", "selected-c-mimalloc.o", 1, {
                "name": name, "raw_name": name, "type": "NOTYPE", "binding": "GLOBAL",
                "visibility": "DEFAULT", "section_index": "UND", "size_bytes": 0,
                "value": "0000000000000000", "version": None, "version_default": False,
            })
            provider = {
                "name": name, "raw_name": name, "type": "FUNC", "binding": binding,
                "visibility": "DEFAULT", "section_index": "7", "size_bytes": 1,
                "value": "0000000000000000", "version": None, "version_default": False,
            }
            add("candidate-static", ".symtab", "definition", "native-c-root.rcgu.o", 0, provider)
            add("candidate-shared", ".dynsym", "definition", None, None, provider)
            add("candidate-shared", ".symtab", "definition", None, None, provider)
            for artifact in ("candidate-static", "candidate-shared"):
                placement_joins.append({
                    "identity": copy.deepcopy(identity), "artifact_key": artifact,
                    "expected_metadata": {
                        "type": "FUNC", "binding": binding, "visibility": "DEFAULT",
                    },
                    "placement_observed": True, "definition_count": 1,
                    "occurrence_indices": [0], "metadata_differences": [{"occurrence_index": 0, "fields": []}],
                })
        return {
            "identities": identities, "occurrences": occurrences,
            "placement_joins": placement_joins, "blockers": blockers,
        }

    def _adapter(self, report: dict[str, object]) -> dict[str, object]:
        with mock.patch.object(
            selection.native_c_allocator_boundary, "validate_report", return_value=report
        ) as replay, mock.patch.object(
            selection.native_c_allocator_boundary,
            "source_resolution",
            return_value=copy.deepcopy(report["inputs"]["source_resolution"]),
        ):
            companion = selection.native_c_allocator_boundary_adapter(
                self.report_path,
                facts=self.facts,
                measurement=self.measurement,
                paths=self.paths,
                source=self.source,
                fixed_c_companion=self.fixed_c_companion,
            )
        replay.assert_called_once_with(
            self.report_path,
            static_preparation=self.preparation,
            static_product=self.static,
            dynamic_product=self.dynamic,
            elf_facts_report=self.elf,
        )
        return companion

    def test_adapter_replays_the_owner_and_binds_current_products_and_producer_account(self) -> None:
        companion = self._adapter(self.boundary_report())
        self.assertEqual(
            companion["status"],
            "native-c-allocator-boundary-observed-with-boundaries",
        )
        self.assertEqual(companion["account"]["imports"], list(self.names))
        self.assertEqual(
            set(companion["products"]),
            {
                "static_manifest", "static_libc", "static_provenance",
                "dynamic_manifest", "dynamic_state", "dynamic_libc",
                "dynamic_shared_provenance",
            },
        )

    def test_selection_source_inputs_bind_the_boundary_reader_contract_and_runtime_sources(self) -> None:
        contract = selection.load_contract()
        inputs = selection.load_source_inputs(contract, selection.CONTRACT_PATH)
        for name in selection.C_ALLOCATOR_BOUNDARY_SOURCE_FILES:
            with self.subTest(name=name):
                self.assertEqual(inputs["bindings"][name], selection.file_identity(ROOT / name))

    def test_adapter_rejects_a_cross_cohort_provenance_substitution(self) -> None:
        report = self.boundary_report()
        report["inputs"]["static"]["provenance"]["sha256"] = "0" * 64
        with mock.patch.object(
            selection.native_c_allocator_boundary, "validate_report", return_value=report
        ), mock.patch.object(
            selection.native_c_allocator_boundary,
            "source_resolution",
            return_value=copy.deepcopy(report["inputs"]["source_resolution"]),
        ), self.assertRaisesRegex(selection.SelectionError, "static_provenance"):
            selection.native_c_allocator_boundary_adapter(
                self.report_path,
                facts=self.facts,
                measurement=self.measurement,
                paths=self.paths,
                source=self.source,
                fixed_c_companion=self.fixed_c_companion,
            )

    def test_adapter_rejects_a_source_resolution_not_reconstructed_from_the_selected_epoch(self) -> None:
        report = self.boundary_report()
        expected = copy.deepcopy(report["inputs"]["source_resolution"])
        report["inputs"]["source_resolution"]["runtime_source_sha256"][
            selection.native_c_allocator_boundary.RUNTIME_SOURCES[0]
        ] = "0" * 64
        with mock.patch.object(
            selection.native_c_allocator_boundary, "validate_report", return_value=report
        ), mock.patch.object(
            selection.native_c_allocator_boundary, "source_resolution", return_value=expected
        ), self.assertRaisesRegex(selection.SelectionError, "source resolution"):
            selection.native_c_allocator_boundary_adapter(
                self.report_path,
                facts=self.facts,
                measurement=self.measurement,
                paths=self.paths,
                source=self.source,
                fixed_c_companion=self.fixed_c_companion,
            )

    def test_exact_seven_static_root_imports_clear_only_their_ordinary_reasons(self) -> None:
        accounting = self.accounting()
        companion = self._adapter(self.boundary_report())
        joins = selection.attach_native_c_allocator_boundary(accounting, companion)
        self.assertEqual([row["identity"]["name"] for row in joins], list(self.names))
        self.assertTrue(all(row["ordinary_import_covered"] for row in joins))
        self.assertFalse(accounting["blockers"])
        self.assertTrue(all(
            selection.ORDINARY_IMPORT_REASON not in row["unresolved"]
            for row in accounting["identities"]
        ))

    def test_exact_c_runtime_imports_clear_only_their_ordinary_reasons(self) -> None:
        accounting = self.runtime_accounting()
        companion = self._adapter(self.boundary_report())
        joins = selection.attach_native_c_allocator_runtime_imports(accounting, companion)
        self.assertEqual([row["identity"]["name"] for row in joins], list(self.runtime_roles))
        self.assertTrue(all(row["ordinary_import_covered"] for row in joins))
        for row in accounting["identities"]:
            self.assertNotIn(selection.ORDINARY_IMPORT_REASON, row["unresolved"])
            if row["identity"]["name"] in {"memcpy", "memset"}:
                self.assertEqual(row["unresolved"], [
                    "candidate definition placement is not selected: candidate-loader",
                ])
            else:
                self.assertEqual(row["unresolved"], [])

    def test_runtime_import_foreign_member_keeps_the_generic_blocker(self) -> None:
        accounting = self.runtime_accounting()
        foreign = copy.deepcopy(accounting["occurrences"][0])
        foreign["index"] = len(accounting["occurrences"])
        foreign["member_name"] = "foreign-c-member.o"
        foreign["member_index"] = 9
        foreign["row"]["row_index"] = foreign["index"]
        accounting["occurrences"].append(foreign)
        joins = selection.attach_native_c_allocator_runtime_imports(
            accounting, self._adapter(self.boundary_report())
        )
        self.assertFalse(joins[0]["ordinary_import_covered"])
        self.assertIn(selection.ORDINARY_IMPORT_REASON, accounting["identities"][0]["unresolved"])

    def test_runtime_import_provider_binding_drift_keeps_the_generic_blocker(self) -> None:
        accounting = self.runtime_accounting()
        static_provider = accounting["occurrences"][1]
        static_provider["row"]["binding"] = "WEAK"
        joins = selection.attach_native_c_allocator_runtime_imports(
            accounting, self._adapter(self.boundary_report())
        )
        self.assertFalse(joins[0]["ordinary_import_covered"])
        self.assertIn(selection.ORDINARY_IMPORT_REASON, accounting["identities"][0]["unresolved"])

    def test_adapter_rejects_a_report_side_c_member_substitution(self) -> None:
        report = self.boundary_report()
        report["inputs"]["c_runtime_import_bindings"]["static_c_member"]["name"] = "forged-member.o"
        with mock.patch.object(
            selection.native_c_allocator_boundary, "validate_report", return_value=report
        ), mock.patch.object(
            selection.native_c_allocator_boundary,
            "source_resolution", return_value=copy.deepcopy(report["inputs"]["source_resolution"]),
        ), self.assertRaisesRegex(selection.SelectionError, "static C member differs"):
            selection.native_c_allocator_boundary_adapter(
                self.report_path,
                facts=self.facts,
                measurement=self.measurement,
                paths=self.paths,
                source=self.source,
                fixed_c_companion=self.fixed_c_companion,
            )

    def test_foreign_same_name_import_keeps_the_generic_blocker(self) -> None:
        accounting = self.accounting()
        foreign = copy.deepcopy(accounting["occurrences"][0])
        foreign["index"] = len(accounting["occurrences"])
        foreign["member_name"] = "foreign.rcgu.o"
        foreign["member_index"] = 8
        foreign["row"]["row_index"] = foreign["index"]
        accounting["occurrences"].append(foreign)
        joins = selection.attach_native_c_allocator_boundary(
            accounting, self._adapter(self.boundary_report())
        )
        self.assertFalse(joins[0]["ordinary_import_covered"])
        record = accounting["identities"][0]
        self.assertIn(selection.ORDINARY_IMPORT_REASON, record["unresolved"])
        self.assertTrue(accounting["blockers"])

    def test_runtime_recheck_rejects_a_product_changed_after_boundary_replay(self) -> None:
        companion = self._adapter(self.boundary_report())
        (self.static / "share/crabc/libc-static.provenance.json").write_bytes(
            b"replaced after boundary replay\n"
        )
        with mock.patch.object(selection, "selection_source", return_value=self.source),              self.assertRaisesRegex(selection.SelectionError, "static_provenance"):
            selection._recheck_runtime_receipt_cohort(
                paths=self.paths,
                facts=self.facts,
                measurement=self.measurement,
                source=self.source,
                registry=None,
                pthread=None,
                c_allocator_boundary=companion,
            )

    def test_public_cli_keeps_the_c_boundary_receipt_independently_optional(self) -> None:
        reconstructed = {
            "identities": [],
            "occurrences": [],
            "closure": {"blockers": [], "complete": False},
        }
        argv = [
            "validate-report", str(self.work / "selection.json"),
            "--measurement-checkout", str(ROOT),
            "--elf-facts", str(self.elf),
            "--base-inventory", str(self.base),
            "--static-product", str(self.static),
            "--dynamic-product", str(self.dynamic),
            "--static-preparation", str(self.preparation),
            "--native-c-allocator-boundary-report", str(self.report_path),
        ]
        with mock.patch.object(selection, "validate_report", return_value=reconstructed) as replay,              contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(selection.main(argv), 0)
        self.assertEqual(
            replay.call_args.kwargs["native_c_allocator_boundary_report"],
            self.report_path,
        )


if __name__ == "__main__":
    unittest.main()
