"""Physical occurrence accounting for the six errno accessor importers."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_selection as selection


def fixture() -> tuple[dict, dict]:
    name = "__errno_location"
    ident = selection.identity(name)
    c_member = {"name": "fixed-c.o", "member_index": 15,
                "member_occurrence": 0, "sha256": "a" * 64}
    provider_member = {"member": "errno-provider.o", "member_index": 20,
                       "member_occurrence": 0}
    imported = {"name": name, "type": "NOTYPE", "binding": "GLOBAL",
                "visibility": "DEFAULT", "section_index": "UND",
                "size_bytes": 0, "value": "0000000000000000"}
    static_provider = {"name": name, "type": "FUNC", "binding": "GLOBAL",
                       "visibility": "DEFAULT", "section_index": "5",
                       "size_bytes": 17, "value": "0000000000000000"}
    shared_provider = {**static_provider, "section_index": "9",
                       "value": "0000000000003000"}

    def occurrence(index: int, artifact: str, table: str, role: str,
                   member: dict | None, symbol: dict) -> dict:
        return {
            "index": index, "artifact_key": artifact, "table": table, "role": role,
            "member_name": (member["name"] if "name" in member else member["member"])
                           if member else None,
            "member_index": member["member_index"] if member else None,
            "member_occurrence": member["member_occurrence"] if member else None,
            "row": {**symbol, "raw_name": name, "version": None,
                    "version_default": False},
        }

    importers = []
    rows = []
    static_links = {"static": [], "static-pie": []}
    shared_calls = []
    for index in range(6):
        member = (c_member if index == 5 else {
            "member": f"rust-importer-{index}.o", "member_index": 10 + index,
            "member_occurrence": 0})
        source_call = {"section": f".text.call_{index}", "offset": 1}
        importers.append({
            "member": {"member": member.get("member", member.get("name")),
                       "member_index": member["member_index"], "member_occurrence": 0},
            "import": imported, "member_sha256": "a" * 64,
            "source_calls": [source_call],
            "shared_caller_functions": [f"call_{index}"],
        })
        rows.append(occurrence(index, "candidate-static", ".symtab", "import", member, imported))
        for mode in static_links:
            static_links[mode].append({
                "member": importers[-1]["member"],
                "resolved_calls": [{**source_call, "call_address": 0x1000 + index * 16,
                                    "target_address": 0x2000}],
                "discarded_calls": [],
            })
        shared_calls.append({"member": importers[-1]["member"],
                             "calls": [{"function": f"call_{index}",
                                        "call_address": 0x2800 + index * 16,
                                        "target_address": 0x3000}]})
    rows.extend((
        occurrence(6, "candidate-static", ".symtab", "definition",
                   provider_member, static_provider),
        occurrence(7, "candidate-shared", ".dynsym", "definition",
                   None, shared_provider),
        occurrence(8, "candidate-shared", ".symtab", "definition",
                   None, shared_provider),
    ))
    accounting = {
        "identities": [{"identity": ident, "selection": {
            "disposition": "public-provider", "owner": "checked-header-provider-routing",
            "group": "declared-callable-providers",
        }, "unresolved": [selection.ORDINARY_IMPORT_REASON]}],
        "occurrences": rows,
        "placement_joins": [{
            "identity": ident, "artifact_key": artifact, "placement_observed": True,
            "definition_count": 1, "occurrence_indices": indices,
            "metadata_differences": [{"occurrence_index": value, "fields": []}
                                     for value in indices],
            "expected_metadata": {"type": "FUNC", "binding": "GLOBAL",
                                  "visibility": "DEFAULT"},
        } for artifact, indices in (("candidate-static", [6]),
                                    ("candidate-shared", [7, 8]))],
        "blockers": [{"code": "identity-unresolved", "identity": ident,
                      "reason": selection.ORDINARY_IMPORT_REASON}],
    }
    projection = {
        "static_provider_member": provider_member,
        "static_provider": static_provider,
        "shared_dynsym_provider": shared_provider,
        "shared_symtab_provider": shared_provider,
        "importers": importers,
        "static_final_links": {mode: {
            "provider_member": provider_member, "provider_address": 0x2000,
            "accessor_tls": {"tls_symbol_offset": 0x24,
                             "tls_segment_size": 0x38, "fs_displacement": -0x14},
            "importers": linked,
        } for mode, linked in static_links.items()},
        "shared_final": {"provider_address": 0x3000, "tls_symbol_offset": 0x2a8,
                         "tls_segment_size": 0x2c8, "tls_relocation_slot": 0x4000,
                         "importers": shared_calls},
        "dynamic_final_import_absent": True,
    }
    companion = {
        "status": "native-c-allocator-boundary-observed-with-boundaries",
        "reader": {}, "contract": {}, "report": {}, "source": {},
        "source_inputs": {}, "products": {}, "measurement_reports": {},
        "account": {"c_runtime_imports": {"static_c_member": c_member,
                    "imports": [{"name": name, "binding": "GLOBAL",
                                 "static_rust_provider_member": provider_member,
                                 "static_rust_provider": static_provider,
                                 "shared_dynsym_provider": shared_provider,
                                 "shared_symtab_provider": shared_provider}]}},
        "private_vm_resolution": {}, "public_weak_resolution": {},
        "ordinary_import_resolutions": {name: projection},
        "limits": list(selection.C_ALLOCATOR_BOUNDARY_LIMITS),
    }
    return accounting, companion


class ErrnoImportAttachmentTests(unittest.TestCase):
    def test_all_six_callers_bind_one_global_tls_accessor(self) -> None:
        accounting, companion = fixture()
        joins = selection._attach_ordinary_static_import(accounting, companion, "__errno_location")
        self.assertEqual([join["identity"]["name"] for join in joins], ["__errno_location"])
        self.assertEqual(len(joins[0]["import_occurrence_indices"]), 6)
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_duplicate_or_wrong_tls_and_final_target_rejects(self) -> None:
        for mutation in ("foreign-import", "duplicate-import", "foreign-provider",
                         "weak-provider", "duplicate-provider", "foreign-final-target",
                         "foreign-shared-target", "wrong-tls-offset", "missing-final-call"):
            with self.subTest(mutation=mutation):
                accounting, companion = fixture()
                projection = companion["ordinary_import_resolutions"]["__errno_location"]
                if mutation == "foreign-import":
                    accounting["occurrences"][0]["member_name"] = "foreign.o"
                elif mutation == "duplicate-import":
                    extra = deepcopy(accounting["occurrences"][0])
                    extra["index"] = 100
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-provider":
                    accounting["occurrences"][6]["member_name"] = "foreign.o"
                elif mutation == "weak-provider":
                    accounting["occurrences"][6]["row"]["binding"] = "WEAK"
                elif mutation == "duplicate-provider":
                    extra = deepcopy(accounting["occurrences"][6])
                    extra["index"] = 100
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-final-target":
                    projection["static_final_links"]["static"]["importers"][0][
                        "resolved_calls"][0]["target_address"] += 1
                elif mutation == "foreign-shared-target":
                    projection["shared_final"]["importers"][0]["calls"][0]["target_address"] += 1
                elif mutation == "wrong-tls-offset":
                    projection["static_final_links"]["static-pie"]["accessor_tls"][
                        "fs_displacement"] += 1
                else:
                    projection["static_final_links"]["static"]["importers"][0][
                        "resolved_calls"] = []
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(accounting, companion, "__errno_location")


def abort_fixture() -> tuple[dict, dict]:
    accounting, companion = fixture()
    name = "abort"
    ident = selection.identity(name)
    record = accounting["identities"][0]
    record["identity"] = ident
    accounting["blockers"][0]["identity"] = ident
    accounting["placement_joins"][0]["identity"] = ident
    accounting["placement_joins"][1]["identity"] = ident
    accounting["occurrences"] = [row for row in accounting["occurrences"]
                                 if row["index"] in {0, 5, 6, 7, 8}]
    for row in accounting["occurrences"]:
        row["row"]["name"] = name
        row["row"]["raw_name"] = name
    claim = companion["account"]["c_runtime_imports"]["imports"][0]
    claim["name"] = name
    for field in ("static_rust_provider", "shared_dynsym_provider", "shared_symtab_provider"):
        claim[field]["name"] = name
    projection = companion["ordinary_import_resolutions"].pop("__errno_location")
    companion["ordinary_import_resolutions"][name] = projection
    projection["static_provider"]["name"] = name
    projection["shared_dynsym_provider"]["name"] = name
    projection["shared_symtab_provider"]["name"] = name
    projection["importers"] = [projection["importers"][0], projection["importers"][5]]
    for index, item in enumerate(projection["importers"]):
        item["import"]["name"] = name
        item["source_calls"][0]["kind"] = (
            "R_X86_64_GOTPCREL" if index == 0 else "R_X86_64_PLT32")
    for mode in ("static", "static-pie"):
        link = projection["static_final_links"][mode]
        link.pop("accessor_tls")
        link["importers"] = [link["importers"][0], link["importers"][5]]
        link["importers"][0]["resolved_calls"][0]["got_slot"] = 0x3500
        link["importers"][0]["resolved_calls"][0]["kind"] = "R_X86_64_GOTPCREL"
        link["importers"][1]["resolved_calls"][0]["kind"] = "R_X86_64_PLT32"
    shared = projection["shared_final"]
    for field in ("tls_symbol_offset", "tls_segment_size", "tls_relocation_slot"):
        shared.pop(field)
    shared["importers"] = [shared["importers"][0], shared["importers"][5]]
    return accounting, companion


class OrdinaryAbortImportAttachmentTests(unittest.TestCase):
    def test_two_archive_call_forms_join_unique_provider(self) -> None:
        accounting, companion = abort_fixture()
        joins = selection._attach_ordinary_static_import(accounting, companion, "abort")
        self.assertEqual([join["identity"]["name"] for join in joins], ["abort"])
        self.assertEqual(len(joins[0]["import_occurrence_indices"]), 2)
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_or_duplicate_importer_provider_and_call_reject(self) -> None:
        for mutation in ("foreign-import", "duplicate-import", "weak-provider",
                         "duplicate-provider", "foreign-got-target", "missing-direct-call",
                         "foreign-shared-target"):
            with self.subTest(mutation=mutation):
                accounting, companion = abort_fixture()
                projection = companion["ordinary_import_resolutions"]["abort"]
                if mutation == "foreign-import":
                    accounting["occurrences"][0]["member_name"] = "foreign.o"
                elif mutation == "duplicate-import":
                    extra = deepcopy(accounting["occurrences"][0])
                    extra["index"] = 100
                    accounting["occurrences"].append(extra)
                elif mutation == "weak-provider":
                    accounting["occurrences"][2]["row"]["binding"] = "WEAK"
                elif mutation == "duplicate-provider":
                    extra = deepcopy(accounting["occurrences"][2])
                    extra["index"] = 100
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-got-target":
                    projection["static_final_links"]["static"]["importers"][0][
                        "resolved_calls"][0]["target_address"] += 1
                elif mutation == "missing-direct-call":
                    projection["static_final_links"]["static-pie"]["importers"][1][
                        "resolved_calls"] = []
                else:
                    projection["shared_final"]["importers"][1]["calls"][0][
                        "target_address"] += 1
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(accounting, companion, "abort")


class OrdinarySingleCImportAttachmentTests(unittest.TestCase):
    def test_selected_c_call_requires_all_three_final_provider_targets(self) -> None:
        accounting, companion = abort_fixture()
        name = "getrusage"
        ident = selection.identity(name)
        accounting["identities"][0]["identity"] = ident
        accounting["blockers"][0]["identity"] = ident
        for placement in accounting["placement_joins"]:
            placement["identity"] = ident
            placement["occurrence_indices"] = [index for index in placement["occurrence_indices"]
                                               if index != 0]
        accounting["occurrences"] = [row for row in accounting["occurrences"]
                                     if row["index"] != 0]
        for row in accounting["occurrences"]:
            row["row"]["name"] = name
            row["row"]["raw_name"] = name
        claim = companion["account"]["c_runtime_imports"]["imports"][0]
        claim["name"] = name
        for field in ("static_rust_provider", "shared_dynsym_provider", "shared_symtab_provider"):
            claim[field]["name"] = name
        projection = companion["ordinary_import_resolutions"].pop("abort")
        companion["ordinary_import_resolutions"][name] = projection
        for field in ("static_provider", "shared_dynsym_provider", "shared_symtab_provider"):
            projection[field]["name"] = name
        projection["importers"] = projection["importers"][1:]
        projection["importers"][0]["import"]["name"] = name
        for link in projection["static_final_links"].values():
            link["importers"] = link["importers"][1:]
        projection["shared_final"]["importers"] = projection["shared_final"]["importers"][1:]

        joins = selection._attach_ordinary_static_import(accounting, companion, name)
        self.assertEqual([join["identity"]["name"] for join in joins], [name])
        self.assertEqual(accounting["blockers"], [])
        for mode in ("static", "static-pie", "shared"):
            with self.subTest(mode=mode):
                mutated_accounting = deepcopy(accounting)
                mutated_accounting["identities"][0]["unresolved"] = [selection.ORDINARY_IMPORT_REASON]
                mutated_accounting["blockers"] = [{"code": "identity-unresolved", "identity": ident,
                                                   "reason": selection.ORDINARY_IMPORT_REASON}]
                mutated = deepcopy(companion)
                calls = (mutated["ordinary_import_resolutions"][name]["shared_final"]["importers"][0]["calls"]
                         if mode == "shared" else mutated["ordinary_import_resolutions"][name]
                         ["static_final_links"][mode]["importers"][0]["resolved_calls"])
                calls[0]["target_address"] += 1
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(mutated_accounting, mutated, name)


class OrdinaryOwnedAioImportAttachmentTests(unittest.TestCase):
    def test_two_rust_callers_require_selected_final_targets(self) -> None:
        accounting, companion = abort_fixture()
        name = "aio_suspend"
        ident = selection.identity(name)
        accounting["identities"][0]["identity"] = ident
        accounting["blockers"][0]["identity"] = ident
        for placement in accounting["placement_joins"]:
            placement["identity"] = ident
        for row in accounting["occurrences"]:
            row["row"]["name"] = name
            row["row"]["raw_name"] = name
        rust_member = {"member": "second-rust-caller.o", "member_index": 25,
                       "member_occurrence": 0}
        accounting["occurrences"][1]["member_name"] = rust_member["member"]
        accounting["occurrences"][1]["member_index"] = rust_member["member_index"]
        projection = companion["ordinary_import_resolutions"].pop("abort")
        projection["dynamic_final_import_absent"] = False
        projection["dynamic_final_owned_imports"] = [
            {"mode": mode, "import_rows": 2,
             "shared_provider_address": projection["shared_final"]["provider_address"]}
            for mode in ("pie", "non-pie")]
        for field in ("static_provider", "shared_dynsym_provider", "shared_symtab_provider"):
            projection[field]["name"] = name
        for item in projection["importers"]:
            item["import"]["name"] = name
        projection["importers"][1]["member"] = rust_member
        projection["importers"][1]["source_calls"][0]["kind"] = "R_X86_64_GOTPCREL"
        for link in projection["static_final_links"].values():
            link["importers"][1]["member"] = rust_member
            link["importers"][1]["resolved_calls"][0]["got_slot"] = 0x3500
            link["importers"][1]["resolved_calls"][0]["kind"] = "R_X86_64_GOTPCREL"
        projection["shared_final"]["importers"][1]["member"] = rust_member

        joins = selection._attach_ordinary_static_import(
            accounting, companion, name, projection_override=projection)
        self.assertEqual([join["identity"]["name"] for join in joins], [name])
        self.assertEqual(accounting["blockers"], [])
        for mutation in ("missing-static", "foreign-pie", "foreign-shared",
                         "foreign-dynamic", "duplicate-importer"):
            with self.subTest(mutation=mutation):
                changed_accounting, changed = deepcopy(accounting), deepcopy(projection)
                changed_accounting["identities"][0]["unresolved"] = [selection.ORDINARY_IMPORT_REASON]
                changed_accounting["blockers"] = [{"code": "identity-unresolved", "identity": ident,
                                                   "reason": selection.ORDINARY_IMPORT_REASON}]
                if mutation == "missing-static":
                    changed["static_final_links"]["static"]["importers"][0]["resolved_calls"] = []
                elif mutation == "foreign-pie":
                    changed["static_final_links"]["static-pie"]["importers"][1][
                        "resolved_calls"][0]["target_address"] += 1
                elif mutation == "foreign-shared":
                    changed["shared_final"]["importers"][0]["calls"][0]["target_address"] += 1
                elif mutation == "foreign-dynamic":
                    changed["dynamic_final_owned_imports"][0]["shared_provider_address"] += 1
                else:
                    extra = deepcopy(changed_accounting["occurrences"][0])
                    extra["index"] = 100
                    changed_accounting["occurrences"].append(extra)
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(
                        changed_accounting, companion, name, projection_override=changed)


class OrdinaryOwnedAioCancelImportAttachmentTests(unittest.TestCase):
    def test_selected_caller_and_discarded_archive_relocation_stay_distinct(self) -> None:
        accounting, companion = abort_fixture()
        name = "aio_cancel"
        ident = selection.identity(name)
        accounting["identities"][0]["identity"] = ident
        accounting["blockers"][0]["identity"] = ident
        for placement in accounting["placement_joins"]:
            placement["identity"] = ident
        for row in accounting["occurrences"]:
            row["row"]["name"] = name
            row["row"]["raw_name"] = name
        second = {"member": "another-rust-caller.o", "member_index": 25,
                  "member_occurrence": 0}
        accounting["occurrences"][1]["member_name"] = second["member"]
        accounting["occurrences"][1]["member_index"] = second["member_index"]
        projection = companion["ordinary_import_resolutions"].pop("abort")
        for field in ("static_provider", "shared_dynsym_provider", "shared_symtab_provider"):
            projection[field]["name"] = name
        for item in projection["importers"]:
            item["import"]["name"] = name
        projection["importers"][1]["member"] = second
        projection["importers"][1]["source_calls"][0]["kind"] = "R_X86_64_GOTPCREL"
        for link in projection["static_final_links"].values():
            link["importers"][1]["member"] = second
            link["importers"][1]["resolved_calls"] = []
            link["importers"][1]["discarded_calls"] = deepcopy(
                projection["importers"][1]["source_calls"])
        shared = projection["shared_final"]
        shared["importers"][1]["member"] = second
        shared["importers"][1]["calls"] = []
        shared["importers"][0]["no_call_source_functions"] = []
        shared["importers"][1]["no_call_source_functions"] = ["call_5"]
        shared["importers"][0]["calls"][0].update(
            {"got_slot": 0x3500, "branch_kind": "indirect-call"})
        shared["provider_calls"] = deepcopy(shared["importers"][0]["calls"])
        projection["dynamic_final_import_absent"] = False
        projection["dynamic_final_owned_imports"] = [
            {"mode": mode, "import_rows": 2,
             "shared_provider_address": shared["provider_address"]}
            for mode in ("pie", "non-pie")]

        joins = selection._attach_ordinary_static_import(
            accounting, companion, name, projection_override=projection)
        self.assertEqual([join["identity"]["name"] for join in joins], [name])
        self.assertEqual(accounting["blockers"], [])
        for mutation in ("missing-retained-call", "foreign-pie-target",
                         "changed-discarded-source", "foreign-shared-target",
                         "duplicate-importer", "foreign-dynamic-target"):
            with self.subTest(mutation=mutation):
                changed_accounting, changed = deepcopy(accounting), deepcopy(projection)
                changed_accounting["identities"][0]["unresolved"] = [selection.ORDINARY_IMPORT_REASON]
                changed_accounting["blockers"] = [{"code": "identity-unresolved", "identity": ident,
                                                   "reason": selection.ORDINARY_IMPORT_REASON}]
                if mutation == "missing-retained-call":
                    changed["static_final_links"]["static"]["importers"][0]["resolved_calls"] = []
                elif mutation == "foreign-pie-target":
                    changed["static_final_links"]["static-pie"]["importers"][0][
                        "resolved_calls"][0]["target_address"] += 1
                elif mutation == "changed-discarded-source":
                    changed["static_final_links"]["static"]["importers"][1][
                        "discarded_calls"][0]["offset"] += 1
                elif mutation == "foreign-shared-target":
                    changed["shared_final"]["provider_calls"][0]["target_address"] += 1
                elif mutation == "duplicate-importer":
                    duplicate = deepcopy(changed_accounting["occurrences"][0])
                    duplicate["index"] = 100
                    changed_accounting["occurrences"].append(duplicate)
                else:
                    changed["dynamic_final_owned_imports"][0]["shared_provider_address"] += 1
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(
                        changed_accounting, companion, name, projection_override=changed)
def fputs_fixture() -> tuple[dict, dict]:
    accounting, companion = abort_fixture()
    name = "fputs"
    ident = selection.identity(name)
    accounting["identities"][0]["identity"] = ident
    accounting["blockers"][0]["identity"] = ident
    for placement in accounting["placement_joins"]:
        placement["identity"] = ident
    for row in accounting["occurrences"]:
        row["row"]["name"] = name
        row["row"]["raw_name"] = name
    claim = companion["account"]["c_runtime_imports"]["imports"][0]
    claim["name"] = name
    for field in ("static_rust_provider", "shared_dynsym_provider", "shared_symtab_provider"):
        claim[field]["name"] = name
    projection = companion["ordinary_import_resolutions"].pop("abort")
    companion["ordinary_import_resolutions"][name] = projection
    for item in projection["importers"]:
        item["import"]["name"] = name
    for mode in ("static", "static-pie"):
        projection["static_final_links"][mode]["importers"][1][
            "resolved_calls"][0]["branch_kind"] = "tail-jump"
    projection["shared_final"]["importers"][1]["calls"][0][
        "branch_kind"] = "tail-jump"
    return accounting, companion


class OrdinaryFputsImportAttachmentTests(unittest.TestCase):
    def test_got_call_and_c_tail_branch_join_one_provider(self) -> None:
        accounting, companion = fputs_fixture()
        joins = selection._attach_ordinary_static_import(accounting, companion, "fputs")
        self.assertEqual([join["identity"]["name"] for join in joins], ["fputs"])
        self.assertEqual(len(joins[0]["import_occurrence_indices"]), 2)
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_or_duplicate_importer_provider_and_branch_reject(self) -> None:
        for mutation in ("foreign-import", "duplicate-import", "weak-provider",
                         "duplicate-provider", "foreign-tail-target", "missing-rust-got-call",
                         "foreign-shared-target"):
            with self.subTest(mutation=mutation):
                accounting, companion = fputs_fixture()
                projection = companion["ordinary_import_resolutions"]["fputs"]
                if mutation == "foreign-import":
                    accounting["occurrences"][0]["member_name"] = "foreign.o"
                elif mutation == "duplicate-import":
                    extra = deepcopy(accounting["occurrences"][0])
                    extra["index"] = 101
                    accounting["occurrences"].append(extra)
                elif mutation == "weak-provider":
                    accounting["occurrences"][2]["row"]["binding"] = "WEAK"
                elif mutation == "duplicate-provider":
                    extra = deepcopy(accounting["occurrences"][2])
                    extra["index"] = 101
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-tail-target":
                    projection["static_final_links"]["static"]["importers"][1][
                        "resolved_calls"][0]["target_address"] += 1
                elif mutation == "missing-rust-got-call":
                    projection["static_final_links"]["static-pie"]["importers"][0][
                        "resolved_calls"] = []
                else:
                    projection["shared_final"]["importers"][1]["calls"][0][
                        "target_address"] += 1
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(accounting, companion, "fputs")


def getenv_fixture() -> tuple[dict, dict]:
    accounting, companion = fputs_fixture()
    name = "getenv"
    ident = selection.identity(name)
    accounting["identities"][0]["identity"] = ident
    accounting["blockers"][0]["identity"] = ident
    for placement in accounting["placement_joins"]:
        placement["identity"] = ident
    for row in accounting["occurrences"]:
        row["row"]["name"] = name
        row["row"]["raw_name"] = name
    claim = companion["account"]["c_runtime_imports"]["imports"][0]
    claim["name"] = name
    for field in ("static_rust_provider", "shared_dynsym_provider", "shared_symtab_provider"):
        claim[field]["name"] = name
    projection = companion["ordinary_import_resolutions"].pop("fputs")
    companion["ordinary_import_resolutions"][name] = projection
    for item in projection["importers"]:
        item["import"]["name"] = name
    return accounting, companion


class OrdinaryGetenvImportAttachmentTests(unittest.TestCase):
    def test_archive_caller_and_final_provider_join(self) -> None:
        accounting, companion = getenv_fixture()
        name = "getenv"
        joins = selection._attach_ordinary_static_import(accounting, companion, name)
        self.assertEqual([join["identity"]["name"] for join in joins], [name])
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_or_duplicate_caller_provider_and_target_reject(self) -> None:
        for mutation in ("foreign-import", "duplicate-import", "weak-provider",
                         "duplicate-provider", "foreign-static-target", "foreign-shared-target"):
            with self.subTest(mutation=mutation):
                accounting, companion = getenv_fixture()
                projection = companion["ordinary_import_resolutions"]["getenv"]
                if mutation == "foreign-import":
                    accounting["occurrences"][0]["member_name"] = "foreign.o"
                elif mutation == "duplicate-import":
                    extra = deepcopy(accounting["occurrences"][0])
                    extra["index"] = 101
                    accounting["occurrences"].append(extra)
                elif mutation == "weak-provider":
                    accounting["occurrences"][2]["row"]["binding"] = "WEAK"
                elif mutation == "duplicate-provider":
                    extra = deepcopy(accounting["occurrences"][2])
                    extra["index"] = 101
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-static-target":
                    projection["static_final_links"]["static-pie"]["importers"][0][
                        "resolved_calls"][0]["target_address"] += 1
                else:
                    projection["shared_final"]["importers"][1]["calls"][0][
                        "target_address"] += 1
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(accounting, companion, "getenv")


def owned_scan_mbrtowc_fixture(name: str = "mbrtowc") -> tuple[dict, dict, dict]:
    accounting, companion = abort_fixture()
    ident = selection.identity(name)
    accounting["identities"][0]["identity"] = ident
    accounting["blockers"][0]["identity"] = ident
    for placement in accounting["placement_joins"]:
        placement["identity"] = ident
    projection = companion["ordinary_import_resolutions"]["abort"]
    c_member = companion["account"]["c_runtime_imports"]["static_c_member"]
    scan_item = next(item for item in projection["importers"]
                     if item["member"]["member_index"] != c_member["member_index"])
    scan_item["import"]["name"] = name
    scan_item["source_calls"][0].update({
        "section": ".text.crabc_owned_scan_vfscanf", "kind": "R_X86_64_PLT32"})
    scan_item["shared_caller_functions"] = ["crabc_owned_scan_vfscanf"]
    projection["importers"] = [scan_item]
    for field in ("static_provider", "shared_dynsym_provider", "shared_symtab_provider"):
        projection[field]["name"] = name
    for mode in ("static", "static-pie"):
        link = projection["static_final_links"][mode]
        linked = next(item for item in link["importers"]
                      if item["member"]["member_index"] == scan_item["member"]["member_index"])
        linked["resolved_calls"][0].update({
            "section": ".text.crabc_owned_scan_vfscanf", "kind": "R_X86_64_PLT32"})
        linked["resolved_calls"][0].pop("got_slot", None)
        link["importers"] = [linked]
    shared = projection["shared_final"]
    shared["importers"] = [next(item for item in shared["importers"]
                                if item["member"]["member_index"] == scan_item["member"]["member_index"])]
    accounting["occurrences"] = [row for row in accounting["occurrences"]
                                 if row["role"] != "import"
                                 or row["member_index"] == scan_item["member"]["member_index"]]
    for row in accounting["occurrences"]:
        row["row"]["name"] = name
        row["row"]["raw_name"] = name
    return accounting, companion, projection


class OwnedScanMbrtowcImportAttachmentTests(unittest.TestCase):
    def test_selected_scan_import_and_unique_provider_join(self) -> None:
        accounting, companion, projection = owned_scan_mbrtowc_fixture()
        joins = selection._attach_ordinary_static_import(
            accounting, companion, "mbrtowc", projection_override=projection)
        self.assertEqual([join["identity"]["name"] for join in joins], ["mbrtowc"])
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_duplicate_or_wrong_final_target_rejects(self) -> None:
        for mutation in ("foreign-import", "duplicate-import", "weak-provider",
                         "duplicate-provider", "foreign-static-call", "foreign-shared-call"):
            with self.subTest(mutation=mutation):
                accounting, companion, projection = owned_scan_mbrtowc_fixture()
                if mutation == "foreign-import":
                    next(row for row in accounting["occurrences"] if row["role"] == "import")[
                        "member_name"] = "foreign.o"
                elif mutation == "duplicate-import":
                    extra = deepcopy(next(row for row in accounting["occurrences"]
                                          if row["role"] == "import"))
                    extra["index"] = 103
                    accounting["occurrences"].append(extra)
                elif mutation == "weak-provider":
                    next(row for row in accounting["occurrences"] if row["role"] == "definition")[
                        "row"]["binding"] = "WEAK"
                elif mutation == "duplicate-provider":
                    extra = deepcopy(next(row for row in accounting["occurrences"]
                                          if row["role"] == "definition"))
                    extra["index"] = 103
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-static-call":
                    projection["static_final_links"]["static-pie"]["importers"][0][
                        "resolved_calls"][0]["target_address"] += 1
                else:
                    projection["shared_final"]["importers"][0]["calls"][0][
                        "target_address"] += 1
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(
                        accounting, companion, "mbrtowc", projection_override=projection)


class OwnedScanMbsinitImportAttachmentTests(unittest.TestCase):
    def test_retained_scan_call_binds_unique_owned_provider(self) -> None:
        accounting, companion, projection = owned_scan_mbrtowc_fixture("mbsinit")
        joins = selection._attach_ordinary_static_import(
            accounting, companion, "mbsinit", projection_override=projection)
        self.assertEqual([join["identity"]["name"] for join in joins], ["mbsinit"])
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_or_duplicate_source_and_final_target_rejects(self) -> None:
        for mutation in ("foreign-import", "duplicate-import", "weak-provider",
                         "duplicate-provider", "foreign-static-call", "foreign-shared-call"):
            with self.subTest(mutation=mutation):
                accounting, companion, projection = owned_scan_mbrtowc_fixture("mbsinit")
                if mutation == "foreign-import":
                    next(row for row in accounting["occurrences"] if row["role"] == "import")[
                        "member_name"] = "foreign.o"
                elif mutation == "duplicate-import":
                    extra = deepcopy(next(row for row in accounting["occurrences"]
                                      if row["role"] == "import"))
                    extra["index"] = 103
                    accounting["occurrences"].append(extra)
                elif mutation == "weak-provider":
                    next(row for row in accounting["occurrences"] if row["role"] == "definition")[
                        "row"]["binding"] = "WEAK"
                elif mutation == "duplicate-provider":
                    extra = deepcopy(next(row for row in accounting["occurrences"]
                                      if row["role"] == "definition"))
                    extra["index"] = 103
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-static-call":
                    projection["static_final_links"]["static-pie"]["importers"][0][
                        "resolved_calls"][0]["target_address"] += 1
                else:
                    projection["shared_final"]["importers"][0]["calls"][0][
                        "target_address"] += 1
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(
                        accounting, companion, "mbsinit", projection_override=projection)


def owned_scan_two_call_fixture() -> tuple[dict, dict, dict]:
    accounting, companion, projection = owned_scan_mbrtowc_fixture("fmodl")
    importer = projection["importers"][0]
    first = importer["source_calls"][0]
    first["section"] = ".text.crabc_owned_scan_decfloat"
    second = deepcopy(first)
    second["offset"] += 16
    importer["source_calls"].append(second)
    importer["shared_caller_functions"] = ["crabc_owned_scan_decfloat"]
    for link in projection["static_final_links"].values():
        first_call = link["importers"][0]["resolved_calls"][0]
        first_call["section"] = first["section"]
        second_call = deepcopy(first_call)
        second_call["offset"] = second["offset"]
        second_call["call_address"] += 16
        link["importers"][0]["resolved_calls"].append(second_call)
    shared_calls = projection["shared_final"]["importers"][0]["calls"]
    shared_calls[0]["function"] = "crabc_owned_scan_decfloat"
    shared_calls[0]["source_function"] = "crabc_owned_scan_decfloat"
    second_shared = deepcopy(shared_calls[0])
    second_shared["call_address"] += 16
    shared_calls.append(second_shared)
    return accounting, companion, projection


class OwnedScanTwoCallImportAttachmentTests(unittest.TestCase):
    def test_both_retained_calls_bind_one_owned_provider(self) -> None:
        accounting, companion, projection = owned_scan_two_call_fixture()
        joins = selection._attach_ordinary_static_import(
            accounting, companion, "fmodl", projection_override=projection)
        self.assertEqual([join["identity"]["name"] for join in joins], ["fmodl"])
        self.assertEqual(accounting["blockers"], [])

    def test_missing_discarded_duplicate_or_foreign_call_rejects(self) -> None:
        for mutation in ("missing-static", "discarded-static", "duplicate-static",
                         "foreign-static", "missing-shared", "duplicate-shared",
                         "foreign-shared", "foreign-importer", "duplicate-importer",
                         "weak-provider", "duplicate-provider"):
            with self.subTest(mutation=mutation):
                accounting, companion, projection = owned_scan_two_call_fixture()
                static = projection["static_final_links"]["static-pie"]["importers"][0]
                shared = projection["shared_final"]["importers"][0]["calls"]
                if mutation == "missing-static":
                    static["resolved_calls"].pop()
                elif mutation == "discarded-static":
                    static["discarded_calls"].append(static["resolved_calls"].pop())
                elif mutation == "duplicate-static":
                    static["resolved_calls"][1]["call_address"] = static["resolved_calls"][0]["call_address"]
                elif mutation == "foreign-static":
                    static["resolved_calls"][1]["target_address"] += 1
                elif mutation == "missing-shared":
                    shared.pop()
                elif mutation == "duplicate-shared":
                    shared[1]["call_address"] = shared[0]["call_address"]
                elif mutation == "foreign-shared":
                    shared[1]["target_address"] += 1
                elif mutation == "foreign-importer":
                    next(row for row in accounting["occurrences"] if row["role"] == "import")[
                        "member_name"] = "foreign.o"
                elif mutation == "duplicate-importer":
                    extra = deepcopy(next(row for row in accounting["occurrences"]
                                      if row["role"] == "import"))
                    extra["index"] = 103
                    accounting["occurrences"].append(extra)
                elif mutation == "weak-provider":
                    next(row for row in accounting["occurrences"] if row["role"] == "definition")[
                        "row"]["binding"] = "WEAK"
                else:
                    extra = deepcopy(next(row for row in accounting["occurrences"]
                                      if row["role"] == "definition"))
                    extra["index"] = 103
                    accounting["occurrences"].append(extra)
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(
                        accounting, companion, "fmodl", projection_override=projection)


def owned_syslog_close_fixture() -> tuple[dict, dict, dict]:
    accounting, companion, projection = owned_scan_mbrtowc_fixture()
    name = "close"
    ident = selection.identity(name)
    accounting["identities"][0]["identity"] = ident
    accounting["blockers"][0]["identity"] = ident
    for placement in accounting["placement_joins"]:
        placement["identity"] = ident
    for row in accounting["occurrences"]:
        row["row"]["name"] = name
        row["row"]["raw_name"] = name
    importer = projection["importers"][0]
    importer["import"]["name"] = name
    importer["source_calls"][0]["kind"] = "R_X86_64_GOTPCREL"
    source_function = importer["shared_caller_functions"][0]
    for field in ("static_provider", "shared_dynsym_provider", "shared_symtab_provider"):
        projection[field]["name"] = name
    for mode in ("static", "static-pie"):
        call = projection["static_final_links"][mode]["importers"][0]["resolved_calls"][0]
        call["kind"] = "R_X86_64_GOTPCREL"
        call["got_slot"] = 0x4000
    shared = projection["shared_final"]
    source_call = shared["importers"][0]["calls"][0]
    source_call.update(function="inlined_owned_caller", source_function=source_function, got_slot=0x5000,
                       branch_kind="indirect-call")
    shared["importers"][0]["no_call_source_functions"] = []
    other_owned = {"function": "other_owned_caller", "call_address": 0x6000,
                   "got_slot": 0x5000, "target_address": shared["provider_address"],
                   "branch_kind": "indirect-call"}
    shared["provider_calls"] = [source_call, other_owned]
    projection["dynamic_final_import_absent"] = False
    projection["dynamic_final_owned_imports"] = [
        {"mode": mode, "import_rows": 2,
         "shared_provider_address": shared["provider_address"]}
        for mode in ("pie", "non-pie")]
    return accounting, companion, projection


class OwnedSyslogCloseImportAttachmentTests(unittest.TestCase):
    def test_one_source_importer_joins_selected_static_and_shared_provider(self) -> None:
        accounting, companion, projection = owned_syslog_close_fixture()
        joins = selection._attach_ordinary_static_import(
            accounting, companion, "close", projection_override=projection)
        self.assertEqual([join["identity"]["name"] for join in joins], ["close"])
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_or_missing_source_and_final_calls_reject(self) -> None:
        for mutation in ("foreign-import", "duplicate-import", "weak-provider",
                         "missing-static-call", "foreign-static-target",
                         "missing-shared-call", "foreign-shared-target",
                         "duplicate-shared-call", "foreign-shared-source"):
            with self.subTest(mutation=mutation):
                accounting, companion, projection = owned_syslog_close_fixture()
                if mutation == "foreign-import":
                    next(row for row in accounting["occurrences"] if row["role"] == "import")[
                        "member_name"] = "foreign.o"
                elif mutation == "duplicate-import":
                    extra = deepcopy(next(row for row in accounting["occurrences"]
                                          if row["role"] == "import"))
                    extra["index"] = 103
                    accounting["occurrences"].append(extra)
                elif mutation == "weak-provider":
                    next(row for row in accounting["occurrences"] if row["role"] == "definition")[
                        "row"]["binding"] = "WEAK"
                elif mutation == "missing-static-call":
                    projection["static_final_links"]["static"]["importers"][0]["resolved_calls"].clear()
                elif mutation == "foreign-static-target":
                    projection["static_final_links"]["static-pie"]["importers"][0][
                        "resolved_calls"][0]["target_address"] += 1
                elif mutation == "missing-shared-call":
                    projection["shared_final"]["importers"][0]["calls"].clear()
                elif mutation == "foreign-shared-target":
                    projection["shared_final"]["provider_calls"][1]["target_address"] += 1
                elif mutation == "duplicate-shared-call":
                    projection["shared_final"]["provider_calls"].append(deepcopy(
                        projection["shared_final"]["provider_calls"][1]))
                else:
                    projection["shared_final"]["importers"][0]["calls"][0][
                        "source_function"] = "foreign_source"
                with self.assertRaises(selection.SelectionError):
                    selection._attach_ordinary_static_import(
                        accounting, companion, "close", projection_override=projection)


if __name__ == "__main__":
    unittest.main()
