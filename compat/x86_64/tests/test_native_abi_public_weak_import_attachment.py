"""Occurrence and final-target joins for the allocator's public weak calls."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_abi_selection as selection
import native_c_allocator_boundary as boundary


def fixture() -> tuple[dict, dict]:
    archive = "/workspace/.work/x86_64/current/usr/lib/libc.a"
    c_member = {"name": "selected-c.o", "member_index": 11, "member_occurrence": 0,
                "sha256": "a" * 64}
    account = {"static_c_member": c_member, "imports": []}
    accounting = {"identities": [], "placement_joins": [], "occurrences": [], "blockers": []}
    claims = []

    def symbol(name: str, kind: str, binding: str, section: str) -> dict:
        return {"name": name, "raw_name": name, "version": None,
                "version_default": False, "type": kind, "binding": binding,
                "visibility": "DEFAULT", "section_index": section,
                "size_bytes": 0 if section == "UND" else 8,
                "value": "0000000000000000" if section == "UND" else "0000000000002000"}

    for index, (name, caller) in enumerate(boundary.PUBLIC_WEAK_IMPORTS.items()):
        key = selection.identity(name)
        rust_member = {"member": f"caller-{index}.o", "member_index": 20 + index,
                       "member_occurrence": 0}
        provider_member = {"member": f"provider-{index}.o", "member_index": 30 + index,
                           "member_occurrence": 0}
        imported = symbol(name, "NOTYPE", "GLOBAL", "UND")
        provider = symbol(name, "FUNC", "WEAK", "5")
        baseline = {"name": name, "binding": "WEAK", "static_c_import": imported,
                    "static_rust_provider_member": provider_member,
                    "static_rust_provider": provider, "shared_dynsym_provider": provider,
                    "shared_symtab_provider": provider}
        account["imports"].append(baseline)
        address = 0x2000 + index * 0x100
        claims.append({"name": name, "caller": caller, "static_c_member": c_member,
                       "static_rust_importer_member": rust_member, "static_rust_import": imported,
                       "static_provider_member": provider_member, "static_provider": provider,
                       "shared_dynsym_provider": provider, "shared_symtab_provider": provider,
                       "source_relocations": {"c": {"section": ".text.c", "offset": 1},
                                              "rust": {"section": f".text.{caller}", "offset": 2}},
                       "static_final_links": {mode: {
                           "provider_address": address, "provider_member": f"{archive}({provider_member['member']})",
                           "c": {"call_address": address - 16, "target_address": address},
                           "rust": {"call_address": address - 32, "got_slot": address + 0x1000,
                                    "target_address": address},
                       } for mode in ("static", "static-pie")},
                       "shared_final_calls": {
                           "c": {"call_address": address - 16, "target_address": address},
                           "rust": {"call_address": address - 32, "got_slot": address + 0x1000,
                                    "target_address": address}},
                       "shared_provider_address": address})
        accounting["identities"].append({
            "identity": key,
            "selection": {"disposition": "public-provider", "owner": "checked-header-provider-routing"},
            "unresolved": [selection.ORDINARY_IMPORT_REASON]})
        accounting["blockers"].append({"code": "identity-unresolved", "identity": key,
                                       "reason": selection.ORDINARY_IMPORT_REASON})
        for local, artifact, table, role, member, row in (
            (0, "candidate-static", ".symtab", "import", c_member, imported),
            (1, "candidate-static", ".symtab", "import", rust_member, imported),
            (2, "candidate-static", ".symtab", "definition", provider_member, provider),
            (3, "candidate-shared", ".dynsym", "definition", None, provider),
            (4, "candidate-shared", ".symtab", "definition", None, provider),
        ):
            number = index * 5 + local
            occurrence = {"index": number, "artifact_key": artifact, "table": table,
                          "role": role, "row": deepcopy(row),
                          "member_name": (member["name"] if "name" in member else member["member"]) if member else None,
                          "member_index": member["member_index"] if member else None,
                          "member_occurrence": member["member_occurrence"] if member else None}
            accounting["occurrences"].append(occurrence)
        for artifact, indices in (("candidate-static", [index * 5 + 2]),
                                  ("candidate-shared", [index * 5 + 3, index * 5 + 4])):
            accounting["placement_joins"].append({
                "identity": key, "artifact_key": artifact, "placement_observed": True,
                "definition_count": 1, "occurrence_indices": indices,
                "metadata_differences": [{"occurrence_index": n, "fields": []} for n in indices],
                "expected_metadata": {"type": "FUNC", "binding": "WEAK", "visibility": "DEFAULT"}})
    companion = {
        "status": "native-c-allocator-boundary-observed-with-boundaries", "reader": {},
        "contract": {}, "report": {}, "source": {}, "source_inputs": {}, "products": {},
        "measurement_reports": {}, "account": {
            "c_runtime_imports": account,
            "c_runtime_static_links": {"static": {"selected_members": {
                "static_c_member": f"{archive}({c_member['name']})"}}}},
        "private_vm_resolution": {},
        "public_weak_resolution": {"imports": claims, "dynamic_final_import_absent": True},
        "limits": list(selection.C_ALLOCATOR_BOUNDARY_LIMITS),
    }
    return accounting, companion


class PublicWeakImportAttachmentTests(unittest.TestCase):
    def test_both_importers_and_weak_provider_discharge_only_their_reasons(self) -> None:
        accounting, companion = fixture()
        joins = selection.attach_native_c_allocator_public_weak_imports(accounting, companion)
        self.assertEqual([join["identity"]["name"] for join in joins],
                         list(boundary.PUBLIC_WEAK_IMPORTS))
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_or_duplicate_importer_or_provider_rejects_join(self) -> None:
        for mutation in ("foreign-c", "foreign-rust", "duplicate-import", "foreign-provider",
                         "duplicate-provider", "foreign-final-target", "foreign-shared-target"):
            with self.subTest(mutation=mutation):
                accounting, companion = fixture()
                if mutation == "foreign-c":
                    accounting["occurrences"][0]["member_name"] = "foreign-c.o"
                elif mutation == "foreign-rust":
                    accounting["occurrences"][1]["member_name"] = "foreign-rust.o"
                elif mutation == "duplicate-import":
                    extra = deepcopy(accounting["occurrences"][1])
                    extra["index"] = 100
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-provider":
                    accounting["occurrences"][2]["member_name"] = "foreign-provider.o"
                elif mutation == "duplicate-provider":
                    extra = deepcopy(accounting["occurrences"][2])
                    extra["index"] = 100
                    accounting["occurrences"].append(extra)
                elif mutation == "foreign-final-target":
                    companion["public_weak_resolution"]["imports"][0]["static_final_links"]["static"]["rust"]["target_address"] += 1
                else:
                    companion["public_weak_resolution"]["imports"][0]["shared_final_calls"]["c"]["target_address"] += 1
                with self.assertRaises(selection.SelectionError):
                    selection.attach_native_c_allocator_public_weak_imports(accounting, companion)


if __name__ == "__main__":
    unittest.main()
