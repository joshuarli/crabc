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
        "errno_import_resolution": projection,
        "limits": list(selection.C_ALLOCATOR_BOUNDARY_LIMITS),
    }
    return accounting, companion


class ErrnoImportAttachmentTests(unittest.TestCase):
    def test_all_six_callers_bind_one_global_tls_accessor(self) -> None:
        accounting, companion = fixture()
        joins = selection.attach_errno_static_imports(accounting, companion)
        self.assertEqual([join["identity"]["name"] for join in joins], ["__errno_location"])
        self.assertEqual(len(joins[0]["import_occurrence_indices"]), 6)
        self.assertEqual(accounting["blockers"], [])

    def test_foreign_duplicate_or_wrong_tls_and_final_target_rejects(self) -> None:
        for mutation in ("foreign-import", "duplicate-import", "foreign-provider",
                         "weak-provider", "duplicate-provider", "foreign-final-target",
                         "foreign-shared-target", "wrong-tls-offset", "missing-final-call"):
            with self.subTest(mutation=mutation):
                accounting, companion = fixture()
                projection = companion["errno_import_resolution"]
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
                    selection.attach_errno_static_imports(accounting, companion)


if __name__ == "__main__":
    unittest.main()
