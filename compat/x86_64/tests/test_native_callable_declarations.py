#!/usr/bin/env python3
"""Focused raw-function declaration accounting tests.

The fixture is intentionally a compact already-replayed envelope.  It retains
the same raw FunctionDecl shape used by the public reader while keeping tests
about declaration agreement rather than compiling headers again.
"""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
COMPAT_X86 = ROOT / "compat" / "x86_64"
MODULE_PATH = COMPAT_X86 / "native_callable_declarations.py"
if str(COMPAT_X86) not in sys.path:
    sys.path.insert(0, str(COMPAT_X86))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ADAPTER = load_module("native_callable_declarations_test", MODULE_PATH)


class NativeCallableDeclarationsTests(unittest.TestCase):
    def occurrence(
        self,
        *,
        index: int,
        tree: str,
        name: str,
        input_header: str,
        profile: str,
        declaring_header: str | None = None,
        qual_type: str = "int (int)",
        mangled: str | None = None,
    ) -> dict:
        language = ADAPTER.PROFILE_LANGUAGES[profile]
        return {
            "ast_node_ordinal": index,
            "definition_observation": "extern-declaration-without-initializer",
            "input_header": input_header,
            "kind": "function",
            "linkage_specifier_languages": [] if language == "c" else ["C"],
            "linkage_status": "source-external-declaration",
            "mangled_name_observation": name if mangled is None else mangled,
            "name": name,
            "occurrence_ordinal": index,
            "previous_declaration": {"kind": "none"},
            "profile": profile,
            "raw_ast_path": f"raw/{tree}/{input_header}/{profile}/ast.json",
            "raw_node_id_observation": f"0x{index:x}",
            "source": {
                "column": 1,
                "declaring_header": declaring_header or input_header,
                "include_root": "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root",
                "line": index + 1,
                "offset": index,
                "origin_resolution": "physical",
                "token_length": len(name),
            },
            "source_language": language,
            "storage_class_observation": "extern",
            "tls_observation": None,
            "tree": tree,
            "type": {"qual_type": qual_type, "desugared_qual_type": None},
            "unmodeled_node_keys": [],
        }

    def envelope(self) -> dict:
        occurrences = []
        next_index = 0

        def add(**kwargs):
            nonlocal next_index
            occurrences.append(self.occurrence(index=next_index, **kwargs))
            next_index += 1

        # Two direct C observations retain a multiplicity-sensitive group.
        for tree in ("candidate", "reference"):
            add(tree=tree, name="foo", input_header="demo.h", profile="c11-gnu")
            add(tree=tree, name="foo", input_header="demo.h", profile="c11-gnu")
            add(tree=tree, name="foo", input_header="demo.h", profile="cxx17-gnu")
            add(
                tree=tree,
                name="transitive_fn",
                input_header="outer.h",
                declaring_header="inner.h",
                profile="c11-gnu",
                qual_type="long (long)",
            )
        add(tree="candidate", name="project_fn", input_header="project.h", profile="c11-gnu")
        add(tree="candidate", name="oracle_fn", input_header="aio.h", profile="c11-strict")
        # A reviewed matrix row can contain tgkill plus ordinary matched
        # declarations.  Its row-level exception must not relabel this one.
        for tree in ("candidate", "reference"):
            add(tree=tree, name="ordinary_in_extension", input_header="aio.h", profile="c11-gnu")

        extension = ADAPTER.callable_extension_contract.load_contract().extensions[0]
        for header in extension.visible_from_headers:
            for profile in extension.visible_profiles:
                add(
                    tree="candidate",
                    name=extension.name,
                    input_header=header,
                    declaring_header=extension.header,
                    profile=profile,
                    qual_type=extension.signature,
                    mangled=extension.c_linkage_symbol,
                )
        jobs = self.jobs(occurrences)
        return {
            "current_selecting_source": {"matches_retained": True, "differences": []},
            "report": {
                "collection": {},
                "final_active_macros": [{"name": "alloca", "tree": "candidate", "form": "function-like"}],
                "inputs": {},
                "jobs": jobs,
                "macro_events": [{"name": "alloca", "tree": "candidate", "event": "define"}],
                "occurrences": occurrences,
                "oracle": ADAPTER.ORACLE,
                "platform": "Linux/x86-64 little-endian",
                "schema": ADAPTER.HEADER_REPORT_SCHEMA,
                "scope": {},
                "status": {},
                "summary": {},
                "target": ADAPTER.TARGET,
            },
        }

    def jobs(self, occurrences: list[dict]) -> list[dict]:
        """Give the compact authenticated-envelope seam realistic raw jobs.

        The public inventory reader owns full artifact replay.  This fixture
        retains the exact job fields consumed by the callable adapter so its
        local FunctionDecl-to-job and physical-dependency joins remain
        observable without embedding a full compiler receipt in this unit
        test.
        """
        grouped: dict[tuple[str, str, str], list[dict]] = {}
        for occurrence in occurrences:
            key = (occurrence["tree"], occurrence["input_header"], occurrence["profile"])
            grouped.setdefault(key, []).append(occurrence)
        jobs = []
        for ordinal, ((tree, header, profile), rows) in enumerate(sorted(grouped.items())):
            root = "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
            base = f"raw/{tree}/{header}/{profile}"
            language = ADAPTER.PROFILE_LANGUAGES[profile]
            dependencies = {f"{root}/{header}"}
            dependencies.update(f"{root}/{row['source']['declaring_header']}" for row in rows)
            artifacts = {
                "ast_command": {"path": f"{base}/ast.command.json", "sha256": "a" * 64, "size": 1},
                "ast_stderr": {"path": f"{base}/ast.stderr.txt", "sha256": "b" * 64, "size": 0},
                "ast_stdout": {"path": f"{base}/ast.json", "sha256": "c" * 64, "size": 1},
                "preprocessor_command": {"path": f"{base}/preprocessor.command.json", "sha256": "d" * 64, "size": 1},
                "preprocessor_stderr": {"path": f"{base}/preprocessor.stderr.txt", "sha256": "e" * 64, "size": 0},
                "preprocessor_stdout": {"path": f"{base}/preprocessor.txt", "sha256": "f" * 64, "size": 1},
                "source": {"path": f"{base}/{'probe.cpp' if language == 'cxx' else 'probe.c'}", "sha256": "1" * 64, "size": 1},
                "status": {"path": f"{base}/status.json", "sha256": "2" * 64, "size": 1},
            }
            jobs.append(
                {
                    "artifacts": artifacts,
                    "dependencies": sorted(dependencies),
                    "detail": "fixture raw declaration records",
                    "header": header,
                    "ordinal": ordinal,
                    "probe_original_path_observation": f"/fixture/{base}/probe.c",
                    "profile": profile,
                    "status": "ok",
                    "tree": tree,
                }
            )
        return jobs

    def authenticated_envelope(self, envelope: dict):
        """Seam returned by the independently tested public inventory reader."""
        report = envelope["report"]
        identities = {
            (job["tree"], job["header"], job["profile"])
            for job in report["jobs"]
        }
        return envelope["current_selecting_source"], report, identities

    def matrix_projection(self) -> dict:
        rows = [
            {"header": "demo.h", "profile": "c11-gnu", "comparison": "matched", "reference_status": "ok"},
            {"header": "demo.h", "profile": "cxx17-gnu", "comparison": "matched", "reference_status": "ok"},
            {"header": "outer.h", "profile": "c11-gnu", "comparison": "matched", "reference_status": "ok"},
            {"header": "project.h", "profile": "c11-gnu", "comparison": "candidate-only-reviewed-project-c-abi-extension", "reference_status": "not-in-pinned-inventory"},
            {"header": "aio.h", "profile": "c11-strict", "comparison": "oracle-not-applicable", "reference_status": "oracle-not-applicable"},
        ]
        extension = ADAPTER.callable_extension_contract.load_contract().extensions[0]
        rows.extend(
            {
                "header": header,
                "profile": profile,
                "comparison": "candidate-only-reviewed-native-callable-extension",
                "reference_status": "ok",
            }
            for header in extension.visible_from_headers
            for profile in extension.visible_profiles
        )
        provenance = {
            "report": {"path": "compat/x86_64/generated/header_abi_matrix/report.json", "sha256": "a" * 64, "size": 1, "mode": 0o644},
            "reader": {"path": "compat/x86_64/header_abi_matrix.py", "sha256": "b" * 64, "size": 1, "mode": 0o644},
            "contract": {"path": "compat/x86_64/header_abi_matrix.toml", "sha256": "c" * 64, "size": 1, "mode": 0o644},
            "extension_contract": {"path": "compat/x86_64/header_callable_extension_contract.toml", "sha256": "d" * 64, "size": 1, "mode": 0o644},
        }
        return ADAPTER.matrix_projection_from_checked_report(
            {"schema": ADAPTER.HEADER_MATRIX_REPORT_SCHEMA, "rows": rows}, provenance=provenance
        )

    def partition(self):
        deferred = {}
        for name, resolution in (("alloca", "compiler-builtin"), ("seqbuf_dump", "consumer-supplied")):
            deferred[name] = {
                "id": f"deferred-{name}",
                "linkage_owner_family": "libc.c-abi-compat",
                "linkage_owner_obligation": "final-callable-provider-archive-closure",
                "members": [name],
                "provider_target": "separate owner",
                "resolution": resolution,
                "semantic_family": "libc.headers-layouts",
                "source_oracle": "fixture",
            }
        return {
            "provider_names": ["foo", "oracle_fn", "ordinary_in_extension", "project_fn", "tgkill", "transitive_fn"],
            "deferred": deferred,
            "abi_only_callables": [{"name": "_fini", "owner": "fixture-feature", "state": "declared", "runner": "fixture"}],
        }

    def account(self, envelope=None, matrix_projection=None, *, authenticated=True, **overrides):
        partition = self.partition()
        partition.update(overrides)
        arguments = {
            "matrix_projection": self.matrix_projection() if matrix_projection is None else matrix_projection,
            **partition,
        }
        selected_envelope = self.envelope() if envelope is None else envelope
        # The public inventory reader is independently exercised by its own
        # suite.  Use this compact authenticated seam for local callable
        # joins; tests that pass ``authenticated=False`` exercise the real
        # full-envelope admission below.
        if authenticated:
            with mock.patch.object(
                ADAPTER.data_declarations,
                "_report_envelope",
                side_effect=self.authenticated_envelope,
            ):
                return ADAPTER.account_declarations(selected_envelope, **arguments)
        return ADAPTER.account_declarations(selected_envelope, **arguments)

    def candidate(self, envelope, *, name: str, profile: str | None = None):
        for row in envelope["report"]["occurrences"]:
            if row["tree"] == "candidate" and row["name"] == name and (profile is None or row["profile"] == profile):
                return row
        self.fail(f"no candidate {name}:{profile}")

    def test_accounts_raw_physical_multiplicity_without_linkage_or_provider_claims(self):
        account = self.account()
        self.assertEqual(account["selected_callable_declaration_status"], "proved-with-explicit-boundaries")
        self.assertEqual(account["scope"]["selected_provider_name_count"], 6)
        self.assertEqual(account["scope"]["category_counts"], {
            "candidate-project-extension": 1,
            "oracle-not-applicable": 1,
            "reference-backed": 4,
            "reviewed-native-extension": 28,
        })
        self.assertEqual(account["scope"]["provider_selection"], "not-evaluated")
        self.assertEqual(account["scope"]["semantic_language_linkage"], "not-proved-by-clang-json")
        self.assertEqual(account["scope"]["desugared_qual_type"], "retained-not-normalized-or-compared")
        foo = next(item for item in account["groups"] if item["name"] == "foo" and item["profile"] == "c11-gnu")
        self.assertEqual(
            foo["candidate_signature_multiset"],
            [{"qual_type": "int (int)", "mangled_name_observation": "foo", "count": 2}],
        )
        self.assertEqual(len(foo["candidate_observations"]), 2)
        transitive = next(item for item in account["groups"] if item["name"] == "transitive_fn")
        self.assertEqual(transitive["input_header"], "outer.h")
        self.assertEqual(transitive["candidate_observations"][0]["source"]["declaring_header"], "inner.h")
        ordinary = next(item for item in account["groups"] if item["name"] == "ordinary_in_extension")
        self.assertEqual(ordinary["category"], "reference-backed")
        self.assertEqual(ordinary["matrix_comparison"], "candidate-only-reviewed-native-callable-extension")
        deferred = {item["name"]: item for item in account["deferred"]}
        self.assertEqual(deferred["alloca"]["raw_function_declaration_status"], "not-observed-by-raw-function-inventory")
        self.assertEqual(deferred["alloca"]["macro_or_legacy_fallback_status"], "not-consumed-as-declaration-evidence")
        self.assertEqual(deferred["seqbuf_dump"]["raw_function_declaration_status"], "not-observed-by-raw-function-inventory")
        self.assertEqual(account["abi_only_callables"][0]["header_declaration_status"], "not-consumed-by-callable-declaration-adapter")

    def test_type_spelling_linker_spelling_profile_and_multiplicity_drift_reject(self):
        for mutation, expected in (
            (lambda envelope: envelope["report"]["occurrences"].remove(self.candidate(envelope, name="foo", profile="c11-gnu")), "signature multiset"),
            (lambda envelope: self.candidate(envelope, name="foo", profile="c11-gnu")["type"].__setitem__("qual_type", "long (int)"), "signature multiset"),
            (lambda envelope: self.candidate(envelope, name="foo", profile="cxx17-gnu").__setitem__("mangled_name_observation", "_Z3fooi"), "signature multiset"),
            (lambda envelope: self.candidate(envelope, name="foo", profile="cxx17-gnu").__setitem__("source_language", "c"), "source_language"),
        ):
            with self.subTest(expected=expected):
                envelope = self.envelope()
                mutation(envelope)
                with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, expected):
                    self.account(envelope=envelope)

    def test_selected_raw_function_must_stay_bound_to_its_job_ast_and_physical_dependency(self):
        swapped_job = self.envelope()
        for row in swapped_job["report"]["occurrences"]:
            if row["name"] == "transitive_fn":
                row["input_header"] = "demo.h"
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "raw AST artifact"):
            self.account(envelope=swapped_job)

        forged_source = self.envelope()
        for row in forged_source["report"]["occurrences"]:
            if row["name"] == "transitive_fn":
                row["source"]["declaring_header"] = "forged/inner.h"
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "physical source has no raw job dependency"):
            self.account(envelope=forged_source)

    def test_signature_pair_encoding_cannot_collide(self):
        envelope = self.envelope()
        candidate_seen = False
        reference_seen = False
        for row in envelope["report"]["occurrences"]:
            if row["name"] != "foo" or row["profile"] != "c11-gnu":
                continue
            if row["tree"] == "candidate" and not candidate_seen:
                row["mangled_name_observation"] = "foo|mangled=bar"
                candidate_seen = True
            elif row["tree"] == "reference" and not reference_seen:
                row["type"]["qual_type"] = "int (int)|mangled=foo"
                row["mangled_name_observation"] = "bar"
                reference_seen = True
        self.assertTrue(candidate_seen and reference_seen)
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "signature multiset"):
            self.account(envelope=envelope)

    def test_full_authenticated_envelope_and_source_difference_invariant_are_required(self):
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "declaration inventory scope"):
            self.account(authenticated=False)
        historical_without_difference = self.envelope()
        historical_without_difference["current_selecting_source"] = {
            "matches_retained": False,
            "differences": [],
        }
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "current source match differs"):
            self.account(envelope=historical_without_difference, authenticated=False)

    def test_reviewed_tgkill_requires_exact_visible_roster_and_c_linker_spelling(self):
        wrong_spelling = self.envelope()
        self.candidate(wrong_spelling, name="tgkill", profile="cxx17-gnu")["mangled_name_observation"] = "_Z6tgkilliii"
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "linker spelling"):
            self.account(envelope=wrong_spelling)

        missing = self.envelope()
        missing["report"]["occurrences"].remove(self.candidate(missing, name="tgkill", profile="c11-bsd"))
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "visible raw roster"):
            self.account(envelope=missing)

        hidden = self.envelope()
        row = next(
            item for item in hidden["report"]["occurrences"]
            if item["tree"] == "candidate" and item["name"] == "tgkill"
            and item["profile"] == "c11-gnu" and item["input_header"] == "signal.h"
        )
        row["profile"] = "c11-strict"
        row["source_language"] = "c"
        row["raw_ast_path"] = row["raw_ast_path"].replace("/c11-gnu/", "/c11-strict/")
        for job in hidden["report"]["jobs"]:
            if job["tree"] == "candidate" and job["header"] == row["input_header"] and job["profile"] == "c11-gnu":
                job["profile"] = "c11-strict"
                job["artifacts"]["ast_stdout"]["path"] = row["raw_ast_path"]
                break
        else:
            self.fail("fixture tgkill job is absent")
        projection = self.matrix_projection()
        projection["rows"].append(
            {
                "header": "signal.h",
                "profile": "c11-strict",
                "comparison": "matched",
                "reference_status": "ok",
            }
        )
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "visible raw roster"):
            self.account(envelope=hidden, matrix_projection=projection)

    def test_adapter_never_replays_the_header_reader_or_uses_macro_as_a_function(self):
        with mock.patch.object(ADAPTER.declaration_inventory, "validate_report") as replay:
            account = self.account()
        replay.assert_not_called()
        deferred = {item["name"]: item for item in account["deferred"]}
        self.assertEqual(deferred["alloca"]["candidate_observations"], [])

    def test_historical_source_is_retained_as_incomplete_context(self):
        envelope = self.envelope()
        envelope["current_selecting_source"] = {
            "matches_retained": False,
            "differences": [{"path": "include/demo.h", "kind": "sha256-differs"}],
        }
        account = self.account(envelope=envelope)
        self.assertEqual(account["selected_callable_declaration_status"], "historical-source-drift-with-explicit-boundaries")
        self.assertFalse(account["source_receipt"]["current_selecting_source_matches_retained"])

    def test_projection_partition_and_raw_schema_tampering_fail_closed(self):
        projection = self.matrix_projection()
        projection["provenance"]["reader"]["path"] = "compat/x86_64/forged.py"
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "provenance paths"):
            self.account(matrix_projection=projection)

        projection = self.matrix_projection()
        projection["rows"][0]["comparison"] = "mismatch"
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "comparison is unusable"):
            self.account(matrix_projection=projection)

        partition = self.partition()
        partition["provider_names"].append("foo")
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "provider roster"):
            self.account(**partition)

        envelope = self.envelope()
        del self.candidate(envelope, name="foo")["type"]["desugared_qual_type"]
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "type fields"):
            self.account(envelope=envelope)

    def test_caller_contract_cannot_weaken_reviewed_type_policy(self):
        weakened = ADAPTER.load_contract()
        weakened["policy"]["physical_raw_function_provenance"] = False
        with self.assertRaisesRegex(ADAPTER.NativeCallableDeclarationsError, "supplied callable declaration contract differs"):
            ADAPTER.account_declarations(
                self.envelope(),
                matrix_projection=self.matrix_projection(),
                contract=weakened,
                **self.partition(),
            )


if __name__ == "__main__":
    unittest.main()
