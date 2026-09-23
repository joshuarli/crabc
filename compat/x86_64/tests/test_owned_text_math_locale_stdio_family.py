"""Contract checks for the immutable text/math/locale/stdio family coordinator."""

from __future__ import annotations

import copy
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))

import owned_text_math_locale_stdio_family as coordinator


SOURCE = {"revision": "a" * 40, "content_sha256": "b" * 64}


class FamilyFixture:
    """Physical declared inputs with only the behavior-owner boundary mocked.

    The coordinator must snapshot these evidence and product roots itself. The
    public component semantics belong to their individual readers, so the tests
    substitute only normalized reader results while retaining the coordinator's
    actual path, product, and mutation checks.
    """

    def __init__(self) -> None:
        scratch = ROOT / ".work/x86_64/test-owned-text-math-locale-stdio-family"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.root = Path(self.temporary.name) / "checkout"
        self.root.mkdir()
        self.roster = self.root / "compat/x86_64/text-math-locale-stdio-family.toml"
        self.roster.parent.mkdir(parents=True)
        self.roster.write_text(
            (ROOT / "compat/x86_64/text-math-locale-stdio-family.toml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        for specification in coordinator.COMPONENTS.values():
            reader = self.root / specification.reader
            reader.parent.mkdir(parents=True, exist_ok=True)
            reader.write_text("# fixture public reader\n", encoding="utf-8")
        self.matrix_path = self.write(".work/family/execution.json", "{}\n")
        self.pthread_path = self.write(".work/pthread/receipt.json", "{}\n")
        self.static_preparation = self.write(".work/static/preparation.json", "{}\n")
        self.dynamic_qualification = self.write(".work/dynamic/qualification.json", "{}\n")
        self.matrix_request = self.write(".work/family/request.json", json.dumps({
            "schema": coordinator.family.SCHEMA,
            "source_mount": str(self.root),
            "static_preparation": self.relative(self.static_preparation),
            "dynamic_qualification": self.relative(self.dynamic_qualification),
        }) + "\n")
        self.products: dict[str, dict[str, Path]] = {}
        for pair in coordinator.PAIRS:
            static = self.root / ".work/products" / pair / "static"
            dynamic = self.root / ".work/products" / pair / "dynamic"
            for product in (static, dynamic):
                product.mkdir(parents=True)
                (product / "payload").write_text(pair + "\n", encoding="utf-8")
            self.products[pair] = {"static": static, "dynamic": dynamic}
        self.reports: dict[str, dict[str, Path]] = {}
        self.aggregate_receipts: dict[str, Path] = {}
        self.aggregate_pair_roots: dict[str, Path] = {}
        self.aggregate_pair_reports: dict[str, Path] = {}
        self.aggregate_pair_payloads: dict[str, Path] = {}
        self.expected_inputs: dict[str, Path] = {}
        for component, specification in coordinator.COMPONENTS.items():
            if specification.request_kind == "aggregate":
                for pair in coordinator.PAIRS:
                    root = self.root / f".work/{component}-pair-evidence" / pair
                    root.mkdir(parents=True)
                    report = self.write(
                        f".work/{component}-pair-evidence/{pair}/report.json", component + ":" + pair + "\n",
                    )
                    payload = self.write(
                        f".work/{component}-pair-evidence/{pair}/retained/nested-payload", pair + "\n",
                    )
                    self.aggregate_pair_roots[pair] = root
                    self.aggregate_pair_reports[pair] = report
                    self.aggregate_pair_payloads[pair] = payload
                aggregate = {
                    "pair_evidence_roots": {
                        pair: self.relative(self.aggregate_pair_roots[pair]) for pair in coordinator.PAIRS
                    },
                    "pairs": {
                        pair: {
                            "report": self.relative(self.aggregate_pair_reports[pair]),
                            "report_sha256": hashlib.sha256(
                                self.aggregate_pair_reports[pair].read_bytes()
                            ).hexdigest(),
                            "execution_cells": list(coordinator.TEXT_COMPONENT_MODES),
                        }
                        for pair in coordinator.PAIRS
                    },
                }
                self.aggregate_receipts[component] = self.write(
                    f".work/evidence/{component}/receipt.json", json.dumps(aggregate, sort_keys=True) + "\n",
                )
                continue
            entries: dict[str, Path] = {}
            for pair in coordinator.PAIRS:
                entries[pair] = self.write(
                    f".work/evidence/{component}/{pair}/report.json", component + ":" + pair + "\n",
                )
                if specification.request_kind == "wordexp-pairs":
                    self.expected_inputs[pair] = self.write(
                        f".work/evidence/{component}/{pair}/expected-inputs.json", pair + "\n",
                    )
            self.reports[component] = entries
        self.request_path = self.write(".work/request.json", json.dumps(self.request(), sort_keys=True) + "\n")
        self.mutate_during_read = False
        self.mutate_aggregate_root = False

    def addCleanup(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, contents: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def request(self) -> dict[str, object]:
        components: dict[str, object] = {}
        for name, specification in coordinator.COMPONENTS.items():
            if specification.request_kind == "aggregate":
                components[name] = {"receipt": self.relative(self.aggregate_receipts[name])}
            elif specification.request_kind == "wordexp-pairs":
                components[name] = {
                    pair: {
                        "report": self.relative(self.reports[name][pair]),
                        "expected_inputs": self.relative(self.expected_inputs[pair]),
                    }
                    for pair in coordinator.PAIRS
                }
            else:
                components[name] = {
                    pair: self.relative(self.reports[name][pair]) for pair in coordinator.PAIRS
                }
        return {
            "schema": coordinator.SCHEMA,
            "family_execution": self.relative(self.matrix_path),
            "pthread_family": self.relative(self.pthread_path),
            "components": components,
        }

    def assembly_reports(self) -> dict[str, dict[str, str]]:
        """The assembler receives raw text reports, before their aggregate exists."""

        reports = {
            name: {pair: self.relative(path) for pair, path in entries.items()}
            for name, entries in self.reports.items()
        }
        reports["text-locale-numeric"] = {
            pair: self.relative(path) for pair, path in self.aggregate_pair_reports.items()
        }
        return reports

    def matrix(self) -> dict[str, object]:
        return {
            "schema": coordinator.family.SCHEMA,
            "status": "workload-matrix-verified",
            "family": "libc.posix-runtime",
            "native_aggregate_complete": False,
            "family_completion": False,
            "public_support": False,
            "request": coordinator.family.file_identity(self.root, self.matrix_request),
            "inputs": {
                "source": SOURCE,
                "static_preparation": coordinator.family.file_identity(self.root, self.static_preparation),
                "dynamic_qualification": coordinator.family.file_identity(self.root, self.dynamic_qualification),
                "oracle": {"fixture": "musl"},
            },
        }

    def pthread(self) -> dict[str, object]:
        return {
            "schema": coordinator.pthread.SCHEMA,
            "status": "installed-behavior-component-verified",
            "family": "libc.pthread-tls",
            "inputs": {
                "family_execution": coordinator.family.file_identity(self.root, self.matrix_path),
                "source": SOURCE,
            },
            "component_complete": True,
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }

    def adapter_results(self, *, source: object = SOURCE,
                        products: dict[str, dict[str, Path]] | None = None,
                        modes: tuple[str, ...] = coordinator.PAIR_MODES,
                        rows: dict[str, dict[str, object]] | None = None) -> dict[str, object]:
        selected_products = self.products if products is None else products
        selected_rows = rows if rows is not None else {
            "text-locale-numeric": {key: {"fixture": True} for key in coordinator.TEXT_LOCALE_NUMERIC_ROWS},
            "stdio": {"stdio.fopen64-alias": {"fixture": True}},
            "stdio-engine": {key: {"fixture": True} for key in coordinator.STDIO_ENGINE_ROWS},
            "calendar": {key: {"fixture": True} for key in coordinator.CALENDAR_ROWS},
        }

        def reader(name: str):
            def validate(root: Path, request: coordinator.ComponentRequest,
                         context: coordinator.MatrixContext) -> dict[str, coordinator.ComponentEvidence]:
                self.assert_context(context)
                if self.mutate_during_read and name == "locale":
                    self.mutate_during_read = False
                    (selected_products["primary"]["dynamic"] / "payload").write_text("changed\n", encoding="utf-8")
                if self.mutate_aggregate_root and name == "text-locale-numeric":
                    self.mutate_aggregate_root = False
                    self.aggregate_pair_payloads["primary"].write_text("changed\n", encoding="utf-8")
                return {
                    pair: coordinator.ComponentEvidence(
                        source=copy.deepcopy(source),
                        products=selected_products[pair],
                        modes=modes,
                        scope=coordinator.COMPONENTS[name].scope,
                        rows=copy.deepcopy(selected_rows.get(name, {})),
                    )
                    for pair in coordinator.PAIRS
                }
            return validate

        return {name: reader(name) for name in coordinator.COMPONENTS}

    def assert_context(self, context: coordinator.MatrixContext) -> None:
        if context.source != SOURCE:
            raise AssertionError("fixture source context differs")
        if context.products != self.products:
            raise AssertionError("fixture product context differs")
        if context.static_preparation != self.static_preparation:
            raise AssertionError("fixture static input differs")
        if context.dynamic_qualification != self.dynamic_qualification:
            raise AssertionError("fixture dynamic input differs")

    def patches(self, adapters: dict[str, object]):
        matrix = self.matrix()

        def input_products(root: Path, request: dict):
            # Keep the real request parser at this boundary: a matrix seals
            # its request file identity rather than embedding its contents.
            coordinator.family._request_paths(root, request)
            return matrix["inputs"], self.products

        return mock.patch.multiple(
            coordinator,
            ROSTER_PATH=self.roster,
            current_source_identity=mock.Mock(return_value=SOURCE),
            _reader_adapters=mock.Mock(return_value=adapters),
        ), mock.patch.object(coordinator.family, "validate_receipt", return_value=matrix), mock.patch.object(
            coordinator.family, "input_products", side_effect=input_products
        ), mock.patch.object(coordinator.pthread, "validate_receipt", return_value=self.pthread())


class TextMathLocaleStdioFamilyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = FamilyFixture()
        self.addCleanup(self.fixture.addCleanup)

    def collect(self, adapters: dict[str, object] | None = None) -> dict[str, object]:
        adapters = self.fixture.adapter_results() if adapters is None else adapters
        patches = self.fixture.patches(adapters)
        with patches[0], patches[1], patches[2], patches[3]:
            return coordinator.collect(self.fixture.root, self.fixture.relative(self.fixture.request_path))

    def test_product_pairs_load_the_sealed_matrix_request(self) -> None:
        patches = self.fixture.patches(self.fixture.adapter_results())
        with patches[2]:
            inputs, products = coordinator._product_pairs(self.fixture.root, self.fixture.matrix())
        self.assertEqual(inputs, self.fixture.matrix()["inputs"])
        self.assertEqual(products, self.fixture.products)

    def test_written_receipt_replays_its_checkout_relative_request(self) -> None:
        fixture = self.fixture
        patches = fixture.patches(fixture.adapter_results())
        output = Path(".work/coordinator/receipt.json")
        (fixture.root / output.parent).mkdir()
        with patches[0], patches[1], patches[2], patches[3]:
            receipt = coordinator.execute(fixture.root, fixture.relative(fixture.request_path), output)
            retained = json.loads(receipt.read_text(encoding="utf-8"))
            replayed = coordinator.validate_receipt(fixture.root, output)
        self.assertEqual(replayed, retained)
        self.assertFalse(replayed["family_completion"])

    def test_product_pairs_reject_changed_matrix_request_before_product_replay(self) -> None:
        matrix = self.fixture.matrix()
        self.fixture.matrix_request.write_text("{}\n", encoding="utf-8")
        with mock.patch.object(coordinator.family, "input_products") as replay:
            with self.assertRaisesRegex(coordinator.FamilyError, "request receipt changed"):
                coordinator._product_pairs(self.fixture.root, matrix)
        replay.assert_not_called()

    def test_rich_text_adapter_accepts_the_public_aggregate_collector_contract(self) -> None:
        import owned_text_locale_numeric_component_receipt as component

        fixture = self.fixture
        context = coordinator.MatrixContext(
            SOURCE, fixture.matrix()["inputs"], fixture.products,
            fixture.static_preparation, fixture.dynamic_qualification,
        )
        request = coordinator.ComponentRequest(
            reports={}, receipt=fixture.aggregate_receipts["text-locale-numeric"],
            evidence_roots=fixture.aggregate_pair_roots,
        )
        patches = fixture.patches(fixture.adapter_results())
        # Exercise the real aggregate writer and public validator together.
        # Only the native leaf/product judges are substituted in this test.
        with patches[2], mock.patch.object(component.static_products, "source_identity", return_value=SOURCE), \
                mock.patch.object(component, "validate_report", return_value=(
                    {"execution_cells": list(component.EXECUTION_CELLS)}, {"fixture": b"same object"},
                )):
            receipt = component.collect(fixture.root, fixture.static_preparation,
                                        fixture.dynamic_qualification, fixture.aggregate_pair_reports)
            request.receipt.write_text(json.dumps(receipt), encoding="utf-8")
            observed = coordinator._text_locale_numeric_adapter(fixture.root, request, context)
        self.assertEqual(set(observed), set(coordinator.PAIRS))
        for pair, evidence in observed.items():
            self.assertEqual(evidence.products, fixture.products[pair])
            self.assertEqual(evidence.modes, coordinator.PAIR_MODES)
            self.assertEqual(evidence.scope, coordinator.COMPONENTS["text-locale-numeric"].scope)
            self.assertEqual(set(evidence.rows), set(coordinator.TEXT_LOCALE_NUMERIC_ROWS))

    def test_assembly_requires_all_three_pairs_and_writes_a_replayable_request(self) -> None:
        """The runnable hand-off has no implicit report discovery or promotion."""

        import owned_text_locale_numeric_component_receipt as component

        fixture = self.fixture
        reports = fixture.assembly_reports()
        expected_inputs = {pair: fixture.relative(path) for pair, path in fixture.expected_inputs.items()}
        output = Path(".work/assembly")
        patches = fixture.patches(fixture.adapter_results())
        with patches[0], patches[1], patches[2], patches[3], \
                mock.patch.object(component.static_products, "source_identity", return_value=SOURCE), \
                mock.patch.object(component, "validate_report", return_value=(
                    {"execution_cells": list(component.EXECUTION_CELLS)}, {"fixture": b"same object"},
                )):
            receipt = coordinator.assemble(
                fixture.root,
                fixture.relative(fixture.matrix_path),
                fixture.relative(fixture.pthread_path),
                reports,
                expected_inputs,
                output,
            )

        request_path = fixture.root / output / "request.json"
        aggregate_path = fixture.root / output / "text-locale-numeric-receipt.json"
        self.assertEqual(receipt, fixture.root / output / "receipt.json")
        self.assertTrue(request_path.is_file())
        self.assertTrue(aggregate_path.is_file())
        request = json.loads(request_path.read_text(encoding="utf-8"))
        self.assertEqual(set(request["components"]), set(coordinator.COMPONENTS))
        self.assertEqual(request["components"]["text-locale-numeric"], {
            "receipt": fixture.relative(aggregate_path),
        })
        retained = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(tuple(retained["capabilities"]), coordinator.CAPABILITIES)
        self.assertFalse(retained["component_complete"])
        self.assertFalse(retained["family_completion"])
        self.assertFalse(retained["promotion_ready"])
        self.assertFalse(retained["public_support"])

    def test_assembly_rejects_a_missing_wordexp_expected_input_before_writing(self) -> None:
        reports = self.fixture.assembly_reports()
        expected = {pair: self.fixture.relative(path) for pair, path in self.fixture.expected_inputs.items()}
        del expected["extracted"]
        output = Path(".work/missing-expected-input")

        with self.assertRaisesRegex(coordinator.FamilyError, "wordexp expected input pair roster differs"):
            coordinator.assemble(
                self.fixture.root,
                self.fixture.relative(self.fixture.matrix_path),
                self.fixture.relative(self.fixture.pthread_path),
                reports,
                expected,
                output,
            )
        self.assertFalse((self.fixture.root / output).exists())

    def test_assembly_rejects_duplicate_report_arguments_before_writing(self) -> None:
        reports = [("locale", "primary", Path(".work/evidence/locale/primary/report.json"))] * 2
        with self.assertRaisesRegex(coordinator.FamilyError, "assembly report is duplicated: locale primary"):
            coordinator._assembly_reports(self.fixture.root, reports)

    def test_assembly_rejects_duplicate_wordexp_expected_input_arguments(self) -> None:
        expected = [("primary", Path(".work/evidence/wordexp/primary/expected-inputs.json"))] * 2
        with self.assertRaisesRegex(coordinator.FamilyError, "wordexp expected input is duplicated: primary"):
            coordinator._assembly_expected_input_entries(expected)

    def test_assembly_rejects_reused_matrix_product_pairs_before_writing(self) -> None:
        fixture = self.fixture
        reused = dict(fixture.products)
        reused["primary"] = fixture.products["reproduction"]
        reports = fixture.assembly_reports()
        expected_inputs = {pair: fixture.relative(path) for pair, path in fixture.expected_inputs.items()}
        patches = fixture.patches(fixture.adapter_results())
        with patches[0], patches[1], patches[3], \
                mock.patch.object(coordinator.family, "input_products", return_value=(fixture.matrix()["inputs"], reused)):
            with self.assertRaisesRegex(coordinator.FamilyError, "POSIX matrix reuses a product pair"):
                coordinator.assemble(
                    fixture.root,
                    fixture.relative(fixture.matrix_path),
                    fixture.relative(fixture.pthread_path),
                    reports,
                    expected_inputs,
                    Path(".work/reused-products"),
                )
        self.assertFalse((fixture.root / ".work/reused-products").exists())

    def test_roster_keeps_the_exact_sixteen_capabilities_and_eighteen_cells(self) -> None:
        roster = coordinator.load_roster(ROOT / "compat/x86_64/text-math-locale-stdio-family.toml")
        self.assertEqual(tuple(roster["capabilities"]), coordinator.CAPABILITIES)
        self.assertEqual(tuple(roster["mode_sets"]["all"]), coordinator.ALL_MODES)
        self.assertEqual(len(coordinator.CAPABILITIES), 16)
        self.assertEqual(len(coordinator.PAIR_MODES), 6)
        self.assertEqual(len(coordinator.ALL_MODES), 18)
        self.assertEqual(coordinator.COMPONENTS["locale"].credits, ())
        self.assertEqual(coordinator.COMPONENTS["numeric"].credits, ())
        self.assertEqual(coordinator.COMPONENTS["stdio"].credits, ())

    def test_positive_control_records_all_components_without_family_or_promotion_claims(self) -> None:
        record = self.collect()
        self.assertEqual(record["status"], "immutable-component-coordination-verified")
        self.assertEqual(tuple(record["capabilities"]), coordinator.CAPABILITIES)
        self.assertFalse(record["component_complete"])
        self.assertFalse(record["family_completion"])
        self.assertFalse(record["promotion_ready"])
        self.assertFalse(record["public_support"])
        for component in coordinator.COMPONENTS:
            self.assertEqual(tuple(record["components"][component]["pairs"]), coordinator.PAIRS)
            for pair in coordinator.PAIRS:
                self.assertEqual(tuple(record["components"][component]["pairs"][pair]["modes"]), coordinator.PAIR_MODES)
        aggregate_pairs = record["components"]["text-locale-numeric"]["pairs"]
        for pair in coordinator.PAIRS:
            self.assertEqual(aggregate_pairs[pair]["evidence_root"]["path"],
                             self.fixture.relative(self.fixture.aggregate_pair_roots[pair]))

    def test_roster_capabilities_are_the_current_parity_family_capabilities(self) -> None:
        parity = tomllib.loads((ROOT / "compat/x86_64/parity.toml").read_text(encoding="utf-8"))
        family = next(item for item in parity["family"] if item["id"] == coordinator.FAMILY)
        self.assertEqual(tuple(family["capabilities"]), coordinator.CAPABILITIES)

    def test_current_math_regex_and_stdio_public_reader_interfaces_match_the_adapter(self) -> None:
        math = importlib.import_module("owned_math_fenv_all_entry_receipt")
        regex = importlib.import_module("owned_regex_component_receipt")
        stdio = importlib.import_module("owned_stdio_component_receipt")
        self.assertEqual(math.SCHEMA, "crabc.x86_64-owned-math-fenv-all-entry-receipt/v1")
        self.assertEqual(regex.SCHEMA, "crabc.x86_64-owned-regex-products/v2")
        self.assertEqual(stdio.SCHEMA, "crabc.x86_64-owned-stdio-products/v3")
        self.assertEqual(tuple(stdio.SCOPE), coordinator.COMPONENTS["stdio"].scope)
        self.assertEqual(tuple(inspect.signature(math.collect).parameters),
                         ("root", "static_preparation", "dynamic_qualification", "reports"))
        self.assertEqual(tuple(inspect.signature(regex.validate_report).parameters),
                         ("root", "report_path", "require_static"))
        self.assertEqual(tuple(inspect.signature(stdio.validate_report).parameters),
                         ("path", "checkout", "require_static"))

    def test_request_rejects_an_omitted_product_pair_before_reader_admission(self) -> None:
        request = self.fixture.request()
        del request["components"]["locale"]["extracted"]
        self.fixture.request_path.write_text(json.dumps(request), encoding="utf-8")
        with self.assertRaisesRegex(coordinator.FamilyError, "locale product-pair roster differs"):
            self.collect()

    def test_reader_rejects_a_substituted_product_pair(self) -> None:
        products = copy.deepcopy(self.fixture.products)
        products["primary"] = self.fixture.products["reproduction"]
        with self.assertRaisesRegex(coordinator.FamilyError, "locale primary product pair differs"):
            self.collect(self.fixture.adapter_results(products=products))

    def test_output_rejects_a_symlinked_parent_hop_inside_checkout_work(self) -> None:
        target = self.fixture.root / ".work/output-target"
        nested = target / "nested"
        nested.mkdir(parents=True)
        (self.fixture.root / ".work/output-link").symlink_to("output-target", target_is_directory=True)
        with self.assertRaisesRegex(coordinator.FamilyError, "output parent traverses a symbolic link"):
            coordinator._fresh_output(self.fixture.root, Path(".work/output-link/nested/receipt.json"))

    def test_output_creation_is_exclusive_after_collection(self) -> None:
        output_parent = self.fixture.root / ".work/output"
        output_parent.mkdir()
        output = output_parent / "receipt.json"

        def create_racing_output(_root: Path, _request: Path) -> dict[str, object]:
            output.write_text("racing output\n", encoding="utf-8")
            return {"fixture": True}

        with mock.patch.object(coordinator, "collect", side_effect=create_racing_output):
            with self.assertRaisesRegex(coordinator.FamilyError, "output is no longer fresh"):
                coordinator.execute(self.fixture.root, Path(".work/request.json"), Path(".work/output/receipt.json"))
        self.assertEqual(output.read_text(encoding="utf-8"), "racing output\n")

    def test_reader_rejects_a_component_source_different_from_the_matrix_source(self) -> None:
        wrong_source = {**SOURCE, "content_sha256": "e" * 64}
        with self.assertRaisesRegex(coordinator.FamilyError, "locale primary source, scope, or mode roster differs"):
            self.collect(self.fixture.adapter_results(source=wrong_source))

    def test_reader_rejects_an_omitted_required_behavior_row(self) -> None:
        rows = {
            "text-locale-numeric": {key: {"fixture": True} for key in coordinator.TEXT_LOCALE_NUMERIC_ROWS[:-1]},
            "stdio": {"stdio.fopen64-alias": {"fixture": True}},
            "stdio-engine": {key: {"fixture": True} for key in coordinator.STDIO_ENGINE_ROWS},
            "calendar": {key: {"fixture": True} for key in coordinator.CALENDAR_ROWS},
        }
        with self.assertRaisesRegex(coordinator.FamilyError, "text-locale-numeric required behavior rows differ"):
            self.collect(self.fixture.adapter_results(rows=rows))

    def test_reader_rejects_an_omitted_mode(self) -> None:
        with self.assertRaisesRegex(coordinator.FamilyError, "locale primary source, scope, or mode roster differs"):
            self.collect(self.fixture.adapter_results(modes=coordinator.PAIR_MODES[:-1]))

    def test_reader_rejects_a_nested_product_payload_mutated_after_component_validation(self) -> None:
        self.fixture.mutate_during_read = True
        with self.assertRaisesRegex(coordinator.FamilyError, "declared input changed during collection"):
            self.collect()

    def test_reader_rejects_an_aggregate_pair_root_payload_mutated_after_validation(self) -> None:
        self.fixture.mutate_aggregate_root = True
        with self.assertRaisesRegex(coordinator.FamilyError, "declared input changed during collection"):
            self.collect()

    def test_reader_rejects_a_nested_product_payload_mutated_during_output_construction(self) -> None:
        original = coordinator._pair_record
        changed = False

        def mutate(root: Path, request: coordinator.ComponentRequest, pair: str,
                   evidence: coordinator.ComponentEvidence,
                   directory_snapshots: object = None) -> dict[str, object]:
            nonlocal changed
            record = original(root, request, pair, evidence, directory_snapshots)
            if not changed:
                changed = True
                (self.fixture.products["primary"]["static"] / "payload").write_text("changed\n", encoding="utf-8")
            return record

        with mock.patch.object(coordinator, "_pair_record", side_effect=mutate):
            with self.assertRaisesRegex(coordinator.FamilyError, "declared input changed during collection"):
                self.collect()

    def test_pair_records_reuse_initial_tree_snapshots_and_keep_final_recheck(self) -> None:
        product = self.fixture.products["primary"]["static"]
        original_snapshot = coordinator.family.snapshot
        calls = 0

        def track(path: Path) -> dict[str, object]:
            nonlocal calls
            if path == product:
                calls += 1
            return original_snapshot(path)

        patches = self.fixture.patches(self.fixture.adapter_results())
        with patches[0], patches[1], patches[2], patches[3], \
                mock.patch.object(coordinator.family, "snapshot", side_effect=track):
            coordinator.collect(self.fixture.root, self.fixture.relative(self.fixture.request_path))
        # Initial snapshot plus the pre-output and post-output mutation checks.
        # Pair records derive their receipt identity from the initial snapshot.
        self.assertEqual(calls, 3)

    def test_reader_rejects_a_retained_input_mutated_while_output_identities_are_built(self) -> None:
        original = coordinator._roster_identity

        def mutate(root: Path, roster: Path) -> dict[str, object]:
            identity = original(root, roster)
            self.fixture.pthread_path.write_text("changed\n", encoding="utf-8")
            return identity

        with mock.patch.object(coordinator, "_roster_identity", side_effect=mutate):
            with self.assertRaisesRegex(coordinator.FamilyError, "declared input changed during collection"):
                self.collect()


if __name__ == "__main__":
    unittest.main()
