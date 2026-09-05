#!/usr/bin/env python3
"""Fail-closed contract tests for the planned x86 loader/libc TLS RuntimeV1."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VALIDATOR_PATH = ROOT / "compat" / "x86_64" / "validate_loader_libc_tls_runtime_v1.py"
DOCUMENT_PATH = ROOT / "docs" / "evidence" / "x86-loader-libc-tls-runtime-v1.md"
LOADER_SOURCE_PATH = ROOT / "ldso" / "src" / "x86_64_initial_graph.rs"
REGISTRY_SOURCE_PATH = ROOT / "ldso" / "src" / "x86_64_initial_tls_registry.rs"
CONSUMER_SOURCE_PATH = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "loader_tls_runtime_v1.rs"
CONSUMER_ROOT_PATH = (
    ROOT / "libc" / "src" / "c_abi" / "x86_64" / "loader_tls_runtime_v1_source_root.rs"
)
STATIC_C_ABI_PATH = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
STATIC_EXPORTS_PATH = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
NATIVE_RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_loader_libc_tls_runtime_v1.sh"
REGISTRY_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_loader_libc_tls_runtime_v1_registry.sh"
)
GENERAL_RUNTIME_SOURCE_ROOT_PATH = (
    ROOT / "ldso" / "src" / "x86_64_general_initial_tls_runtime_v1_source_root.rs"
)
GENERAL_RUNTIME_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_loader_libc_general_tls_runtime_v1.sh"
)
GENERAL_RUNTIME_TARGET_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_loader_libc_general_tls_runtime_v1_target_root.sh"
)
GENERAL_RUNTIME_GRAPH_PATH = ROOT / "ldso" / "src" / "x86_64_general_initial_graph.rs"
GENERAL_RUNTIME_STATE_PATH = ROOT / "ldso" / "src" / "x86_64_general_initial_tls_state.rs"
DYNAMIC_MAIN_THREAD_ROOT_PATH = (
    ROOT / "ldso" / "src" / "x86_64_dynamic_main_thread_runtime_v1_source_root.rs"
)
DYNAMIC_MAIN_THREAD_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_dynamic_main_thread_runtime_v1.sh"
)
DYNAMIC_MAIN_THREAD_TARGET_RUNNER_PATH = (
    ROOT / "compat" / "x86_64" / "run_dynamic_main_thread_runtime_v1_target_root.sh"
)
DYNAMIC_MAIN_THREAD_LIBC_ROOT_PATH = (
    ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dynamic_main_thread_runtime_v1_source_root.rs"
)
DYNAMIC_MAIN_THREAD_LIBC_PATH = (
    ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dynamic_main_thread_runtime_v1.rs"
)
DYNAMIC_MAIN_THREAD_CRT_PATH = ROOT / "crt" / "src" / "x86_64_dynamic_startup.rs"
DISPATCHER_PATH = ROOT / "scripts" / "dev-x86_64.sh"
STRUCTURE_PATH = ROOT / "scripts" / "check_structure.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runtime_v1 = load_module("x86_loader_libc_tls_runtime_v1", VALIDATOR_PATH)


class LoaderLibcTlsRuntimeV1ContractTests(unittest.TestCase):
    def contract(self) -> dict[str, object]:
        return copy.deepcopy(runtime_v1.load_toml(runtime_v1.CONTRACT_PATH))

    def test_checked_in_contract_is_explicitly_planned_and_non_promoting(self) -> None:
        report = runtime_v1.validate_contract(self.contract())

        self.assertEqual(report["id"], "x86-loader-libc-tls-runtime-v1")
        self.assertEqual(report["status"], "implemented-unqualified")
        self.assertFalse(report["runtime_v1_published"])
        self.assertTrue(report["private_initial_tls_foundation"])
        self.assertTrue(report["private_initial_tls_registry_foundation"])
        self.assertTrue(report["private_general_initial_tls_foundation"])
        self.assertTrue(report["private_general_initial_tls_runtime_v1_foundation"])
        self.assertTrue(report["private_dynamic_main_thread_runtime_v1_bridge"])
        self.assertEqual(
            report["initial_tls_foundation_state"], "implemented-private-evidence-only"
        )
        self.assertEqual(
            report["initial_tls_registry_foundation_state"],
            "implemented-private-evidence-only",
        )
        self.assertEqual(
            report["general_initial_tls_materialization_state"],
            "implemented-private-evidence-only",
        )
        self.assertEqual(
            report["general_initial_tls_runtime_v1_foundation_state"],
            "implemented-private-evidence-only",
        )
        self.assertEqual(
            report["dynamic_main_thread_runtime_v1_bridge_state"],
            "implemented-private-evidence-only",
        )
        self.assertEqual(
            report["current_runtime_v1_producers"],
            [
                "ldso-general-initial-tls-runtime-v1",
                "ldso-dynamic-main-thread-runtime-v1",
                "owned-dynamic-runtime-v1",
            ],
        )
        self.assertEqual(report["process_modes"], ["static", "dynamic"])
        self.assertEqual(
            report["evidence_states"], ["private-foundation-complete"] * 4 + ["implemented-unqualified"] * 5
        )

    def test_static_dynamic_selection_and_owner_are_not_interchangeable(self) -> None:
        mutations = (
            (
                "static selector",
                lambda contract: contract["process_modes"]["static"].__setitem__(
                    "selector", "elf-type-et-exec"
                ),
                "static mode contract drifted",
            ),
            (
                "dynamic owner",
                lambda contract: contract["process_modes"]["dynamic"].__setitem__(
                    "dtv_owner", "crabc-libc"
                ),
                "dynamic mode contract drifted",
            ),
            (
                "static dso loading",
                lambda contract: contract["process_modes"]["static"].__setitem__(
                    "runtime_tls_modules", "allowed"
                ),
                "static mode contract drifted",
            ),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                contract = self.contract()
                mutate(contract)
                with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, message):
                    runtime_v1.validate_contract(contract)

    def test_variant_ii_and_dtv_growth_boundaries_fail_closed(self) -> None:
        mutations = (
            (
                "thread pointer register",
                lambda contract: contract["variant_ii"].__setitem__(
                    "thread_pointer_register", "%gs"
                ),
                "Variant-II contract drifted",
            ),
            (
                "tls direction",
                lambda contract: contract["variant_ii"].__setitem__(
                    "tls_direction", "above-thread-pointer"
                ),
                "Variant-II contract drifted",
            ),
            (
                "unsafe growth",
                lambda contract: contract["dtv"].__setitem__(
                    "runtime_tls_load", "allow-fixed-dtv"
                ),
                "DTV contract drifted",
            ),
            (
                "stale DTV reclamation",
                lambda contract: contract["dtv"].__setitem__(
                    "old_dtv_reclamation", "free-after-pointer-swap"
                ),
                "DTV contract drifted",
            ),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                contract = self.contract()
                mutate(contract)
                with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, message):
                    runtime_v1.validate_contract(contract)

    def test_only_the_dedicated_general_artifacts_are_private_runtime_v1_producers(self) -> None:
        contract = self.contract()
        artifacts = contract["current_artifact"]
        assert isinstance(artifacts, list)
        by_id = {row["id"]: row for row in artifacts if isinstance(row, dict)}
        for artifact_id in (
            "libc-static-initial-tls-v1",
            "libc-static-pthread-worker",
            "ldso-fixed-initial-tls-graph",
        ):
            with self.subTest(artifact_id=artifact_id):
                self.assertFalse(by_id[artifact_id]["runtime_v1_producer"])
        self.assertTrue(by_id["ldso-general-initial-tls-runtime-v1"]["runtime_v1_producer"])
        self.assertTrue(by_id["ldso-dynamic-main-thread-runtime-v1"]["runtime_v1_producer"])

        by_id["libc-static-initial-tls-v1"]["runtime_v1_producer"] = True

        with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, "current-artifact"):
            runtime_v1.validate_contract(contract)

        contract = self.contract()
        artifacts = contract["current_artifact"]
        assert isinstance(artifacts, list)
        by_id = {row["id"]: row for row in artifacts if isinstance(row, dict)}
        by_id["ldso-general-initial-tls-runtime-v1"]["runtime_v1_producer"] = False
        with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, "current-artifact"):
            runtime_v1.validate_contract(contract)

        contract = self.contract()
        artifacts = contract["current_artifact"]
        assert isinstance(artifacts, list)
        by_id = {row["id"]: row for row in artifacts if isinstance(row, dict)}
        by_id["ldso-dynamic-main-thread-runtime-v1"]["runtime_v1_producer"] = False
        with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, "current-artifact"):
            runtime_v1.validate_contract(contract)

    def test_foundations_stay_private_and_only_the_runtime_integration_remains_planned(self) -> None:
        contract = self.contract()
        evidence = contract["evidence"]
        assert isinstance(evidence, list)
        first = evidence[0]
        assert isinstance(first, dict)
        first["state"] = "complete"
        with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, "evidence"):
            runtime_v1.validate_contract(contract)

        contract = self.contract()
        foundation = contract["initial_tls_foundation"]
        assert isinstance(foundation, dict)
        foundation["general_dynamic_product"] = True
        with self.assertRaisesRegex(
            runtime_v1.TlsRuntimeContractError, "initial-TLS foundation"
        ):
            runtime_v1.validate_contract(contract)

        contract = self.contract()
        registry = contract["initial_tls_registry_foundation"]
        assert isinstance(registry, dict)
        registry["general_dynamic_product"] = True
        with self.assertRaisesRegex(
            runtime_v1.TlsRuntimeContractError, "initial-TLS registry foundation"
        ):
            runtime_v1.validate_contract(contract)

        contract = self.contract()
        integration = contract["integration"]
        assert isinstance(integration, list)
        first = integration[0]
        assert isinstance(first, dict)
        first["state"] = "complete"
        with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, "future-integration"):
            runtime_v1.validate_contract(contract)

        contract = self.contract()
        integration = contract["integration"]
        assert isinstance(integration, list)
        general_initial_tls = next(
            row
            for row in integration
            if isinstance(row, dict) and row["id"] == "ldso-x86-main-thread-materialization"
        )
        general_initial_tls["state"] = "complete"
        with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, "future-integration"):
            runtime_v1.validate_contract(contract)

        contract = self.contract()
        integration = contract["integration"]
        assert isinstance(integration, list)
        general_runtime_v1 = next(
            row
            for row in integration
            if isinstance(row, dict)
            and row["id"] == "ldso-x86-general-runtime-v1-publication"
        )
        general_runtime_v1["state"] = "complete"
        with self.assertRaisesRegex(runtime_v1.TlsRuntimeContractError, "future-integration"):
            runtime_v1.validate_contract(contract)

    def test_evidence_document_explains_the_checked_mode_and_rejection_boundaries(self) -> None:
        document = DOCUMENT_PATH.read_text(encoding="utf-8")
        for phrase in (
            "loader-libc-tls-runtime-v1.toml",
            "PT_INTERP",
            "ET_DYN",
            "Variant II",
            "%fs:0",
            "%fs:8",
            "must fail before mapping, relocation, constructors",
            "not RuntimeV1 producers",
            "Implemented private general initial-TLS RuntimeV1 wire",
            "Implemented private dynamic main-thread RuntimeV1 bridge",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, document)

    def test_private_runtime_v1_foundation_validates_before_tls_access(self) -> None:
        """The first producer/consumer seam remains private and fail-closed.

        This is deliberately a source-boundary test as well as the native
        runner below: it prevents the isolated consumer from leaking into the
        selected static libc root while pinning the validation order that the
        malformed-pointer native fixtures exercise.
        """

        loader = LOADER_SOURCE_PATH.read_text(encoding="utf-8")
        consumer = CONSUMER_SOURCE_PATH.read_text(encoding="utf-8")
        consumer_root = CONSUMER_ROOT_PATH.read_text(encoding="utf-8")
        static_c_abi = STATIC_C_ABI_PATH.read_text(encoding="utf-8")
        static_exports = STATIC_EXPORTS_PATH.read_text(encoding="utf-8")
        runner = NATIVE_RUNNER_PATH.read_text(encoding="utf-8")
        dispatcher = DISPATCHER_PATH.read_text(encoding="utf-8")

        for phrase in (
            "pub struct LoaderLibcTlsRuntimeV1",
            "publish_loader_tls_runtime_v1",
            "__crabc_x86_64_loader_tls_runtime_v1",
            "crabc_loader_libc_tls_runtime_v1",
            ".hidden __crabc_x86_64_loader_tls_runtime_v1",
        ):
            with self.subTest(loader_phrase=phrase):
                self.assertIn(phrase, loader)
        for malformed in ("magic", "version", "abi_size", "mode", "owner", "generation"):
            with self.subTest(malformed=malformed):
                self.assertIn(
                    f"crabc_loader_libc_tls_runtime_v1_bad_{malformed}", loader
                )

        validation = consumer.index("validate_loader_tls_runtime_v1")
        tls_access = consumer.index("read_volatile")
        self.assertLess(validation, tls_access)
        for phrase in (
            "RECORD_MAGIC",
            "RECORD_VERSION",
            "RECORD_SIZE",
            "LoaderLibcTlsRuntimeV1Header",
            "header.abi_size != RECORD_SIZE",
            "PROCESS_MODE_DYNAMIC",
            "OWNER_LDSO",
            "GENERATION_INITIAL",
            "crabc_loader_libc_tls_runtime_v1_static_mode",
        ):
            with self.subTest(consumer_phrase=phrase):
                self.assertIn(phrase, consumer)

        self.assertIn("loader_tls_runtime_v1.rs", consumer_root)
        self.assertNotIn("static_c_abi.rs", consumer_root)
        self.assertNotIn("loader_tls_runtime_v1", static_c_abi)
        self.assertNotIn("__crabc_x86_loader_tls_runtime_v1_attach", static_exports)
        for phrase in (
            "for malformed in magic version abi_size mode owner generation",
            "ld-runtime-v1-poisoned-dtv",
            "ld-runtime-v1-bad-$malformed",
            "main-static",
            "PT_INTERP",
            "--dyn-syms",
        ):
            with self.subTest(runner_phrase=phrase):
                self.assertIn(phrase, runner)

        self.assertIn("loader-libc-tls-runtime-v1", dispatcher)
        self.assertIn("run_loader_libc_tls_runtime_v1_tests", dispatcher)

    def test_initial_tls_registry_is_sealed_and_rejects_runtime_growth(self) -> None:
        """Initial IDs have one owner; runtime growth has no silent fallback."""

        registry = REGISTRY_SOURCE_PATH.read_text(encoding="utf-8")
        runner = REGISTRY_RUNNER_PATH.read_text(encoding="utf-8")
        loader = LOADER_SOURCE_PATH.read_text(encoding="utf-8")
        dispatcher = DISPATCHER_PATH.read_text(encoding="utf-8")
        structure = STRUCTURE_PATH.read_text(encoding="utf-8")

        for phrase in (
            "TlsModuleId",
            "InitialTlsGeneration",
            "InitialTlsRegistry",
            "RegistryPhase",
            "Planning",
            "Sealed",
            "RuntimeTlsGrowthError",
            "DtvGrowthProtocolUnavailable",
            "assign_initial",
            "seal",
            "reject_runtime_tls_growth",
            "runtime_tls_growth_rejection_does_not_mutate_the_sealed_registry",
        ):
            with self.subTest(registry_phrase=phrase):
                self.assertIn(phrase, registry)

        self.assertIn("x86_64_initial_tls_registry", loader)
        self.assertIn("INITIAL_TLS_RUNTIME_V1_REGISTRY", loader)
        self.assertIn("x86_64_initial_tls_registry.rs", runner)
        self.assertIn("rustc --edition=2021 --test", runner)
        self.assertIn("loader-libc-tls-runtime-v1-registry", dispatcher)
        self.assertIn("X86_RUNTIME_FOUNDATION_LOADER_LIBC_SOURCES", structure)
        self.assertIn("ldso/src/x86_64_initial_tls_registry.rs", structure)

    def test_general_initial_tls_materialization_is_private_and_transactional(self) -> None:
        contract = self.contract()
        integration = contract["integration"]
        assert isinstance(integration, list)
        materialization = next(
            row
            for row in integration
            if isinstance(row, dict) and row["id"] == "ldso-x86-main-thread-materialization"
        )
        self.assertEqual(materialization["id"], "ldso-x86-main-thread-materialization")
        self.assertEqual(materialization["state"], "implemented-private-evidence-only")
        self.assertEqual(
            materialization["path"],
            "ldso/src/x86_64_general_initial_tls_source_root.rs",
        )
        self.assertIn("reserve-publication-before-arch-set-fs", materialization["boundary"])
        self.assertIn("ordinary-no-runtimev1", materialization["boundary"])
        self.assertIn("run_ldso_general_initial_tls.sh", materialization["native_evidence"])
        self.assertIn("no-libc-descriptor", materialization["scope"])

        state = (ROOT / "ldso" / "src" / "x86_64_general_initial_tls_state.rs").read_text(
            encoding="utf-8"
        )
        common_state = (
            ROOT / "ldso" / "src" / "x86_64_general_initial_loader_state.rs"
        ).read_text(encoding="utf-8")
        graph = (ROOT / "ldso" / "src" / "x86_64_general_initial_graph.rs").read_text(
            encoding="utf-8"
        )
        dispatcher = DISPATCHER_PATH.read_text(encoding="utf-8")
        for phrase in (
            "PublicationReserved",
            "reserve_publication",
            "PublicationUnavailable",
            "loader: GeneralInitialLoaderState",
            "GENERAL_INITIAL_TLS_ATTACHMENT",
            "pre_fs_publication_reservation_rolls_back_and_allows_retry",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, state)
        for phrase in (
            "GeneralInitialLoaderPhase",
            "Vacant",
            "Discovering",
            "Prepared",
            "Reserved",
            "Ready",
            "GENERAL_INITIAL_LOADER_PUBLICATION",
            "pub(crate) fn reserve_publication",
            "pub(crate) unsafe fn commit",
            "pub(crate) fn retained",
        ):
            with self.subTest(common_state_phrase=phrase):
                self.assertIn(phrase, common_state)
        self.assertNotIn("graph: InitialGraphState", state)
        self.assertNotIn("objects: [Object; MAX_OBJECTS]", state)
        self.assertLess(
            common_state.index("pub(crate) fn prepare"),
            common_state.index("pub(crate) fn reserve_publication"),
        )
        self.assertLess(
            common_state.index("pub(crate) fn reserve_publication"),
            common_state.index("pub(crate) unsafe fn commit"),
        )
        self.assertLess(
            graph.index("state.reserve_publication()"),
            graph.index("state.materialize_initial_tls()"),
        )
        self.assertIn("unsafe { state.commit(installed) };", graph)
        self.assertNotIn("state.commit() }.map_err", graph)
        for command in (
            "ldso-general-initial-tls)",
            "ldso-general-initial-tls-target-root)",
        ):
            with self.subTest(command=command):
                self.assertIn(command, dispatcher)

    def test_general_runtime_v1_is_a_separate_private_ready_last_wire(self) -> None:
        contract = self.contract()
        foundation = contract["general_initial_tls_runtime_v1_foundation"]
        assert isinstance(foundation, dict)
        self.assertEqual(foundation["state"], "implemented-private-evidence-only")
        self.assertEqual(
            foundation["producer"],
            "ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs:"
            "crabc_general_initial_graph+crabc_general_initial_tls_materialization_v1+"
            "crabc_general_loader_libc_tls_runtime_v1",
        )
        self.assertIn("paired-general-initial-state", foundation["publication"])
        self.assertIn("before-arch-get-fs-or-tcb-dtv-read", foundation["validation"])
        self.assertIn("private-local-hidden-static-symbol", foundation["record_visibility"])
        self.assertIn("strong-main-and-weak-dso-reject-before-arch-set-fs", foundation["import_rule"])
        self.assertFalse(foundation["general_dynamic_product"])
        self.assertFalse(foundation["capability_or_family_promotion"])

        integration = contract["integration"]
        assert isinstance(integration, list)
        publication = next(
            row
            for row in integration
            if isinstance(row, dict)
            and row["id"] == "ldso-x86-general-runtime-v1-publication"
        )
        self.assertEqual(publication["state"], "implemented-private-evidence-only")
        self.assertIn("paired-pre-arch-set-fs", publication["boundary"])
        self.assertIn("ready-last", publication["boundary"])
        self.assertIn("dependency-callbacks-only-after-ready", publication["boundary"])
        self.assertIn("no-crt-handoff-installed-dynamic-product", publication["scope"])
        self.assertIn("pthread-new-thread-dtv-growth", publication["scope"])

        root = GENERAL_RUNTIME_SOURCE_ROOT_PATH.read_text(encoding="utf-8")
        graph = GENERAL_RUNTIME_GRAPH_PATH.read_text(encoding="utf-8")
        state = GENERAL_RUNTIME_STATE_PATH.read_text(encoding="utf-8")
        consumer = CONSUMER_SOURCE_PATH.read_text(encoding="utf-8")
        runner = GENERAL_RUNTIME_RUNNER_PATH.read_text(encoding="utf-8")
        target_runner = GENERAL_RUNTIME_TARGET_RUNNER_PATH.read_text(encoding="utf-8")
        dispatcher = DISPATCHER_PATH.read_text(encoding="utf-8")

        for phrase in (
            "crabc_general_initial_graph",
            "crabc_general_initial_tls_materialization_v1",
            "crabc_general_loader_libc_tls_runtime_v1",
        ):
            with self.subTest(root_phrase=phrase):
                self.assertIn(phrase, root)
        self.assertLess(
            graph.index("state.reserve_publication()"),
            graph.index("state.reserve_runtime_v1_publication()"),
        )
        self.assertLess(
            graph.index("state.reserve_runtime_v1_publication()"),
            graph.index("state.materialize_initial_tls()"),
        )
        self.assertLess(
            graph.index("state.materialize_initial_tls()"),
            graph.index("state.commit_runtime_v1(installed)"),
        )
        self.assertLess(
            graph.index("state.commit_runtime_v1(installed)"),
            graph.rindex("unsafe { dispatch_dependency_initializers(&initializers) };"),
        )
        for phrase in (
            "GeneralLoaderLibcTlsRuntimeV1",
            "size_of::<GeneralLoaderLibcTlsRuntimeV1>() == 72",
            "GENERAL_LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED",
            "GENERAL_LOADER_TLS_RUNTIME_V1_STATE_PUBLISHING",
            "GENERAL_LOADER_TLS_RUNTIME_V1_STATE_READY",
            "reserve_loader_tls_runtime_v1_descriptor",
            "release_loader_tls_runtime_v1_descriptor_reservation",
            "publish_reserved_loader_tls_runtime_v1",
        ):
            with self.subTest(state_phrase=phrase):
                self.assertIn(phrase, state)
        self.assertLess(
            consumer.index("unsafe fn validate_loader_tls_runtime_v1"),
            consumer.index("unsafe fn current_thread_pointer"),
        )
        self.assertLess(
            consumer.index("unsafe fn validate_loader_tls_runtime_v1"),
            consumer.index("read_volatile"),
        )
        for phrase in (
            "general-runtime-v1-state-tests",
            "SHT_SYMTAB",
            "SHT_DYNSYM",
            "page-rounded PT_GNU_RELRO",
            "strong-main-record.o",
            "libleft-weak-record.so",
            "expect_rejection_before_fs",
            "main-static",
        ):
            with self.subTest(runner_phrase=phrase):
                self.assertIn(phrase, runner)
        self.assertIn("CRABC_LDSO_GENERAL_TLS_RUNTIME_V1_ROOT=crabc-target", target_runner)
        for command in (
            "loader-libc-general-tls-runtime-v1)",
            "loader-libc-general-tls-runtime-v1-target-root)",
        ):
            with self.subTest(command=command):
                self.assertIn(command, dispatcher)

    def test_dynamic_main_thread_bridge_stays_direct_scrt1_evidence_only(self) -> None:
        contract = self.contract()
        bridge = contract["dynamic_main_thread_runtime_v1_bridge"]
        assert isinstance(bridge, dict)
        self.assertEqual(bridge["state"], "implemented-private-evidence-only")
        self.assertIn("crabc_dynamic_main_thread_runtime_v1", bridge["producer"])
        self.assertIn("--dynamic-main-thread-runtime-v1", bridge["scrt1"])
        self.assertIn("before-private-dynamic-libc-startup", bridge["attachment"])
        self.assertIn("strong-main-and-weak-dso-reject-before-arch-set-fs", bridge["owned_crt_import_rule"])
        self.assertIn("dso-definition-cannot-interpose", bridge["owned_crt_import_rule"])
        self.assertIn("loader-validates-real-scrt1-main-tags-without-dispatch", bridge["main_lifecycle"])
        self.assertIn("poisoned-dtv-reject-before-preinit", bridge["descriptor_failure"])
        self.assertFalse(bridge["general_dynamic_product"])
        self.assertFalse(bridge["capability_or_family_promotion"])

        root = DYNAMIC_MAIN_THREAD_ROOT_PATH.read_text(encoding="utf-8")
        runner = DYNAMIC_MAIN_THREAD_RUNNER_PATH.read_text(encoding="utf-8")
        target_runner = DYNAMIC_MAIN_THREAD_TARGET_RUNNER_PATH.read_text(encoding="utf-8")
        libc_root = DYNAMIC_MAIN_THREAD_LIBC_ROOT_PATH.read_text(encoding="utf-8")
        libc = DYNAMIC_MAIN_THREAD_LIBC_PATH.read_text(encoding="utf-8")
        crt = DYNAMIC_MAIN_THREAD_CRT_PATH.read_text(encoding="utf-8")
        dispatcher = DISPATCHER_PATH.read_text(encoding="utf-8")

        for phrase in (
            "crabc_general_initial_graph",
            "crabc_general_initial_tls_materialization_v1",
            "crabc_general_loader_libc_tls_runtime_v1",
            "crabc_dynamic_main_thread_runtime_v1",
        ):
            with self.subTest(root_phrase=phrase):
                self.assertIn(phrase, root)
        attach = crt.index("__crabc_x86_loader_tls_runtime_v1_attach")
        self.assertLess(attach, crt.index("__libc_start_main(", attach))
        self.assertIn("errno.rs", libc_root)
        for phrase in (
            "fn __libc_start_main",
            "rtld_fini.is_some()",
            "errno::get_errno()",
            "__crabc_dynamic_main_thread_runtime_v1_fini_state",
        ):
            with self.subTest(libc_phrase=phrase):
                self.assertIn(phrase, libc)
        for phrase in (
            "--dynamic-main-thread-runtime-v1",
            "Scrt1.o",
            "PIMFL",
            "strong-main-owned-record.o",
            "weak-owned-record",
            "owned-record-definition",
            "expect_empty_status_127",
            "expect_rejection_before_fs",
            "poisoned-dtv",
        ):
            with self.subTest(runner_phrase=phrase):
                self.assertIn(phrase, runner)
        self.assertIn(
            "CRABC_DYNAMIC_MAIN_THREAD_RUNTIME_V1_LOADER_ROOT=crabc-target", target_runner
        )
        for command in (
            "dynamic-main-thread-runtime-v1)",
            "dynamic-main-thread-runtime-v1-target-root)",
        ):
            with self.subTest(command=command):
                self.assertIn(command, dispatcher)


if __name__ == "__main__":
    unittest.main()
