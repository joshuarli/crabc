#!/usr/bin/env python3
"""Validate the current private x86 loader/libc TLS RuntimeV1 contract.

The contract is intentionally stricter than a checklist: it pins one owner
for each process mode and refuses to relabel either existing fixed-TLS fixture
as a general loader/libc handoff.  This validator does not run a runtime
fixture and cannot promote a capability or family.
"""

from __future__ import annotations

import argparse
import json
import tomllib
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "loader-libc-tls-runtime-v1.toml"

SCHEMA = "crabc.x86_64-loader-libc-tls-runtime/v1"
CONTRACT_ID = "x86-loader-libc-tls-runtime-v1"

OWNED_RUNTIME = {'state': 'implemented-unqualified', 'producer': 'ldso/src/x86_64_general_initial_tls_state.rs:GeneralInitialTlsState::commit_runtime_v1', 'entry': 'ldso/src/x86_64_general_initial_graph.rs:run_with_initial_tls', 'attachment': 'libc/src/c_abi/x86_64/owned_dynamic_attachment.rs', 'carrier': 'crt/src/x86_64_dynamic_startup.rs', 'worker_adapter': 'libc/src/c_abi/x86_64/dynamic_tls.rs', 'runtime_view': 'ldso/src/x86_64_runtime_tls_view.rs', 'worker_owner': 'ldso/src/x86_64_initial_worker_tls.rs', 'initial_wire': 'FS+8 initial DTV and FS+16 initial count remain immutable', 'current_view': 'FS+24 atomically publishes current generation and module-count view', 'module_ids': 'monotonic registry IDs; all live threads prepared before publication', 'old_views': 'retained until worker quiescence; initial thread storage retained for process lifetime', 'worker_operation': 'loader allocates current generation under runtime guard and owns release token', 'attachment_order': 'validate 72-byte descriptor and 144-byte owned CRT record before libc TLS access', 'fork': 'loader registry and surviving TLS repair before libc thread registry repair', 'qualification': 'owned_dynamic_qualification.py live three-product receipt only', 'timer_callback_reset': '__crabc_x86_64_reset_current_tls_v1: unsafe extern C fn() -> i32; registered current TP, application signals blocked after TSD cleanup; loader guard, no allocation, validate all modules then reset relocated template and TBSS bytes; preserve TCB/DTV/token; 0 success or -EINVAL private invariant failure'}

TARGET = {
    "system": "Linux",
    "machine": "x86_64",
    "endianness": "little",
    "abi": "LP64",
    "kernel_msrv": "5.10",
}

PROCESS_MODES = {
    "static": {
        "selector": "no-pt-interp",
        "tcb_owner": "crabc-libc/static-initial-tls-v1",
        "dtv_owner": "none",
        "runtime_tls_modules": "forbidden",
        "thread_creation": "libc-static-owner",
    },
    "dynamic": {
        "selector": "pt-interp-installed-crabc-ldso",
        "tcb_owner": "crabc-ldso/runtime-v1",
        "dtv_owner": "crabc-ldso/runtime-v1",
        "runtime_tls_modules": "loader-owned-all-thread-dtv-growth",
        "thread_creation": "libc-consumes-ldso-runtime-v1",
    },
}

RUNTIME_V1 = {
    "descriptor_owner": "crabc-ldso",
    "descriptor_visibility": "private-loader-libc-handoff",
    "descriptor_validation": "magic-version-abi-size-mode-owner-before-tls-access",
    "mode_exclusivity": "exactly-one-process-mode-owner-before-any-tls-access",
    "main_thread_inputs": "validated-main-and-initial-dso-pt-tls-descriptors-in-loader-link-map-order",
    "main_thread_outputs": "installed-fs-thread-pointer-initialized-tcb-dtv-generation-and-libc-attachment-slot",
    "new_thread_inputs": "current-loader-generation-and-libc-thread-initializer",
    "new_thread_outputs": "fresh-thread-pointer-ready-for-clone_settls-or-explicit-failure",
    "pthread_rule": "libc-never-allocates-or-resizes-dynamic-dtv-or-installs-dynamic-fs-base-directly",
    "tls_get_addr_rule": "dynamic-__tls_get_addr-resolves-only-through-current-loader-runtime-v1",
    "fork_child_order": "loader-repair-before-libc-thread-registry-repair",
}

INITIAL_TLS_FOUNDATION = {
    "state": "implemented-private-evidence-only",
    "producer": "ldso/src/x86_64_initial_graph.rs:crabc_initial_tls_graph+crabc_loader_libc_tls_runtime_v1",
    "consumer": "libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs",
    "record": "__crabc_x86_64_loader_tls_runtime_v1",
    "selector": "fixed-graph-pt-interp-only",
    "validation": "ready-magic-version-abi-size-mode-owner-generation-before-tcb-dtv-read",
    "static_mode": "no-pt-interp-static-consumer-stub-rejects-without-loader-import-or-fs-access",
    "dynamic_tls_growth": "not-implemented-and-not-implied",
    "pthread_or_clone_settls": "not-implemented-and-not-implied",
    "general_dynamic_product": False,
    "capability_or_family_promotion": False,
    "native_evidence": "compat/x86_64/run_loader_libc_tls_runtime_v1.sh",
}

INITIAL_TLS_REGISTRY_FOUNDATION = {
    "state": "implemented-private-evidence-only",
    "owner": "ldso/src/x86_64_initial_tls_registry.rs",
    "integration": "crabc_initial_tls_graph+crabc_loader_libc_tls_runtime_v1-fixed-planner-install-publish-only",
    "initial_module_ids": "typed-one-based-loader-order-object-index-to-module-id",
    "generation": "typed-initial-generation-one-planning-to-sealed-only",
    "runtime_tls_dtv_growth": "explicit-dtv-growth-protocol-unavailable-rejection-without-registry-or-dtv-mutation",
    "general_initial_graph": "integrated-ordinary-general-initial-tls-materialization-and-separate-general-runtimev1-private-publication-only-no-runtime-growth",
    "general_dynamic_product": False,
    "capability_or_family_promotion": False,
    "native_evidence": "compat/x86_64/run_loader_libc_tls_runtime_v1_registry.sh",
}

GENERAL_INITIAL_TLS_RUNTIME_V1_FOUNDATION = {
    "state": "implemented-private-evidence-only",
    "producer": (
        "ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs:"
        "crabc_general_initial_graph+crabc_general_initial_tls_materialization_v1+"
        "crabc_general_loader_libc_tls_runtime_v1"
    ),
    "consumer": "libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs",
    "record": "__crabc_x86_64_loader_tls_runtime_v1",
    "selector": "bounded-general-initial-pt-interp-only",
    "publication": "paired-general-initial-state-and-descriptor-reservations-before-arch-set-fs-then-ready-last",
    "validation": "ready-magic-version-abi-size-mode-owner-generation-before-arch-get-fs-or-tcb-dtv-read",
    "record_visibility": "private-local-hidden-static-symbol-no-dynsym-outside-page-rounded-relro",
    "import_rule": "only-main-image-undefined-weak-got-record-import-strong-main-and-weak-dso-reject-before-arch-set-fs",
    "dynamic_tls_growth": "not-implemented-and-not-implied",
    "pthread_or_clone_settls": "not-implemented-and-not-implied",
    "dynamic_crt_handoff": "not-implemented-and-not-implied",
    "general_dynamic_product": False,
    "capability_or_family_promotion": False,
    "native_evidence": (
        "compat/x86_64/run_loader_libc_general_tls_runtime_v1.sh+"
        "compat/x86_64/run_loader_libc_general_tls_runtime_v1_target_root.sh"
    ),
}

DYNAMIC_MAIN_THREAD_RUNTIME_V1_BRIDGE = {
    "state": "implemented-private-evidence-only",
    "producer": (
        "ldso/src/x86_64_dynamic_main_thread_runtime_v1_source_root.rs:"
        "crabc_general_initial_graph+crabc_general_initial_tls_materialization_v1+"
        "crabc_general_loader_libc_tls_runtime_v1+crabc_dynamic_main_thread_runtime_v1"
    ),
    "scrt1": (
        "crt/build_x86_64.py:--dynamic-main-thread-runtime-v1->"
        "crt/src/x86_64_dynamic_startup.rs:"
        "__crabc_x86_loader_tls_runtime_v1_attach-before-__libc_start_main"
    ),
    "consumer": "libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_source_root.rs",
    "record": "__crabc_x86_64_loader_tls_runtime_v1",
    "selector": "bounded-general-initial-pt-interp-only-real-scrt1",
    "attachment": "main-resident-runtimev1-consumer-before-private-dynamic-libc-startup",
    "owned_crt_import_rule": (
        "only-real-scrt1-main-undefined-default-visible-weak-object-glob-dat-zero-addend-"
        "is-forced-null-before-lookup-strong-main-and-weak-dso-reject-before-arch-set-fs-"
        "dso-definition-cannot-interpose"
    ),
    "main_lifecycle": (
        "loader-validates-real-scrt1-main-tags-without-dispatch-scrt1-dispatches-"
        "preinit-init-and-fini-callbacks"
    ),
    "descriptor_failure": (
        "magic-version-abi-size-mode-owner-generation-and-poisoned-dtv-reject-before-"
        "preinit-init-main-or-private-dynamic-libc"
    ),
    "dynamic_tls_errno": (
        "main-and-private-dynamic-libc-pt-tls-and-dynamic-errno-observe-one-"
        "loader-installed-generation"
    ),
    "dynamic_tls_growth": "not-implemented-and-not-implied",
    "pthread_or_clone_settls": "not-implemented-and-not-implied",
    "loader_finalizer_or_dependency_lifecycle": "not-implemented-and-not-implied",
    "general_dynamic_product": False,
    "capability_or_family_promotion": False,
    "native_evidence": (
        "compat/x86_64/run_dynamic_main_thread_runtime_v1.sh+"
        "compat/x86_64/run_dynamic_main_thread_runtime_v1_target_root.sh"
    ),
}

VARIANT_II = {
    "thread_pointer_register": "%fs",
    "tcb_self_word": "%fs:0",
    "dtv_pointer_word": "%fs:8",
    "tls_direction": "below-thread-pointer",
    "template_validation": "pt-tls-filesz-lte-memsz-power-of-two-align-and-vaddr-offset-phase",
    "materialization": "copy-filesz-zero-tbss-preserve-max-alignment-and-source-phase",
    "static_tls_access": "local-exec-only-under-static-initial-tls-v1",
}

DTV = {
    "module_ids": "nonzero-stable-loader-owned-while-module-is-addressable",
    "generation": "monotonic-loader-owned-registry-generation",
    "initial_population": "all-initial-pt-tls-modules-before-dynamic-tls-relocations-or-libc-handoff",
    "runtime_tls_load": "prepare-all-live-thread-views-before-atomic-registry-and-view-publication",
    "growth_completion": "registry-growth-current-thread-refresh-new-thread-current-generation-and-safe-old-dtv-reclamation",
    "old_dtv_reclamation": "retain-until-no-thread-or-loader-reader-can-observe-old-dtv",
    "tls_module_unload": "retain-successful-load-mappings-and-module-ids-through-exit; rollback-failed-transactions-before-publication",
}

CURRENT_ARTIFACTS = [
    {
        "id": "libc-static-initial-tls-v1",
        "path": "libc/src/c_abi/x86_64/static_tls.rs",
        "state": "private-fixture",
        "runtime_v1_producer": False,
    },
    {
        "id": "libc-static-pthread-worker",
        "path": "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "state": "private-fixture",
        "runtime_v1_producer": False,
    },
    {
        "id": "ldso-fixed-initial-tls-graph",
        "path": "ldso/src/x86_64_initial_graph.rs",
        "state": "private-fixture",
        "runtime_v1_producer": False,
    },
    {
        "id": "ldso-general-initial-tls-runtime-v1",
        "path": "ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs",
        "state": "implemented-private-evidence-only",
        "runtime_v1_producer": True,
    },
    {
        "id": "ldso-dynamic-main-thread-runtime-v1",
        "path": "ldso/src/x86_64_dynamic_main_thread_runtime_v1_source_root.rs",
        "state": "implemented-private-evidence-only",
        "runtime_v1_producer": True,
    },
]

CURRENT_ARTIFACTS.append({
    "id": "owned-dynamic-runtime-v1",
    "path": "ldso/src/x86_64_general_initial_tls_state.rs",
    "mode": "owned-dynamic",
    "boundary": "owned-producer-with-growth-worker-adapter-and-crt-attachment-requires-live-product-qualification",
    "runtime_v1_producer": True,
})

INTEGRATION = [
    {
        "id": "ldso-runtime-v1-producer",
        "path": "ldso/src/x86_64_general_initial_tls_state.rs",
        "boundary": "own-the-registry-generation-dtv-growth-and-private-descriptor",
        "state": "implemented-unqualified",
    },
    {
        "id": "ldso-x86-main-thread-materialization",
        "path": "ldso/src/x86_64_general_initial_tls_source_root.rs",
        "boundary": "loader-owned-general-initial-only-pt-tls-layout-before-dtpmod64-dtpoff64-relocations-reserve-publication-before-arch-set-fs-and-nonfallibly-commit-in-the-ordinary-no-runtimev1-or-crt-handoff-root",
        "state": "implemented-private-evidence-only",
        "native_evidence": "compat/x86_64/run_ldso_general_initial_tls.sh+compat/x86_64/run_ldso_general_initial_tls_target_root.sh",
        "scope": "bounded-general-initial-graph-generation-one-only-no-libc-descriptor-pthread-new-thread-dtv-growth-runtime-map-dlopen-crt-or-product-promotion",
    },
    {
        "id": "ldso-x86-general-runtime-v1-publication",
        "path": "ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs",
        "boundary": "bounded-arbitrary-initial-pt-tls-graph-runtimev1-paired-pre-arch-set-fs-state-and-descriptor-reservation-nonfallible-retained-state-commit-72-byte-loader-owned-descriptor-ready-last-and-dependency-callbacks-only-after-ready",
        "state": "implemented-private-evidence-only",
        "native_evidence": (
            "compat/x86_64/run_loader_libc_general_tls_runtime_v1.sh+"
            "compat/x86_64/run_loader_libc_general_tls_runtime_v1_target_root.sh"
        ),
        "scope": "bounded-general-initial-graph-generation-one-only-local-hidden-72-byte-record-no-crt-handoff-installed-dynamic-product-pthread-new-thread-dtv-growth-replacement-runtime-map-dlopen-unload-or-product-family-capability-promotion",
    },
    {
        "id": "libc-dynamic-pthread-consumer",
        "path": "libc/src/c_abi/x86_64/pthread_create_join.rs",
        "boundary": "consume-runtime-v1-new-thread-operation-instead-of-static-tls-allocation",
        "state": "implemented-unqualified",
    },
    {
        "id": "libc-static-mode-separation",
        "path": "libc/src/c_abi/x86_64/static_tls.rs",
        "boundary": "retain-no-pt-interp-static-owner-and-refuse-dynamic-runtimev1-substitution",
        "state": "implemented-unqualified",
    },
    {
        "id": "crt-private-handoff-carrier",
        "path": "ldso/src/x86_64_initial_graph.rs",
        "boundary": "carry-validated-runtime-v1-through-owned-dynamic-crt-record-before-libc-tls-access",
        "state": "implemented-unqualified",
    },
    {
        "id": "dynamic-tls-regression-to-product",
        "path": "compat/x86_64/run_ldso_initial_tls.sh",
        "boundary": "retain-fixed-graph-tls-as-regression-while-installed-dynamic-product-gains-runtimev1-evidence",
        "state": "implemented-unqualified",
    },
]

EVIDENCE = [
    {
        "id": "runtime-v1-descriptor-negative-validation",
        "state": "private-foundation-complete",
        "required": "bad-magic-version-size-mode-owner-and-generation-with-live-coordinates-plus-poisoned-dtv-are-rejected-before-tls-access",
        "scope": "one-fixed-initial-tls-graph-private-record-no-growth-no-pthread-no-product-promotion",
    },
    {
        "id": "general-initial-tls-materialization",
        "state": "private-foundation-complete",
        "required": "bounded-diamond-initial-pt-tls-graph-proves-loader-order-module-ids-variant-ii-copy-tbss-alignment-direct-tls-index-resolution-pre-fs-malformed-rejection-and-publication-reservation-rollback",
        "scope": "general-initial-only-loader-state-no-runtimev1-descriptor-libc-handoff-pthread-dtv-growth-runtime-map-dlopen-crt-or-product-promotion",
    },
    {
        "id": "general-runtime-v1-descriptor-publication",
        "state": "private-foundation-complete",
        "required": "source-and-cargo-target-root-bounded-diamond-prove-paired-pre-fs-reservation-rollback-72-byte-local-hidden-nondynsym-writable-non-page-rounded-relro-record-unpublished-publishing-ready-ready-before-constructor-attach-metadata-and-poisoned-dtv-rejection-strong-main-and-weak-dso-import-rejection-before-fs-and-static-no-pt-interp-observer-rejection-without-record-import",
        "scope": "one-general-initial-generation-loader-observer-wire-no-crt-handoff-installed-dynamic-product-pthread-new-thread-dtv-growth-replacement-runtime-map-dlopen-unload-or-product-family-capability-promotion",
    },
    {
        "id": "dynamic-main-thread-runtime-v1-bridge",
        "state": "private-foundation-complete",
        "required": (
            "source-and-cargo-target-root-real-scrt1-attach-before-private-libc-startup-"
            "prove-pimfl-main-and-libc-dynamic-tls-and-errno-null-owned-handoff-dso-"
            "definition-noninterposition-metadata-and-poisoned-dtv-rejection-before-"
            "callbacks-and-strong-main-weak-dso-owned-record-rejection-before-fs"
        ),
        "scope": (
            "one-general-initial-generation-real-scrt1-private-dynamic-libc-evidence-"
            "no-owned-crt-carrier-loader-finalizer-dependency-lifecycle-handoff-installed-"
            "product-pthread-new-thread-dtv-growth-runtime-map-dlopen-unload-or-product-"
            "family-capability-promotion"
        ),
    },
    {
        "id": "initial-dynamic-variant-ii-layout",
        "state": "implemented-unqualified",
        "required": "installed-dynamic-pie-and-non-pie-prove-tls-template-copy-tbss-alignment-fs-self-and-dtv",
    },
    {
        "id": "pthread-dynamic-thread-materialization",
        "state": "implemented-unqualified",
        "required": "owned-pthread-workers-observe-fresh-libc-and-dso-tls-with-clone_settls-from-runtimev1",
    },
    {
        "id": "runtime-tls-dtv-growth",
        "state": "implemented-unqualified",
        "required": "runtime-pt-tls-dso-before-and-after-worker-creation-proves-generation-refresh-and-safe-reclamation",
    },
    {
        "id": "runtime-new-ie-rejection",
        "state": "implemented-unqualified",
        "required": "runtime-new-ie-rejected-before-callback-and-publication-while-gd-growth-and-initial-ie-reopen-remain-supported",
    },
    {
        "id": "fork-cancellation-and-tls-lifetime",
        "state": "implemented-unqualified",
        "required": "loader-pthread-fork-repair-cancellation-and-dlclose-or-retention-stress-runs-through-owned-dynamic-artifacts",
    },
]


class TlsRuntimeContractError(ValueError):
    """The private TLS RuntimeV1 contract has drifted or been overclaimed."""


def load_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as source:
            value = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise TlsRuntimeContractError(f"cannot read TLS RuntimeV1 contract {path}: {error}") from error
    if not isinstance(value, dict):
        raise TlsRuntimeContractError("TLS RuntimeV1 contract must be a TOML table")
    return value


def require_exact_mapping(value: object, expected: Mapping[str, object], label: str) -> None:
    if not isinstance(value, Mapping) or dict(value) != dict(expected):
        raise TlsRuntimeContractError(f"{label} contract drifted")


def require_exact_rows(value: object, expected: list[dict[str, object]], label: str) -> None:
    if not isinstance(value, list) or value != expected:
        raise TlsRuntimeContractError(f"{label} contract drifted")


def validate_contract(document: Mapping[str, object]) -> dict[str, object]:
    expected_top_level = {
        "schema",
        "id",
        "status",
        "non_promoting",
        "oracle",
        "target",
        "process_modes",
        "runtime_v1",
        "initial_tls_foundation",
        "initial_tls_registry_foundation",
        "general_initial_tls_runtime_v1_foundation",
        "dynamic_main_thread_runtime_v1_bridge",
        "variant_ii",
        "dtv",
        "current_artifact",
        "integration",
        "evidence",
        "owned_runtime",
    }
    if set(document) != expected_top_level:
        raise TlsRuntimeContractError("TLS RuntimeV1 top-level contract drifted")
    if document.get("schema") != SCHEMA or document.get("id") != CONTRACT_ID:
        raise TlsRuntimeContractError("TLS RuntimeV1 identity contract drifted")
    if document.get("status") != "implemented-unqualified" or document.get("non_promoting") is not True:
        raise TlsRuntimeContractError("TLS RuntimeV1 status must remain implemented-unqualified and non-promoting")
    if document.get("oracle") != (
        "musl-1.2.6 ldso/dynlink.c initial TLS and DTV lifecycle; "
        "Linux 5.10 x86-64 ARCH_SET_FS and CLONE_SETTLS"
    ):
        raise TlsRuntimeContractError("TLS RuntimeV1 oracle contract drifted")

    require_exact_mapping(document.get("owned_runtime"), OWNED_RUNTIME, "owned runtime")
    require_exact_mapping(document.get("target"), TARGET, "TLS RuntimeV1 target")
    process_modes = document.get("process_modes")
    if not isinstance(process_modes, Mapping) or set(process_modes) != set(PROCESS_MODES):
        raise TlsRuntimeContractError("process mode roster drifted")
    require_exact_mapping(process_modes.get("static"), PROCESS_MODES["static"], "static mode")
    require_exact_mapping(process_modes.get("dynamic"), PROCESS_MODES["dynamic"], "dynamic mode")
    require_exact_mapping(document.get("runtime_v1"), RUNTIME_V1, "RuntimeV1 handshake")
    require_exact_mapping(
        document.get("initial_tls_foundation"),
        INITIAL_TLS_FOUNDATION,
        "initial-TLS foundation",
    )
    require_exact_mapping(
        document.get("initial_tls_registry_foundation"),
        INITIAL_TLS_REGISTRY_FOUNDATION,
        "initial-TLS registry foundation",
    )
    require_exact_mapping(
        document.get("general_initial_tls_runtime_v1_foundation"),
        GENERAL_INITIAL_TLS_RUNTIME_V1_FOUNDATION,
        "general initial-TLS RuntimeV1 foundation",
    )
    require_exact_mapping(
        document.get("dynamic_main_thread_runtime_v1_bridge"),
        DYNAMIC_MAIN_THREAD_RUNTIME_V1_BRIDGE,
        "dynamic main-thread RuntimeV1 bridge",
    )
    require_exact_mapping(document.get("variant_ii"), VARIANT_II, "Variant-II")
    require_exact_mapping(document.get("dtv"), DTV, "DTV")
    require_exact_rows(document.get("current_artifact"), CURRENT_ARTIFACTS, "current-artifact")
    require_exact_rows(document.get("integration"), INTEGRATION, "future-integration")
    require_exact_rows(document.get("evidence"), EVIDENCE, "evidence")

    for row in CURRENT_ARTIFACTS:
        path = ROOT / row["path"]
        if not path.is_file():
            raise TlsRuntimeContractError(f"current-artifact path is missing: {row['path']}")
    for row in INTEGRATION:
        path = ROOT / row["path"]
        if not path.exists():
            raise TlsRuntimeContractError(f"future-integration path is missing: {row['path']}")
    for path in (
        ROOT / "ldso" / "src" / "x86_64_initial_graph.rs",
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "loader_tls_runtime_v1.rs",
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "loader_tls_runtime_v1_source_root.rs",
        ROOT / "compat" / "x86_64" / "run_loader_libc_tls_runtime_v1.sh",
        ROOT / "ldso" / "src" / "x86_64_initial_tls_registry.rs",
        ROOT / "compat" / "x86_64" / "run_loader_libc_tls_runtime_v1_registry.sh",
        ROOT / "ldso" / "src" / "x86_64_general_initial_loader_state.rs",
        ROOT / "ldso" / "src" / "x86_64_general_initial_tls_state.rs",
        ROOT / "ldso" / "src" / "x86_64_general_initial_tls_source_root.rs",
        ROOT / "ldso" / "src" / "x86_64_general_initial_tls_runtime_v1_source_root.rs",
        ROOT / "compat" / "x86_64" / "run_ldso_general_initial_tls.sh",
        ROOT / "compat" / "x86_64" / "run_ldso_general_initial_tls_target_root.sh",
        ROOT / "compat" / "x86_64" / "run_loader_libc_general_tls_runtime_v1.sh",
        ROOT / "compat" / "x86_64" / "run_loader_libc_general_tls_runtime_v1_target_root.sh",
        ROOT / "ldso" / "src" / "x86_64_dynamic_main_thread_runtime_v1_source_root.rs",
        ROOT / "crt" / "build_x86_64.py",
        ROOT / "crt" / "src" / "x86_64_dynamic_startup.rs",
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dynamic_main_thread_runtime_v1_source_root.rs",
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "dynamic_main_thread_runtime_v1.rs",
        ROOT / "compat" / "x86_64" / "run_dynamic_main_thread_runtime_v1.sh",
        ROOT / "compat" / "x86_64" / "run_dynamic_main_thread_runtime_v1_target_root.sh",
    ):
        if not path.is_file():
            raise TlsRuntimeContractError(f"initial-TLS foundation path is missing: {path.relative_to(ROOT)}")

    integration_by_id = {row["id"]: row for row in INTEGRATION}
    return {
        "schema": SCHEMA,
        "id": CONTRACT_ID,
        "status": "implemented-unqualified",
        "runtime_v1_published": False,
        "private_initial_tls_foundation": True,
        "initial_tls_foundation_state": INITIAL_TLS_FOUNDATION["state"],
        "private_initial_tls_registry_foundation": True,
        "initial_tls_registry_foundation_state": INITIAL_TLS_REGISTRY_FOUNDATION["state"],
        "private_general_initial_tls_foundation": True,
        "general_initial_tls_materialization_state": integration_by_id[
            "ldso-x86-main-thread-materialization"
        ]["state"],
        "private_general_initial_tls_runtime_v1_foundation": True,
        "general_initial_tls_runtime_v1_foundation_state": GENERAL_INITIAL_TLS_RUNTIME_V1_FOUNDATION[
            "state"
        ],
        "private_dynamic_main_thread_runtime_v1_bridge": True,
        "dynamic_main_thread_runtime_v1_bridge_state": DYNAMIC_MAIN_THREAD_RUNTIME_V1_BRIDGE[
            "state"
        ],
        "current_runtime_v1_producers": [
            row["id"] for row in CURRENT_ARTIFACTS if row["runtime_v1_producer"]
        ],
        "process_modes": list(PROCESS_MODES),
        "evidence_states": [row["state"] for row in EVIDENCE],
        "integration": [row["id"] for row in INTEGRATION],
    }


def load_contract() -> dict[str, object]:
    report = validate_contract(load_toml(CONTRACT_PATH))
    sys.path.insert(0, str(CONTRACT_PATH.parent))
    import owned_dynamic_qualification as qualification
    try:
        receipt = qualification.load_publication()
    except (qualification.QualificationError, OSError, ValueError) as error:
        raise TlsRuntimeContractError(f"invalid RuntimeV1 publication evidence: {error}") from error
    if receipt is not None:
        report["status"] = "verified"
        report["runtime_v1_published"] = True
        report["qualification_source_sha256"] = receipt["source_sha256"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the validated non-promoting report")
    arguments = parser.parse_args(argv)
    report = load_contract()
    if arguments.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"{report['id']}: {report['status']}; "
            "private initial-TLS foundation is not a published RuntimeV1 product"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TlsRuntimeContractError as error:
        raise SystemExit(f"x86 loader/libc TLS RuntimeV1 contract: {error}")
