#!/usr/bin/env python3
"""Focused boundary tests for private x86 general initial-TLS materialization."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LOADER = ROOT / "ldso" / "src" / "x86_64_initial_graph.rs"
GENERAL_GRAPH = ROOT / "ldso" / "src" / "x86_64_general_initial_graph.rs"
COMMON_STATE = ROOT / "ldso" / "src" / "x86_64_general_initial_loader_state.rs"
STATE = ROOT / "ldso" / "src" / "x86_64_general_initial_tls_state.rs"
SOURCE_ROOT = ROOT / "ldso" / "src" / "x86_64_general_initial_tls_source_root.rs"
RUNNER = ROOT / "compat" / "x86_64" / "run_ldso_general_initial_tls.sh"
TARGET_RUNNER = (
    ROOT / "compat" / "x86_64" / "run_ldso_general_initial_tls_target_root.sh"
)


class GeneralInitialTlsMaterializationTests(unittest.TestCase):
    def test_common_loader_owner_and_tls_sidecar_are_explicit_and_generation_one_only(self) -> None:
        common_state = COMMON_STATE.read_text(encoding="utf-8")
        state = STATE.read_text(encoding="utf-8")
        root = SOURCE_ROOT.read_text(encoding="utf-8")

        for required in (
            "GeneralInitialTlsPhase",
            "Discovery",
            "Planned",
            "Relocated",
            "PublicationReserved",
            "Materialized",
            "Committed",
            "RolledBack",
            "InitialTlsRegistry",
            "InitialTlsGeneration",
            "ObjectIdentity",
            "TlsModuleId",
            "reject_runtime_tls_growth",
            "reserve_publication",
            "DtvGrowthProtocolUnavailable",
            "commit",
            "rollback",
        ):
            with self.subTest(required=required):
                self.assertIn(required, state)

        for required in (
            "GeneralInitialLoaderPhase",
            "Vacant",
            "Discovering",
            "Prepared",
            "Reserved",
            "Ready",
            "GENERAL_INITIAL_LOADER_PUBLICATION",
            "pub(crate) fn prepare",
            "pub(crate) fn reserve_publication",
            "pub(crate) unsafe fn commit",
            "pub(crate) fn retained",
            "attach_initial_tls",
            "map_provenance",
            "graph: InitialGraphState",
            "objects: [Object; MAX_OBJECTS]",
        ):
            with self.subTest(common_required=required):
                self.assertIn(required, common_state)

        for required in (
            "loader: GeneralInitialLoaderState",
            "GeneralInitialTlsAttachment",
            "GENERAL_INITIAL_TLS_ATTACHMENT",
            "self.loader.attach_initial_tls()",
            "publish_initial_tls_attachment",
        ):
            with self.subTest(sidecar_required=required):
                self.assertIn(required, state)

        self.assertNotIn("graph: InitialGraphState", state)
        self.assertNotIn("objects: [Object; MAX_OBJECTS]", state)
        self.assertNotIn("GENERAL_INITIAL_TLS_PUBLISHING", state)
        self.assertNotIn("GENERAL_INITIAL_TLS_COMMITTED", state)
        self.assertLess(
            common_state.index("pub(crate) fn prepare"),
            common_state.index("pub(crate) fn reserve_publication"),
        )
        self.assertLess(
            common_state.index("pub(crate) fn reserve_publication"),
            common_state.index("pub(crate) unsafe fn commit"),
        )
        # The ordinary direct root cannot accidentally acquire the descriptor
        # just because its shared state also carries the separate cfg-isolated
        # general RuntimeV1 producer.
        self.assertIn("crabc_general_loader_libc_tls_runtime_v1", state)
        self.assertNotIn("crabc_general_loader_libc_tls_runtime_v1", root)

    def test_general_tls_cfg_is_isolated_from_fixed_runtime_v1_and_keeps_tls_relocations_narrow(self) -> None:
        loader = LOADER.read_text(encoding="utf-8")
        graph = GENERAL_GRAPH.read_text(encoding="utf-8")

        self.assertIn("crabc_general_initial_tls_materialization_v1", loader)
        self.assertIn("x86_64_general_initial_tls_state", loader)
        self.assertIn("R_X86_64_DTPMOD64", loader)
        self.assertIn("R_X86_64_DTPOFF64", loader)
        self.assertIn("R_X86_64_TLSDESC", loader)
        self.assertIn("__tls_get_addr", loader)
        self.assertIn("materialize_initial_tls", graph)
        self.assertIn("reject_runtime_tls_growth", graph)
        self.assertLess(
            graph.index("state.reserve_publication()"),
            graph.index("state.materialize_initial_tls()"),
        )
        self.assertIn("unsafe { state.commit(installed) };", graph)
        self.assertNotIn("state.commit() }.map_err", graph)
        self.assertIn("not a RuntimeV1 producer", graph)

    def test_native_evidence_has_a_separate_general_tls_root_and_negative_coverage(self) -> None:
        root = SOURCE_ROOT.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        target_runner = TARGET_RUNNER.read_text(encoding="utf-8")

        self.assertIn("crabc_general_initial_tls_materialization_v1", root)
        for required in (
            "DTPMOD64",
            "DTPOFF64",
            "TLSDESC",
            "TPOFF",
            "p_filesz",
            "capacity",
            "overflow",
            "ARCH_SET_FS",
            "duplicate",
            "tbss",
            "alignment",
        ):
            with self.subTest(required=required):
                self.assertIn(required, runner)
        self.assertIn("CRABC_LDSO_GENERAL_INITIAL_TLS_ROOT=crabc-target", target_runner)


if __name__ == "__main__":
    unittest.main()
