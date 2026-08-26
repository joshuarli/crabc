#!/usr/bin/env python3
"""Focused contract tests for the x86 runtime-parity ledger."""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "validate_parity_ledger.py"
SPEC = importlib.util.spec_from_file_location("x86_parity_ledger", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)


class X86ParityLedgerTests(unittest.TestCase):
    def data(self) -> dict[str, object]:
        return copy.deepcopy(ledger.load_toml(ledger.LEDGER_PATH))

    @staticmethod
    def family(data: dict[str, object], identifier: str) -> dict[str, object]:
        entries = data["family"]
        assert isinstance(entries, list)
        for entry in entries:
            assert isinstance(entry, dict)
            if entry["id"] == identifier:
                return entry
        raise AssertionError(f"missing family: {identifier}")

    def test_checked_in_ledger_is_closed_and_not_a_public_support_claim(self) -> None:
        report = ledger.validate_ledger(self.data())
        self.assertEqual(report["schema"], "crabc.x86_64-runtime-parity/v1")
        self.assertEqual(report["family_count"], 26)
        self.assertEqual(report["status_counts"], {"foundation-verified": 7, "planned": 19})
        self.assertEqual(report["capability_count"], 223)
        self.assertEqual(len(report["capability_owners"]), 223)
        self.assertFalse(report["promotion_ready"])
        self.assertFalse(report["public_support"])

    def test_foundations_remain_narrow_and_source_or_artifact_scoped(self) -> None:
        data = self.data()
        direct = self.family(data, "facade.direct")
        remaining = self.family(data, "facade.record-owning")
        self.assertEqual(self.family(data, "libc.raw-syscall")["status"], "foundation-verified")
        self.assertEqual(self.family(data, "libc.errno-tls")["status"], "foundation-verified")
        self.assertEqual(self.family(data, "ldso.relative-relocation")["status"], "foundation-verified")
        self.assertEqual(self.family(data, "crt.static-pie")["status"], "foundation-verified")
        self.assertEqual(self.family(data, "libc.headers-layouts")["status"], "planned")
        self.assertEqual(self.family(data, "ldso.dynamic-runtime")["status"], "planned")
        self.assertEqual(self.family(data, "sysroot.owned-artifact")["status"], "planned")
        for capability in (
            "io.readiness-poll",
            "io.readiness-ppoll",
            "event.pause",
            "process.pid-observation",
            "process.identity-triples",
            "process.identity",
            "process.session-observation",
            "process.pidfd-open",
            "thread.identity",
            "thread.cpu-observation",
            "system.load-average",
            "system.name-observation",
            "system.identity-info",
            "memory.mapping-remap",
            "memory.mapping-locking",
            "memory.mapping-sync",
            "memory.advice",
            "memory.residency",
            "filesystem.access-advice",
            "filesystem.readahead",
            "process.fcntl-lock-observation",
            "process.scheduling-priority",
            "process.scheduler-priority-bounds",
            "time.realtime-millis",
            "time.timespec-get",
            "time.process-cpu-observation",
            "time.relative-sleep",
            "time.sleep-aliases",
        ):
            self.assertIn(capability, direct["capabilities"])
            self.assertNotIn(capability, remaining["capabilities"])
        for capability in (
            "io.readiness",
            "io.readiness-epoll",
            "memory.vm",
            "time.clock-query",
            "time.clock-sleep",
        ):
            self.assertNotIn(capability, direct["capabilities"])
            self.assertIn(capability, remaining["capabilities"])
        self.assertIn(
            "crabc-rs/tests/x86_64_epoll.rs", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_epoll_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/tests/x86_64_timerfd.rs", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/tests/x86_64_pselect.rs", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/tests/x86_64_rlimit.rs", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/tests/x86_64_rusage.rs", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/tests/x86_64_times.rs", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/tests/x86_64_getgroups.rs", remaining["source_owners"]
        )
        self.assertIn(
            "crabc-rs/src/process_x86_64.rs", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_timerfd_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_pselect_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_rlimit_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_rusage_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_times_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_x86_getgroups_reference.sh", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/x86_rusage_reference_probe.c", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/x86_times_reference_probe.c", remaining["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/x86_getgroups_reference_probe.c", remaining["source_owners"]
        )
        self.assertEqual(
            remaining["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh epoll-reference",
        )
        self.assertEqual(remaining["native_evidence"][0]["state"], "required")
        self.assertEqual(
            remaining["native_evidence"][1]["command"],
            "./scripts/dev-x86_64.sh timerfd-reference",
        )
        self.assertEqual(remaining["native_evidence"][1]["state"], "required")
        self.assertEqual(
            remaining["native_evidence"][2]["command"],
            "./scripts/dev-x86_64.sh pselect-reference",
        )
        self.assertEqual(remaining["native_evidence"][2]["state"], "required")
        self.assertEqual(
            remaining["native_evidence"][3]["command"],
            "./scripts/dev-x86_64.sh rlimit-reference",
        )
        self.assertEqual(remaining["native_evidence"][3]["state"], "required")
        self.assertEqual(
            remaining["native_evidence"][4]["command"],
            "./scripts/dev-x86_64.sh rusage-reference",
        )
        self.assertEqual(remaining["native_evidence"][4]["state"], "required")
        self.assertEqual(
            remaining["native_evidence"][5]["command"],
            "./scripts/dev-x86_64.sh times-reference",
        )
        self.assertEqual(remaining["native_evidence"][5]["state"], "required")
        self.assertEqual(
            remaining["native_evidence"][6]["command"],
            "./scripts/dev-x86_64.sh getgroups-reference",
        )
        self.assertEqual(remaining["native_evidence"][6]["state"], "required")
        self.assertNotIn("filesystem.path-core", direct["capabilities"])
        self.assertIn("filesystem.path-core", remaining["capabilities"])
        self.assertNotIn("filesystem.access-advice", remaining["capabilities"])
        self.assertNotIn("process.scheduling-priority", remaining["capabilities"])
        self.assertNotIn("process.resource-limits", direct["capabilities"])
        self.assertIn("process.resource-limits", remaining["capabilities"])
        self.assertIn("process.resource-limits-targeted", remaining["capabilities"])
        self.assertNotIn("process.resource-usage", direct["capabilities"])
        self.assertIn("process.resource-usage", remaining["capabilities"])
        self.assertNotIn("time.process-accounting", direct["capabilities"])
        self.assertIn("time.process-accounting", remaining["capabilities"])
        self.assertNotIn("process.supplementary-groups", direct["capabilities"])
        self.assertIn("process.supplementary-groups", remaining["capabilities"])
        pthread_tls = self.family(data, "libc.pthread-tls")
        self.assertEqual(pthread_tls["status"], "planned")
        self.assertIn("libc/src/c_abi/x86_64/atomic.rs", pthread_tls["source_owners"])
        self.assertEqual(
            pthread_tls["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh libc-atomic",
        )

    def test_musl_oracle_is_a_native_precondition_not_public_support(self) -> None:
        data = self.data()
        family = self.family(data, "oracle.musl-toolchain")
        self.assertEqual(family["status"], "foundation-verified")
        self.assertEqual(
            family["native_evidence"][0]["command"],
            "./scripts/dev-x86_64.sh musl-oracle",
        )
        self.assertIn("compat/x86_64/run_musl_oracle.sh", family["source_owners"])
        self.assertIn("docker/x86_64-musl-oracle-gcc", family["source_owners"])

    def test_every_musl_backed_family_depends_on_the_musl_oracle(self) -> None:
        data = self.data()
        for entry in data["family"]:
            assert isinstance(entry, dict)
            if entry["id"] != "oracle.musl-toolchain" and ledger.has_musl_oracle(entry):
                self.assertIn("oracle.musl-toolchain", entry["depends_on"])

        self.family(data, "libc.posix-runtime")["depends_on"].remove("oracle.musl-toolchain")
        with self.assertRaisesRegex(ledger.LedgerError, "must depend on oracle.musl-toolchain"):
            ledger.validate_ledger(data)

    def test_symbols_gate_is_accounted_for_by_the_abi_differential_family(self) -> None:
        data = self.data()
        self.assertIn("symbols", self.family(data, "compat.abi-differential")["aarch64_gates"])

    def test_baseline_capabilities_are_read_from_the_baseline_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.toml"
            path.write_text(
                '[[capability]]\nid = "dynamic.capability"\nkind = "semantic"\n',
                encoding="utf-8",
            )
            self.assertEqual(ledger.baseline_capability_ids(path), {"dynamic.capability"})

    def test_rejects_an_unassigned_baseline_capability(self) -> None:
        data = self.data()
        capabilities = self.family(data, "facade.direct")["capabilities"]
        assert isinstance(capabilities, list)
        capabilities.remove("random.state")
        with self.assertRaisesRegex(ledger.LedgerError, "leaves baseline capabilities unmapped: random.state"):
            ledger.validate_ledger(data)

    def test_rejects_a_duplicate_or_stale_capability_mapping(self) -> None:
        duplicate = self.data()
        self.family(duplicate, "core.architecture")["capabilities"].append("random.state")
        with self.assertRaisesRegex(ledger.LedgerError, "mapped by both"):
            ledger.validate_ledger(duplicate)

        stale = self.data()
        self.family(stale, "core.architecture")["capabilities"].append("obsolete.capability")
        with self.assertRaisesRegex(ledger.LedgerError, "maps stale baseline capabilities: obsolete.capability"):
            ledger.validate_ledger(stale)

    def test_rejects_a_missing_promotion_family(self) -> None:
        data = self.data()
        promotion = data["promotion"]
        assert isinstance(promotion, dict)
        required = promotion["required_families"]
        assert isinstance(required, list)
        required.pop()
        with self.assertRaisesRegex(ledger.LedgerError, "roster drifted"):
            ledger.validate_ledger(data)

    def test_rejects_a_dependency_that_is_not_earlier(self) -> None:
        data = self.data()
        self.family(data, "core.architecture")["depends_on"] = ["performance.release"]
        with self.assertRaisesRegex(ledger.LedgerError, "is not earlier"):
            ledger.validate_ledger(data)

    def test_rejects_a_foundation_misrepresented_as_complete_evidence(self) -> None:
        data = self.data()
        evidence = self.family(data, "libc.raw-syscall")["native_evidence"]
        assert isinstance(evidence, list) and evidence
        assert isinstance(evidence[0], dict)
        evidence[0]["state"] = "required"
        with self.assertRaisesRegex(ledger.LedgerError, "entirely verified"):
            ledger.validate_ledger(data)

    def test_rejects_an_unknown_aarch64_gate(self) -> None:
        data = self.data()
        self.family(data, "facade.direct")["aarch64_gates"] = ["invented-gate"]
        with self.assertRaisesRegex(ledger.LedgerError, "unknown AArch64 gates"):
            ledger.validate_ledger(data)


if __name__ == "__main__":
    unittest.main()
