#!/usr/bin/env python3
"""Focused admission and retained-observation tests for public data evidence."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "public_data_ordinary_link_evidence_test",
    ROOT / "compat/x86_64/public_data_ordinary_link_evidence.py",
)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


class PublicDataOrdinaryLinkEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/x86_64/public-data-ordinary-link-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.root = Path(self.temporary.name)
        (self.root / ".work/input/static/products/primary/share/crabc").mkdir(parents=True)
        (self.root / ".work/input/dynamic/share/crabc").mkdir(parents=True)
        self.preparation = self.root / ".work/input/static/preparation.json"
        self.static = self.root / ".work/input/static/products/primary"
        self.dynamic = self.root / ".work/input/dynamic"
        self.static_manifest = self.static / "share/crabc/manifest.json"
        self.dynamic_manifest = self.dynamic / "share/crabc/manifest.json"
        self.dynamic_state = self.dynamic / "share/crabc/dynamic-product-state.json"
        for path in (self.preparation, self.static_manifest, self.dynamic_manifest, self.dynamic_state):
            path.write_text("{}\n", encoding="utf-8")
        self.source = {"revision": "a" * 40, "content_sha256": "b" * 64}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def preparation_record(self, product: Path | None = None) -> dict:
        product = self.static if product is None else product
        manifest = evidence.work_file_identity(self.root, product / "share/crabc/manifest.json", "static manifest")
        return {
            "source": dict(self.source),
            "products": {"primary": {"path": product.relative_to(self.root).as_posix(), "manifest": manifest}},
        }

    def admit(self, *, preparation: dict | None = None, state_source: str | None = None,
              product: Path | None = None) -> dict:
        preparation = self.preparation_record(product) if preparation is None else preparation
        state_source = self.source["content_sha256"] if state_source is None else state_source
        with (
            mock.patch.object(evidence.static_products, "validate_receipt", return_value=preparation),
            mock.patch.object(evidence.static_products, "source_identity", return_value=dict(self.source)),
            mock.patch.object(
                evidence.qualification,
                "product_identity",
                return_value=hashlib.sha256(self.dynamic_manifest.read_bytes()).hexdigest(),
            ),
            mock.patch.object(evidence.qualification, "read", return_value={"source_sha256": state_source}),
        ):
            return evidence.admit_inputs(self.root, self.preparation, self.static, self.dynamic)

    def test_policy_selects_exact_32_objects_and_ten_declared_aliases(self) -> None:
        objects, aliases = evidence.selected_objects()
        self.assertEqual(len(objects), 32)
        self.assertEqual(len(aliases), 10)
        self.assertEqual({item["name"] for item in objects if item["declaration_kind"] == "abi-only"},
                         evidence.ABI_ONLY_NAMES)
        self.assertNotIn("_dl_debug_addr", {item["name"] for item in objects})

    def test_omitted_object_or_alias_is_rejected_before_probe_observation(self) -> None:
        contract = copy.deepcopy(evidence.selection.load_contract())
        contract["object_contracts"] = [
            item for item in contract["object_contracts"] if item["name"] != "stdout"
        ]
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "32"):
            evidence.selected_objects(contract)
        contract = copy.deepcopy(evidence.selection.load_contract())
        next(item for item in contract["object_contracts"] if item["name"] == "tzname")["alias_target"] = ""
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "aliases"):
            evidence.selected_objects(contract)

    def test_probe_alignment_and_alias_literals_are_bound_to_typed_policy(self) -> None:
        contract = copy.deepcopy(evidence.selection.load_contract())
        next(item for item in contract["object_contracts"] if item["name"] == "__timezone")["alignment_bytes"] = 16
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "probe alignment"):
            evidence.selected_objects(contract)

    def test_admission_rejects_wrong_prepared_primary_and_source_mismatch(self) -> None:
        wrong = self.root / ".work/input/static/products/other"
        (wrong / "share/crabc").mkdir(parents=True)
        (wrong / "share/crabc/manifest.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "not preparation primary"):
            self.admit(preparation=self.preparation_record(wrong))
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "source digests differ"):
            self.admit(state_source="c" * 64)

    def test_admission_returns_both_sealed_product_identities(self) -> None:
        admitted = self.admit()
        self.assertEqual(admitted["source"], self.source)
        self.assertEqual(admitted["static_preparation"]["primary"]["path"],
                         self.static.relative_to(self.root).as_posix())
        self.assertEqual(admitted["dynamic_product"]["path"], self.dynamic.relative_to(self.root).as_posix())

    def test_strict_json_accepts_raw_command_arrays_and_rejects_nonfinite_numbers(self) -> None:
        command = self.root / ".work/raw-command.json"
        command.write_text('["/usr/bin/readelf", "-hW", "probe.o"]\n', encoding="utf-8")
        self.assertEqual(
            evidence.read_json(command, "raw command", list),
            ["/usr/bin/readelf", "-hW", "probe.o"],
        )
        malformed = self.root / ".work/nonfinite.json"
        malformed.write_text('[1e9999]\n', encoding="utf-8")
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "non-finite"):
            evidence.read_json(malformed, "nonfinite command", list)

    def test_fresh_output_rejects_a_dangling_symlink(self) -> None:
        output = self.root / ".work/dangling-output"
        output.symlink_to("does-not-exist")
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "symlink"):
            evidence.fresh_output(self.root, output)

    def test_output_cannot_enter_a_supplied_preparation_or_product_tree(self) -> None:
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "preparation cohort"):
            evidence.admit_output_disjoint(
                self.root, self.root / ".work/input/static/new-output",
                self.preparation, self.static, self.dynamic,
            )
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "dynamic product"):
            evidence.admit_output_disjoint(
                self.root, self.root / ".work/input/dynamic/new-output",
                self.preparation, self.static, self.dynamic,
            )

    def test_cli_requires_each_collect_option_once_without_abbreviation(self) -> None:
        arguments = [
            "collect", "--static-preparation", ".work/preparation.json",
            "--static-product", ".work/static", "--dynamic-product", ".work/dynamic",
            "--output", ".work/output",
        ]
        parsed = evidence.parse_cli(arguments)
        self.assertEqual(parsed.static_preparation, Path(".work/preparation.json"))
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                evidence.parse_cli([*arguments, "--output", ".work/second-output"])
            with self.assertRaises(SystemExit):
                evidence.parse_cli([
                    "collect", "--static-prep", ".work/preparation.json",
                    "--static-product", ".work/static", "--dynamic-product", ".work/dynamic",
                    "--output", ".work/output",
                ])

    def test_command_roster_round_trips_and_keeps_candidate_file_names_separate_from_owner(self) -> None:
        inputs = self.admit()
        work = self.root / ".work/command-roster"
        work.mkdir()
        tools = {
            name: {"original": {"path": "/sealed/" + name}}
            for name in ("static_driver", "dynamic_driver", "oracle_wrapper", "compiler", "linker",
                         "env", "readelf")
        }
        tools["chroot"] = {
            "original": {"path": "/bin/coreutils"},
            "invocation": {"path": "/usr/sbin/chroot", "physical_path": "/bin/coreutils"},
        }
        expected = evidence.expected_commands(self.root, work, inputs, tools)
        self.assertEqual(tuple(expected), evidence.expected_command_labels())
        self.assertEqual(
            expected["dynamic-pie-kernel"]["argv"],
            ["/sealed/env", "-i", "/usr/sbin/chroot", evidence.mounted(self.root, work / "candidate-root"),
             "/consumer-pie"],
        )
        self.assertNotIn("candidate-dynamic-pie-kernel", expected)
        records = []
        (work / "raw").mkdir()
        for label, item in expected.items():
            command = evidence.raw_path(work, label, "command.json")
            stdout = evidence.raw_path(work, label, "stdout")
            stderr = evidence.raw_path(work, label, "stderr")
            status = evidence.raw_path(work, label, "status")
            command.write_text(json.dumps(item["argv"]) + "\n", encoding="utf-8")
            stdout.write_bytes(evidence.EXPECTED_STDOUT if label in evidence.EXECUTION_LABELS else b"")
            stderr.write_bytes(b"")
            status.write_bytes(b"0\n")
            records.append({
                "label": label, "argv": item["argv"], "cwd": item["cwd"], "outcome": "ok",
                "command": evidence.work_file_identity(self.root, command, "command"),
                "stdout": evidence.work_file_identity(self.root, stdout, "stdout"),
                "stderr": evidence.work_file_identity(self.root, stderr, "stderr"),
                "status": evidence.work_file_identity(self.root, status, "status"),
            })
        evidence.write_new_json(work / "commands.json", records)
        replayed = evidence.read_json(work / "commands.json", "commands", list)
        evidence.validate_command_records(self.root, work, inputs, tools, replayed)
        substituted = copy.deepcopy(replayed)
        unrelated = work / "unrelated.stdout"
        unrelated.write_bytes(b"")
        next(item for item in substituted if item["label"] == "object-symbols")["stdout"] = evidence.work_file_identity(
            self.root, unrelated, "substituted stdout"
        )
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "raw path"):
            evidence.validate_command_records(self.root, work, inputs, tools, substituted)

    def test_chroot_commands_keep_the_sealed_multicall_invocation_spelling(self) -> None:
        inputs = self.admit()
        work = self.root / ".work/chroot-command"
        work.mkdir()
        tools = {
            name: {"original": {"path": "/sealed/" + name}}
            for name in ("static_driver", "dynamic_driver", "oracle_wrapper", "compiler", "linker",
                         "env", "readelf")
        }
        tools["chroot"] = {
            "original": {"path": "/bin/coreutils"},
            "invocation": {"path": "/usr/sbin/chroot", "physical_path": "/bin/coreutils"},
        }
        commands = evidence.expected_commands(self.root, work, inputs, tools)
        self.assertEqual(
            commands["oracle-dynamic-pie-kernel"]["argv"][:3],
            ["/sealed/env", "-i", "/usr/sbin/chroot"],
        )

    def test_collector_raw_writer_round_trips_to_symbol_and_elf_projections(self) -> None:
        output = self.root / ".work/collector-raw-round-trip"
        output.mkdir()
        collector = evidence.Collector(self.root, output, self.preparation, self.static, self.dynamic)

        def capture(label: str, payload: bytes) -> None:
            collector.run(label, [sys.executable, "-c", "import sys; sys.stdout.buffer.write(" + repr(payload) + ")"])

        symbols = b"""Symbol table '.symtab' contains 1 entry:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND probe
"""
        capture("object-symbols", symbols)
        for name, expected in evidence.EXECUTABLE_ELF_MODES.items():
            (output / name).write_bytes((name + " executable").encode("ascii"))
            header = (
                "  Class:                             ELF64\n"
                "  Data:                              2's complement, little endian\n"
                "  Machine:                           Advanced Micro Devices X86-64\n"
                f"  Type:                              {expected['type']} (test)\n"
            ).encode("ascii")
            capture(name + "-header", header)
            program = b""
            if expected["interpreter"] is not None:
                program = (
                    b"  INTERP         0x000000 0x0000000000000000 0x0000000000000000\n"
                    + f"      [Requesting program interpreter: {expected['interpreter']}]\n".encode("ascii")
                )
            capture(name + "-program", program)
        evidence.write_new_json(output / "commands.json", collector.commands)
        commands = evidence.read_json(output / "commands.json", "collector commands", list)
        object_command = next(record for record in commands if record["label"] == "object-symbols")
        self.assertEqual(
            evidence.resolve_work_identity(self.root, object_command["stdout"], "collector symbols stdout"),
            evidence.raw_path(output, "object-symbols", "stdout"),
        )
        self.assertEqual(evidence.rows_for(output, "object-symbols")[0]["name"], "probe")
        observed = evidence.executable_observations(self.root, output)
        evidence.write_new_json(output / "executables.json", observed)
        evidence.validate_executable_observations(
            self.root, output, evidence.read_json(output / "executables.json", "collector executables", dict),
        )

    def test_timeout_retains_terminal_outcome_and_kills_owned_descendants(self) -> None:
        output = self.root / ".work/timeout"
        output.mkdir()
        child_pid = self.root / ".work/timeout-child.pid"
        child = (
            "import os, time\n"
            f"open({str(child_pid)!r}, 'w', encoding='ascii').write(str(os.getpid()))\n"
            "time.sleep(30)\n"
        )
        parent = (
            "import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
            "time.sleep(30)\n"
        )
        collector = evidence.Collector(self.root, output, self.preparation, self.static, self.dynamic)
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "timed out"):
            collector.run("timeout", [sys.executable, "-c", parent], timeout_seconds=0.1)
        self.assertEqual((output / "raw/timeout.status").read_text(encoding="ascii").split(":", 1)[0], "timed-out")
        self.assertEqual(collector.commands[-1]["outcome"], "timed-out")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(int(child_pid.read_text(encoding="ascii")), 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail("timeout left an owned descendant alive")

    def test_execution_root_replay_binds_interpreters_and_consumers(self) -> None:
        work = self.root / ".work/execution"
        dynamic = self.root / ".work/execution-product"
        (dynamic / "lib").mkdir(parents=True)
        (dynamic / "lib/ld-crabc-x86_64.so.1").write_bytes(b"candidate interpreter")
        (dynamic / "lib/ld-crabc-x86_64.so.1").chmod(0o600)
        (dynamic / "usr/lib").mkdir(parents=True)
        (dynamic / "usr/lib/libc.so").write_bytes(b"candidate libc")
        (work / "qualification-oracle").mkdir(parents=True)
        (work / "qualification-oracle/runtime").write_bytes(b"oracle interpreter")
        for owner in ("dynamic", "oracle-dynamic"):
            for mode in ("pie", "non-pie"):
                (work / (owner + "-" + mode)).parent.mkdir(parents=True, exist_ok=True)
                (work / (owner + "-" + mode)).write_bytes((owner + mode).encode())
        import shutil
        shutil.copytree(dynamic, work / "candidate-root", symlinks=True)
        oracle_root = work / "oracle-root"
        (oracle_root / "lib").mkdir(parents=True)
        shutil.copy2(work / "qualification-oracle/runtime", oracle_root / "lib/ld-musl-x86_64.so.1")
        (oracle_root / "lib/libc.so").symlink_to("ld-musl-x86_64.so.1")
        for mode in ("pie", "non-pie"):
            shutil.copy2(work / ("dynamic-" + mode), work / "candidate-root" / ("consumer-" + mode))
            shutil.copy2(work / ("oracle-dynamic-" + mode), oracle_root / ("consumer-" + mode))
        roots = evidence.capture_execution_roots(self.root, work, dynamic)
        evidence.static_products.make_retained_evidence_readable(work)
        evidence.validate_execution_roots(self.root, work, dynamic, roots)
        (work / "candidate-root/lib/ld-crabc-x86_64.so.1").write_bytes(b"changed interpreter")
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "execution root"):
            evidence.validate_execution_roots(self.root, work, dynamic, roots)
        (work / "candidate-root/lib/ld-crabc-x86_64.so.1").write_bytes(b"candidate interpreter")
        (work / "candidate-root/consumer-pie").write_bytes(b"changed consumer")
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "consumer|execution root"):
            evidence.validate_execution_roots(self.root, work, dynamic, roots)

    def test_oracle_static_inputs_are_retained_without_live_opt_replay(self) -> None:
        work = self.root / ".work/oracle-static"
        work.mkdir()
        sources = {}
        for name in evidence.ORACLE_STATIC_INPUTS:
            path = self.root / ".work/oracle-inputs" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((name + " bytes").encode())
            sources[name] = path
        recorded = evidence.capture_oracle_static_inputs(work, sources)
        for name in evidence.ORACLE_STATIC_INPUTS:
            recorded[name]["original"]["path"] = str(evidence.ORACLE_STATIC_INPUTS[name])
        evidence.validate_oracle_static_inputs(work, recorded)
        rebound = copy.deepcopy(recorded)
        rebound["libc_a"]["original"]["path"] = "/arbitrary/oracle/libc.a"
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "original path"):
            evidence.validate_oracle_static_inputs(work, rebound)
        (work / "inputs/oracle-static/libc_a").write_bytes(b"changed")
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "oracle static"):
            evidence.validate_oracle_static_inputs(work, recorded)

    def test_all_oracle_and_candidate_executables_reopen_raw_elf_mode_views(self) -> None:
        work = self.root / ".work/executables"
        (work / "raw").mkdir(parents=True)
        for name, expected in evidence.EXECUTABLE_ELF_MODES.items():
            (work / name).write_bytes((name + " binary").encode())
            header = (
                "  Class:                             ELF64\n"
                "  Data:                              2's complement, little endian\n"
                "  Machine:                           Advanced Micro Devices X86-64\n"
                f"  Type:                              {expected['type']} (test)\n"
            )
            program = ""
            if expected["interpreter"] is not None:
                program = (
                    "  INTERP         0x000000 0x0000000000000000 0x0000000000000000\n"
                    f"      [Requesting program interpreter: {expected['interpreter']}]\n"
                )
            evidence.raw_path(work, name + "-header", "stdout").write_text(header, encoding="utf-8")
            evidence.raw_path(work, name + "-program", "stdout").write_text(program, encoding="utf-8")
        observed = evidence.executable_observations(self.root, work)
        evidence.write_new_json(work / "executables.json", observed)
        replayed = evidence.read_json(work / "executables.json", "executables", dict)
        evidence.validate_executable_observations(self.root, work, replayed)
        expected_interpreter = evidence.EXECUTABLE_ELF_MODES["dynamic-pie"]["interpreter"]
        evidence.raw_path(work, "dynamic-pie-program", "stdout").write_text(
            f"      [Requesting program interpreter: {expected_interpreter}-incorrect]\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "interpreter"):
            evidence.validate_executable_observations(self.root, work, observed)
        evidence.raw_path(work, "dynamic-pie-program", "stdout").write_text(
            f"      [Requesting program interpreter: {expected_interpreter}]\n"
            f"      [Requesting program interpreter: {expected_interpreter}]\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "interpreter"):
            evidence.validate_executable_observations(self.root, work, observed)
        evidence.raw_path(work, "oracle-static-header", "stdout").write_text(
            "Class: ELF64\nData: 2's complement, little endian\n"
            "Machine: Advanced Micro Devices X86-64\nType: DYN (test)\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "ELF"):
            evidence.validate_executable_observations(self.root, work, observed)

    def test_retained_tool_roster_seals_actual_compiler_linker_and_reader_bytes(self) -> None:
        inputs = self.admit()
        (self.static / "bin").mkdir()
        (self.dynamic / "bin").mkdir()
        (self.static / "bin/crabc-cc").write_bytes(b"static driver")
        (self.dynamic / "bin/crabc-cc-dynamic").write_bytes(b"dynamic driver")
        work = self.root / ".work/tools"
        tools = {}
        for role in evidence.TOOL_ROLES:
            retained = work / "inputs/tools" / role
            retained.parent.mkdir(parents=True, exist_ok=True)
            retained.write_bytes((role + " bytes").encode())
            retained.chmod(0o600)
            retained_identity = evidence.inventory.file_record(retained, logical_path=f"inputs/tools/{role}")
            if role == "static_driver":
                original_path = evidence.mounted(self.root, self.static / "bin/crabc-cc")
            elif role == "dynamic_driver":
                original_path = evidence.mounted(self.root, self.dynamic / "bin/crabc-cc-dynamic")
            elif role == "oracle_wrapper":
                original_path = "/usr/local/bin/crabc-x86_64-musl-gcc"
            elif role == "env":
                original_path = "/usr/bin/env"
            elif role == "readelf":
                original_path = str(evidence.inventory.TOOL_PATHS["readelf"])
            elif role == "chroot":
                original_path = "/bin/coreutils"
            else:
                original_path = "/sealed/" + role
            original = dict(retained_identity)
            original["path"] = original_path
            original["mode"] = 0o755
            tools[role] = {"original": original, "retained": retained_identity}
            if role == "chroot":
                tools[role]["invocation"] = {
                    "path": "/usr/sbin/chroot", "physical_path": "/bin/coreutils",
                }
        evidence.write_new_json(work / "tools.json", tools)
        replayed = evidence.read_json(work / "tools.json", "tool roster", dict)
        evidence.validate_tool_roster(self.root, work, inputs, replayed)
        wrong_invocation = copy.deepcopy(replayed)
        wrong_invocation["chroot"]["invocation"]["path"] = "/bin/coreutils"
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "chroot invocation"):
            evidence.validate_tool_roster(self.root, work, inputs, wrong_invocation)
        (work / "inputs/tools/linker").write_bytes(b"different linker")
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "tool replay"):
            evidence.validate_tool_roster(self.root, work, inputs, tools)

    def test_tool_snapshot_accepts_the_existing_path_hash_mode_identity_shape(self) -> None:
        work = self.root / ".work/tool-shape"
        source = self.root / ".work/tool-source"
        source.write_bytes(b"tool bytes")
        source.chmod(0o755)
        source_identity = evidence.wordexp._tool_identity(source, "fixture tool")
        snapshot = evidence.retain_tool_snapshot(work, "fixture", source_identity)
        self.assertEqual(
            {key: snapshot["original"][key] for key in source_identity},
            source_identity,
        )
        self.assertIn("size", snapshot["original"])

    def test_live_tool_roster_projects_snapshot_identity_for_chroot_applet_check(self) -> None:
        work = self.root / ".work/live-tool-roster"
        physical = self.root / ".work/fixture-coreutils"
        invocation = self.root / ".work/fixture-chroot"
        physical.write_bytes(b"tool bytes")
        physical.chmod(0o755)
        invocation.symlink_to(physical)
        with (
            mock.patch.object(evidence, "CHROOT_INVOCATION", invocation),
            mock.patch.object(evidence, "CHROOT_PHYSICAL", physical),
        ):
            source = evidence.wordexp._tool_identity(invocation, "fixture chroot")
            snapshot = evidence.retain_tool_snapshot(work, "chroot", source)
            snapshot["invocation"] = evidence.capture_chroot_invocation(source)
            tools = {
                role: {"original": dict(snapshot["original"])}
                for role in evidence.TOOL_ROLES
            }
            tools["chroot"] = snapshot
            evidence.write_new_json(work / "tools.json", tools)
            replayed = evidence.read_json(work / "tools.json", "live tool roster", dict)
            evidence.require_live_tool_roster(replayed)

    def test_retained_snapshot_replays_after_readability_finalization(self) -> None:
        work = self.root / ".work/finalized-snapshot"
        source = self.root / ".work/finalized-tool"
        source.write_bytes(b"tool bytes")
        source.chmod(0o755)
        snapshot = evidence.retain_tool_snapshot(work, "fixture", evidence.wordexp._tool_identity(source, "fixture"))
        evidence.static_products.make_retained_evidence_readable(work)
        evidence.inventory._validate_snapshot(
            work, snapshot, "finalized fixture", expected_retained_path="inputs/tools/fixture"
        )

    def test_candidate_link_rejects_a_wrong_driver_receipt_path(self) -> None:
        inputs = self.admit()
        work = self.root / ".work/receipt"
        work.mkdir()
        for name in ("probe.o", "static", "static-pie", "dynamic-pie", "dynamic-non-pie",
                     "static.crabc-link.json", "static-pie.crabc-link.json",
                     "dynamic-pie.crabc-link.json", "dynamic-non-pie.crabc-link.json"):
            (work / name).write_bytes(b"retained\n")
        links = {}
        tools = {"linker": {"original": {"path": "/opt/ld.lld", "sha256": "d" * 64}}}
        for mode, linkage, kind in (
            ("static", "static", "static"), ("static-pie", "static-pie", "static"),
            ("dynamic-pie", "pie", "dynamic"), ("dynamic-non-pie", "non-pie", "dynamic"),
        ):
            receipt = work / (mode + ".crabc-link.json")
            links[mode] = {
                "linkage": linkage, "product": kind,
                "receipt": evidence.work_file_identity(self.root, receipt, "receipt"),
                "executable": evidence.work_file_identity(self.root, work / mode, "executable"),
                "linker": {"path": "/opt/ld.lld", "sha256": "d" * 64},
                "product_manifest": (inputs["static_preparation"]["primary"]["manifest"]
                                     if kind == "static" else inputs["dynamic_product"]["manifest"]),
            }
        with mock.patch.object(evidence.products, "validate_retained_link", return_value={"receipt_sha256": "x"}) as reader:
            evidence.validate_links(self.root, work, inputs, tools, links)
            self.assertEqual(reader.call_count, 4)
        links["static"]["receipt"]["path"] = links["static-pie"]["receipt"]["path"]
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "artifact path"):
            evidence.validate_links(self.root, work, inputs, tools, links)
        links["static"]["receipt"]["path"] = evidence.work_file_identity(
            self.root, work / "static.crabc-link.json", "receipt"
        )["path"]
        links["static"]["linker"] = {"path": "/receipt-controlled-ld.lld", "sha256": "d" * 64}
        with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "independent roster"):
            evidence.validate_links(self.root, work, inputs, tools, links)

    def test_observation_rejects_static_alignment_and_declared_alias_drift(self) -> None:
        objects, aliases = evidence.selected_objects()
        policy = {"names": [item["name"] for item in objects], "aliases": aliases}
        contracts = {item["name"]: item for item in objects}

        def row(name: str, *, value: str = "0000000000001000") -> dict:
            contract = contracts[name]
            return {
                "name": name, "type": contract["type"], "binding": contract["binding"],
                "visibility": contract["visibility"], "version": None, "version_default": False,
                "section_index": "9", "value": value, "size_bytes": contract["size_bytes"],
            }

        imports = [
            {
                "name": name, "type": "NOTYPE", "binding": "GLOBAL", "visibility": "DEFAULT",
                "version": None, "version_default": False, "section_index": "UND",
                "value": "0000000000000000", "size_bytes": 0,
            }
            for name in [*policy["names"], "write"]
        ]

        def static_rows() -> list[dict]:
            rows = {name: row(name, value=f"{0x1000 + index * 0x100:x}") for index, name in enumerate(policy["names"])}
            for alias in aliases:
                target = rows[alias["target"]]
                rows[alias["name"]] = row(alias["name"], value=target["value"])
            return list(rows.values())

        current = static_rows()
        with mock.patch.object(evidence, "rows_for", side_effect=lambda _work, label:
                               imports if label == "object-symbols" else current):
            observations = evidence.observe(self.root, self.root / ".work", policy)
            self.assertEqual(len(observations["imports"]), 33)

        misaligned = static_rows()
        next(item for item in misaligned if item["name"] == "__environ")["value"] = "3"
        with mock.patch.object(evidence, "rows_for", side_effect=lambda _work, label:
                               imports if label == "object-symbols" else misaligned):
            with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "alignment"):
                evidence.observe(self.root, self.root / ".work", policy)

        alias_drift = static_rows()
        next(item for item in alias_drift if item["name"] == "timezone")["value"] = "0000000000007ff8"
        with mock.patch.object(evidence, "rows_for", side_effect=lambda _work, label:
                               imports if label == "object-symbols" else alias_drift):
            with self.assertRaisesRegex(evidence.PublicDataEvidenceError, "alias"):
                evidence.observe(self.root, self.root / ".work", policy)

    def oracle_identity(self, work: Path) -> dict:
        oracle_dir = work / "qualification-oracle"
        oracle_dir.mkdir()
        files = {}
        for name in evidence.qualification.ORACLE_FILES:
            path = oracle_dir / name
            if name == "compiler_wrapper":
                path.write_bytes((ROOT / "docker/x86_64-musl-oracle-gcc").read_bytes())
            elif name == "source_manifest":
                pins = tomllib.loads((ROOT / "compat/upstreams.toml").read_text())["musl"]
                path.write_text(
                    "format=crabc-pinned-musl-oracle-v1\n"
                    + f"version={pins['version']}\nsource_sha256={pins['sha256']}\n"
                    + f"fallback_revision={pins['fallback_revision']}\narchitecture=x86_64\n",
                    encoding="utf-8",
                )
            elif name == "specs_manifest":
                path.write_text("placeholder\n", encoding="utf-8")
            else:
                path.write_bytes((name + "-retained").encode())
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        (oracle_dir / "specs_manifest").write_text(
            files["specs"] + "  /opt/musl-1.2.6/lib/musl-gcc.specs\n", encoding="utf-8"
        )
        files["specs_manifest"] = hashlib.sha256((oracle_dir / "specs_manifest").read_bytes()).hexdigest()
        return {
            "version": "musl-1.2.6", "runtime_sha256": files["runtime"],
            "compiler_wrapper_sha256": files["compiler_wrapper"],
            "pins_sha256": hashlib.sha256((ROOT / "compat/upstreams.toml").read_bytes()).hexdigest(),
            "files": files,
        }

    def test_host_oracle_replay_uses_retained_bytes_and_rejects_tamper(self) -> None:
        work_parent = ROOT / ".work/x86_64/public-data-ordinary-link-tests"
        with tempfile.TemporaryDirectory(dir=work_parent) as directory:
            work = Path(directory)
            oracle = self.oracle_identity(work)
            with mock.patch.object(evidence.qualification, "require_live_oracle",
                                   side_effect=AssertionError("host replay must not probe /opt")):
                evidence.validate_oracle_identity(work, oracle)
            (work / "qualification-oracle/runtime").write_bytes(b"changed")
            with self.assertRaises(evidence.qualification.QualificationError):
                evidence.validate_oracle_identity(work, oracle)


if __name__ == "__main__":
    unittest.main()
