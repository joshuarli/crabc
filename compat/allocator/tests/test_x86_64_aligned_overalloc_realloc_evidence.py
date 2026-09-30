#!/usr/bin/env python3
"""Pure contract tests for private native x86-64 aligned realloc evidence."""

from __future__ import annotations

import copy
import hashlib
import io
import shutil
import tarfile
from contextlib import contextmanager
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/allocator/x86_64_aligned_overalloc_realloc_evidence.py"
spec = importlib.util.spec_from_file_location("aligned_overalloc_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


class SchemaTests(unittest.TestCase):
    def test_schema_binds_private_native_scope_geometry_and_rust_selection(self):
        schema = evidence.load_schema()
        self.assertEqual(schema, evidence._schema_template())
        self.assertEqual(schema["target"], evidence.EXPECTED_TARGET)
        self.assertEqual(schema["upstream"], evidence.EXPECTED_UPSTREAM)
        self.assertEqual(schema["scope"], evidence.EXPECTED_SCOPE)
        self.assertTrue(schema["scope"]["ordinary_arena_backed_offset_aligned_request_only"])
        self.assertFalse(schema["scope"]["public_x86_libc_or_ldso_support"])
        self.assertEqual(schema["rust_test"]["test_filter"], evidence.RUST_TEST_FILTER)
        self.assertEqual(schema["trace"]["expected_values"]["trace.aligned_overalloc.adjust"], 57)
        self.assertEqual(schema["trace"]["expected_values"]["trace.aligned_overalloc.growth_usable"], 103)
        self.assertEqual(schema["c_probe_sha256"], evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()))

    def test_schema_rejects_scope_trace_anchor_or_format_drift(self):
        mutations = (
            (lambda value: value["scope"].update({"public_x86_libc_or_ldso_support": True}), "checked-in schema drifted"),
            (lambda value: value["trace"]["expected_values"].update({"trace.aligned_overalloc.valid": 0}), "checked-in schema drifted"),
            (lambda value: value["source_anchors"][0].update({"sha256": "0" * 64}), "checked-in schema drifted"),
            (lambda value: value.update({"format": True}), "checked-in schema drifted"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                value = evidence.load_schema()
                mutate(value)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as stream:
                    json.dump(value, stream)
                    stream.flush()
                    with self.assertRaisesRegex(evidence.EvidenceError, message):
                        evidence.load_schema(Path(stream.name))


class CommandAndTraceTests(unittest.TestCase):
    def test_c_command_retains_fixed_release_pthread_and_tls_selection(self):
        schema = evidence.load_schema()
        temporary = Path("/tmp/aligned-overalloc-realloc-evidence")
        source = temporary / "source/mimalloc-3.5.0"
        command = evidence.c_trace_command("/usr/bin/musl-gcc", source, temporary / "aligned-overalloc-realloc.c", temporary / "aligned-overalloc-realloc-c", schema)
        evidence.validate_c_command(command, schema)
        evidence.validate_normalized_c_command(evidence.normalize_command(command, temporary, source), schema)
        with self.assertRaisesRegex(evidence.EvidenceError, "pthread/TLS"):
            evidence.validate_c_command([part for part in command if part != "-pthread"], schema)

    def test_trace_parser_requires_the_exact_address_independent_record(self):
        trace = evidence.parse_trace("\n".join([evidence.TRACE_BEGIN, *(f"{key}={value}" for key, value in evidence.EXPECTED_TRACE_VALUES.items()), evidence.TRACE_END]), description="test trace")
        evidence.validate_trace(trace, description="test trace")
        self.assertEqual(evidence.compare_traces(trace, trace)["status"], "matched")
        with self.assertRaisesRegex(evidence.EvidenceError, "raw address"):
            evidence.parse_trace(f"{evidence.TRACE_BEGIN}\ntrace.aligned_overalloc.pointer=0x1\n{evidence.TRACE_END}", description="test trace")
        changed = dict(trace)
        changed["trace.aligned_overalloc.valid"] = 0
        with self.assertRaisesRegex(evidence.EvidenceError, "value mismatches"):
            evidence.validate_trace(changed, description="test trace")


class ReportTests(unittest.TestCase):
    def complete_report(self) -> dict[str, object]:
        schema = evidence.load_schema()
        temporary = Path("/tmp/aligned-overalloc-realloc-evidence")
        trace = dict(evidence.EXPECTED_TRACE_VALUES)
        return evidence.report_from_results(
            schema=schema,
            provenance={"execution_mode": "native", "host_architecture": "x86_64"},
            archive_sha256=evidence.EXPECTED_ARCHIVE_SHA256,
            anchors=schema["source_anchors"],
            c_probe={
                "build_command": evidence.normalize_command(evidence.c_trace_command("/usr/bin/musl-gcc", temporary / "source/mimalloc-3.5.0", temporary / "aligned-overalloc-realloc.c", temporary / "aligned-overalloc-realloc-c", schema), temporary, temporary / "source/mimalloc-3.5.0"),
                "elf": evidence.EXPECTED_C_ELF,
                "run_command": ["<temporary-evidence-root>/aligned-overalloc-realloc-c"],
                "source_sha256": evidence.sha256_bytes(evidence.C_TRACE_PROBE.encode()),
                "trace": trace,
            },
            rust_probe={
                "cargo_command": evidence.normalize_command(evidence.rust_trace_command("/usr/bin/cargo", temporary / "rust-target"), temporary, None),
                "lockfile": {"path": evidence.relative(evidence.LOCKFILE), "sha256": evidence.sha256_file(evidence.LOCKFILE)},
                "passed_test_count": 1,
                "source": {"path": evidence.relative(evidence.RUST_TEST_SOURCE), "sha256": evidence.sha256_file(evidence.RUST_TEST_SOURCE)},
                "target_dir": {"isolated": True, "retained": False, "value": "<temporary-evidence-root>/rust-target"},
                "trace": trace,
            },
        )

    def test_report_is_private_and_binds_both_probe_identities(self):
        report = self.complete_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["comparison"], {"compared_value_count": 29, "status": "matched"})
        self.assertTrue(report["scope"]["terminal_arena_release_only"])
        self.assertFalse(report["scope"]["public_crabc_support"])
        self.assertIn("--locked", report["rust_probe"]["cargo_command"])

    def test_report_rejects_weakened_elf_rust_or_scope_evidence(self):
        report = self.complete_report()
        mutations = (
            (lambda value: value["c_probe"].update({"elf": {}}), "C identity"),
            (lambda value: value["rust_probe"]["cargo_command"].remove("--locked"), "Rust command drifted"),
            (lambda value: value["scope"].update({"terminal_arena_release_only": False}), "private boundary"),
            (lambda value: value["rust_probe"].update({"passed_test_count": True}), "Rust test selection"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                weakened = copy.deepcopy(report)
                mutate(weakened)
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.validate_report(weakened)


class SourceApiControlTests(unittest.TestCase):
    def observation(self, refused=False):
        values = {"request": 81, "alignment": 128, "offset": 11,
                  "allocated": 1, "zero": 1, "aligned": 1,
                  "usable": 0 if refused else 107,
                  "usable_errno": 22 if refused else 0,
                  "reallocated": 1, "realloc_aligned": 1,
                  "copied": 0 if refused else 1,
                  "realloc_errno": 22 if refused else 0,
                  "free_returned": 1, "free_errno": 22 if refused else 0}
        return "".join(f"{key}={value}\n" for key, value in values.items()).encode()

    def diagnostic(self):
        return b"".join(f"mimalloc: error: thread 0x123: {api}: invalid (unaligned) pointer: 0x456\n".encode()
                        for api in ("mi_usable_size", "mi_usable_size", "mi_free", "mi_free"))

    def test_valid_client_all_profiles_and_exact_c_debug_refusal(self):
        for profile in ("release", "debug-1", "stat-1", "stat-2"):
            for backend in ("c", "native"):
                refused = profile == "debug-1" and backend == "c"
                evidence.validate_source_api_observation(profile, backend, "process", int(refused),
                    self.observation(refused), self.diagnostic() if refused else b"")

    def test_refusal_is_not_matched_nonzero_or_a_native_waiver(self):
        for profile, backend, kind, status, stdout, stderr in (
            ("release", "c", "process", 1, self.observation(True), self.diagnostic()),
            ("debug-1", "native", "process", 1, self.observation(True), self.diagnostic()),
            ("debug-1", "c", "process", 0, self.observation(), b""),
            ("debug-1", "c", "timeout", 1, self.observation(True), self.diagnostic()),
            ("debug-1", "c", "process", 1, self.observation(True), b"unrelated error\n"),
            ("stat-2", "native", "process", 0, self.observation().replace(b"copied=1", b"copied=0"), b""),
        ):
            with self.subTest(profile=profile, backend=backend, kind=kind):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_source_api_observation(profile, backend, kind, status, stdout, stderr)

    def test_failed_real_compiler_process_keeps_raw_failure_without_receipt(self):
        m4, record, stress, receipts = evidence.source_api_helpers()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            directory = Path(temporary)
            source = directory / "pinned-source"
            (source / "include").mkdir(parents=True)
            (source / "include/mimalloc.h").write_text("header")
            (source / "LICENSE").write_text("license")
            (source / "src").mkdir()
            (source / "src/static.c").write_text("static source")
            (directory / "archive").write_bytes(b"archive")
            with mock.patch.object(evidence.run, "ARTIFACT_ROOT", directory / "products"), \
                 mock.patch.object(evidence.run, "require_native_x86_64", return_value={}), \
                 mock.patch.object(evidence.run, "load_pin", return_value={"archive_root": "mimalloc-3.5.0"}), \
                 mock.patch.object(evidence.run, "fetch_archive", return_value=directory / "archive"), \
                 mock.patch.object(evidence.run, "safe_extract", return_value=source), \
                 mock.patch.object(evidence.run, "require_tool", return_value="/bin/false"), \
                 mock.patch.object(receipts, "source_seal", return_value={"revision": "a" * 40}), \
                 mock.patch.object(receipts, "write_receipt") as publish, \
                 mock.patch.object(evidence, "source_api_helpers", return_value=(m4, record, stress, receipts)):
                with self.assertRaisesRegex(evidence.EvidenceError, "oracle-build failed"):
                    evidence.run_source_api_control()
                publish.assert_not_called()
            logs = list(directory.rglob("release-oracle-build.json"))
            self.assertEqual(len(logs), 1)
            raw = json.loads(logs[0].read_text())
            self.assertEqual((raw["kind"], raw["status"]), ("process", 1))
            self.assertEqual(logs[0].with_suffix(".stderr").read_bytes(), b"")

    def test_changed_geometry_duplicate_or_missing_field_fails(self):
        original = self.observation()
        for changed in (original.replace(b"offset=11", b"offset=7"), original + b"copied=1\n",
                        original.replace(b"free_returned=1\n", b"")):
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_source_api_observation("release", "native", "process", 0, changed, b"")


class SourceApiCommandAuthorityTests(unittest.TestCase):
    def test_wrong_profile_features_flags_link_and_execution_are_rejected(self):
        m4, _, _, _ = evidence.source_api_helpers()
        root, work = Path("/checkout"), Path("/checkout/.work/control/run-one")
        source = work / "source/mimalloc-3.5.0"
        tools = {"musl-gcc": "/tools/musl-gcc", "cargo": "/tools/cargo", "readelf": "/tools/readelf"}
        commands = evidence.source_api_commands(root, work, source, "debug-1", tools, m4)
        for step, mutate in (
            ("native-build", lambda c: c.__setitem__(c.index("crabc-mimalloc/mi-debug-1"), "crabc-mimalloc/mi-stat-2")),
            ("oracle-build", lambda c: c.__setitem__(c.index("-DMI_DEBUG=1"), "-DMI_DEBUG=0")),
            ("caller-build", lambda c: c.__setitem__(c.index("-DMI_PADDING=1"), "-DMI_PADDING=0")),
            ("native-link", lambda c: c.__setitem__(2, str(work / "release/native-mi-adapter.a"))),
            ("c-link", lambda c: c.__setitem__(1, str(work / "release/caller.o"))),
            ("native-execute", lambda c: c.__setitem__(0, str(work / "release/native"))),
            ("c-execute", lambda c: c.__setitem__(0, "/unrelated/c")),
            ("c-elf", lambda c: c.__setitem__(0, "/untrusted/readelf")),
        ):
            changed = list(commands[step]); mutate(changed)
            with self.subTest(step=step):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_source_api_command(step, changed, commands)
        for step, command in commands.items():
            evidence.validate_source_api_command(step, command, commands)

    def test_normalization_accepts_checkout_move_but_rejects_escape_or_role_change(self):
        work = ".work/control/run-one"
        self.assertEqual(evidence.source_api_recorded_root(["/image/checkout/" + work + "/debug-1/c", "--valid-offset-client"], work), Path("/image/checkout"))
        for argv in (["/unrelated/c", "--valid-offset-client"],
                     ["/image/checkout/" + work + "/../debug-1/c", "--valid-offset-client"]):
            with self.assertRaises(evidence.EvidenceError):
                evidence.source_api_recorded_root(argv, work)


class SourceApiSealedAuthorityTests(unittest.TestCase):
    @contextmanager
    def sealed_control(self):
        m4, record, stress, receipts = evidence.source_api_helpers()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            root = Path(temporary)
            work = root / ".work/control/run-one"
            work.mkdir(parents=True)
            archive = work / "mimalloc-3.5.0.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                for name in ("include/mimalloc.h", "src/static.c", "src/alloc.c", "LICENSE"):
                    data = ("pinned fixture " + name).encode()
                    member = tarfile.TarInfo("mimalloc-3.5.0/" + name)
                    member.size = len(data)
                    stream.addfile(member, io.BytesIO(data))
            pin = {"archive_root": "mimalloc-3.5.0", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
            source = evidence.run.safe_extract(archive, work / "source", pin["archive_root"])
            fixture = root / "compat/allocator/native-aligned-realloc-x86_64.c"
            fixture.parent.mkdir(parents=True)
            shutil.copy2(evidence.SOURCE_API_FIXTURE, fixture)
            products = {"mimalloc-3.5.0.tar.gz": archive}
            for original in (fixture, source / "include/mimalloc.h", source / "src/static.c", source / "LICENSE"):
                retained = work / original.name
                shutil.copy2(original, retained)
                products[original.name] = retained
            seal = {"revision": "a" * 40, "worktree_sha256": hashlib.sha256(b"").hexdigest()}
            execution = {"execution_mode": "native", "host_architecture": "x86_64", "image_id": "sha256:" + "1" * 64}
            inputs = work / "inputs.json"
            inputs.write_text(json.dumps({"source": seal, "execution": execution, "upstream": pin,
                                         "parameters": evidence.SOURCE_API_PARAMETERS}))
            products["inputs.json"] = inputs
            tools = {name: "/tools/" + name for name in ("musl-gcc", "cargo", "readelf")}
            cases = []
            observations = SourceApiControlTests()
            for profile in evidence.SOURCE_API_PROFILES:
                directory = work / profile
                directory.mkdir()
                for name in ("oracle.o", "caller.o", "native-mi-adapter.a", "c", "native"):
                    path = directory / name
                    path.write_bytes((profile + "/" + name).encode())
                    products[profile + "-" + name] = path
                commands = evidence.source_api_commands(root, work, source, profile, tools, m4)
                for case_id in evidence.source_api_case_ids():
                    if not case_id.startswith(profile + "-"):
                        continue
                    step = case_id[len(profile) + 1:]
                    refused = case_id == "debug-1-c-execute"
                    stdout = observations.observation(refused) if step.endswith("-execute") else b""
                    stderr = observations.diagnostic() if refused else b""
                    if step.endswith("-elf"):
                        stdout = b"ELF64 little endian Advanced Micro Devices X86-64"
                    raw = {"command": commands[step], "kind": "process", "status": int(refused),
                           "stdout": stress.bytes_record(stdout), "stderr": stress.bytes_record(stderr)}
                    paths = [work / (case_id + suffix) for suffix in (".json", ".stdout", ".stderr")]
                    paths[0].write_text(json.dumps(raw))
                    paths[1].write_bytes(stdout); paths[2].write_bytes(stderr)
                    cases.append((case_id, int(refused), paths))
            with mock.patch.object(evidence, "ROOT", root), \
                 mock.patch.object(evidence, "SOURCE_API_FIXTURE", fixture), \
                 mock.patch.object(evidence, "source_api_helpers", return_value=(m4, record, stress, receipts)), \
                 mock.patch.object(evidence.run, "TEMP_ROOT", root / ".work/reader"), \
                 mock.patch.object(evidence.run, "load_pin", return_value=pin), \
                 mock.patch.object(evidence.run, "require_tool", side_effect=lambda name: tools[name]), \
                 mock.patch.object(evidence.run, "require_native_x86_64", return_value=execution), \
                 mock.patch.object(receipts, "source_seal", return_value=seal):
                def publish():
                    return receipts.write_receipt(root, evidence.SOURCE_API_RUNNER, work, products, cases,
                                                  evidence.SOURCE_API_PARAMETERS, True)
                publish()
                yield root, work, products, cases, receipts, publish

    def test_valid_sealed_profile_control_is_readable(self):
        with self.sealed_control():
            self.assertEqual(len(evidence.read_source_api_control().cases), 36)

    def test_resealed_wrong_commands_fail_despite_valid_statuses_and_runtime(self):
        for case_id, mutate in (
            ("debug-1-native-build", lambda c: c.__setitem__(c.index("crabc-mimalloc/mi-debug-1"), "crabc-mimalloc/mi-stat-2")),
            ("debug-1-oracle-build", lambda c: c.__setitem__(c.index("-DMI_DEBUG=1"), "-DMI_DEBUG=0")),
            ("debug-1-native-link", lambda c: c.__setitem__(2, c[2].replace("debug-1", "release"))),
            ("debug-1-native-execute", lambda c: c.__setitem__(0, c[0].replace("debug-1", "release"))),
        ):
            with self.subTest(case_id=case_id), self.sealed_control() as (root, work, products, cases, receipts, publish):
                path = work / (case_id + ".json")
                raw = json.loads(path.read_text()); mutate(raw["command"]); path.write_text(json.dumps(raw))
                publish()
                receipts.read_receipt(root, evidence.SOURCE_API_RUNNER, expected_statuses=evidence.SOURCE_API_NEGATIVE)
                with self.assertRaisesRegex(evidence.EvidenceError, "command authority"):
                    evidence.read_source_api_control()

    def test_resealed_source_or_original_artifact_drift_is_rejected(self):
        for name in ("mimalloc.h", "LICENSE", "static.c", "debug-1-native"):
            with self.subTest(product=name), self.sealed_control() as (_, _, products, _, _, publish):
                original = products[name]
                if name == "debug-1-native":
                    # The newly sealed receipt still cites the executed copy;
                    # its original command operand has drifted independently.
                    products[name] = evidence.source_api_helpers()[3].receipt_directory(evidence.ROOT, evidence.SOURCE_API_RUNNER) / "products" / name
                original.write_bytes(b"changed authentic-looking product")
                publish()
                with self.assertRaises(evidence.EvidenceError):
                    evidence.read_source_api_control()


if __name__ == "__main__":
    unittest.main()
