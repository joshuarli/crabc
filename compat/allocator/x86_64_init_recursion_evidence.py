#!/usr/bin/env python3
"""Compare one explicit pinned-C initialization recovery route with Rust.

The pinned C fixture explicitly initializes the process, then gives one native
worker the sequence ``mi_thread_init`` -> repeated ``mi_thread_init`` ->
``mi_thread_done`` -> repeated ``mi_thread_done`` -> ``mi_thread_init`` ->
``mi_thread_done``.  It records only whether each source-visible default
Theap state is initialized or empty.  The Rust half exercises the corresponding
crate-private later-worker attachment and records the same normalized state
sequence.  Rust deliberately refuses a direct second mutable attachment;
the C source returns the existing default Theap.  Both records mean that the
recursive entry keeps one current owner.

This is private native Linux/x86-64 evidence for the named source paths.  It
does not claim a public allocator API, runtime callback integration, automatic
pthread cleanup, process-shutdown parity, or completion of the metadata and
runtime-owner work that remains outside this source-owner slice.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-init-recursion-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/init-recursion.json"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"
RUST_TRACE_SOURCE = ROOT / "crabc-mimalloc/src/main_heap_thread.rs"
TRACE_FILTER = "main_heap_thread::tests::emit_x86_64_init_recursion_teardown_c_rust_trace"
TRACE_BEGIN = "CRABC_MI_INIT_RECURSION_TRACE_BEGIN"
TRACE_END = "CRABC_MI_INIT_RECURSION_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"
EVIDENCE_LABEL = "init-recursion"
EVIDENCE_KIND = "mimalloc-x86_64-explicit-init-recursion-teardown-differential-evidence"
TEMPORARY_PREFIX = "crabc-mimalloc-x86-init-recursion-"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded initialization/recursion differential cannot establish its claim."""


EXPECTED_TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "rust_target": TARGET,
    "system": "linux",
}
EXPECTED_UPSTREAM = {
    "archive_root": "mimalloc-3.5.0",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "version": "3.5.0",
}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_PROFILE = "linux-x86_64-private-explicit-init-recursion-teardown"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "automatic_pthread_destructor_claimed": False,
    "constructor_or_callback_integration_claimed": False,
    "emulation_accepted": False,
    "explicit_process_and_worker_thread_route_only": True,
    "general_allocator_or_api_claimed": False,
    "general_process_shutdown_claimed": False,
    "metadata_completion_claimed": False,
    "native_linux_x86_64_required": True,
    "one_current_owner_on_recursive_entry": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_x86_libc_or_ldso_support": False,
    "runtime_lifecycle_callback_parity_claimed": False,
    "rust_direct_second_mutable_owner_refused": True,
    "thread_recovery_after_explicit_teardown_only": True,
}
EXPECTED_COMPILE_DEFINITIONS = (
    "-DMI_SHARED_LIB",
    "-DMI_SHARED_LIB_EXPORT",
    "-DMI_LIBC_MUSL=1",
    "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
)
EXPECTED_C_ELF = {
    "class": "ELF64",
    "endianness": "little",
    "machine": "Advanced Micro Devices X86-64",
}
# Hashes are of the exact upstream line intervals, not of local ports.
EXPECTED_SOURCE_ANCHORS = (
    ("src/prim/prim.c", 29, 46, "6d2be652e1c17c43fc281807cde2f15d8b9ffee28bd294639d8628eceefe3712"),
    ("src/init.c", 305, 360, "8b5a6af8d90da7f2cb33cf5c6211c9325234840d57a54c25be891e49e4d354e5"),
    ("src/init.c", 377, 422, "eaa34dbcd2df052853490df70c9f8ed19b481bb9d1363a0bf61331758f2fb165"),
    ("src/init.c", 448, 481, "478b40823b940f620731b48121f6da86b4c288c97b9ddddcd03e915e92b11a25"),
    ("src/init.c", 536, 592, "1f3a0d2b3751b4d3270abe60c46aeef48ef78de91fe1dcfb6d5cc802a5d1480e"),
)
EXPECTED_TRACE_VALUES = {
    "trace.init_recursion.first_default_initialized": 1,
    "trace.init_recursion.reentrant_entry_preserves_one_owner": 1,
    "trace.init_recursion.first_teardown_clears_default": 1,
    "trace.init_recursion.repeated_teardown_keeps_default_empty": 1,
    "trace.init_recursion.recovery_default_initialized": 1,
    "trace.init_recursion.final_teardown_clears_default": 1,
    "trace.init_recursion.valid": 1,
}
EXPECTED_LIFECYCLE_CHECKS = (
    {
        "filter": "once::tests::recursive_entry_is_nonblocking_and_does_not_complete",
        "source": "crabc-mimalloc/src/once.rs",
    },
    {
        "filter": "process_init::tests::process_main_once_blocks_a_distinct_racer_until_release_and_refuses_reentry",
        "source": "crabc-mimalloc/src/process_init.rs",
    },
    {
        "filter": "thread_local::tests::persistent_compiler_tls_owner_rejects_reentry_then_recovers_the_same_owner",
        "source": "crabc-mimalloc/src/thread_local.rs",
    },
)


C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private init-recursion fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private init-recursion fixture requires the fixed release profile
#endif

typedef struct worker_trace_s {
  bool first_default_initialized;
  bool reentrant_entry_preserves_one_owner;
  bool first_teardown_clears_default;
  bool repeated_teardown_keeps_default_empty;
  bool recovery_default_initialized;
  bool final_teardown_clears_default;
} worker_trace_t;

static void* worker_main(void* argument) {
  worker_trace_t* const trace = (worker_trace_t*)argument;
  mi_theap_t* first = NULL;
  mi_theap_t* repeated = NULL;
  mi_theap_t* recovered = NULL;

  mi_thread_init();
  first = _mi_theap_default();
  trace->first_default_initialized = mi_theap_is_initialized(first);

  // `src/init.c:_mi_thread_init_with_heap` must take its existing-default
  // return path here rather than creating a second TLD/Theap owner.
  mi_thread_init();
  repeated = _mi_theap_default();
  trace->reentrant_entry_preserves_one_owner =
      (first == repeated && mi_theap_is_initialized(repeated));

  mi_thread_done();
  trace->first_teardown_clears_default =
      !mi_theap_is_initialized(_mi_theap_default());

  // `_mi_thread_done` must return before touching an already empty default.
  mi_thread_done();
  trace->repeated_teardown_keeps_default_empty =
      !mi_theap_is_initialized(_mi_theap_default());

  mi_thread_init();
  recovered = _mi_theap_default();
  trace->recovery_default_initialized = mi_theap_is_initialized(recovered);

  mi_thread_done();
  trace->final_teardown_clears_default =
      !mi_theap_is_initialized(_mi_theap_default());
  return NULL;
}

int main(void) {
  worker_trace_t trace = { 0 };
  pthread_t worker;
  bool valid = false;

  // `MI_PRIM_HAS_PROCESS_ATTACH` suppresses the compiler constructor. This
  // makes the fixture's process state explicit and keeps callback behavior
  // outside the claim.
  mi_process_init();
  if (pthread_create(&worker, NULL, worker_main, &trace) != 0) goto done;
  if (pthread_join(worker, NULL) != 0) goto done;
  valid = (trace.first_default_initialized
           && trace.reentrant_entry_preserves_one_owner
           && trace.first_teardown_clears_default
           && trace.repeated_teardown_keeps_default_empty
           && trace.recovery_default_initialized
           && trace.final_teardown_clears_default);

done:
  printf("CRABC_MI_INIT_RECURSION_TRACE_BEGIN\n");
  printf("trace.init_recursion.first_default_initialized=%d\n", trace.first_default_initialized);
  printf("trace.init_recursion.reentrant_entry_preserves_one_owner=%d\n", trace.reentrant_entry_preserves_one_owner);
  printf("trace.init_recursion.first_teardown_clears_default=%d\n", trace.first_teardown_clears_default);
  printf("trace.init_recursion.repeated_teardown_keeps_default_empty=%d\n", trace.repeated_teardown_keeps_default_empty);
  printf("trace.init_recursion.recovery_default_initialized=%d\n", trace.recovery_default_initialized);
  printf("trace.init_recursion.final_teardown_clears_default=%d\n", trace.final_teardown_clears_default);
  printf("trace.init_recursion.valid=%d\n", valid);
  printf("CRABC_MI_INIT_RECURSION_TRACE_END\n");
  return valid ? 0 : 2;
}
'''


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    return sha256_bytes(path.read_bytes())


def exactly_matches(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(observed, dict)
        return set(observed) == set(expected) and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(observed, list)
        return len(observed) == len(expected) and all(
            exactly_matches(value, expected_value)
            for value, expected_value in zip(observed, expected)
        )
    return observed == expected


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError("init-recursion source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def validate_probe_source(probe: str = C_TRACE_PROBE) -> None:
    required = (
        "MI_PRIM_HAS_PROCESS_ATTACH",
        "mi_process_init();",
        "mi_thread_init();",
        "mi_thread_done();",
        "first == repeated",
        "CRABC_MI_INIT_RECURSION_TRACE_BEGIN",
    )
    if not all(fragment in probe for fragment in required):
        raise EvidenceError("init-recursion C probe loses its explicit source route")
    if "_mi_auto_process_init" in probe or "pthread_key" in probe:
        raise EvidenceError("init-recursion C probe widens into a callback claim")


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 init-recursion schema") from error
    expected_fields = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "schema", "scope", "source_anchors", "target", "trace", "upstream",
    }
    if not isinstance(schema, dict) or set(schema) != expected_fields:
        raise EvidenceError("init-recursion schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("unsupported init-recursion evidence format")
    if schema["schema"] != "crabc-mimalloc-x86_64-init-recursion-evidence":
        raise EvidenceError("unsupported init-recursion evidence schema")
    if schema["profile"] != EXPECTED_PROFILE or not exactly_matches(schema["target"], EXPECTED_TARGET):
        raise EvidenceError("init-recursion target/profile drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("init-recursion upstream drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("init-recursion scope drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned init-recursion identity") from error
    if (pin["sha256"] != EXPECTED_ARCHIVE_SHA256
            or pin["archive_root"] != EXPECTED_UPSTREAM["archive_root"]
            or pin["revision"] != EXPECTED_UPSTREAM["revision"]
            or pin["version"] != EXPECTED_UPSTREAM["version"]):
        raise EvidenceError("init-recursion upstream pin drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("init-recursion C source set drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("init-recursion release flags drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("init-recursion compile definitions drifted")
    if not exactly_matches(schema["trace"], {
        "begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES,
    }):
        raise EvidenceError("init-recursion trace contract drifted")
    validate_probe_source()
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("init-recursion C probe hash drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("init-recursion source anchors drifted")
    observed = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("init-recursion source anchor shape drifted")
        observed.append((anchor.get("member"), anchor.get("start_line"), anchor.get("end_line"), anchor.get("sha256")))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("init-recursion source anchor contract drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated = []
    for anchor in schema["source_anchors"]:
        path = source / str(anchor["member"])
        digest = sha256_bytes(
            source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))
        ) if path.is_file() else None
        if digest != anchor["sha256"]:
            raise EvidenceError(f"init-recursion source anchor drifted: {anchor['member']}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(
            output, begin=TRACE_BEGIN, end=TRACE_END, description=description,
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    mismatches = sorted(
        key for key, expected in EXPECTED_TRACE_VALUES.items()
        if type(trace.get(key)) is int and trace[key] != expected
    )
    if missing or unexpected or mismatches:
        raise EvidenceError(f"{description} violates the fixed {len(EXPECTED_TRACE_VALUES)}-field trace contract")


def compare_traces(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C init-recursion trace")
    validate_trace(rust_trace, description="Rust init-recursion trace")
    if dict(c_trace) != dict(rust_trace):
        raise EvidenceError("C and Rust init-recursion traces differ")
    return {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text):])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text):])
        else:
            normalized.append(part)
    return normalized


def c_trace_command(
    compiler: str, source: Path, probe_source: Path, binary: Path, schema: Mapping[str, Any],
) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"),
        *schema["release_flags"], str(probe_source),
        *(str(source / member) for member in schema["release_source_set"]),
        "-pthread", "-o", str(binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(schema["compile_definitions"]) or flags != list(schema["release_flags"]):
        raise EvidenceError("init-recursion C release command drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("init-recursion C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc":
        raise EvidenceError("init-recursion C compiler drifted")
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/init-recursion.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/init-recursion-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("init-recursion normalized C command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any],
) -> dict[str, Any]:
    probe_source = temporary / "init-recursion.c"
    binary = temporary / "init-recursion-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C init-recursion fixture build")
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "pinned C init-recursion ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        if int(execution["status"]) != 0:
            raise EvidenceError(
                f"pinned C init-recursion fixture failed ({execution['status']}):\n"
                f"{execution['stdout']}{execution['stderr']}"
            )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C init-recursion trace")
    validate_trace(trace, description="pinned C init-recursion trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/init-recursion-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def rust_test_command(cargo: str, target_dir: Path, test_filter: str) -> list[str]:
    return [
        cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir),
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", test_filter,
        "--", "--exact", "--nocapture", "--test-threads=1",
    ]


def run_rust_test(cargo: str, target_dir: Path, test_filter: str) -> tuple[list[str], str]:
    command = rust_test_command(cargo, target_dir, test_filter)
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = run.command_record(command, cwd=ROOT, env=environment)
        run.require_success(execution, f"Rust init-recursion check {test_filter}")
        output = str(execution["stdout"]) + "\n" + str(execution["stderr"])
        if run.parse_rust_test_count(output) != 1:
            raise EvidenceError(f"Rust init-recursion check did not pass exactly one test: {test_filter}")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    return command, output


def build_rust_trace(cargo: str, temporary: Path) -> dict[str, Any]:
    target_dir = temporary / "rust-target"
    command, output = run_rust_test(cargo, target_dir, TRACE_FILTER)
    trace = parse_trace(output, description="Rust init-recursion trace")
    validate_trace(trace, description="Rust init-recursion trace")
    return {
        "cargo_command": normalize_command(command, temporary, None),
        "lockfile": {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)},
        "passed_test_count": 1,
        "source": {"path": relative(RUST_TRACE_SOURCE), "sha256": sha256_file(RUST_TRACE_SOURCE)},
        "target_dir": {
            "isolated": True, "retained": False,
            "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        },
        "trace": trace,
    }


def build_lifecycle_checks(cargo: str, temporary: Path) -> list[dict[str, Any]]:
    target_dir = temporary / "rust-target"
    records = []
    for check in EXPECTED_LIFECYCLE_CHECKS:
        command, _ = run_rust_test(cargo, target_dir, check["filter"])
        source = ROOT / check["source"]
        records.append({
            "cargo_command": normalize_command(command, temporary, None),
            "filter": check["filter"],
            "passed_test_count": 1,
            "source": {"path": check["source"], "sha256": sha256_file(source)},
            "target_dir": {
                "isolated": True, "retained": False,
                "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
            },
        })
    return records


def report_from_results(
    *, schema: Mapping[str, Any], provenance: Mapping[str, str], archive_sha256: str,
    anchors: Sequence[Mapping[str, Any]], c_probe: Mapping[str, Any],
    rust_probe: Mapping[str, Any], lifecycle_checks: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("init-recursion evidence inputs lack trace records")
    report = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": EVIDENCE_KIND,
        "lifecycle_checks": [dict(check) for check in lifecycle_checks],
        "profile": schema["profile"],
        "provenance": dict(provenance),
        "rust_probe": dict(rust_probe),
        "scope": schema["scope"],
        "source": {
            "archive_sha256": archive_sha256,
            "anchors": [dict(anchor) for anchor in anchors],
            "release_flags": list(schema["release_flags"]),
            "release_source_set": list(schema["release_source_set"]),
        },
        "status": "passed",
        "target": schema["target"],
        "trace": schema["trace"],
        "upstream": schema["upstream"],
    }
    validate_report(report)
    return report


def validate_rust_command(command: object, target_name: str, test_filter: str) -> None:
    if not isinstance(command, list) or not command or Path(command[0]).name != "cargo":
        raise EvidenceError("init-recursion Rust compiler drifted")
    expected = [
        "test", "--locked", "--target", TARGET, "--target-dir",
        f"{NORMALIZED_EVIDENCE_ROOT}/{target_name}", "-p", "crabc-mimalloc", "--lib",
        "--no-default-features", test_filter, "--", "--exact", "--nocapture", "--test-threads=1",
    ]
    if command[1:] != expected:
        raise EvidenceError("init-recursion Rust command drifted")


def validate_report(report: Mapping[str, Any]) -> None:
    required = {
        "c_probe", "comparison", "format", "kind", "lifecycle_checks", "profile", "provenance",
        "rust_probe", "scope", "source", "status", "target", "trace", "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("init-recursion report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("init-recursion report must record a passing format-1 result")
    if report["kind"] != EVIDENCE_KIND or report["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("init-recursion report identity drifted")
    if (not exactly_matches(report["target"], EXPECTED_TARGET)
            or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
            or not exactly_matches(report["scope"], EXPECTED_SCOPE)):
        raise EvidenceError("init-recursion report boundary drifted")
    if not any(exactly_matches(report["provenance"], candidate) for candidate in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    )):
        raise EvidenceError("init-recursion report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("init-recursion report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("init-recursion report source record drifted")
    if (source["archive_sha256"] != run.load_pin()["sha256"]
            or not exactly_matches(source["anchors"], schema["source_anchors"])
            or not exactly_matches(source["release_flags"], schema["release_flags"])
            or not exactly_matches(source["release_source_set"], schema["release_source_set"])):
        raise EvidenceError("init-recursion report source identity drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("init-recursion report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"}:
        raise EvidenceError("init-recursion report Rust probe record drifted")
    if (not exactly_matches(c_probe["elf"], EXPECTED_C_ELF)
            or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/init-recursion-c"]
            or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8"))):
        raise EvidenceError("init-recursion report C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("init-recursion report Rust trace selection drifted")
    if not exactly_matches(rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}):
        raise EvidenceError("init-recursion report Rust lockfile drifted")
    if not exactly_matches(rust_probe["source"], {"path": relative(RUST_TRACE_SOURCE), "sha256": sha256_file(RUST_TRACE_SOURCE)}):
        raise EvidenceError("init-recursion report Rust source drifted")
    if not exactly_matches(rust_probe["target_dir"], {
        "isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
    }):
        raise EvidenceError("init-recursion report Rust target directory drifted")
    validate_rust_command(rust_probe["cargo_command"], "rust-target", TRACE_FILTER)
    validate_trace(c_probe["trace"], description="recorded C init-recursion trace")
    validate_trace(rust_probe["trace"], description="recorded Rust init-recursion trace")
    compare_traces(c_probe["trace"], rust_probe["trace"])
    if not exactly_matches(report["comparison"], {
        "compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched",
    }):
        raise EvidenceError("init-recursion report comparison drifted")
    checks = report["lifecycle_checks"]
    if not isinstance(checks, list) or len(checks) != len(EXPECTED_LIFECYCLE_CHECKS):
        raise EvidenceError("init-recursion lifecycle batch drifted")
    for observed, expected in zip(checks, EXPECTED_LIFECYCLE_CHECKS):
        if not isinstance(observed, dict) or set(observed) != {"cargo_command", "filter", "passed_test_count", "source", "target_dir"}:
            raise EvidenceError("init-recursion lifecycle check record drifted")
        if observed["filter"] != expected["filter"] or observed["passed_test_count"] != 1:
            raise EvidenceError("init-recursion lifecycle check selection drifted")
        source_record = {"path": expected["source"], "sha256": sha256_file(ROOT / expected["source"])}
        if not exactly_matches(observed["source"], source_record):
            raise EvidenceError("init-recursion lifecycle source drifted")
        if not exactly_matches(observed["target_dir"], {
            "isolated": True, "retained": False,
            "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target",
        }):
            raise EvidenceError("init-recursion lifecycle target directory drifted")
        validate_rust_command(observed["cargo_command"], "rust-target", expected["filter"])


def bounded_temporary_directory() -> tempfile.TemporaryDirectory[str]:
    configured = os.environ.get("TMPDIR")
    temporary_root = Path(configured) if configured else ROOT / ".work/allocator-x86_64/tmp"
    temporary_root.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=TEMPORARY_PREFIX, dir=temporary_root)


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    schema = load_schema()
    provenance = require_native_x86_64()
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
        compiler = run.require_tool("musl-gcc")
        cargo = run.require_tool("cargo")
        readelf = run.require_tool("readelf")
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with bounded_temporary_directory() as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c_trace(compiler, readelf, source, temporary, schema)
        rust_probe = build_rust_trace(cargo, temporary)
        lifecycle_checks = build_lifecycle_checks(cargo, temporary)
        report = report_from_results(
            schema=schema, provenance=provenance, archive_sha256=pin["sha256"], anchors=anchors,
            c_probe=c_probe, rust_probe=rust_probe, lifecycle_checks=lifecycle_checks,
        )
    run.write_json(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 {EVIDENCE_LABEL} evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        f"allocator x86-64 {EVIDENCE_LABEL} evidence: PASS "
        f"({report['comparison']['compared_value_count']} values; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
