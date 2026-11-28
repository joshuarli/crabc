#!/usr/bin/env python3
"""Compare pinned C and process-owned Rust fresh OS-page prefix-trim failure receivers."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
TARGET = "os::tests::emit_process_os_page_prefix_trim_trace"
PREFIX = "m2.os_page_prefix_trim."
COMMON = (
    "memory_exact", "prefix_exact", "terminal_exact", "middle_length", "escaped_prefix_length",
    "reserved_claim", "committed_claim", "mmap_claim", "reserved_final", "committed_final",
    "warning_fragments", "warning_bodies", "warning_order", "warning_before_stats",
    "raw_middle", "raw_prefix", "raw_no_stats",
)
RUST_ONLY = ("prefix_still_live",)
LINE = re.compile("^" + re.escape(PREFIX) + r"([a-z_]+)=(-?[0-9]+)$")


def parse_trace(output: str, source: str, fields: tuple[str, ...]) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in output.splitlines():
        # Libtest prints its test name and status prefix without a newline
        # before the first `--nocapture` line.
        candidate = line.rsplit(" ... ", 1)[-1]
        match = LINE.fullmatch(candidate)
        if match is None:
            if candidate.startswith(PREFIX):
                raise harness.HarnessError(f"{source} has malformed trace line: {candidate}")
            continue
        field, raw = match.groups()
        if field in values:
            raise harness.HarnessError(f"{source} repeats {field}")
        values[field] = int(raw)
    if set(values) != set(fields):
        raise harness.HarnessError(
            f"{source} trace roster differs: missing={sorted(set(fields) - set(values))}, "
            f"unexpected={sorted(set(values) - set(fields))}"
        )
    return values


def run(offline: bool) -> Path:
    architecture = harness.native_evidence_architecture()
    harness.require_native_evidence(architecture)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / architecture / "m2-process-os-page-prefix-trim"
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    with harness.temporary_directory(prefix="m2-process-os-page-prefix-trim-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(FIXTURE), "-Wl,--wrap=mmap", "-Wl,--wrap=munmap", "-pthread",
            "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, "pinned C fresh OS-page prefix-trim oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, "pinned C fresh OS-page prefix-trim oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C", COMMON)

    rust_command = ["python3", "compat/allocator/run_unit_x86_64.py", TARGET]
    rust = harness.command_record(rust_command, cwd=harness.ROOT, timeout_seconds=300)
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, "Rust fresh OS-page prefix-trim receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust", (*COMMON, *RUST_ONLY))
    differences = [f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
                   for field in COMMON if c_trace[field] != rust_trace[field]]
    if differences:
        raise harness.HarnessError("fresh OS-page prefix-trim receiver differs: " + "; ".join(differences))
    evidence = {
        "status": "passed",
        "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(FIXTURE),
        "c_executable": harness.artifact_record(binary),
        "rust_test": TARGET,
        "trace": rust_trace,
    }
    path = artifacts / "evidence.json"
    harness.write_json(path, evidence)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        print(run(args.offline))
    except (harness.HarnessError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
