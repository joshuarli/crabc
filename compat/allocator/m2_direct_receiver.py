"""Build one pinned-C direct receiver, run its Rust test, and retain both transcripts.

Each producer names its fixture, extra pinned sources and link wrappers, the
trace prefix, and the expected relations it shares with Rust and the fields
only one side records. The aggregate re-parses the four retained streams.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
from pathlib import Path
from typing import Mapping, Sequence

import run as harness


DEFAULT_COMPILE_DEFINITIONS = (
    "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
)


def embedded_probe(module_path: Path, attribute: str) -> str:
    """Read one producer's embedded pinned-C probe without running its receiver."""

    spec = importlib.util.spec_from_file_location(f"crabc_direct_probe_{module_path.stem}", module_path)
    if spec is None or spec.loader is None:
        raise harness.HarnessError(f"embedded C probe owner is absent: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    probe = getattr(module, attribute, None)
    if not isinstance(probe, str) or not probe:
        raise harness.HarnessError(f"embedded C probe {attribute} is absent from {module_path}")
    return probe


def parse_trace(output: str, source: str, prefix: str, fields: set[str]) -> dict[str, int]:
    line = re.compile(re.escape(prefix) + r"([a-z][a-z0-9_.]*)=(-?[0-9]+)")
    values: dict[str, int] = {}
    for raw in output.splitlines():
        # Libtest prints its test name and status prefix without a newline
        # before the first `--nocapture` line.
        candidate = raw.rsplit(" ... ", 1)[-1]
        match = line.fullmatch(candidate)
        if match is None:
            if candidate.startswith(prefix):
                raise harness.HarnessError(f"{source} has malformed trace line: {candidate}")
            continue
        field, value = match.groups()
        if field in values:
            raise harness.HarnessError(f"{source} repeats {field}")
        values[field] = int(value)
    if set(values) != fields:
        raise harness.HarnessError(
            f"{source} trace roster differs: missing={sorted(fields - set(values))}, "
            f"unexpected={sorted(set(values) - fields)}"
        )
    return values


def run_receiver(
    *,
    artifact: str,
    fixture: Path,
    rust_test: str,
    prefix: str,
    common: Mapping[str, int],
    c_only: Mapping[str, int],
    rust_only: Mapping[str, int],
    offline: bool,
    sources: Sequence[str] = (),
    link: Sequence[str] = (),
    defines: Sequence[str] = (),
    rust_command: Sequence[str] | None = None,
    c_receipt_key: str | None = None,
    host_equal: Sequence[str] = (),
    c_probe: str | None = None,
    compile_definitions: Sequence[str] = DEFAULT_COMPILE_DEFINITIONS,
) -> Path:
    architecture = harness.native_evidence_architecture()
    harness.require_native_evidence(architecture)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    artifacts = harness.ARTIFACT_ROOT / architecture / artifact
    artifacts.mkdir(parents=True, exist_ok=True)
    binary = artifacts / "pinned-c-oracle"
    translation_unit = fixture
    if c_probe is not None:
        translation_unit = artifacts / "pinned-c-probe.c"
        translation_unit.write_text(
            harness.target_local_c_probe(embedded_probe(fixture, c_probe), architecture), encoding="utf-8",
        )
    with harness.temporary_directory(prefix=f"{artifact}-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            *compile_definitions, *defines, "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(translation_unit), *(str(source / item) for item in sources), *link,
            "-pthread", "-o", str(binary),
        ]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        harness.require_success(build, f"pinned C {artifact} oracle build")
        c_run = harness.command_record([str(binary)], cwd=source, timeout_seconds=120)
    (artifacts / "pinned-c.stdout").write_text(str(c_run["stdout"]), encoding="utf-8")
    (artifacts / "pinned-c.stderr").write_text(str(c_run["stderr"]), encoding="utf-8")
    harness.require_success(c_run, f"pinned C {artifact} oracle")
    c_trace = parse_trace(str(c_run["stdout"]), "pinned C", prefix, set(common) | set(c_only) | set(host_equal))

    rust = harness.command_record(
        list(rust_command) if rust_command is not None
        else ["python3", "compat/allocator/run_unit_x86_64.py", rust_test],
        cwd=harness.ROOT, timeout_seconds=900,
    )
    (artifacts / "rust.stdout").write_text(str(rust["stdout"]), encoding="utf-8")
    (artifacts / "rust.stderr").write_text(str(rust["stderr"]), encoding="utf-8")
    harness.require_success(rust, f"Rust {artifact} receiver")
    rust_trace = parse_trace(str(rust["stdout"]), "Rust", prefix, set(common) | set(rust_only) | set(host_equal))
    differences = [
        f"{field}: C={c_trace[field]} Rust={rust_trace[field]} expected={want}"
        for field, want in common.items()
        if c_trace[field] != want or rust_trace[field] != want
    ]
    differences.extend(
        f"{field}: C={c_trace[field]} Rust={rust_trace[field]}"
        for field in host_equal if c_trace[field] != rust_trace[field]
    )
    differences.extend(
        f"C {field}={c_trace[field]}, expected {want}"
        for field, want in c_only.items() if c_trace[field] != want
    )
    differences.extend(
        f"Rust {field}={rust_trace[field]}, expected {want}"
        for field, want in rust_only.items() if rust_trace[field] != want
    )
    if differences:
        raise harness.HarnessError(f"{artifact} differs: " + "; ".join(differences))
    evidence = {
        "status": "passed", "pinned_revision": pin["revision"],
        "fixture": harness.artifact_record(fixture),
        "c_executable": harness.artifact_record(binary),
        "rust_test": rust_test, "trace": rust_trace,
    }
    if c_receipt_key is not None:
        evidence[c_receipt_key] = {field: c_trace[field] for field in c_only}
    path = artifacts / "evidence.json"
    harness.write_json(path, evidence)
    return path


def run_spec(spec: Mapping[str, object], offline: bool) -> Path:
    """Run one receiver from its aggregate inventory record."""

    c_receipt = spec["c_receipt"]
    return run_receiver(
        artifact=spec["artifact"], fixture=harness.ROOT / spec["fixture"], rust_test=spec["rust_test"],
        prefix=spec["trace_prefix"], common=spec["common"], c_only=spec["c_only"],
        rust_only=spec["rust_only"], offline=offline, sources=spec.get("c_sources", ()),
        link=spec.get("c_link", ()), defines=spec.get("c_defines", ()),
        rust_command=spec.get("rust_command"),
        c_receipt_key=None if c_receipt is None else c_receipt[0],
        host_equal=spec.get("host_equal", ()), c_probe=spec.get("c_probe"),
        compile_definitions=spec.get("c_compile_definitions", DEFAULT_COMPILE_DEFINITIONS),
    )


def main(check_id: str, description: str | None) -> None:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        spec = harness.M2_AARCH64_ADDED_DIRECT_RECEIVER_SPECS.get(check_id)
        if spec is None:
            raise harness.HarnessError(f"direct receiver {check_id} has no inventory record")
        print(run_spec(spec, args.offline))
    except (harness.HarnessError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
