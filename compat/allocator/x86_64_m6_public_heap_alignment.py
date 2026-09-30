#!/usr/bin/env python3
"""Compare public Heap allocation content, failure, and ownership with pinned source."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7

DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_public_heap_alignment_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-public-heap-alignment"
BEGIN = "CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_BEGIN"
END = "CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_END"
EXPECTED = {
    "alignment.heap": "1,1",
    "alignment.case0": "1,1,1,1,1,1",
    "alignment.case1": "1,1,1,1,1,1",
    "alignment.case2": "1,1,1,1,1,1",
    "alignment.case3": "1,1,1,1,1,1",
    "alignment.case4": "1,1,1,1,1,1",
    "alignment.case5": "1,1,1,1,1,1",
    "alignment.failure0": "1,22",
    "alignment.failure1": "1,22",
    "alignment.failure2": "1,22",
    "alignment.failure3": "1,12",
    "alignment.worker": "1,1,1,1,1,1",
    "alignment.before_delete": "1,1",
    "alignment.after_delete": "1,0,1",
    "alignment.freed_after_delete": "1",
    "alignment.second_heap": "1",
    "alignment.second_block": "1",
    "alignment.second_destroyed": "1",
    "alignment.destroy": "1,1",
    "contract.growth": "1",
    "contract.allocations": "1",
    "contract.strings": "1",
    "contract.failures": "1",
    "contract.replacements": "1",
    "contract.lifetime": "1",
}


PROFILES = ("release", "debug-1", "stat-1", "stat-2")
ALLOCATIONS = (
    "mi_heap_malloc", "mi_heap_zalloc", "mi_heap_calloc", "mi_heap_mallocn",
    "mi_heap_malloc_small", "mi_heap_zalloc_small", "mi_heap_malloc_aligned",
    "mi_heap_malloc_aligned_at", "mi_heap_zalloc_aligned", "mi_heap_zalloc_aligned_at",
    "mi_heap_calloc_aligned", "mi_heap_calloc_aligned_at", "mi_heap_alloc_new", "mi_heap_alloc_new_n",
)
REPLACEMENTS = (
    "mi_heap_realloc", "mi_heap_reallocn", "mi_heap_rezalloc", "mi_heap_recalloc",
    "mi_heap_realloc_aligned", "mi_heap_realloc_aligned_at", "mi_heap_rezalloc_aligned",
    "mi_heap_rezalloc_aligned_at", "mi_heap_recalloc_aligned", "mi_heap_recalloc_aligned_at",
)
STRINGS = ("mi_heap_strdup", "mi_heap_strndup", "mi_heap_realpath")


def expected_observations(profile: str) -> dict[str, str]:
    if profile not in PROFILES:
        raise harness.HarnessError(f"unsupported public Heap allocation profile: {profile}")
    expected = {key: value for key, value in EXPECTED.items()
                if profile == "release" or key.startswith("contract.")}
    count_errno = 12 if profile == "debug-1" else 0
    for index, entry in enumerate(ALLOCATIONS):
        expected[f"entry.{entry}.normal"] = "1,1,1,1,1"
        expected[f"entry.{entry}.refusal"] = "1,12,1"
        if index in (4, 5):
            # The small API has a size precondition; refusal uses a valid size.
            value = "source-small-size-precondition"
        else:
            errno = count_errno if index in (2, 3, 10, 11, 13) else 22 if 6 <= index <= 9 else 12
            value = f"1,{errno},1"
        expected[f"entry.{entry}.overflow"] = value
        if index >= 12:
            expected[f"entry.{entry}.refusal_handler"] = "4"
    for index, entry in enumerate(REPLACEMENTS):
        expected[f"entry.{entry}.normal"] = "1,1,1,1"
        expected[f"entry.{entry}.refusal"] = "1,12,1"
        expected[f"entry.{entry}.overflow"] = f"1,{22 if index >= 4 else 12},1"
        if index in (1, 3, 8, 9):
            expected[f"entry.{entry}.count_overflow"] = f"1,{count_errno},1"
    for entry in (*STRINGS, "mi_heap_reallocf"):
        expected[f"entry.{entry}.normal"] = "1,1,1"
        expected[f"entry.{entry}.refusal"] = "1,12,1"
    for entry in STRINGS[:2]:
        expected[f"entry.{entry}.null"] = "1"
    for entry in (*ALLOCATIONS, *REPLACEMENTS, *STRINGS, "mi_heap_reallocf"):
        expected[f"entry.{entry}.lifetime"] = "1,1,1"
    expected["entry.mi_heap_reallocf.overflow"] = "1,12,1"
    return expected


def observations(result: dict, profile: str, label: str) -> dict[str, str]:
    harness.require_success(result, label)
    actual = m7.parse_options_trace(str(result["stdout"]), label, BEGIN, END)
    expected = expected_observations(profile)
    if actual != expected:
        differences = {key: (expected.get(key), actual.get(key))
                       for key in expected.keys() | actual.keys() if expected.get(key) != actual.get(key)}
        raise harness.HarnessError(f"{label} observations differ: {differences}")
    return actual


def compare_runs(c_run: dict, rust_run: dict, profile: str) -> int:
    c_trace = observations(c_run, profile, "pinned C public Heap allocation")
    rust_trace = observations(rust_run, profile, "native Rust public Heap allocation")
    m7.compare_options_traces(c_trace, rust_trace)
    c_errors = re.findall(r"(?:aligned allocation[^\n]*|out of memory[^\n]*)", str(c_run["stderr"]))
    rust_errors = re.findall(r"(?:aligned allocation[^\n]*|out of memory[^\n]*)", str(rust_run["stderr"]))
    if c_errors != rust_errors:
        raise harness.HarnessError(f"Heap alignment diagnostics differ: {c_errors!r} != {rust_errors!r}")
    return len(c_trace)


def record(artifacts: Path, name: str, result: dict) -> None:
    (artifacts / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
    (artifacts / f"{name}.log").write_text(str(result["stdout"]) + str(result["stderr"]))


def verify_oracle_source(source: Path) -> None:
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    with tarfile.open(archive, "r:gz") as stream:
        members = {member.name[len(pin["archive_root"]) + 1:]: member
                   for member in stream.getmembers() if member.isfile()}
        actual = {str(path.relative_to(source)) for path in source.rglob("*") if path.is_file()}
        if actual != set(members):
            raise harness.HarnessError("retained oracle source differs from the pinned archive roster")
        for name, member in members.items():
            archived = stream.extractfile(member)
            if archived is None or hashlib.sha256(archived.read()).hexdigest() != hashlib.sha256((source / name).read_bytes()).hexdigest():
                raise harness.HarnessError(f"retained oracle source differs from pinned bytes: {name}")


def replay(artifacts: Path, profile: str) -> int:
    identity = json.loads((artifacts / "artifacts.json").read_text())
    required = {"public-heap-alignment-c", "public-heap-alignment-rust", "native-adapter.a",
                "c-build.json", "rust-build.json", "rust-link.json", "c.json", "rust.json",
                "native_heap_allocation_contract.json", "run-state.json"}
    if set(identity) != required:
        raise harness.HarnessError("retained public Heap inputs are incomplete")
    for name, digest in identity.items():
        if hashlib.sha256((artifacts / name).read_bytes()).hexdigest() != digest:
            raise harness.HarnessError(f"retained public Heap bytes changed: {name}")
    state = json.loads((artifacts / "run-state.json").read_text())
    current_execution = harness.require_native_x86_64(require_image_identity=True)
    harness.validate_native_execution_provenance(state["native_execution_provenance"],
        expected_image_id=current_execution["image_id"])
    current_source = harness.canonical_current_git_source_state(harness.ROOT)
    if state["source_before"] != state["source_after"] or state["source_after"] != current_source:
        raise harness.HarnessError("retained public Heap source differs from the current source")
    harness.canonical_upstream_stress_clean_git_source(current_source, "public Heap replay")
    if state["profile"] != profile:
        raise harness.HarnessError("retained public Heap profile differs")
    output = artifacts if profile == "release" else artifacts.parent
    verify_oracle_source(output / "source" / harness.load_pin()["archive_root"])
    originals = {side: json.loads((artifacts / f"{side}.json").read_text()) for side in ("c", "rust")}
    count = compare_runs(originals["c"], originals["rust"], profile)
    for name in ("c-build", "rust-build", "rust-link", "native_heap_allocation_contract"):
        result = json.loads((artifacts / f"{name}.json").read_text())
        harness.require_success(result, f"retained {name}")
        if name == "native_heap_allocation_contract" and harness.parse_rust_test_count(
                str(result["stdout"]) + str(result["stderr"])) != 1:
            raise harness.HarnessError("retained native allocation test did not execute exactly one test")
    fresh = {side: harness.command_record([str(artifacts / f"public-heap-alignment-{side}")],
             cwd=artifacts, env={}, timeout_seconds=60) for side in ("c", "rust")}
    if compare_runs(fresh["c"], fresh["rust"], profile) != count:
        raise harness.HarnessError("retained public Heap observations changed")
    return count


def run_differential(profile: str = "release", *, output: Path = ARTIFACTS, replay_only: bool = False) -> int:
    harness.require_native_x86_64()
    expected_observations(profile)
    artifacts = output if profile == "release" else output / profile
    if replay_only:
        return replay(artifacts, profile)
    artifacts.mkdir(parents=True, exist_ok=True)
    if (artifacts / "c.json").exists():
        raise harness.HarnessError("public Heap output already contains a run; preserve the earlier attempt")
    source_before = harness.canonical_current_git_source_state(harness.ROOT)
    execution_before = harness.require_native_x86_64(require_image_identity=True)
    pin = harness.load_pin()
    source_root = output / "source"
    source = (source_root / pin["archive_root"] if source_root.exists() else
              harness.safe_extract(harness.fetch_archive(pin, True), source_root, pin["archive_root"]))
    verify_oracle_source(source)
    compiler = harness.require_tool("musl-gcc")
    client_flags = ("-DCRABC_MI_HEAP_ALLOCATION_CONTRACT_ONLY=1",) if profile != "release" else ()
    c_driver = artifacts / "public-heap-alignment-c"
    c_build = harness.command_record(
        [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
         *m4.api_profile_flags(profile), *client_flags, "-I", str(source / "include"),
         "-I", str(source / "src"), str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)], cwd=source)
    record(artifacts, "c-build", c_build)
    harness.require_success(c_build, "Public Heap alignment C build")
    c_run = harness.command_record([str(c_driver)], cwd=artifacts, env={}, timeout_seconds=60)
    record(artifacts, "c", c_run)
    observations(c_run, profile, "pinned C public Heap allocation")
    target = output.parent / "public-heap-alignment-shared-build" / "cargo-target"
    build = harness.command_record(
        [harness.require_tool("cargo"), "build", "--locked", "--release", "--target", m4.RUST_TARGET,
         "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target),
         *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())],
        cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=m4.EVIDENCE_TIMEOUT_SECONDS)
    record(artifacts, "rust-build", build)
    harness.require_success(build, "public Heap native adapter build")
    library = artifacts / "native-adapter.a"
    shutil.copy2(target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, library)
    rust_driver = artifacts / "public-heap-alignment-rust"
    link = harness.command_record(
        [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", f"-DMI_DEBUG={int(profile == 'debug-1')}",
         *client_flags, "-I", str(source / "include"), str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source)
    record(artifacts, "rust-link", link)
    harness.require_success(link, "Public Heap alignment Rust link")
    rust_run = harness.command_record([str(rust_driver)], cwd=artifacts, env={}, timeout_seconds=60)
    record(artifacts, "rust", rust_run)
    count = compare_runs(c_run, rust_run, profile)
    direct = harness.command_record(
        [harness.require_tool("cargo"), "test", "--locked", "--offline", "--target", m4.RUST_TARGET,
         "-p", "crabc-mimalloc", "--no-default-features",
         *(("--features", f"mi-{profile}") if profile != "release" else ()),
         "--test", "native_heap_allocation_contract",
         "heap_requests_preserve_content_failure_and_legal_release_lifetimes",
         "--", "--exact", "--nocapture", "--test-threads=1"], cwd=harness.ROOT, timeout_seconds=900)
    record(artifacts, "native_heap_allocation_contract", direct)
    harness.require_success(direct, "public Heap direct allocation ownership contract")
    if harness.parse_rust_test_count(str(direct["stdout"]) + str(direct["stderr"])) != 1:
        raise harness.HarnessError("public Heap direct allocation ownership contract did not execute exactly one test")
    source_after = harness.canonical_current_git_source_state(harness.ROOT)
    if source_before != source_after:
        raise harness.HarnessError("public Heap source changed during execution")
    (artifacts / "run-state.json").write_text(json.dumps({
        "profile": profile, "source_before": source_before, "source_after": source_after,
        "native_execution_provenance": harness.native_execution_attestation(execution_before,
            harness.require_native_x86_64(require_image_identity=True)),
    }, indent=2) + "\n")
    retained = ("public-heap-alignment-c", "public-heap-alignment-rust", "native-adapter.a",
                "c-build.json", "rust-build.json", "rust-link.json", "c.json", "rust.json",
                "native_heap_allocation_contract.json", "run-state.json")
    (artifacts / "artifacts.json").write_text(json.dumps({
        name: hashlib.sha256((artifacts / name).read_bytes()).hexdigest() for name in retained}, indent=2) + "\n")
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=(*PROFILES, "all"), default="release")
    parser.add_argument("--output", type=Path, default=ARTIFACTS)
    parser.add_argument("--replay", action="store_true")
    arguments = parser.parse_args()
    output = arguments.output.resolve()
    try:
        output.relative_to(harness.ARTIFACT_ROOT.resolve())
    except ValueError as error:
        raise harness.HarnessError("public Heap output must stay inside the owning artifact root") from error
    for profile in PROFILES if arguments.profile == "all" else (arguments.profile,):
        count = run_differential(profile, output=output, replay_only=arguments.replay)
        scope = "entry transaction and legacy alignment" if profile == "release" else "entry transaction only"
        print(f"Public Heap allocation ({profile}, {scope}): {count} source-built C/Rust observations match", flush=True)
