#!/usr/bin/env python3
"""Pinned-C/Rust differential for non-main Heap creation, deletion, and destruction.

Three traces: Heaps of a child subprocess (`lifecycle`), Heaps of the process
main subprocess on the main thread (`main`), and a main-subprocess Heap
attached by a later thread (`later`), each C/Rust pair in fresh processes.

The C oracle drives pinned `mi_heap_new`, `mi_heap_delete`, and `mi_heap_destroy`
on a thread of a child subprocess; the Rust test drives
`types::heap_registry::lifecycle` on a child member thread. Both print the same
ordered, address-free fields.

The optional fault controls refuse caller-managed arena commits before a
Heap's first Theap and before a later page, then retry with the same owners.
They also reuse isolated pinned metadata-publication refusal comparisons and
the existing TLD/Theap rollback and regular TLS-slot allocation regressions.
An ordinary managed arena with OS fallback disabled also refuses Heap-image
allocation before list publication. Key-creation failure remains unmodeled.
"""

from pathlib import Path
import argparse
import json
import os
import re
import shutil

import run as harness
import x86_64_m6_public_child_heap as public_child_heap
import x86_64_initialization_tld_evidence as initialization
import perf_integrated_x86_64 as integrated
import perf_engine_x86_64 as engine


TEST = "types::heap_registry::lifecycle::tests::source_ordered_empty_heap_lifecycle_trace"
FIELD_COUNT = 108
# Heaps of the process main subprocess, each side in its own process.
MAIN_TEST = "subproc::main_heaps::tests::source_ordered_main_subprocess_heap_trace"
MAIN_FIELD_COUNT = 32
# A non-main Heap of the process main subprocess attached by a later thread.
LATER_TEST = "subproc::main_heaps::tests::source_ordered_main_subprocess_later_thread_heap_trace"
LATER_FIELD_COUNT = 21
FAULT_TEST = "managed_commit_refusal_preserves_heap_theap_and_caller_until_retry"
FAULT_BRANCHES = (
    "later-main-tld-metadata-allocation-failure",
    "later-main-theap-metadata-allocation-failure",
)
FAULT_UNITS = (
    "main_heap_thread::tests::later_tld_metadata_failure_precedes_theap_allocation_and_root_publication",
    "main_heap_thread::tests::later_theap_metadata_failure_releases_its_tld_before_root_publication",
    "subproc::main_heaps::tests::heap_theap_survives_first_regular_slot_allocation_failure",
)


def trace(output: str, section: str = "lifecycle", count: int = FIELD_COUNT) -> list[int]:
    rows = re.findall(rf"^(?:test \S+ \.\.\. )?m6\.heap\.{section}\.(\d+)=(-?\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in rows] != list(range(count)):
        raise harness.HarnessError(
            f"heap {section} trace requires {count} ordered fields"
        )
    return [int(value) for _, value in rows]


def compare(section: str, expected: list[int], observed: list[int]) -> None:
    if expected != observed:
        differences = [
            f"{index}: C={c_value} Rust={rust_value}"
            for index, (c_value, rust_value) in enumerate(zip(expected, observed))
            if c_value != rust_value
        ]
        raise harness.HarnessError(
            f"pinned C/Rust heap {section} differs: " + ", ".join(differences)
        )


def fault_product(target: Path, artifacts: Path, *, integration: bool) -> Path:
    command = ["cargo", "test", "--locked", "--offline", "--target",
               "x86_64-unknown-linux-musl", "--target-dir", str(target),
               "-p", "crabc-mimalloc", "--no-default-features"]
    command += (["--features", "native-runtime-test-audit", "--test", "native_heap_lifecycle_faults"]
                if integration else ["--lib"])
    record = harness.command_record([*command, "--no-run", "--message-format=json"],
                                    cwd=harness.ROOT, timeout_seconds=900)
    name = "native" if integration else "unit"
    (artifacts / f"{name}-build.log").write_text(str(record["stdout"]) + str(record["stderr"]))
    harness.require_success(record, f"Heap fault {name} build")
    executables = []
    for line in str(record["stdout"]).splitlines():
        if line.startswith("{"):
            row = json.loads(line)
            if row.get("reason") == "compiler-artifact" and row.get("executable"):
                executables.append(Path(row["executable"]))
    if len(executables) != 1:
        raise harness.HarnessError(f"Heap fault {name} build did not name one executable")
    product = artifacts / f"heap-fault-{name}"
    shutil.copy2(executables[0], product)
    return product


def run_faults(*, replay: bool = False) -> None:
    harness.require_native_x86_64()
    image_id = os.environ.get("CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID", "")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise harness.HarnessError("Heap fault evidence requires an immutable execution image")
    artifacts = harness.ARTIFACT_ROOT / "x86_64/heap-lifecycle/faults"
    artifacts.mkdir(parents=True, exist_ok=True)
    comparison_path = artifacts / "comparison.json"
    if replay:
        recorded = harness.read_json(comparison_path)
        if recorded["provenance"]["image_id"] != image_id:
            raise harness.HarnessError("Heap fault execution image changed")
        if recorded["provenance"]["git"] != engine.git_provenance():
            raise harness.HarnessError("Heap fault exact Git source changed")
        unmet = integrated.source_seal_unmet(recorded["provenance"]["seal"])
        if unmet:
            raise harness.HarnessError("; ".join(unmet))
        for row in recorded["provenance"]["inputs"]:
            if engine.file_record(harness.ROOT / row["path"]) != row:
                raise harness.HarnessError(f"Heap fault input changed: {row['path']}")
        for row in recorded["provenance"]["products"]:
            if engine.file_record(harness.ROOT / row["path"]) != row:
                raise harness.HarnessError(f"Heap fault product changed: {row['path']}")
        c_product = artifacts / "heap-fault-c"
        native_product = artifacts / "heap-fault-native"
        unit_product = artifacts / "heap-fault-unit"
    else:
        pin = harness.load_pin()
        archive = harness.fetch_archive(pin, True)
        with harness.temporary_directory(prefix="heap-lifecycle-fault-source-") as directory:
            source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
            command = [harness.require_tool("musl-gcc"), "-std=c11", "-D_GNU_SOURCE", "-fPIC",
                "-ftls-model=initial-exec", "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT",
                "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
                "-I", str(source / "include"), "-I", str(source / "src"),
                *harness.CONFIGURATION_PROFILES["release"],
                str(Path(__file__).with_suffix(".c")), "-pthread", "-o", str(artifacts / "heap-fault-c")]
            build = harness.command_record(command, cwd=source, timeout_seconds=300)
            (artifacts / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
            harness.require_success(build, "Heap fault C build")
            for branch in FAULT_BRANCHES:
                initialization.build_c_branch(harness.require_tool("musl-gcc"), source, artifacts, branch)
        c_product = artifacts / "heap-fault-c"
        native_product = fault_product(artifacts / "native-target", artifacts, integration=True)
        unit_product = fault_product(artifacts / "unit-target", artifacts, integration=False)

    def execute(product: Path, arguments: list[str], log: str, env: dict[str, str] | None = None) -> str:
        record = harness.command_record([str(product), *arguments], cwd=harness.ROOT, env=env, timeout_seconds=120)
        output = str(record["stdout"]) + str(record["stderr"])
        (artifacts / log).write_text(output)
        harness.require_success(record, f"Heap fault {log}")
        return output

    suffix = "replay" if replay else "run"
    c_output = execute(c_product, ["faults"], f"c-{suffix}.log")
    native_output = execute(native_product, [FAULT_TEST, "--exact", "--nocapture", "--test-threads=1"], f"native-{suffix}.log")
    if harness.parse_rust_test_count(native_output) != 1:
        raise harness.HarnessError("Heap fault integration did not execute one test")
    c_trace = trace(c_output, "fault", 16)
    native_trace = trace(native_output, "fault", 16)
    compare("fault", c_trace, native_trace)
    c_image_output = execute(c_product, ["image-faults"], f"c-image-{suffix}.log")
    native_image_output = execute(native_product, [FAULT_TEST, "--exact", "--nocapture", "--test-threads=1"],
                                  f"native-image-{suffix}.log", {"CRABC_HEAP_FAULT_CASE": "heap-image"})
    if harness.parse_rust_test_count(native_image_output) != 1:
        raise harness.HarnessError("Heap-image fault integration did not execute one test")
    c_image = trace(c_image_output, "image_fault", 12)
    native_image = trace(native_image_output, "image_fault", 12)
    compare("image_fault", c_image, native_image)
    products = [c_product, native_product, unit_product]
    rows = []
    for branch in FAULT_BRANCHES:
        index = initialization.branch_index(branch)
        c_branch = artifacts / "c" / branch / initialization.BRANCH_C_PROBE_NAMES[index]
        products.append(c_branch)
        c_output = execute(c_branch, [], f"{branch}-c-{suffix}.log")
        rust_output = execute(unit_product, [initialization.BRANCH_TARGETS[index], "--exact", "--nocapture", "--test-threads=1"], f"{branch}-rust-{suffix}.log")
        if harness.parse_rust_test_count(rust_output) != 1:
            raise harness.HarnessError(f"Heap fault branch did not execute one test: {branch}")
        c_values = initialization.parse_branch_trace(branch, c_output, source="pinned C")
        rust_values = initialization.parse_branch_trace(branch, rust_output, source="Rust")
        initialization.validate_branch_trace(branch, c_values, source="pinned C")
        initialization.validate_branch_trace(branch, rust_values, source="Rust")
        rows.append({"id": branch, "c_trace": c_values, "rust_trace": rust_values,
                     "comparison": initialization.compare_branch_trace(branch, c_values, rust_values)})
    for unit in FAULT_UNITS:
        output = execute(unit_product, [unit, "--exact", "--nocapture", "--test-threads=1"], f"{unit.rsplit('::', 1)[-1]}-{suffix}.log")
        if harness.parse_rust_test_count(output) != 1:
            raise harness.HarnessError(f"Heap fault unit did not execute one test: {unit}")
    observed = {"c_trace": c_trace, "rust_trace": native_trace,
                "c_image_trace": c_image, "rust_image_trace": native_image, "branches": rows}
    if replay:
        if observed != {key: recorded[key] for key in observed}:
            raise harness.HarnessError("Retained Heap fault physical traces changed")
    else:
        inputs = [Path(__file__), Path(__file__).with_suffix(".c"),
                  Path(initialization.__file__), Path(harness.__file__),
                  harness.ALLOCATOR_ROOT / "m2_later_main_theap_metadata_failure_x86_64.c",
                  harness.ROOT / "crabc-mimalloc/tests/native_heap_lifecycle_faults.rs"]
        harness.write_json(comparison_path, {**observed, "provenance": {
            "seal": integrated.source_seal(), "git": engine.git_provenance(), "image_id": image_id,
            "inputs": [engine.file_record(path) for path in inputs],
            "products": [engine.file_record(path) for path in products]}})
    print(f"Heap fault controls: 28 public C/native observations, two paired metadata-publication refusals, three isolated retry/TLS controls passed; {artifacts}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/heap-lifecycle"
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="heap-lifecycle-source-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        command = [harness.require_tool("musl-gcc"), "-std=c11", "-fPIC",
            "-ftls-model=initial-exec", "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT",
            "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(Path(__file__).with_suffix(".c").resolve()), "-pthread",
            "-o", str(artifacts / "oracle")]
        build = harness.command_record(command, cwd=source, timeout_seconds=300)
        (artifacts / "c-build.log").write_text(build["stdout"] + build["stderr"])
        harness.require_success(build, "heap lifecycle C build")
        oracle = harness.command_record([str(artifacts / "oracle")], cwd=source, timeout_seconds=60)
        (artifacts / "c.log").write_text(oracle["stdout"] + oracle["stderr"])
        harness.require_success(oracle, "heap lifecycle C oracle")
        main_oracle = harness.command_record([str(artifacts / "oracle"), "main"], cwd=source, timeout_seconds=60)
        (artifacts / "c-main.log").write_text(main_oracle["stdout"] + main_oracle["stderr"])
        harness.require_success(main_oracle, "heap lifecycle main-subprocess C oracle")
        later_oracle = harness.command_record([str(artifacts / "oracle"), "later"], cwd=source, timeout_seconds=60)
        (artifacts / "c-later.log").write_text(later_oracle["stdout"] + later_oracle["stderr"])
        harness.require_success(later_oracle, "heap lifecycle later-thread C oracle")
    rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", TEST],
        cwd=harness.ROOT, timeout_seconds=900)
    (artifacts / "rust.log").write_text(rust["stdout"] + rust["stderr"])
    harness.require_success(rust, "heap lifecycle Rust test")
    main_rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", MAIN_TEST],
        cwd=harness.ROOT, timeout_seconds=900)
    (artifacts / "rust-main.log").write_text(main_rust["stdout"] + main_rust["stderr"])
    harness.require_success(main_rust, "heap lifecycle main-subprocess Rust test")
    later_rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", LATER_TEST],
        cwd=harness.ROOT, timeout_seconds=900)
    (artifacts / "rust-later.log").write_text(later_rust["stdout"] + later_rust["stderr"])
    harness.require_success(later_rust, "heap lifecycle later-thread Rust test")
    compare("lifecycle", trace(oracle["stdout"]), trace(rust["stdout"]))
    compare("main", trace(main_oracle["stdout"], "main", MAIN_FIELD_COUNT),
        trace(main_rust["stdout"], "main", MAIN_FIELD_COUNT))
    compare("later", trace(later_oracle["stdout"], "later", LATER_FIELD_COUNT),
        trace(later_rust["stdout"], "later", LATER_FIELD_COUNT))
    public_count = public_child_heap.run_differential()
    print(f"heap lifecycle: {FIELD_COUNT} + {MAIN_FIELD_COUNT} + {LATER_FIELD_COUNT} private values and {public_count} public child keys match pinned C/Rust; {artifacts}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--faults", action="store_true")
    parser.add_argument("--replay", action="store_true")
    arguments = parser.parse_args()
    if arguments.replay and not arguments.faults:
        parser.error("--replay requires --faults")
    if arguments.faults:
        run_faults(replay=arguments.replay)
    else:
        main()
        run_faults()
