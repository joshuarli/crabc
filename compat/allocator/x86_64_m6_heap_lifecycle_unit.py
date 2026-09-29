#!/usr/bin/env python3
"""Compare private Rust child Heap ownership transitions with pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m6_child_heap_in_arena_two_worker as oracle


TEST = "types::heap_registry::lifecycle::tests::child_selected_arena_two_workers_hold_and_release_exact_theap_slices"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-lifecycle-unit"
FIELDS = (
    "two_before",
    "two_refs",
    "two_detached",
    "two_first_released",
    "two_held",
    "two_released",
)


def trace(output: str, prefix: str) -> dict[str, str]:
    rows = re.findall(rf"^(?:test \S+ \.\.\. )?{prefix}\.([a-z_]+)=([0-9,]+)$", output, re.MULTILINE)
    if len(rows) != len(FIELDS) or [key for key, _ in rows] != list(FIELDS):
        raise harness.HarnessError(f"{prefix} ownership trace has missing, repeated, or unordered fields: {rows}")
    return dict(rows)


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-heap-lifecycle-unit-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        driver = temporary / "heap-lifecycle-unit-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(oracle.DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(driver)],
            cwd=source, timeout_seconds=300,
        )
        (ARTIFACTS / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "two-worker child Heap source build")
        c_run = harness.command_record([str(driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "two-worker child Heap source run")
        c_trace = trace(str(c_run["stderr"]), "source")

    rust = harness.command_record(
        ["python3", "compat/allocator/run_unit_x86_64.py", TEST],
        cwd=harness.ROOT, timeout_seconds=900,
    )
    (ARTIFACTS / "rust.log").write_text(str(rust["stdout"]) + str(rust["stderr"]))
    harness.require_success(rust, "two-worker child Heap private Rust unit")
    rust_trace = trace(str(rust["stdout"]), "unit")
    if c_trace != rust_trace:
        raise harness.HarnessError(f"child Heap owner transitions differ: C={c_trace} Rust={rust_trace}")
    print(f"child Heap lifecycle unit: {len(c_trace)} pinned-C/private-Rust ownership transitions match; {ARTIFACTS}")


if __name__ == "__main__":
    main()
