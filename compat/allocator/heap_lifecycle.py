#!/usr/bin/env python3
"""Pinned-C/Rust differential for non-main Heap creation, deletion, and destruction.

The C oracle drives pinned `mi_heap_new`, `mi_heap_delete`, and `mi_heap_destroy`
on a thread of a child subprocess; the Rust test drives
`types::heap_registry::lifecycle` on a child member thread. Both print the same
ordered, address-free fields.
"""

from pathlib import Path
import re

import run as harness


TEST = "types::heap_registry::lifecycle::tests::source_ordered_empty_heap_lifecycle_trace"
FIELD_COUNT = 52


def trace(output: str) -> list[int]:
    rows = re.findall(r"^(?:test \S+ \.\.\. )?m6\.heap\.lifecycle\.(\d+)=(-?\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in rows] != list(range(FIELD_COUNT)):
        raise harness.HarnessError(
            f"heap lifecycle trace requires {FIELD_COUNT} ordered fields"
        )
    return [int(value) for _, value in rows]


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
    rust = harness.command_record(["python3", "compat/allocator/run_unit_x86_64.py", TEST],
        cwd=harness.ROOT, timeout_seconds=900)
    (artifacts / "rust.log").write_text(rust["stdout"] + rust["stderr"])
    harness.require_success(rust, "heap lifecycle Rust test")
    expected = trace(oracle["stdout"])
    observed = trace(rust["stdout"])
    if expected != observed:
        differences = [
            f"{index}: C={c_value} Rust={rust_value}"
            for index, (c_value, rust_value) in enumerate(zip(expected, observed))
            if c_value != rust_value
        ]
        raise harness.HarnessError(
            "pinned C/Rust heap lifecycle differs: " + ", ".join(differences)
        )
    print(f"heap lifecycle: {FIELD_COUNT} pinned C/Rust values match; {artifacts}")


if __name__ == "__main__":
    main()
