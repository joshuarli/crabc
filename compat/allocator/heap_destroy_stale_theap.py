#!/usr/bin/env python3
"""Differential reproduction for mimalloc PR #1420's stale cached Theap."""

from pathlib import Path
import re

import run as harness


FIXTURE = Path(__file__).with_suffix(".c")
ANCHOR = "      mi_assert_internal(theap->tld==NULL);\n"
PATCH = "      mi_atomic_store_ptr_release(mi_heap_t, &theap->heap, NULL);\n"
TRACE = re.compile(r"^m6\.heap\.stale\.(reused|cached_old|cache_changed|contains)=(\d+)$", re.MULTILINE)


def build_and_run(source: Path, output: Path, artifacts: Path, label: str) -> tuple[int, str]:
    command = [
        harness.require_tool("musl-gcc"), "-std=c11", "-D_GNU_SOURCE", "-fPIC", "-ftls-model=initial-exec",
        "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
        "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
        "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
        str(FIXTURE.resolve()), "-pthread", "-o", str(output),
    ]
    build = harness.command_record(command, cwd=source, timeout_seconds=300)
    (artifacts / f"{label}-build.log").write_text(build["stdout"] + build["stderr"])
    harness.require_success(build, f"stale Theap {label} C build")
    run = harness.command_record([str(output)], cwd=source, timeout_seconds=60)
    output = str(run["stdout"]) + str(run["stderr"])
    (artifacts / f"{label}-run.log").write_text(f"status={run['status']}\n" + output)
    return int(run["status"]), output


def observe(label: str, status: int, output: str, expected: tuple[int, int, int, int]) -> None:
    rows = TRACE.findall(output)
    values = tuple(int(value) for _, value in rows)
    names = [name for name, _ in rows]
    complete = names == ["reused", "cached_old", "cache_changed", "contains"] and values == expected
    cached_then_crashed = (
        label == "pinned v3.5.0"
        and names == ["reused", "cached_old"]
        and values == (1, 1)
        and status < 0
    )
    if not complete and not cached_then_crashed:
        raise harness.HarnessError(f"stale Theap {label} expected {expected}, got {values}")
    if not cached_then_crashed and status != (0 if expected[2:] == (1, 1) else 1):
        raise harness.HarnessError(f"stale Theap {label} had unexpected exit status {status}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = harness.ARTIFACT_ROOT / "x86_64/heap-destroy-stale-theap"
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="heap-destroy-stale-theap-") as directory:
        root = Path(directory)
        pinned_root = root / "pinned"
        patched_root = root / "patched"
        pinned_root.mkdir()
        patched_root.mkdir()
        source = harness.safe_extract(archive, pinned_root, pin["archive_root"])
        patched = harness.safe_extract(archive, patched_root, pin["archive_root"])
        heap_source = patched / "src/heap.c"
        content = heap_source.read_text()
        if content.count(ANCHOR) != 1:
            raise harness.HarnessError("pinned heap.c no longer has the expected PR #1420 insertion point")
        heap_source.write_text(content.replace(ANCHOR, ANCHOR + PATCH, 1))
        (artifacts / "pinned").mkdir(exist_ok=True)
        (artifacts / "patched").mkdir(exist_ok=True)
        pinned_status, pinned_output = build_and_run(source, artifacts / "pinned/repro", artifacts, "pinned")
        patched_status, patched_output = build_and_run(patched, artifacts / "patched/repro", artifacts, "patched")
    observe("pinned v3.5.0", pinned_status, pinned_output, (1, 1, 0, 0))
    observe("PR #1420 patch", patched_status, patched_output, (1, 1, 1, 1))
    print(f"stale cached Theap: pinned v3.5.0 fails after Heap address reuse; PR #1420's one-line heap invalidation passes; {artifacts}")


if __name__ == "__main__":
    main()
