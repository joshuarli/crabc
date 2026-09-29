#!/usr/bin/env python3
"""Compare a deleted Heap's remote final free and former owner exit."""

import argparse
from pathlib import Path

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_deleted_heap_remote_exit_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-deleted-heap-remote-exit"
BEGIN = "CRABC_MI_M6_DELETED_HEAP_REMOTE_EXIT_BEGIN"
END = "CRABC_MI_M6_DELETED_HEAP_REMOTE_EXIT_END"
EXPECTED = {
    "before": {
        "remote.event_alloc": "1",
        "remote.event_deleted": "1",
        "remote.event_owner_return": "1",
        "remote.event_owner_exit": "1",
        "remote.event_free_start": "1",
        "remote.event_free_done": "1",
        "remote.mode": "0,1",
        "remote.ready": "1,1,1",
        "remote.published": "1,1,1,37",
        "remote.exit": "1,1",
        "remote.collect": "1,1",
        "remote.stats": "0,0,0,0,-1,0",
    },
    "after": {
        "remote.event_alloc": "1",
        "remote.event_deleted": "1",
        "remote.event_owner_return": "1",
        "remote.event_owner_exit": "1",
        "remote.event_free_start": "1",
        "remote.event_free_done": "1",
        "remote.mode": "1,1",
        "remote.ready": "1,1,1",
        "remote.published": "1,1,1,37",
        "remote.exit": "1,1",
        "remote.collect": "1,1",
        "remote.stats": "0,0,0,-1,0,0",
    },
}
EVENT_ORDER = {
    "before": ("alloc", "deleted", "free_start", "free_done", "owner_return", "owner_exit"),
    "after": ("alloc", "deleted", "owner_return", "owner_exit", "free_start", "free_done"),
}


def check_event_order(stdout: str, mode: str, label: str) -> None:
    events = tuple(
        line.removeprefix("remote.event_").split("=", 1)[0]
        for line in stdout.splitlines()
        if line.startswith("remote.event_")
    )
    if events != EVENT_ORDER[mode]:
        raise harness.HarnessError(f"{label} event order changed: {events}")


def run_differential(source_only: bool, modes: tuple[str, ...]) -> dict[str, int]:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-deleted-heap-remote-exit-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "deleted-heap-remote-exit-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Deleted Heap remote-exit C build")
        c_runs = {}
        c_traces = {}
        for mode in modes:
            c_run = harness.command_record([str(c_driver), mode], cwd=temporary, env={}, timeout_seconds=60)
            (ARTIFACTS / f"c-{mode}.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
            harness.require_success(c_run, f"Deleted Heap remote-exit C run ({mode})")
            c_trace = m7.parse_options_trace(str(c_run["stdout"]), f"C deleted Heap remote exit ({mode})", BEGIN, END)
            check_event_order(str(c_run["stdout"]), mode, "pinned C")
            if c_trace != EXPECTED[mode]:
                raise harness.HarnessError(f"pinned deleted Heap remote-exit trace changed ({mode}): {c_trace}")
            c_runs[mode] = c_run
            c_traces[mode] = c_trace
        if source_only:
            for mode in modes:
                print(c_traces[mode])
            return {mode: len(c_traces[mode]) for mode in modes}
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "deleted-heap-remote-exit-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2", "-I", str(source / "include"),
             str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Deleted Heap remote-exit Rust link")
        for mode in modes:
            rust_run = harness.command_record([str(rust_driver), mode], cwd=temporary, env={}, timeout_seconds=60)
            (ARTIFACTS / f"rust-{mode}.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
            harness.require_success(rust_run, f"Deleted Heap remote-exit Rust run ({mode})")
            rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), f"Rust deleted Heap remote exit ({mode})", BEGIN, END)
            check_event_order(str(rust_run["stdout"]), mode, "Rust")
            m7.compare_options_traces(c_traces[mode], rust_trace)
            if str(c_runs[mode]["stderr"]) != str(rust_run["stderr"]):
                raise harness.HarnessError(f"deleted Heap remote-exit diagnostics differ ({mode})")
        return {mode: len(c_traces[mode]) for mode in modes}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--mode", choices=("before", "after", "both"), default="both")
    arguments = parser.parse_args()
    modes = ("before", "after") if arguments.mode == "both" else (arguments.mode,)
    counts = run_differential(arguments.source_only, modes)
    for mode in modes:
        print(f"Deleted Heap remote exit ({mode}): {counts[mode]} keys")
