#!/usr/bin/env python3
"""Compare Heap destruction while an exited creator's second worker stays attached."""

from pathlib import Path
import os
import sys

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_heap_destroy_racing_detach_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-heap-destroy-racing-detach"
BEGIN = "CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_BEGIN"
END = "CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_END"
EXPECTED = {"race.completed": "64", "race.owners": "0,0"}
REPETITIONS = 32


def run_differential(audit: bool = False, interleave: bool = False) -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    artifacts = ARTIFACTS / ("thread-done-interleave" if interleave else "thread-done-audit") if audit else ARTIFACTS
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-heap-destroy-racing-detach-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "heap-destroy-racing-detach-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-ftls-model=initial-exec",
             "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(c_driver)],
            cwd=source,
        )
        (artifacts / "c-build.log").write_text(str(c_build["stdout"]) + str(c_build["stderr"]))
        harness.require_success(c_build, "Heap destroy racing detach C build")
        c_logs = []
        for attempt in range(REPETITIONS):
            c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
            c_logs.append(str(c_run["stdout"]) + str(c_run["stderr"]))
            (artifacts / "c.log").write_text("\n".join(c_logs))
            harness.require_success(c_run, f"Heap destroy racing detach C run {attempt}")
            c_trace = m7.parse_options_trace(str(c_run["stdout"]), "C Heap destroy racing detach", BEGIN, END)
            if c_trace != EXPECTED:
                raise harness.HarnessError(f"pinned Heap destroy racing detach changed on run {attempt}: {c_trace}")
        if audit:
            target = temporary / "cargo-target"
            environment = dict(os.environ)
            environment["RUSTFLAGS"] = "--cfg crabc_native_thread_done_audit --check-cfg=cfg(crabc_native_thread_done_audit)"
            build = harness.command_record(
                [harness.require_tool("cargo"), "build", "--locked", "--release",
                 "--target", m4.RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--target-dir", str(target)],
                cwd=harness.ROOT, env=environment, timeout_seconds=m4.EVIDENCE_TIMEOUT_SECONDS,
            )
            (artifacts / "rust-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
            harness.require_success(build, "isolated thread-done observation adapter build")
            library = target / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        else:
            library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "heap-destroy-racing-detach-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-D_GNU_SOURCE", "-O2",
             *(("-DCRABC_NATIVE_THREAD_DONE_AUDIT=1",) if audit else ()),
             *(("-DCRABC_NATIVE_THREAD_DONE_INTERLEAVE=1",) if interleave else ()),
             "-I", str(source / "include"), str(DRIVER), str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (artifacts / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "Heap destroy racing detach Rust link")
        rust_logs = []
        for attempt in range(REPETITIONS):
            rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
            rust_logs.append(str(rust_run["stdout"]) + str(rust_run["stderr"]))
            (artifacts / "rust.log").write_text("\n".join(rust_logs))
            harness.require_success(rust_run, f"Heap destroy racing detach Rust run {attempt}")
            rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "Rust Heap destroy racing detach", BEGIN, END)
            if audit:
                # Joining every worker precedes these observations. A refusal
                # remains visible alongside the unchanged source owner totals.
                ordering = rust_trace.pop("race.destroy_before_drain", "uncontrolled")
                finish = rust_trace.pop("race.finish")
                refusal = rust_trace.pop("race.refusal")
                if finish != "128,0,0,0,0" or refusal != "0,0,0,0":
                    raise harness.HarnessError(
                        f"joined worker teardown refused on run {attempt}: finish={finish} refusal={refusal} destroy_before_drain={ordering} owners={rust_trace['race.owners']}"
                    )
                if interleave and ordering != "0":
                    raise harness.HarnessError(f"Heap destroy completed inside its retained owner drain on run {attempt}")
            m7.compare_options_traces(c_trace, rust_trace)
            if str(c_run["stderr"]) != str(rust_run["stderr"]):
                raise harness.HarnessError(f"Heap destroy racing detach diagnostics differ on run {attempt}")
        return len(c_trace) * REPETITIONS


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--thread-done-audit"], ["--thread-done-interleave"]):
        raise SystemExit("usage: x86_64_m6_heap_destroy_racing_detach.py [--thread-done-audit|--thread-done-interleave]")
    audit = bool(sys.argv[1:])
    count = run_differential(audit, sys.argv[1:] == ["--thread-done-interleave"])
    if not sys.argv[1:]:
        run_differential(True, True)
    print(f"Heap destroy racing detach: {count} source-built C/Rust keys match; joined drain/detach observations passed")
