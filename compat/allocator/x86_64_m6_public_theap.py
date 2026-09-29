#!/usr/bin/env python3
"""Compare public default-Theap switching and direct allocation with pinned C."""

from pathlib import Path
import re

import run as harness
import x86_64_m4_gate as m4
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m6_public_theap_driver.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m6-public-theap"
BEGIN = "CRABC_MI_M6_PUBLIC_THEAP_TRACE_BEGIN"
END = "CRABC_MI_M6_PUBLIC_THEAP_TRACE_END"
SOURCE_STAGES = {
    "base": "1,1,0",
    "other": "1,1,1",
    "reject": "1,1",
    "direct_before": "1,1",
    "switch": "1,1,1",
    "allocate": "1,1,1,1",
    "still_switched": "1,1",
    "variants": "1,1,1,1,1,1,1,1,1",
    "overflow": "1,1",
    "bad_alignment": "1,1",
    "aligned_selection": "1,1,1,1",
    "default_aligned_growth": "1,1,1",
    "reuse": "1,1,1",
    "expand": "1,1,1",
    "failed_realloc": "1,1,1,1",
    "cross_heap": "1,1,1,1",
    "zero_realloc": "1,1",
    "null_rezalloc": "1,1",
    "guarded": "1",
    "stats": "1,1,1,1,1,1,1",
    "visitor": "1,1,1,1,1,1,1,1",
    "collect": "1,1,1,1",
    "restore": "1,1",
    "after": "1,1",
    "done": "1",
}
SOURCE_TRACE = {
    **{f"{context}.{stage}": value
       for context in ("main", "worker", "child", "fork")
       for stage, value in SOURCE_STAGES.items()},
    "main.after_worker": "1",
    "main.after_child": "1",
    "main.after_fork": "1,1",
    "fork.base": "1,0,1",
}


def require_trace(trace: dict[str, str], side: str) -> None:
    if set(trace) != set(SOURCE_TRACE):
        raise harness.HarnessError(
            f"{side} public Theap keys differ: "
            f"missing={sorted(set(SOURCE_TRACE) - set(trace))} "
            f"extra={sorted(set(trace) - set(SOURCE_TRACE))}"
        )
    for key, value in trace.items():
        if not re.fullmatch(r"[01](?:,[01])*", value):
            raise harness.HarnessError(f"{side} {key} is malformed: {value}")
    if side == "c" and trace != SOURCE_TRACE:
        raise harness.HarnessError(f"pinned C public Theap image changed: {trace}")


def main() -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-public-theap-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "public-theap-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *harness.CONFIGURATION_PROFILES["release"],
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (ARTIFACTS / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "public Theap C build")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "public Theap C run")
        for context in ("main", "worker", "child", "fork"):
            if re.findall(rf"^source\.{context}=([01]),([01]),([01])$",
                          str(c_run["stderr"]), re.MULTILINE) != [("1", "1", "1")]:
                raise harness.HarnessError(f"pinned C {context} Theap ownership differs")
        for context in ("main", "worker", "child", "fork"):
            if re.findall(rf"^source\.{context}\.collect_empty=([01])$",
                          str(c_run["stderr"]), re.MULTILINE) != ["1"]:
                raise harness.HarnessError(f"pinned C {context} force collection leaves live Theap pages")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "c", BEGIN, END)
        require_trace(c_trace, "c")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "public-theap-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (ARTIFACTS / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "public Theap Rust link")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (ARTIFACTS / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "public Theap Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "rust", BEGIN, END)
        require_trace(rust_trace, "rust")
        m7.compare_options_traces(c_trace, rust_trace)
        for test in (
            "source_api::tests::switched_default_aligned_allocation_keeps_selected_heap",
            "source_api::tests::switched_default_reallocation_keeps_selected_heap",
            "source_api::tests::direct_theap_variants_preserve_roots_and_reallocation_lifetime",
            "runtime_lifecycle::tests::worker_fixed_theap_collection_preserves_auxiliary_default",
            "runtime_lifecycle::tests::runtime_loader_tail_releases_once_before_delayed_output",
        ):
            record = harness.command_record(
                ["python3", "compat/allocator/run_unit_x86_64.py", test],
                cwd=harness.ROOT, timeout_seconds=900,
            )
            (ARTIFACTS / f"{test.rsplit('::', 1)[-1]}.log").write_text(
                str(record["stdout"]) + str(record["stderr"]))
            harness.require_success(record, f"public Theap regression {test}")
        print(f"public Theap allocation and collection: {len(c_trace)} source-built C/Rust keys match; five fresh-process regressions pass")


if __name__ == "__main__":
    main()
