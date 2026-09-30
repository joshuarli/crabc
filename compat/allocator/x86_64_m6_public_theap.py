#!/usr/bin/env python3
"""Compare public default-Theap switching and direct allocation with pinned C."""

import argparse
from pathlib import Path
import re
import shutil

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
    "interleaved": "1",
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
    "guarded": "1,1,1,1,1,1,1,1,1",
    "stats": "1,1,1,1,1,1,1",
    "visitor": "1,1,1,1,1,1,1,1",
    "collect": "1,1,1,1",
    "restore": "1,1",
    "after": "1,1",
    "delete_live": "1,1,1",
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


def require_trace(trace: dict[str, str], side: str, guarded_only: bool = False) -> None:
    selected_stages = {"base", "other", "reject", "direct_before", "switch", "guarded", "restore", "done"}
    expected = ({key: value for key, value in SOURCE_TRACE.items()
                 if key.rsplit(".", 1)[-1] in selected_stages or key.startswith("main.after_")}
                if guarded_only else SOURCE_TRACE)
    if set(trace) != set(expected):
        raise harness.HarnessError(
            f"{side} public Theap keys differ: "
            f"missing={sorted(set(expected) - set(trace))} "
            f"extra={sorted(set(trace) - set(expected))}"
        )
    for key, value in trace.items():
        if not re.fullmatch(r"[01](?:,[01])*", value):
            raise harness.HarnessError(f"{side} {key} is malformed: {value}")
    if side == "c" and trace != expected:
        raise harness.HarnessError(f"pinned C public Theap image changed: {trace}")


def main(profile: str = "release", guarded_only: bool = False) -> None:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    if profile not in ("release", "debug-1", "stat-1", "stat-2"):
        raise harness.HarnessError(f"unsupported public Theap profile: {profile}")
    artifacts = ARTIFACTS if profile == "release" else ARTIFACTS / profile
    if guarded_only:
        artifacts = artifacts / "guarded-configuration"
    client_flags = ("-DCRABC_PUBLIC_GUARDED_CONFIGURATION_ONLY=1",) if guarded_only else ()
    artifacts.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory("crabc-mimalloc-m6-public-theap-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "public-theap-c"
        build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             "-DCRABC_M6_SOURCE_INTERNAL=1", *m4.api_profile_flags(profile), *client_flags,
             "-I", str(source / "include"), "-I", str(source / "src"),
             str(DRIVER), str(source / "src/static.c"),
             "-pthread", "-o", str(c_driver)], cwd=source,
        )
        (artifacts / "c-build.log").write_text(str(build["stdout"]) + str(build["stderr"]))
        harness.require_success(build, "public Theap C build")
        shutil.copy2(c_driver, artifacts / "public-theap-c")
        c_run = harness.command_record([str(c_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (artifacts / "c.log").write_text(str(c_run["stdout"]) + str(c_run["stderr"]))
        harness.require_success(c_run, "public Theap C run")
        for context in ("main", "worker", "child", "fork"):
            if re.findall(rf"^source\.{context}=([01]),([01]),([01])$",
                          str(c_run["stderr"]), re.MULTILINE) != [("1", "1", "1")]:
                raise harness.HarnessError(f"pinned C {context} Theap ownership differs")
        for context in (() if guarded_only else ("main", "worker", "child", "fork")):
            if re.findall(rf"^source\.{context}\.collect_empty=([01])$",
                          str(c_run["stderr"]), re.MULTILINE) != ["1"]:
                raise harness.HarnessError(f"pinned C {context} force collection leaves live Theap pages")
        c_trace = m7.parse_options_trace(str(c_run["stdout"]), "c", BEGIN, END)
        require_trace(c_trace, "c", guarded_only)
        library = m4.build_adapter_library(temporary, profile)
        rust_driver = temporary / "public-theap-rust"
        link = harness.command_record(
            [compiler, "-std=c11", "-O2", *client_flags, "-I", str(source / "include"), str(DRIVER),
             str(library), "-pthread", "-o", str(rust_driver)], cwd=source,
        )
        (artifacts / "rust-link.log").write_text(str(link["stdout"]) + str(link["stderr"]))
        harness.require_success(link, "public Theap Rust link")
        shutil.copy2(rust_driver, artifacts / "public-theap-rust")
        rust_run = harness.command_record([str(rust_driver)], cwd=temporary, env={}, timeout_seconds=60)
        (artifacts / "rust.log").write_text(str(rust_run["stdout"]) + str(rust_run["stderr"]))
        harness.require_success(rust_run, "public Theap Rust run")
        rust_trace = m7.parse_options_trace(str(rust_run["stdout"]), "rust", BEGIN, END)
        require_trace(rust_trace, "rust", guarded_only)
        m7.compare_options_traces(c_trace, rust_trace)
        if guarded_only:
            print(f"public Theap guarded configuration ({profile}): {len(c_trace)} source-built C/Rust keys match")
            return
        direct_test = "public_theap_selection_allocation_collection_and_lifetime"
        direct = harness.command_record(
            [harness.require_tool("cargo"), "test", "--locked", "--offline", "--target", m4.RUST_TARGET,
             "-p", "crabc-mimalloc", "--no-default-features",
             *(("--features", f"mi-{profile}") if profile != "release" else ()), "--test", "native_theap_contract",
             direct_test, "--", "--exact", "--nocapture", "--test-threads=1"],
            cwd=harness.ROOT, timeout_seconds=900,
        )
        (artifacts / "native_theap_contract.log").write_text(
            str(direct["stdout"]) + str(direct["stderr"]))
        harness.require_success(direct, "public Theap direct runtime contract")
        if len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                          str(direct["stdout"]), re.MULTILINE)) != 1:
            raise harness.HarnessError("public Theap direct runtime contract did not execute exactly one test")
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
            (artifacts / f"{test.rsplit('::', 1)[-1]}.log").write_text(
                str(record["stdout"]) + str(record["stderr"]))
            harness.require_success(record, f"public Theap regression {test}")
        print(f"public Theap allocation and collection: {len(c_trace)} source-built C/Rust keys match; direct runtime contract and five fresh-process regressions pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("release", "debug-1", "stat-1", "stat-2"), default="release")
    parser.add_argument("--guarded-only", action="store_true",
                        help="run the bounded configuration and live-client transaction")
    arguments = parser.parse_args()
    main(arguments.profile, arguments.guarded_only)
