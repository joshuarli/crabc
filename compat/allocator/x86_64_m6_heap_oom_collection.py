#!/usr/bin/env python3
"""Compare pinned-C and Rust generic allocation-retry collection observations."""

import os
from pathlib import Path

import run as harness


C_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_oom_collect_oracle.c"
RUST_TEST = "single_thread::tests::generic_oom_retry_collects_remote_frees_across_regular_bins"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/heap-lifecycle/generic-oom-collection"
OBSERVATION = "oom_retry_released_remote_empty_other_bin=1"


def observation(output: str, side: str) -> str:
    if side == "pinned C":
        if output != f"{OBSERVATION}\n":
            raise harness.HarnessError("pinned C generic OOM collection output must be exactly one observation")
    elif side == "Rust":
        expected = f"test {RUST_TEST} ... {OBSERVATION}"
        rows = [line for line in output.splitlines() if "=" in line]
        if rows != [expected]:
            raise harness.HarnessError(f"Rust generic OOM collection observation is absent or malformed: {rows}")
    else:
        raise harness.HarnessError(f"unknown generic OOM collection source: {side}")
    return OBSERVATION


def run() -> str:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with harness.temporary_directory(prefix="heap-oom-collection-source-") as directory:
        source = harness.safe_extract(archive, Path(directory), pin["archive_root"])
        executable = Path(directory) / "oom-collection-c"
        command = [harness.require_tool("musl-gcc"), "-std=c11", "-ftls-model=initial-exec",
            "-DMI_LIBC_MUSL=1", *harness.CONFIGURATION_PROFILES["release"],
            "-I", str(source / "include"), "-I", str(source / "src"),
            str(C_ORACLE), "-pthread", "-o", str(executable)]
        c_build = harness.command_record(command, cwd=source, timeout_seconds=300)
        (ARTIFACTS / "c-build.log").write_text(c_build["stdout"] + c_build["stderr"])
        harness.require_success(c_build, "generic OOM collection pinned-C build")
        c_run = harness.command_record([str(executable)], cwd=directory, env={}, timeout_seconds=60)
        (ARTIFACTS / "c.log").write_text(c_run["stdout"] + c_run["stderr"])
        harness.require_success(c_run, "generic OOM collection pinned-C run")
        c_observation = observation(c_run["stdout"], "pinned C")

    rust_command = ["cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
        "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST,
        "--", "--exact", "--nocapture", "--test-threads=1"]
    rust_environment = {**os.environ, "CARGO_PROFILE_DEV_OPT_LEVEL": "0", "CARGO_PROFILE_TEST_OPT_LEVEL": "0"}
    rust = harness.command_record(rust_command, cwd=harness.ROOT,
        env=rust_environment, timeout_seconds=60)
    (ARTIFACTS / "rust.log").write_text(rust["stdout"] + rust["stderr"])
    harness.require_success(rust, "generic OOM collection Rust unit")
    if harness.parse_rust_test_count(rust["stdout"]) != 1:
        raise harness.HarnessError("generic OOM collection did not execute exactly one Rust test")
    rust_observation = observation(rust["stdout"], "Rust")
    if c_observation != rust_observation:
        raise harness.HarnessError(
            f"generic OOM collection differs: pinned C={c_observation} Rust={rust_observation}")
    return c_observation

