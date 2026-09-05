#!/usr/bin/env python3
"""Bounded huge registry differential; simulated primitives, not huge VM qualification."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("allocator_run", ROOT / "compat/allocator/run.py")
assert spec and spec.loader
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


def trace(output: str) -> list[int]:
    pairs = re.findall(r"(?<!\S)m2\.huge\.registry\.(\d+)=(\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in pairs] != list(range(8)):
        raise run.HarnessError("huge registry trace must contain exactly eight ordered fields")
    return [int(value) for _, value in pairs]


def checked(command: list[str], description: str, cwd: Path = ROOT) -> dict:
    result = run.command_record(command, cwd=cwd)
    run.require_success(result, description)
    return result


def main() -> int:
    if os.uname().machine != "x86_64" or os.environ.get("CRABC_EXECUTION_MODE") != "native":
        raise run.HarnessError("huge registry evidence requires the pinned native x86 launcher")
    pin = run.load_pin()
    archive = run.fetch_archive(pin, True)
    revision = checked(["git", "rev-parse", "HEAD"], "source revision")["stdout"].strip()
    dirty = checked(["git", "status", "--porcelain"], "source status")["stdout"]
    with tempfile.TemporaryDirectory(prefix="huge-registry-") as name:
        temporary = Path(name)
        source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        binary = temporary / "huge-registry-c"
        checked([run.require_tool("musl-gcc"), "-std=c11", "-DMI_SHARED_LIB",
            "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *run.CONFIGURATION_PROFILES["release"],
            str(ROOT / "compat/allocator/m2_huge_registry_x86_64.c"), "-pthread", "-o", str(binary)],
            "pinned C huge registry build")
        header = checked([run.require_tool("readelf"), "-h", str(binary)], "C ELF identity")
        elf = run.parse_elf_identity(header["stdout"], "x86_64")
        c = checked([str(binary)], "pinned C huge registry execution")
        rust = checked([run.require_tool("cargo"), "test", "--locked", "--target",
            "x86_64-unknown-linux-musl", "-p", "crabc-mimalloc", "--lib", "--no-default-features",
            "arena::owned::tests::huge_", "--", "--nocapture", "--test-threads=1"],
            "Rust huge registry ownership tests")
        output = rust["stdout"] + "\n" + rust["stderr"]
        count = run.parse_rust_test_count(output)
        if count != 3:
            raise run.HarnessError(f"expected three huge registry ownership tests, got {count}")
        c_trace, rust_trace = trace(c["stdout"]), trace(output)
        if c_trace != rust_trace or c_trace != [3, 17, 1, 1, 1, 1, 0, 0]:
            raise run.HarnessError(f"huge registry trace mismatch: C={c_trace}, Rust={rust_trace}")
        report = {"status": "passed", "architecture": "x86_64", "execution": "native",
            "revision": revision, "source_dirty": bool(dirty), "upstream": pin,
            "c_elf": elf, "values": c_trace, "rust_tests": count,
            "scope": "same-registry huge ownership and multi-arena publication",
            "nonclaims": ["kernel huge-page allocation", "reservation/startup callers",
                "process cleanup and failed-page tracker ownership", "M2 closure", "AArch64"]}
    after = checked(["git", "rev-parse", "HEAD"], "final revision")["stdout"].strip()
    after_dirty = checked(["git", "status", "--porcelain"], "final source status")["stdout"]
    if revision != after or dirty != after_dirty:
        raise run.HarnessError("source revision changed during huge registry evidence")
    path = ROOT / "compat/reports/allocator/x86_64/huge-registry.json"
    run.write_json(path, report)
    print(f"allocator huge registry differential: PASS (8 values, 3 ownership tests; {path})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (run.HarnessError, OSError, ValueError) as error:
        print(f"allocator huge registry differential: FAIL: {error}")
        raise SystemExit(1)
