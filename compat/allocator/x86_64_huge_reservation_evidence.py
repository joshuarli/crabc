#!/usr/bin/env python3
"""Pinned huge interleave/free policy, owned cleanup, and startup fault evidence."""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("allocator_run", ROOT / "compat/allocator/run.py")
assert spec and spec.loader
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
TESTS = (
    "arena::owned::huge::tests::huge_interleave_preserves_source_distribution_timeout_and_first_error",
    "arena::owned::huge::tests::huge_cleanup_retains_metadata_and_only_failed_pages_until_raw_retry",
    "arena::owned::huge::tests::huge_cleanup_metadata_failure_preserves_full_owner_before_any_free",
    "arena::owned::huge::tests::huge_reservation_primitive_failure_needs_no_tracking_metadata",
    "arena::owned::huge::tests::huge_successful_reservation_keeps_metadata_tracking_unallocated",
    "arena::owned::huge::tests::huge_rejected_primitive_cleanup_never_consumes_the_published_prefix",
    "os::tests::huge_release_moves_owned_tracking_with_the_exact_failed_page_set",
    "os::tests::huge_os_release_walks_after_failures_and_records_exact_page_bits",
    "process_init::tests::huge_failed_startup_reservation_preserves_the_later_regular_option",
    "process_init::tests::huge_startup_attempt_precedes_the_explicit_regular_reservation",
)


def checked(command: list[str], description: str) -> dict:
    record = run.command_record(command, cwd=ROOT)
    run.require_success(record, description)
    return record


def extract(source: Path, signature: str) -> tuple[str, dict]:
    text = source.read_text()
    definition = re.search(re.escape(signature) + r"[^;{]*\{", text)
    if definition is None:
        raise run.HarnessError(f"missing pinned definition: {signature}")
    start = definition.start()
    opening = definition.end() - 1
    depth = 1
    end = opening + 1
    while depth:
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
        end += 1
    function = text[start:end]
    return function, {"member": "src/" + source.name, "signature": signature,
        "start_line": text[:start].count("\n") + 1,
        "end_line": text[:end].count("\n") + 1,
        "sha256": hashlib.sha256(function.encode()).hexdigest()}


def trace(output: str, kind: str, count: int) -> list[int]:
    pairs = re.findall(r"(?<!\S)m2\.huge\." + kind + r"\.(\d+)=(\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in pairs] != list(range(count)):
        raise run.HarnessError(f"{kind} trace must have exactly {count} ordered fields")
    return [int(value) for _, value in pairs]


def main() -> int:
    if os.uname().machine != "x86_64" or os.environ.get("CRABC_EXECUTION_MODE") != "native":
        raise run.HarnessError("huge reservation evidence requires the pinned native x86 launcher")
    pin = run.load_pin()
    archive = run.fetch_archive(pin, True)
    revision = checked(["git", "rev-parse", "HEAD"], "source revision")["stdout"].strip()
    dirty = checked(["git", "status", "--porcelain"], "source status")["stdout"]
    with run.temporary_directory("huge-reservation-") as name:
        temporary = Path(name)
        source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        interleave, first_anchor = extract(source / "src/arena.c", "int mi_reserve_huge_os_pages_interleave(")
        free, second_anchor = extract(source / "src/os.c", "static void mi_os_free_huge_os_pages(")
        template = (ROOT / "compat/allocator/m2_huge_reservation_x86_64.c").read_text()
        probe = temporary / "huge-reservation.c"
        probe.write_text(template.replace("/* INTERLEAVE_SOURCE */", interleave).replace("/* HUGE_FREE_SOURCE */", free))
        binary = temporary / "huge-reservation-c"
        checked([run.require_tool("musl-gcc"), "-std=c11", "-O2", str(probe), "-o", str(binary)],
            "pinned C huge policy build")
        header = checked([run.require_tool("readelf"), "-h", str(binary)], "C ELF identity")
        elf = run.parse_elf_identity(header["stdout"], "x86_64")
        c = checked([str(binary)], "pinned C huge policy execution")
        rust_output = ""
        for test in TESTS:
            rust = checked([run.require_tool("cargo"), "test", "--locked", "--target",
                "x86_64-unknown-linux-musl", "-p", "crabc-mimalloc", "--lib", "--no-default-features",
                test, "--", "--exact", "--nocapture", "--test-threads=1"], test)
            output = rust["stdout"] + "\n" + rust["stderr"]
            if run.parse_rust_test_count(output) != 1:
                raise run.HarnessError(f"{test} did not run exactly once")
            rust_output += output + "\n"
        values = {}
        for kind, count in (("interleave", 66), ("free", 3)):
            c_values, rust_values = trace(c["stdout"], kind, count), trace(rust_output, kind, count)
            if c_values != rust_values:
                raise run.HarnessError(f"{kind} mismatch: C={c_values}, Rust={rust_values}")
            values[kind] = c_values
        report = {"status": "passed", "architecture": "x86_64", "execution": "native",
            "revision": revision, "source_dirty": bool(dirty), "upstream": pin,
            "c_elf": elf, "source_anchors": [first_anchor, second_anchor], "values": values,
            "rust_tests": list(TESTS), "scope": "source huge policy, durable failed-page ownership, startup reservation order",
            "nonclaims": ["hardware huge-page success", "C metadata failure-recovery parity",
                "diagnostic callbacks", "full M2 closure", "AArch64 qualification"]}
    after = checked(["git", "rev-parse", "HEAD"], "final revision")["stdout"].strip()
    after_dirty = checked(["git", "status", "--porcelain"], "final source status")["stdout"]
    if revision != after or dirty != after_dirty:
        raise run.HarnessError("source state changed during huge reservation evidence")
    path = ROOT / "compat/reports/allocator/x86_64/huge-reservation.json"
    run.write_json(path, report)
    path.chmod(0o644)
    print(f"allocator huge reservation evidence: PASS (69 values, 10 focused tests; {path})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (run.HarnessError, OSError, ValueError) as error:
        print(f"allocator huge reservation evidence: FAIL: {error}")
        raise SystemExit(1)
