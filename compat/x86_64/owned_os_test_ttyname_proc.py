#!/usr/bin/env python3
"""Prove os-test's untouched ttyname sources need only basic's private procfs.

This focused native evidence is deliberately narrower than the ten-suite
``owned_os_test.py`` campaign.  It compiles the two pinned original sources once
with the supplied dynamic product and once with pinned static musl, then runs
both binaries in two otherwise identical disposable basic roots: an unmounted
empty ``/proc`` reservation and the bounded procfs fixture.  It records raw
status/stdout/stderr bytes for every source, side, and root.  The runner makes
no source edit, no runtime-provider change, and no aggregate qualification
claim.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from typing import Any

import owned_os_test as os_test
import owned_posix_product_evidence as product_evidence

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-os-test-ttyname-proc/v1"
SOURCE_CASES = ("ttyname", "ttyname_r")
SOURCE_FLAGS = (
    "-Wall",
    "-Wextra",
    "-Werror=implicit-function-declaration",
    "-D_GNU_SOURCE",
    "-D_BSD_SOURCE",
    "-D_ALL_SOURCE",
    "-D_DEFAULT_SOURCE",
)

# These are the unchanged pinned basic sources' observed reports.  A missing
# /proc cannot be treated as a candidate defect; the proc-mounted root must
# make both product and musl pass with the same raw streams.
EXPECTED_RUNS = {
    "without-proc": {
        "ttyname": {"status": 1, "stdout": b"", "stderr": b"ttyname: ENOENT\n"},
        "ttyname_r": {"status": 1, "stdout": b"", "stderr": b"ttyname_r: ENOENT\n"},
    },
    "with-proc": {
        "ttyname": {"status": 0, "stdout": b"", "stderr": b""},
        "ttyname_r": {"status": 0, "stdout": b"", "stderr": b""},
    },
}


class ProofError(RuntimeError):
    """The focused source proof is incomplete or differs from its contract."""


def artifact(work: Path, path: Path, value: bytes) -> dict[str, Any]:
    """Retain raw bytes and their decoded observation without eliding either."""
    return {**os_test.retain_bytes(work, path, value), **os_test.stream_snapshot(value)}


def capture(work: Path, stem: Path, command: list[str], environment: dict[str, str], timeout: float,
            *, cwd: Path | None = None) -> dict[str, Any]:
    """Run one bounded command and retain exact status/stdout/stderr bytes."""
    try:
        process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, start_new_session=True)
    except OSError as error:
        status: int | str = "EXEC_ERROR"
        stdout, stderr = b"", (str(error) + "\n").encode()
    else:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            status = process.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
            status = "TIMEOUT"
    status_bytes = (str(status) + "\n").encode()
    return {
        "command": command,
        "cwd": str(cwd) if cwd is not None else None,
        "timeout_seconds": timeout,
        "status": status,
        "raw": {
            "status": artifact(work, work / "raw" / stem.with_suffix(".status"), status_bytes),
            "stdout": artifact(work, work / "raw" / stem.with_suffix(".stdout"), stdout),
            "stderr": artifact(work, work / "raw" / stem.with_suffix(".stderr"), stderr),
        },
    }


def require_success(record: dict[str, Any], label: str) -> None:
    if record["status"] != 0:
        raise ProofError(f"{label} failed with status {record['status']}")


def source_binding(source: Path, name: str) -> tuple[Path, dict[str, Any]]:
    path = source / "basic" / "unistd" / f"{name}.c"
    os_test.require_regular(path, f"pinned os-test {name} source")
    return path, {"path": str(path), "sha256": os_test.sha256(path),
                  "byte_length": path.stat().st_size, "mode": path.stat().st_mode & 0o7777}


def equal_raw(left: dict[str, Any], right: dict[str, Any], label: str) -> None:
    if left["status"] != right["status"]:
        raise ProofError(f"{label} status differs between candidate and musl")
    for stream in ("status", "stdout", "stderr"):
        if left["raw"][stream]["sha256"] != right["raw"][stream]["sha256"]:
            raise ProofError(f"{label} {stream} bytes differ between candidate and musl")


def require_expected(record: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    if record["status"] != expected["status"]:
        raise ProofError(f"{label} raw status differs from the pinned-source expectation")
    for stream in ("stdout", "stderr"):
        expected_stream = os_test.stream_snapshot(expected[stream])
        actual = record["raw"][stream]
        if any(actual[field] != value for field, value in expected_stream.items()):
            raise ProofError(f"{label} raw {stream} differs from the pinned-source expectation")


def build_programs(work: Path, product: Path, source: Path, environment: dict[str, str], timeout: float) -> dict[str, Any]:
    """Build each original source once per side, with no copied or edited input."""
    candidate_root = work / "candidate"
    musl_root = work / "musl"
    candidate_root.mkdir()
    musl_root.mkdir()
    driver = product / "bin" / "crabc-cc-dynamic"
    musl = Path(os_test.MUSL_COMPILER)
    os_test.require_regular(driver, "supplied dynamic compiler")
    os_test.require_regular(musl, "pinned musl compiler")
    programs: dict[str, Any] = {}
    for name in SOURCE_CASES:
        source_path, binding = source_binding(source, name)
        candidate_object = candidate_root / f"{name}.o"
        candidate = candidate_root / name
        compile_record = capture(
            work, Path("build") / f"{name}.candidate-compile",
            [str(driver), "--dynamic-pie", "-c", str(source_path), "-o", str(candidate_object), *SOURCE_FLAGS],
            environment, timeout, cwd=source / "basic",
        )
        require_success(compile_record, f"candidate compile for unchanged {name}.c")
        link_record = capture(
            work, Path("build") / f"{name}.candidate-link",
            [str(driver), "--dynamic-pie", str(candidate_object), "-o", str(candidate)],
            environment, timeout, cwd=source / "basic",
        )
        require_success(link_record, f"candidate link for unchanged {name}.c")
        receipt = Path(str(candidate) + ".crabc-link.json")
        os_test.require_regular(candidate_object, f"candidate {name} object")
        os_test.require_regular(candidate, f"candidate {name} executable")
        os_test.require_regular(receipt, f"candidate {name} link receipt")
        try:
            link_identity = product_evidence.validate_link(product, candidate_object.absolute(), candidate.absolute(), receipt,
                                                            "pie")
        except (OSError, RuntimeError) as error:
            raise ProofError(f"candidate {name} link receipt is invalid: {error}") from error
        musl_binary = musl_root / name
        musl_record = capture(
            work, Path("build") / f"{name}.musl-static",
            [str(musl), "-static", "-fno-pie", "-no-pie", *SOURCE_FLAGS, str(source_path), "-o", str(musl_binary)],
            environment, timeout, cwd=source / "basic",
        )
        require_success(musl_record, f"pinned-musl static compile/link for unchanged {name}.c")
        os_test.require_regular(musl_binary, f"pinned-musl {name} executable")
        programs[name] = {
            "source": binding,
            "candidate": {
                "path": os_test.artifact_path(work, candidate),
                "sha256": os_test.sha256(candidate),
                "object_path": os_test.artifact_path(work, candidate_object),
                "object_sha256": os_test.sha256(candidate_object),
                "receipt_path": os_test.artifact_path(work, receipt),
                "receipt_sha256": os_test.sha256(receipt),
                "link_identity": link_identity,
                "compile": compile_record,
                "link": link_record,
            },
            "musl_static": {"path": os_test.artifact_path(work, musl_binary), "sha256": os_test.sha256(musl_binary),
                            "compile_link": musl_record},
        }
    return programs


def install_programs(runtime: Path, programs: dict[str, Any], work: Path) -> dict[str, Any]:
    """Place byte-bound candidate and musl binaries beneath the disposable source tree."""
    installed: dict[str, Any] = {}
    for name, program in programs.items():
        target = runtime / "work" / "basic" / "unistd" / name
        musl_target = runtime / "work" / "basic" / "unistd" / f"musl-{name}"
        os_test.retain_file(work / program["candidate"]["path"], target)
        os_test.retain_file(work / program["musl_static"]["path"], musl_target)
        if os_test.sha256(target) != program["candidate"]["sha256"] or os_test.sha256(musl_target) != program["musl_static"]["sha256"]:
            raise ProofError(f"runtime program copy differs from its built {name} input")
        installed[name] = {
            "candidate": {"path": str(target), "sha256": os_test.sha256(target)},
            "musl_static": {"path": str(musl_target), "sha256": os_test.sha256(musl_target)},
        }
    return installed


def close_runtime(work: Path, variant: str, control: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Unmount fixtures before post-run integrity inspection; never walk a live procfs."""
    private = control.get("private_proc")
    if isinstance(private, dict) and isinstance(private.get("mount"), dict) and private["mount"].get("status") == 0:
        if "unmount" not in private:
            private["unmount"] = os_test.unmount_private_proc(private)
    devpts = control.get("private_devpts")
    if isinstance(devpts, dict) and devpts.get("status") == 0 and "unmount" not in devpts:
        devpts["unmount"] = os_test.unmount_private_devpts(devpts)
    safe_proc = os_test.private_proc_postwalk_safe(private)
    safe_devpts = devpts is None or devpts.get("unmount", {}).get("status") == 0
    if not safe_proc or not safe_devpts:
        control["focused_product_integrity"] = {
            "passed": False,
            "difference": {"error": "fixture teardown failed before post-run payload inspection"},
        }
        return control, False
    if "product_payload_before" not in control or "execution_root_after_setup" not in control:
        control["focused_product_integrity"] = {"passed": False, "difference": {"error": "runtime setup was incomplete"}}
        return control, False
    control, intact = os_test.retain_execution_integrity(work, f"ttyname-proc-{variant}", control)
    control["focused_product_integrity"] = control["product_payload"]
    return control, intact


def run_variant(work: Path, product: Path, source: Path, roster: list[dict[str, Any]], programs: dict[str, Any],
                environment: dict[str, str], timeout: float, variant: str) -> dict[str, Any]:
    """Run the same installed binaries in an empty or mounted procfs basic root."""
    runtime = work / "runtime" / variant
    control: dict[str, Any] = {"root": str(runtime), "setup_status": "ERROR"}
    result: dict[str, Any] = {"root": str(runtime), "mount_procfs": variant == "with-proc", "runs": {}, "passed": False}
    failure: str | None = None
    try:
        control = os_test.prepare_execution_root(product, source, runtime, "basic", True, roster)
        private = control.get("private_proc")
        if not isinstance(private, dict):
            raise ProofError("basic runtime did not reserve its private procfs mountpoint")
        if variant == "with-proc":
            os_test.mount_private_proc(runtime, private)
        elif "mount" in private or "namespace" in private or "unmount" in private:
            raise ProofError("unmounted source-proof root unexpectedly mounted procfs")
        result["installed_programs"] = install_programs(runtime, programs, work)
        for name in SOURCE_CASES:
            candidate = capture(
                work, Path("execution") / variant / f"{name}.candidate",
                [os_test.PRIVATE_PROC_WITNESS_CHROOT, str(runtime), "/lib/ld-crabc-x86_64.so.1",
                 f"/work/basic/unistd/{name}"], environment, timeout,
            )
            musl = capture(
                work, Path("execution") / variant / f"{name}.musl-static",
                [os_test.PRIVATE_PROC_WITNESS_CHROOT, str(runtime), f"/work/basic/unistd/musl-{name}"],
                environment, timeout,
            )
            equal_raw(candidate, musl, f"{variant}/{name}")
            require_expected(candidate, EXPECTED_RUNS[variant][name], f"{variant}/{name}")
            result["runs"][name] = {"candidate": candidate, "musl_static": musl}
    except (OSError, RuntimeError, os_test.RunnerError) as error:
        failure = str(error)
    finally:
        control, intact = close_runtime(work, variant, control)
        result["execution_control"] = control
        result["product_intact"] = intact
    if failure is not None:
        result["error"] = failure
    result["passed"] = failure is None and result["product_intact"] and set(result["runs"]) == set(SOURCE_CASES)
    return result


def run_profile(values: argparse.Namespace) -> int:
    if values.timeout <= 0:
        raise ProofError("--timeout must be positive")
    temporary = os_test.physical_work_directory(os.environ.get("TMPDIR", ""), "TMPDIR")
    product = os_test.physical_work_directory(values.dynamic_sysroot, "dynamic product")
    source = os_test.physical_work_directory(values.os_test_root, "os-test source")
    work = Path(tempfile.mkdtemp(prefix="owned-os-test-ttyname-proc.", dir=temporary))
    report: dict[str, Any] = {"schema": SCHEMA, "passed": False, "work": str(work), "timeout_seconds": values.timeout,
                              "source_cases": list(SOURCE_CASES), "expected_runs": {
                                  variant: {name: {"status": row["status"], "stdout": row["stdout"].decode(),
                                                   "stderr": row["stderr"].decode()} for name, row in cases.items()}
                                  for variant, cases in EXPECTED_RUNS.items()}, "variants": []}
    live_proc_roots: set[Path] = set()
    try:
        source_before = os_test.validate_source_root(source)
        product_before = os_test.validate_dynamic_product(product)
        product_roster = os_test.tree_roster(product)
        report["source"] = {"before": source_before, "inputs": {name: source_binding(source, name)[1] for name in SOURCE_CASES}}
        report["product"] = {"before": product_before, "payload_roster": product_roster}
        static = os_test.load_module("owned_os_test_ttyname_proc_static", product / "share/crabc/crabc_cc_static.py")
        environment = static.clean_environment()
        if environment != {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1", "TZ": "UTC"}:
            raise ProofError("supplied dynamic product has an unexpected clean command environment")
        report["environment"] = environment
        musl_before = os_test.musl_oracle_identity(work, "before")
        programs = build_programs(work, product, source, environment, values.timeout)
        report["programs"] = programs
        for variant in ("without-proc", "with-proc"):
            result = run_variant(work, product, source, product_roster, programs, environment, values.timeout, variant)
            report["variants"].append(result)
            private = result["execution_control"].get("private_proc")
            if isinstance(private, dict) and not os_test.private_proc_postwalk_safe(private):
                live_proc_roots.add(Path(private["mountpoint"]))
        source_after = os_test.validate_source_root(source)
        product_after = os_test.validate_dynamic_product(product)
        roster_after = os_test.tree_roster(product)
        musl_after = os_test.musl_oracle_identity(work, "after")
        report["source"]["after"] = source_after
        report["product"]["after"] = product_after
        report["product"]["payload_after"] = roster_after
        report["musl_oracle"] = {"before": musl_before, "after": musl_after,
                                  "unchanged": os_test.same_musl_oracle(musl_before, musl_after)}
        if source_after != source_before:
            raise ProofError("focused proof changed the pinned os-test source checkout")
        if product_after != product_before or roster_after != product_roster:
            raise ProofError("focused proof changed the supplied dynamic product")
        if not report["musl_oracle"]["unchanged"]:
            raise ProofError("focused proof changed the pinned musl oracle")
        report["passed"] = all(variant["passed"] for variant in report["variants"])
    except (OSError, RuntimeError, os_test.RunnerError) as error:
        report["error"] = str(error)
    finally:
        report_path = work / "ttyname-proc.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        os_test.make_evidence_host_readable(work, skip_roots=live_proc_roots)
        print(f"owned os-test ttyname proc evidence: {work}")
    return 0 if report["passed"] else 1


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="per compiler, linker, mount witness, or target run timeout in seconds (default: 20)")
    parser.add_argument("--os-test-root", type=Path,
                        default=ROOT / ".work/x86_64/source-oracles" / f"os-test-{os_test.OS_TEST_REVISION}")
    parser.add_argument("dynamic_sysroot")
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    try:
        return run_profile(parse_arguments(arguments))
    except (OSError, RuntimeError, os_test.RunnerError) as error:
        print(f"owned os-test ttyname proc: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
