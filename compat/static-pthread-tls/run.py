#!/usr/bin/env python3
"""Compare the conventional static pthread/TLS fixture with pinned musl.

The source is compiled once with the pinned musl headers, then linked into
both a pinned-musl reference and a crabc ``libc.a`` candidate using the same
musl CRT objects.  The report preserves link commands, raw process results,
and artifact hashes so a passing static lifecycle check remains auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


MUSL_VERSION = "1.2.6"
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/fixtures/static_pthread_tls_test.c"
DEFAULT_REPORT = ROOT / "compat/reports/static-pthread-tls/latest.json"
EXPECTED_STDOUT = b"static pthread tls ok\n"
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 300.0


class RunnerError(RuntimeError):
    """A setup or build failure, distinct from a runtime mismatch."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--musl-root",
        type=Path,
        default=Path(os.environ.get("MUSL_ROOT", f"/opt/musl-{MUSL_VERSION}")),
        help=f"pinned musl installation (default: MUSL_ROOT or /opt/musl-{MUSL_VERSION})",
    )
    parser.add_argument(
        "--musl-cc",
        default=os.environ.get("MUSL_CC", "musl-gcc"),
        help="pinned musl compiler command (default: MUSL_CC or musl-gcc)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CRABC_TARGET_DIR", ROOT / "target/debug")),
        help="directory containing crabc libc.a",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path(os.environ.get("CRABC_STATIC_PTHREAD_TLS_REPORT", DEFAULT_REPORT)),
        help="JSON report destination",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("CRABC_STATIC_PTHREAD_TLS_TIMEOUT", DEFAULT_TIMEOUT)),
        help=f"maximum seconds for each binary (default: {DEFAULT_TIMEOUT:g})",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_text(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def stream_record(stream: bytes) -> dict[str, object]:
    return {
        "byte_length": len(stream),
        "sha256": hashlib.sha256(stream).hexdigest(),
        "hex": stream.hex(),
        "text": stream.decode("utf-8", errors="replace"),
    }


def run_binary(binary: Path, timeout: float) -> dict[str, object]:
    try:
        result = subprocess.run(
            [str(binary)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "status": "TIMEOUT",
            "stdout": stream_record(error.stdout or b""),
            "stderr": stream_record(error.stderr or b""),
        }
    except OSError as error:
        return {
            "status": f"EXEC_ERROR:{error.errno or 'unknown'}",
            "stdout": stream_record(b""),
            "stderr": stream_record(str(error).encode()),
        }
    return {
        "status": result.returncode,
        "stdout": stream_record(result.stdout),
        "stderr": stream_record(result.stderr),
    }


def require_file(path: Path, description: str) -> Path:
    if not path.is_file():
        raise RunnerError(f"{description} not found: {path}")
    return path.resolve()


def build_command(
    compiler: list[str], crt: Path, crti: Path, input_file: Path, libc: Path, crtn: Path, output: Path
) -> list[str]:
    return compiler + [
        "-static",
        "-no-pie",
        "-nostdlib",
        "-fno-stack-protector",
        str(crt),
        str(crti),
        str(input_file),
        str(libc),
        str(crtn),
        "-o",
        str(output),
    ]


def compile_source(compiler: list[str], source: Path, headers: Path, output: Path) -> list[str]:
    return compiler + [
        "-std=c11",
        "-fno-stack-protector",
        "-isystem",
        str(headers),
        "-c",
        str(source),
        "-o",
        str(output),
    ]


def run(args: argparse.Namespace) -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise RunnerError("requires native Linux AArch64 (the pinned musl oracle is AArch64)")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > MAX_TIMEOUT:
        raise RunnerError(f"--timeout must be > 0 and <= {MAX_TIMEOUT:g}: {args.timeout}")
    root = args.musl_root.expanduser().resolve()
    if root.name != f"musl-{MUSL_VERSION}":
        raise RunnerError(f"--musl-root must name pinned musl-{MUSL_VERSION}: {root}")
    compiler_parts = shlex.split(args.musl_cc)
    if not compiler_parts or shutil.which(compiler_parts[0]) is None:
        raise RunnerError(f"compiler not found: {args.musl_cc}")
    headers = require_file(root / "include/stdio.h", "pinned musl headers")
    del headers
    crt = require_file(root / "lib/crt1.o", "musl crt1.o")
    crti = require_file(root / "lib/crti.o", "musl crti.o")
    crtn = require_file(root / "lib/crtn.o", "musl crtn.o")
    musl_libc = require_file(root / "lib/libc.a", "musl libc.a")
    source = require_file(SOURCE, "static pthread/TLS fixture")
    target_dir = args.target_dir.expanduser().resolve()
    crabc_libc = require_file(target_dir / "libc.a", "crabc libc.a")

    report: dict[str, Any] = {
        "runner": "crabc-static-pthread-tls",
        "schema": 1,
        "passed": False,
        "workload": "static_pthread_tls_lifecycle",
        "musl_version": MUSL_VERSION,
        "source": {"path": str(source), "sha256": sha256_file(source)},
        "artifacts": {
            "musl_libc": {"path": str(musl_libc), "sha256": sha256_file(musl_libc)},
            "crabc_libc": {"path": str(crabc_libc), "sha256": sha256_file(crabc_libc)},
        },
        "provenance": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version,
            "compiler": compiler_parts,
            "musl_root": str(root),
            "target_dir": str(target_dir),
            "timeout_seconds": args.timeout,
        },
    }
    with tempfile.TemporaryDirectory(prefix="crabc-static-pthread-tls-") as work_name:
        work = Path(work_name)
        object_file = work / "fixture.o"
        compile_cmd = compile_source(compiler_parts, source, root / "include", object_file)
        compile_result = subprocess.run(compile_cmd, check=False, capture_output=True)
        report["compile"] = {
            "command": command_text(compile_cmd),
            "status": compile_result.returncode,
            "stdout": stream_record(compile_result.stdout),
            "stderr": stream_record(compile_result.stderr),
        }
        if compile_result.returncode != 0:
            return report

        reference_binary = work / "musl-reference"
        candidate_binary = work / "crabc-candidate"
        reference_cmd = build_command(compiler_parts, crt, crti, object_file, musl_libc, crtn, reference_binary)
        candidate_cmd = build_command(compiler_parts, crt, crti, object_file, crabc_libc, crtn, candidate_binary)
        report["links"] = {
            "reference": command_text(reference_cmd),
            "candidate": command_text(candidate_cmd),
        }
        reference_link = subprocess.run(reference_cmd, check=False, capture_output=True)
        candidate_link = subprocess.run(candidate_cmd, check=False, capture_output=True)
        report["link_results"] = {
            "reference": {"status": reference_link.returncode, "stderr": stream_record(reference_link.stderr)},
            "candidate": {"status": candidate_link.returncode, "stderr": stream_record(candidate_link.stderr)},
        }
        if reference_link.returncode != 0 or candidate_link.returncode != 0:
            return report
        reference = run_binary(reference_binary, args.timeout)
        candidate = run_binary(candidate_binary, args.timeout)
        report["reference"] = reference
        report["candidate"] = candidate
        report["comparison"] = {
            "status_match": reference["status"] == candidate["status"],
            "stdout_match": reference["stdout"] == candidate["stdout"],
            "stderr_match": reference["stderr"] == candidate["stderr"],
            "expected_candidate_stdout": stream_record(EXPECTED_STDOUT),
        }
        report["passed"] = (
            report["comparison"]["status_match"]
            and report["comparison"]["stdout_match"]
            and report["comparison"]["stderr_match"]
            and candidate["status"] == 0
            and candidate["stdout"]["hex"] == EXPECTED_STDOUT.hex()
        )
    return report


def main() -> int:
    args = parse_args()
    try:
        report = run(args)
    except RunnerError as error:
        print(f"static-pthread-tls: ERROR: {error}", file=sys.stderr)
        return 2
    report_path = args.report.expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"static-pthread-tls: report: {report_path}")
    if report.get("passed") is not True:
        print("static-pthread-tls: FAIL", file=sys.stderr)
        return 1
    print("static-pthread-tls: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
