#!/usr/bin/env python3
"""Build and run libc-test against crabc's dynamic libc.

This is the execution half of the harness. It intentionally uses subprocess
argument lists instead of a shell so compiler paths, diagnostics, and timeout
classification are explicit. ``report.py`` remains the owner of structured
report parsing and aggregation.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


LIBRARIES = (
    "libc",
    "libpthread",
    "libm",
    "librt",
    "libcrypt",
    "libdl",
    "libresolv",
    "libutil",
)
SUPPORTED_SUBSETS = ("functional", "math", "regression", "api", "all")
# These cases are not meaningful on Docker's root overlay. Each exception is
# a reviewable record: test identity, observed reason, upstream/spec source,
# and the date it was rechecked against the pinned musl oracle.
ORACLE_ENVIRONMENT_SKIPS: dict[tuple[str, str], dict[str, str]] = {
    ("regression", "statvfs"): {
        "kind": "oracle_environment",
        "reason": "pinned musl also reports zero inode capacity for Docker's root overlay",
        "reference": "https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/regression/statvfs.c",
        "verified": "2026-08-20",
    },
}
# These exact hard-rounding identities emit libc-test's tolerated X diagnostics
# with the same result bits under pinned musl 1.2.6 and crabc on native AArch64.
# Keep this separate from environment skips so the exception cannot silently
# widen to neighboring math tests; the evidence file preserves the raw bit
# vectors and the native verification conditions.
ORACLE_EXPECTATION_SKIPS: dict[tuple[str, str], dict[str, str]] = {
    ("math", "acosh"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc return identical bits for libc-test's tolerated hard-rounding diagnostics",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/acosh.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/acosh.c + src/math/special/acosh.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "asinh"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc return identical bits for libc-test's tolerated hard-rounding diagnostics",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/asinh.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/asinh.c + src/math/special/asinh.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "sinh"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc return identical bits for libc-test's tolerated hard-rounding diagnostic",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/sinh.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/sinh.c + src/math/crlibm/sinh.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "j0"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc produce identical IEEE-754 vectors and libc-test X/ulperr diagnostics; only %a presentation differs",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/j0.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/j0.c + src/math/special/j0.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-bessel-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "jn"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc produce identical IEEE-754 vectors and libc-test X/ulperr diagnostics; only %a presentation differs",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/jn.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/jn.c + src/math/sanity/jn.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-bessel-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "jnf"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc produce identical IEEE-754 vectors and libc-test X/ulperr diagnostics; only %a presentation differs",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/jnf.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/jnf.c + src/math/sanity/jnf.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-bessel-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "y0"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc produce identical IEEE-754 vectors and libc-test X/ulperr diagnostics; only %a presentation differs",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/y0.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/y0.c + src/math/special/y0.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-bessel-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "y0f"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc produce identical IEEE-754 vectors and libc-test X/ulperr diagnostics; only %a presentation differs",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/y0f.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/y0f.c + src/math/sanity/y0f.h + src/math/special/y0f.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-bessel-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "ynf"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc produce identical IEEE-754 vectors and libc-test X/ulperr diagnostics; only %a presentation differs",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/ynf.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/ynf.c + src/math/sanity/ynf.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-bessel-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "lgamma"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc return identical bits for the remaining libc-test diagnostic at special/lgamma.h:145",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/lgamma.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/lgamma.c + src/math/special/lgamma.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-gamma-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "lgammaf"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc return identical bits for the remaining libc-test diagnostic at sanity/lgammaf.h:3",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/lgammaf.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/lgammaf.c + src/math/sanity/lgammaf.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-gamma-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "lgammaf_r"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc return identical bits for the remaining libc-test diagnostic at sanity/lgammaf_r.h:3",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/lgammaf_r.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/lgammaf_r.c + src/math/sanity/lgammaf_r.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-gamma-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
    ("math", "tgamma"): {
        "kind": "oracle_expectation",
        "reason": "pinned musl and crabc return identical bits for the remaining libc-test diagnostics at sanity/tgamma.h:4,7 and special/tgamma.h:47,60,62",
        "reference": "https://musl.libc.org/releases/musl-1.2.6.tar.gz (src/math/tgamma.c); https://github.com/laputa-systems/libc-test/blob/68edb8bd73dab8147ee54c8bec638f4d2b3cff37/src/math/tgamma.c + src/math/sanity/tgamma.h + src/math/special/tgamma.h",
        "verified": "2026-08-20",
        "evidence": "oracle-evidence/math-gamma-aarch64-musl-1.2.6-2026-08-20.txt",
        "architecture": "aarch64",
    },
}
# The upstream functional/crypt program bundles supported SHA-crypt calls with
# deliberately excluded MD5-crypt and bcrypt calls. Keep that composite test
# visible as one profile-limitation skip; `tests/crypt.rs` directly verifies
# the supported dependency-backed SHA boundary.
PROFILE_LIMITATION_SKIPS: dict[tuple[str, str], dict[str, str]] = {
    ("functional", "crypt"): {
        "kind": "profile_limitation",
        "reason": "the combined upstream crypt test requires deliberately unsupported MD5-crypt and bcrypt formats",
        "reference": "compat/crabc-rs/crypt-profile.md",
        "verified": "2026-08-22",
    },
}
KNOWN_SKIPS = {
    **ORACLE_ENVIRONMENT_SKIPS,
    **ORACLE_EXPECTATION_SKIPS,
    **PROFILE_LIMITATION_SKIPS,
}
ORACLE_FUNCTIONS: dict[str, tuple[str, int]] = {
    "acosh": ("unary", 64),
    "asinh": ("unary", 64),
    "sinh": ("unary", 64),
    "j0": ("bits", 64),
    "jn": ("indexed", 64),
    "jnf": ("indexed", 32),
    "y0": ("bits", 64),
    "y0f": ("bits", 32),
    "ynf": ("indexed", 32),
    "lgamma": ("gamma", 64),
    "lgammaf": ("gamma", 32),
    "lgammaf_r": ("gamma_r", 32),
    "tgamma": ("unary", 64),
}
COMMON_ARCHIVE_OBJECTS = (
    "fdfill",
    "memfill",
    "mtest",
    "path",
    "print",
    "rand",
    "setrlim",
    "utf8",
    "vmfill",
)
BASE_CFLAGS = (
    "-pipe",
    "-std=c99",
    "-D_POSIX_C_SOURCE=200809L",
    "-Wall",
    "-Wno-unused-function",
    "-Wno-missing-braces",
    "-Wno-unused",
    "-Wno-overflow",
    "-Wno-unknown-pragmas",
    "-fno-builtin",
    "-frounding-math",
    "-Werror=implicit-function-declaration",
    "-Werror=implicit-int",
    "-Werror=pointer-sign",
    "-Werror=pointer-arith",
    "-g",
    "-D_FILE_OFFSET_BITS=64",
)

# libc-test's API probe names two optional/legacy constants unconditionally,
# while musl 1.2.6 intentionally does not expose either one.  Keep the
# upstream probe intact and compile a per-run copy that uses the conventional
# availability guards.  This is deliberately a source adaptation, not an
# oracle skip: every other declaration in api/unistd.c remains a strict
# crabc-header check.  Do not add names here unless the pinned musl header is
# rechecked first.
API_UNISTD_OPTIONAL_CONSTANTS = (
    "_PC_TIMESTAMP_RESOLUTION",
    "_SC_XOPEN_UUCP",
)


def replace_symlink(target: Path, link: Path) -> None:
    """Replace one known harness link without following a broken symlink."""

    if os.path.lexists(link):
        if link.is_dir() and not link.is_symlink():
            raise RuntimeError(f"refusing to replace directory: {link}")
        link.unlink()
    link.symlink_to(target)


def execute(
    command: list[str],
    *,
    cwd: Path | None = None,
    stderr_path: Path | None = None,
    stdout_to_stderr: bool = False,
) -> int:
    """Run a command and return its status, retaining shell-loop resilience."""

    stderr_file = None
    try:
        if stderr_path is not None:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_file = stderr_path.open("wb")
        completed = subprocess.run(
            command,
            cwd=cwd,
            stderr=subprocess.STDOUT if stdout_to_stderr else stderr_file,
            stdout=stderr_file if stdout_to_stderr else None,
            check=False,
        )
        return completed.returncode
    except OSError as error:
        message = f"{command[0]}: {error}\n"
        if stderr_file is not None:
            stderr_file.write(message.encode())
        else:
            sys.stderr.write(message)
        return 127
    finally:
        if stderr_file is not None:
            stderr_file.close()


def execute_timeout(command: list[str], cwd: Path, output_path: Path, env: dict[str, str]) -> int:
    """Run one test for at most 30 seconds, matching ``timeout``'s 124 code."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("wb") as output:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
        return completed.returncode
    except subprocess.TimeoutExpired:
        return 124
    except OSError as error:
        output_path.write_text(f"{command[0]}: {error}\n", encoding="utf-8")
        return 127


def append_text(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(text)


def append_diagnostic(path: Path, source: Path) -> None:
    try:
        diagnostic = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    append_text(path, diagnostic)


def _evidence_bits(token: str, width: int) -> int:
    if not re.fullmatch(r"[0-9a-fA-F]+", token):
        raise ValueError(f"invalid {width}-bit evidence value: {token!r}")
    value = int(token, 16)
    if value >= (1 << width):
        raise ValueError(f"{width}-bit evidence value is out of range: {token!r}")
    return value


def parse_oracle_evidence(evidence: Path, function: str) -> list[dict[str, Any]]:
    """Parse the exact vector records used by one oracle expectation skip."""

    try:
        kind, width = ORACLE_FUNCTIONS[function]
    except KeyError as error:
        raise ValueError(f"no raw-bit verifier definition for {function!r}") from error
    try:
        lines = evidence.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"cannot read oracle evidence {evidence}: {error}") from error

    records: list[dict[str, Any]] = []
    section: str | None = None
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != function:
            continue
        fields = line.split()
        try:
            if kind in ("unary", "gamma", "gamma_r"):
                values = {
                    key: value
                    for key, value in (field.split("=", 1) for field in fields[1:])
                    if key
                }
                if "input_bits" not in values or "result_bits" not in values:
                    raise ValueError("missing input_bits or result_bits")
                record: dict[str, Any] = {
                    "input_bits": _evidence_bits(values["input_bits"].removeprefix("0x"), width),
                    "result_bits": _evidence_bits(values["result_bits"].removeprefix("0x"), width),
                    "source_line": int(fields[0]),
                }
                if "signgam" in values:
                    record["sign"] = int(values["signgam"], 0)
                if "sign" in values:
                    record["sign"] = int(values["sign"], 0)
            else:
                expected_fields = 6 if kind == "indexed" else 5
                if len(fields) != expected_fields:
                    raise ValueError(f"expected {expected_fields} fields, got {len(fields)}")
                if int(fields[1], 0) != 0:
                    raise ValueError("only round-to-nearest evidence is supported")
                input_index = 3 if kind == "indexed" else 2
                record = {
                    "source_line": int(fields[0]),
                    "n": int(fields[2], 0) if kind == "indexed" else None,
                    "input_bits": _evidence_bits(fields[input_index], width),
                    "expected_bits": _evidence_bits(fields[input_index + 1], width),
                    "result_bits": _evidence_bits(fields[input_index + 2], width),
                }
            records.append(record)
        except (IndexError, ValueError) as error:
            raise ValueError(f"{evidence}:{line_number}: {error}") from error
    if not records:
        raise ValueError(f"{evidence}: section [{function}] has no vector records")
    return records


def _c_bits_literal(bits: int, width: int) -> str:
    suffix = "ULL" if width == 64 else "U"
    return f"0x{bits:0{width // 4}x}{suffix}"


def render_oracle_verifier(function: str, records: list[dict[str, Any]]) -> str:
    """Render a standalone C verifier for the checked-in raw-bit vectors."""

    kind, width = ORACLE_FUNCTIONS[function]
    float_type = "double" if width == 64 else "float"
    from_bits = "from_bits64" if width == 64 else "from_bits32"
    result_bits = "bits64" if width == 64 else "bits32"
    lines = [
        "#include <math.h>",
        "#include <stdint.h>",
        "#include <stdio.h>",
        "#include <string.h>",
        "",
        "static double from_bits64(uint64_t bits) { double value; memcpy(&value, &bits, sizeof value); return value; }",
        "static float from_bits32(uint32_t bits) { float value; memcpy(&value, &bits, sizeof value); return value; }",
        "static uint64_t bits64(double value) { uint64_t bits; memcpy(&bits, &value, sizeof bits); return bits; }",
        "static uint32_t bits32(float value) { uint32_t bits; memcpy(&bits, &value, sizeof bits); return bits; }",
        "extern int signgam;",
        "",
        "int main(void) {",
    ]
    for index, record in enumerate(records):
        input_literal = _c_bits_literal(record["input_bits"], width)
        expected_literal = _c_bits_literal(record["result_bits"], width)
        call_input = f"{from_bits}({input_literal})"
        sign_check = ""
        if function == "lgamma":
            lines.append(f"    {float_type} result_{index} = lgamma({call_input});")
            lines.append(f"    int sign_{index} = signgam;")
        elif function == "lgammaf":
            lines.append(f"    {float_type} result_{index} = lgammaf({call_input});")
            lines.append(f"    int sign_{index} = signgam;")
        elif function == "lgammaf_r":
            lines.append(f"    int sign_{index} = 0;")
            lines.append(f"    {float_type} result_{index} = lgammaf_r({call_input}, &sign_{index});")
        elif kind == "indexed":
            lines.append(
                f"    {float_type} result_{index} = {function}({record['n']}, {call_input});"
            )
        else:
            lines.append(f"    {float_type} result_{index} = {function}({call_input});")
        if "sign" in record:
            sign_check = f" || sign_{index} != {record['sign']}"
        lines.append(
            f"    if ({result_bits}(result_{index}) != {expected_literal}{sign_check}) {{"
        )
        lines.append(
            f"        fprintf(stderr, \"{function} vector {index} mismatch: got %llu expected %llu\\n\","
        )
        lines.append(
            f"            (unsigned long long){result_bits}(result_{index}), (unsigned long long){expected_literal});"
        )
        if "sign" in record:
            lines.append(
                f"        fprintf(stderr, \"{function} vector {index} sign: got %d expected {record['sign']}\\n\", sign_{index});"
            )
        lines.append("        return 1;")
        lines.append("    }")
    lines.extend(("    return 0;", "}"))
    return "\n".join(lines) + "\n"


def verify_oracle_expectation(
    function: str,
    skip: dict[str, str],
    script_dir: Path,
    crabc_dir: Path,
    libc_test_dir: Path,
    fake_libs: Path,
    ldso_so: Path,
    build_dir: Path,
    runtime_env: dict[str, str],
) -> tuple[bool, Path, str]:
    """Run the current candidate against every vector in one oracle record."""

    evidence = script_dir / skip["evidence"]
    verifier_dir = build_dir / "oracle"
    verifier_dir.mkdir(parents=True, exist_ok=True)
    source = verifier_dir / f"{function}.c"
    executable = verifier_dir / f"{function}.exe"
    diagnostic = verifier_dir / f"{function}.err"
    try:
        records = parse_oracle_evidence(evidence, function)
        source.write_text(render_oracle_verifier(function, records), encoding="utf-8")
    except (OSError, ValueError) as error:
        diagnostic.write_text(f"oracle evidence verifier setup failed: {error}\n", encoding="utf-8")
        return False, diagnostic, str(error)

    compile_command = [
        "musl-gcc",
        "-std=c99",
        "-D_GNU_SOURCE",
        "-frounding-math",
        "-fno-builtin",
        f"-I{crabc_dir / 'include'}",
        "-fPIE",
        "-pie",
        f"-Wl,--dynamic-linker={ldso_so}",
        "-Wl,--allow-shlib-undefined",
        "-L",
        str(fake_libs),
        "-o",
        str(executable),
        str(source),
        "-lc",
        "-lm",
    ]
    if execute(compile_command, stderr_path=diagnostic) != 0:
        return False, diagnostic, f"oracle verifier compile failed for {function}"
    status = execute_timeout([str(executable)], libc_test_dir, diagnostic, runtime_env)
    if status != 0:
        if status == 124:
            return False, diagnostic, f"oracle verifier timed out for {function}"
        return False, diagnostic, f"oracle verifier found a current mismatch for {function}"
    return True, diagnostic, f"verified {len(records)} raw-bit vector(s) for {function}"


def record_event(path: Path, suite: str, test: str, status: str, phase: str, reason: str, diagnostic: Path) -> None:
    with path.open("a", encoding="utf-8") as events:
        events.write(f"{suite}\t{test}\t{status}\t{phase}\t{reason}\t{diagnostic}\n")


def compiler_flags(libc_test_dir: Path, common_build: Path) -> list[str]:
    return [
        f"-I{common_build}",
        f"-I{libc_test_dir / 'src' / 'common'}",
        *BASE_CFLAGS,
    ]


def render_options_header(preprocessor_output: str) -> str:
    """Convert libc-test's preprocessed feature options into a C header."""

    marker_seen = False
    pending_name: str | None = None
    definitions: list[str] = []
    for raw_line in preprocessor_output.splitlines():
        if "optiongroups_unistd_end" in raw_line:
            marker_seen = True
            continue
        if not marker_seen or not raw_line or raw_line.startswith("#"):
            continue
        fields = raw_line.split()
        if len(fields) == 1:
            if pending_name is None:
                pending_name = fields[0]
            else:
                definitions.append(f"#define {pending_name} {fields[0]}")
                pending_name = None
        elif pending_name is not None:
            definitions.append(f"#define {pending_name} {fields[-1]}")
            pending_name = None
        else:
            definitions.append(f"#define {fields[0]} {fields[-1]}")
    return "/* Generated from libc-test/src/common/options.h.in. */\n" + "\n".join(definitions) + "\n"


def generate_options_header(libc_test_dir: Path, crabc_dir: Path, common_build: Path) -> None:
    """Generate libc-test feature-option declarations from crabc's headers."""

    template = libc_test_dir / "src" / "common" / "options.h.in"
    destination = common_build / "options.h"
    try:
        completed = subprocess.run(
            ["musl-gcc", "-E", f"-I{crabc_dir / 'include'}", "-"],
            input=template.read_bytes(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"could not generate libc-test options.h: {error}") from error
    if completed.returncode != 0:
        diagnostics = completed.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"could not generate libc-test options.h:\n{diagnostics}")
    destination.write_text(
        render_options_header(completed.stdout.decode("utf-8", errors="replace")),
        encoding="utf-8",
    )


def api_header_flags(crabc_dir: Path) -> list[str]:
    """Compile API checks against crabc headers without musl-header fallback."""

    try:
        completed = subprocess.run(
            ["gcc", "-print-file-name=include"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"could not locate the GCC builtin headers: {error}") from error
    builtin_include = Path(completed.stdout.strip())
    if completed.returncode != 0 or not builtin_include.is_dir():
        raise RuntimeError("could not locate the GCC builtin headers for strict API checks")
    return [
        "-nostdinc",
        f"-isystem{crabc_dir / 'include'}",
        f"-isystem{builtin_include}",
    ]


def prepare_api_unistd_source(source: Path, directory_build: Path) -> Path:
    """Guard the two libc-test unistd constants absent from pinned musl.

    The explicit match count makes an upstream-source change a harness error
    rather than silently broadening or removing this narrow adaptation.
    """

    if source.name != "unistd.c":
        return source
    contents = source.read_text(encoding="utf-8")
    for constant in API_UNISTD_OPTIONAL_CONSTANTS:
        check = f"C({constant})"
        if contents.count(check) != 1:
            raise RuntimeError(
                f"expected exactly one {check} in pinned libc-test api/unistd.c"
            )
        contents = contents.replace(check, f"#ifdef {constant}\n{check}\n#endif")
    prepared = directory_build / "prepared-source" / source.name
    prepared.parent.mkdir(parents=True, exist_ok=True)
    prepared.write_text(contents, encoding="utf-8")
    return prepared


def setup_crabc(script_dir: Path, crabc_dir: Path, libc_so: Path, ldso_so: Path) -> tuple[Path, Path, Path]:
    fake_libs = script_dir / "fake-libs"
    build_dir = script_dir / "build"
    report_dir = script_dir / "reports"
    fake_libs.mkdir(parents=True, exist_ok=True)
    build_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    if not libc_so.is_file() or not ldso_so.is_file():
        print(">>> Building crabc...")
        result = execute(["cargo", "build"], cwd=crabc_dir, stdout_to_stderr=True)
        if result != 0:
            print("FATAL: cargo build failed")
            raise SystemExit(1)
    print(f">>> Using libc.so: {libc_so}")
    print(f">>> Using libldso.so: {ldso_so}")

    print(">>> Setting up fake-libs...")
    for library in LIBRARIES:
        replace_symlink(libc_so, fake_libs / f"{library}.so")

    return fake_libs, build_dir, report_dir


def build_runtest(
    libc_test_dir: Path,
    crabc_dir: Path,
    fake_libs: Path,
    build_dir: Path,
) -> Path:
    print(">>> Building runtest.exe (host tool)...")
    common_build = build_dir / "common"
    common_build.mkdir(parents=True, exist_ok=True)
    generate_options_header(libc_test_dir, crabc_dir, common_build)
    flags = compiler_flags(libc_test_dir, common_build)

    for source in sorted((libc_test_dir / "src" / "common").glob("*.c")):
        base = source.stem
        command = ["musl-gcc", *flags]
        if base == "mtest":
            command.append(f"-I{crabc_dir / 'include'}")
        command.extend(["-c", "-o", str(common_build / f"{base}.o"), str(source)])
        execute(command, stderr_path=common_build / f"{base}.o.err")

    archive_objects = [str(common_build / f"{name}.o") for name in COMMON_ARCHIVE_OBJECTS]
    execute(["ar", "rc", str(common_build / "libtest.a"), *archive_objects], stderr_path=common_build / "ar.err")
    execute(["ranlib", str(common_build / "libtest.a")])

    runtest = common_build / "runtest.exe"
    execute(
        [
            "musl-gcc",
            "-g",
            "-o",
            str(runtest),
            str(common_build / "runtest.o"),
            str(common_build / "libtest.a"),
            "-lpthread",
            "-lm",
            "-lrt",
        ],
        stderr_path=common_build / "runtest.err",
    )
    if not runtest.is_file() or not os.access(runtest, os.X_OK):
        print("FATAL: failed to build runtest.exe")
        try:
            print((common_build / "runtest.err").read_text(encoding="utf-8", errors="replace"), end="")
        except OSError:
            pass
        raise SystemExit(1)
    print(">>> runtest.exe built OK")
    return runtest


def exported_symbol_count(libc_so: Path) -> int | None:
    """Count every defined dynamic export, not only global text symbols."""

    try:
        completed = subprocess.run(
            ["nm", "-D", "--defined-only", str(libc_so)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return sum(bool(line.strip()) for line in completed.stdout.splitlines())


def append_failure_lines(raw_report: Path, source: Path) -> None:
    try:
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    matching = [line for line in lines if re.search(r"undefined reference|cannot find", line, re.IGNORECASE)]
    if matching:
        append_text(raw_report, "".join(f"{line}\n" for line in matching))


def write_human_summary(
    summary_report: Path,
    raw_report: Path,
    libc_so: Path,
    subset: str,
    counters: dict[str, int],
) -> str:
    symbol_count = exported_symbol_count(libc_so)
    symbols = str(symbol_count) if symbol_count is not None else "unknown"
    date_result = subprocess.run(["date"], capture_output=True, text=True, check=False)
    date_text = date_result.stdout.strip() or datetime.now().ctime()
    lines = [
        "libc-test Integration Report",
        "============================",
        f"Date: {date_text}",
        f"libc.so: {libc_so}",
        f"Symbols: {symbols}",
        f"Subset: {subset}",
        "",
        "Results",
        "-------",
        f"Total:      {counters['TOTAL']}",
        f"PASS:       {counters['PASS']}",
        f"FAIL:       {counters['FAIL']}",
        f"BUILDERROR: {counters['BUILDERROR']}",
        f"TIMEOUT:    {counters['TIMEOUT']}",
        f"SKIP:       {counters['SKIP']}",
        f"Other:      {counters['OTHER']}",
        "",
        "Failure Breakdown (by category):",
        "",
    ]
    try:
        raw_lines = raw_report.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        raw_lines = []
    for status, title in (("BUILDERROR", "BUILDERROR tests:"), ("FAIL", "FAIL tests:"), ("TIMEOUT", "TIMEOUT tests:"), ("SKIP", "SKIP tests:"), ("PASS", "PASS tests:")):
        matching = [line[len(status) + 1 :] for line in raw_lines if line.startswith(f"{status} ")]
        if matching:
            lines.append(title)
            lines.extend(f"  {line}" for line in matching)
            lines.append("")
    summary_text = "\n".join(lines) + "\n"
    summary_report.write_text(summary_text, encoding="utf-8")
    return summary_text


def generate_structured_reports(
    script_dir: Path,
    report_dir: Path,
    events_report: Path,
    results_report: Path,
    missing_symbol_report: Path,
    structured_report: Path,
    subset: str,
    libc_so: Path,
    ldso_so: Path,
    summary_report: Path,
    raw_report: Path,
) -> None:
    python = sys.executable
    symbol_count = exported_symbol_count(libc_so)
    symbol_value = str(symbol_count) if symbol_count is not None else "unknown"
    result = execute(
        [
            python,
            str(script_dir / "report.py"),
            "--events",
            str(events_report),
            "--results",
            str(results_report),
            "--missing-symbols",
            str(missing_symbol_report),
            "--report",
            str(structured_report),
            "--subset",
            subset,
            "--libc-so",
            str(libc_so),
            "--ldso-so",
            str(ldso_so),
            "--symbols-exported",
            symbol_value,
            "--human-summary",
            str(summary_report),
            "--raw",
            str(raw_report),
        ]
    )
    if result != 0:
        print("WARNING: structured report generation failed", file=sys.stderr)
        return
    replace_symlink(results_report.name, report_dir / "latest-results.jsonl")
    replace_symlink(missing_symbol_report.name, report_dir / "latest-missing-symbols.tsv")
    replace_symlink(structured_report.name, report_dir / "latest-report.json")
    print(f"Structured report: {structured_report}")
    print(f"Results: {results_report}")
    print(f"Missing-symbol graph: {missing_symbol_report}")


def run_subset(subset: str, script_dir: Path, crabc_dir: Path, libc_test_dir: Path) -> int:
    libc_so = crabc_dir / "target" / "debug" / "libc.so"
    ldso_so = crabc_dir / "target" / "debug" / "libldso.so"
    fake_libs, build_dir, report_dir = setup_crabc(script_dir, crabc_dir, libc_so, ldso_so)
    runtest = build_runtest(libc_test_dir, crabc_dir, fake_libs, build_dir)

    print(f">>> Building and running {subset} tests...")
    dirs = ("functional", "math", "regression", "api") if subset == "all" else (subset,)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_report = report_dir / f"raw_{timestamp}.txt"
    summary_report = report_dir / f"summary_{timestamp}.txt"
    results_report = report_dir / f"results_{timestamp}.jsonl"
    missing_symbol_report = report_dir / f"missing-symbols_{timestamp}.tsv"
    structured_report = report_dir / f"report_{timestamp}.json"
    events_report = report_dir / f"events_{timestamp}.tsv"
    raw_report.write_text("", encoding="utf-8")
    events_report.write_text("", encoding="utf-8")

    counters = {
        "TOTAL": 0,
        "BUILDERROR": 0,
        "FAIL": 0,
        "PASS": 0,
        "TIMEOUT": 0,
        "SKIP": 0,
        "OTHER": 0,
    }
    flags = compiler_flags(libc_test_dir, build_dir / "common")
    strict_api_flags = api_header_flags(crabc_dir) if "api" in dirs else []
    architecture = platform.machine()
    runtime_env = os.environ.copy()
    runtime_env["LD_LIBRARY_PATH"] = str(fake_libs)

    for directory in dirs:
        source_dir = libc_test_dir / "src" / directory
        if not source_dir.is_dir():
            print(f"WARNING: {source_dir} not found, skipping")
            continue
        print(f">>> Processing {directory}...")
        directory_build = build_dir / directory
        directory_build.mkdir(parents=True, exist_ok=True)

        for dso_source in sorted(source_dir.glob("*_dso.c")):
            dso_base = dso_source.stem
            shared_object = directory_build / f"{dso_base}.so"
            execute(
                [
                    "musl-gcc",
                    *flags,
                    "-shared",
                    "-fPIC",
                    "-o",
                    str(shared_object),
                    str(dso_source),
                    "-L",
                    str(fake_libs),
                    "-lc",
                ],
                stderr_path=directory_build / f"{dso_base}.so.err",
            )
            replace_symlink(shared_object, source_dir / f"{dso_base}.so")

        for source in sorted(source_dir.glob("*.c")):
            base = source.stem
            if base.endswith("_dso"):
                continue
            counters["TOTAL"] += 1
            skip = KNOWN_SKIPS.get((directory, base))
            if skip is not None and skip.get("architecture") not in (None, platform.machine()):
                skip = None
            if skip is not None:
                if skip.get("kind") == "oracle_expectation":
                    verified, diagnostic, verification_detail = verify_oracle_expectation(
                        base,
                        skip,
                        script_dir,
                        crabc_dir,
                        libc_test_dir,
                        fake_libs,
                        ldso_so,
                        build_dir,
                        runtime_env,
                    )
                    if not verified:
                        append_text(raw_report, f"FAIL {directory}/{base}: {verification_detail}\n")
                        append_diagnostic(raw_report, diagnostic)
                        record_event(
                            events_report,
                            directory,
                            base,
                            "FAIL",
                            "oracle_verify",
                            verification_detail,
                            diagnostic,
                        )
                        counters["FAIL"] += 1
                        continue
                skip_detail = (
                    f"{skip['reason']}; reference={skip['reference']}; "
                    f"verified={skip['verified']}"
                )
                if skip.get("kind") == "oracle_expectation":
                    skip_detail += f"; current={verification_detail}"
                if "evidence" in skip:
                    skip_detail += f"; evidence={skip['evidence']}"
                if "architecture" in skip:
                    skip_detail += f"; architecture={skip['architecture']}"
                append_text(raw_report, f"SKIP {directory}/{base}: {skip_detail}\n")
                record_event(
                    events_report,
                    directory,
                    base,
                    "SKIP",
                    "preflight",
                    f"{skip['kind']}:{skip_detail}",
                    Path("-"),
                )
                counters["SKIP"] += 1
                continue
            object_file = directory_build / f"{base}.o"
            extra_flags: list[str] = []
            if architecture == "x86_64":
                extra_flags.append("-mlong-double-64")
            if directory == "math":
                extra_flags.append(f"-I{crabc_dir / 'include'}")
            elif base == "crypt":
                extra_flags.append(f"-I{crabc_dir / 'include'}")
            if directory == "api":
                extra_flags.extend(
                    ("-pedantic-errors", "-Werror", "-Wno-unused", "-D_XOPEN_SOURCE=700")
                )
            compile_error = directory_build / f"{base}.o.err"
            compiler = "gcc" if directory == "api" else "musl-gcc"
            directory_api_flags = strict_api_flags if directory == "api" else []
            compile_source = (
                prepare_api_unistd_source(source, directory_build)
                if directory == "api"
                else source
            )
            compile_status = execute(
                [
                    compiler,
                    *directory_api_flags,
                    *flags,
                    *extra_flags,
                    "-c",
                    "-o",
                    str(object_file),
                    str(compile_source),
                ],
                stderr_path=compile_error,
            )
            if compile_status != 0:
                append_text(raw_report, f"BUILDERROR {directory}/{base}: compile failed\n")
                append_diagnostic(raw_report, compile_error)
                record_event(events_report, directory, base, "BUILDERROR", "compile", "compile_error", compile_error)
                counters["BUILDERROR"] += 1
                continue

            if directory == "api":
                append_text(raw_report, f"PASS {directory}/{base}\n")
                record_event(events_report, directory, base, "PASS", "compile", "passed", compile_error)
                counters["PASS"] += 1
                continue

            executable = directory_build / f"{base}.exe"
            companion = directory_build / f"{base}_dso.so"
            link_error = directory_build / f"{base}.ld.err"
            link_command = [
                "musl-gcc",
                "-L",
                str(fake_libs),
                "-g",
                "-rdynamic",
                "-o",
                str(executable),
                f"-Wl,--dynamic-linker={ldso_so}",
                "-Wl,--allow-shlib-undefined",
                "-Wl,-rpath=$ORIGIN",
                str(object_file),
            ]
            if companion.is_file():
                link_command.append(str(companion))
            link_command.extend(
                [
                    str(build_dir / "common" / "libtest.a"),
                    "-lpthread",
                    "-lm",
                    "-lrt",
                    "-lcrypt",
                    "-ldl",
                    "-lresolv",
                    "-lutil",
                ]
            )
            link_status = execute(link_command, stderr_path=link_error)
            if link_status != 0:
                append_text(raw_report, f"BUILDERROR {directory}/{base}: link failed\n")
                append_failure_lines(raw_report, link_error)
                record_event(events_report, directory, base, "BUILDERROR", "link", "link_error", link_error)
                counters["BUILDERROR"] += 1
                continue

            error_file = directory_build / f"{base}.err"
            run_status = execute_timeout(
                [str(runtest), "-w", "", str(executable)],
                libc_test_dir,
                error_file,
                runtime_env,
            )
            if run_status == 124:
                append_text(raw_report, f"TIMEOUT {directory}/{base}\n")
                record_event(events_report, directory, base, "TIMEOUT", "run", "timeout", error_file)
                counters["TIMEOUT"] += 1
            elif run_status == 0 and error_file.stat().st_size == 0:
                append_text(raw_report, f"PASS {directory}/{base}\n")
                record_event(events_report, directory, base, "PASS", "run", "passed", error_file)
                counters["PASS"] += 1
            else:
                append_text(raw_report, f"FAIL {directory}/{base}\n")
                try:
                    failure_lines = error_file.read_text(encoding="utf-8", errors="replace").splitlines()[:5]
                except OSError:
                    failure_lines = []
                if failure_lines:
                    append_text(raw_report, "".join(f"{line}\n" for line in failure_lines))
                record_event(events_report, directory, base, "FAIL", "run", "test_failure", error_file)
                counters["FAIL"] += 1

    summary_text = write_human_summary(summary_report, raw_report, libc_so, subset, counters)
    print(f"Raw report: {raw_report}")
    print(summary_text, end="")
    generate_structured_reports(
        script_dir,
        report_dir,
        events_report,
        results_report,
        missing_symbol_report,
        structured_report,
        subset,
        libc_so,
        ldso_so,
        summary_report,
        raw_report,
    )
    replace_symlink(summary_report.name, report_dir / "latest-summary.txt")
    replace_symlink(raw_report.name, report_dir / "latest-raw.txt")
    print(f"\n>>> Done. Reports in {report_dir}/")
    return 0


def main(argv: list[str]) -> int:
    script_dir = Path(__file__).resolve().parent
    crabc_dir = script_dir.parent
    libc_test_dir = Path(os.environ.get("LIBC_TEST_DIR", "/home/root/libc-test"))
    if len(argv) > 2:
        print("usage: runner.py [functional|math|regression|api|all]", file=sys.stderr)
        return 2
    subset = argv[1] if len(argv) == 2 else "functional"
    if subset not in SUPPORTED_SUBSETS:
        print(f"ERROR: unsupported libc-test subset: {subset}", file=sys.stderr)
        return 2
    return run_subset(subset, script_dir, crabc_dir, libc_test_dir)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
