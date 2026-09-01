#!/usr/bin/env python3
"""Prove crabc-mimalloc's private AArch64 compiler-TLS access model."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[3]


def default_work_root() -> Path:
    """Return the checkout-local boundary for generated TLS evidence."""

    configured = os.environ.get("CRABC_WORK_DIR")
    if not configured:
        return ROOT / ".work"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else ROOT / path


WORK_ROOT = default_work_root()
TEMP_ROOT = WORK_ROOT / "tmp/allocator"
REPORT = WORK_ROOT / "reports/allocator/tls-codegen.json"


def temporary_directory(prefix: str) -> tempfile.TemporaryDirectory:
    """Create disposable TLS-probe state below the configured work root."""

    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=TEMP_ROOT)


ROOT_NAMES = (
    "DYNAMIC_BACKING_ROOT",
    "FAST_SLOT_ROOT",
    "DEFAULT_THEAP_ROOT",
    "CACHED_THEAP_ROOT",
    "THREAD_ID_HELPER_ROOT",
)
NONZERO_INITIAL_ROOTS = frozenset(
    {"DYNAMIC_BACKING_ROOT", "DEFAULT_THEAP_ROOT", "CACHED_THEAP_ROOT"}
)
ZERO_INITIAL_ROOTS = frozenset({"FAST_SLOT_ROOT", "THREAD_ID_HELPER_ROOT"})
WITNESSES = (
    "crabc_mimalloc_tls_probe_dynamic_get",
    "crabc_mimalloc_tls_probe_fast_get",
    "crabc_mimalloc_tls_probe_default_get",
    "crabc_mimalloc_tls_probe_cached_get",
    "crabc_mimalloc_tls_probe_identity_get",
    "crabc_mimalloc_tls_probe_identity_helper_address",
    "crabc_mimalloc_tls_probe_reset",
)
DIRECT_ROOT_WITNESSES = frozenset(WITNESSES) - {
    "crabc_mimalloc_tls_probe_identity_get"
}
FORBIDDEN_TLS_FORMS = (
    "__tls_get_addr",
    "TLSDESC",
    "TLSGD",
    "TLSLD",
    "DTPMOD",
    "DTPREL",
)
EXPECTED_TLS_RELOCATIONS = (
    "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21",
    "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC",
)


class VerificationError(RuntimeError):
    pass


def run(command: Sequence[str], *, env: dict[str, str] | None = None, binary: bool = False):
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr if not binary else completed.stderr.decode(errors="replace")
        raise VerificationError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{stderr}"
        )
    return completed.stdout


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise VerificationError(f"required pinned-image tool is unavailable: {name}")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_from_cargo_output(output: str) -> Path:
    artifact: Path | None = None
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("reason") != "compiler-artifact":
            continue
        target = event.get("target")
        if not isinstance(target, dict) or target.get("name") != "crabc_mimalloc":
            continue
        for filename in event.get("filenames", []):
            candidate = Path(filename)
            if candidate.suffix == ".rlib":
                artifact = candidate
    if artifact is None:
        raise VerificationError("cargo did not report the crabc_mimalloc rlib")
    return artifact


def extract_single_object(ar: str, archive: Path, destination: Path) -> str:
    members = run([ar, "t", str(archive)]).splitlines()
    objects = [member for member in members if member.endswith(".o")]
    if len(objects) != 1:
        raise VerificationError(
            f"expected one codegen-unit object in the probe rlib, found {objects}"
        )
    object_bytes = run([ar, "p", str(archive), objects[0]], binary=True)
    destination.write_bytes(object_bytes)
    return objects[0]


def section_names(readelf_sections: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    pattern = re.compile(r"^\s*\[\s*(\d+)\]\s+(\S+)", re.MULTILINE)
    for match in pattern.finditer(readelf_sections):
        sections[match.group(1)] = match.group(2)
    return sections


def root_symbols(symbol_table: str) -> dict[str, dict[str, str | int]]:
    found: dict[str, dict[str, str | int]] = {}
    pattern = re.compile(
        r"^\s*\d+:\s+\S+\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$",
        re.MULTILINE,
    )
    for match in pattern.finditer(symbol_table):
        size, symbol_type, binding, visibility, section, symbol_name = match.groups()
        for root_name in ROOT_NAMES:
            if root_name not in symbol_name:
                continue
            if root_name in found:
                raise VerificationError(f"duplicate TLS root symbol: {root_name}")
            found[root_name] = {
                "name": symbol_name,
                "size": int(size),
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "section_index": section,
            }
    missing = sorted(set(ROOT_NAMES) - set(found))
    if missing:
        raise VerificationError(f"missing private TLS root symbols: {missing}")
    return found


def reject_forbidden_tls_forms(text: str) -> None:
    present = [forbidden for forbidden in FORBIDDEN_TLS_FORMS if forbidden in text]
    if present:
        raise VerificationError(f"forbidden dynamic TLS access forms are present: {present}")


def cargo_probe_command(cargo: str) -> list[str]:
    """Build both AArch64 TLS controls from the checked-in lockfile."""

    return [
        cargo,
        "rustc",
        "--locked",
        "--offline",
        "-p",
        "crabc-mimalloc",
        "--lib",
        "--features",
        "tls-codegen-probe",
        "--message-format=json-render-diagnostics",
        "--",
    ]


def main() -> int:
    cargo = require_tool("cargo")
    rustc = require_tool("rustc")
    ar = require_tool("ar")
    readelf = require_tool("readelf")
    objdump = require_tool("objdump")
    file_tool = require_tool("file")

    rustc_version = run([rustc, "-vV"])
    if "host: aarch64-unknown-linux-musl" not in rustc_version:
        raise VerificationError(
            "TLS codegen evidence must run in the pinned native aarch64-unknown-linux-musl image"
        )

    with temporary_directory(prefix="crabc-mimalloc-tls-") as temporary:
        temporary_root = Path(temporary)
        target_dir = temporary_root / "target"
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(target_dir)
        cargo_base_command = cargo_probe_command(cargo)
        common_codegen_flags = [
            "-Copt-level=3",
            "-Cdebug-assertions=no",
            "-Coverflow-checks=no",
            "-Ccodegen-units=1",
            "-Cdebuginfo=0",
            "-Cstrip=none",
            "-Awarnings",
        ]
        cargo_command = cargo_base_command + [
            "-Ztls-model=initial-exec",
            *common_codegen_flags,
        ]
        cargo_output = run(cargo_command, env=environment)
        archive = artifact_from_cargo_output(cargo_output)
        object_path = temporary_root / "crabc_mimalloc_tls_probe.o"
        archive_member = extract_single_object(ar, archive, object_path)

        file_output = run([file_tool, str(object_path)])
        if "ARM aarch64" not in file_output or "relocatable" not in file_output:
            raise VerificationError(f"probe object is not AArch64 relocatable ELF: {file_output.strip()}")
        normalized_file_output = file_output.replace(str(object_path), "<probe-object>")

        symbol_table = run([readelf, "-sW", str(object_path)])
        dynamic_symbols = run([readelf, "--dyn-syms", "-W", str(object_path)])
        relocations = run([readelf, "-rW", str(object_path)])
        sections_output = run([readelf, "-SW", str(object_path)])
        sections = section_names(sections_output)
        symbols = root_symbols(symbol_table)

        for root_name, symbol in symbols.items():
            observed = (symbol["type"], symbol["binding"], symbol["visibility"], symbol["size"])
            expected = ("TLS", "GLOBAL", "HIDDEN", 8)
            if observed != expected:
                raise VerificationError(
                    f"{root_name} has {observed}, expected private AArch64 TLS {expected}"
                )
            if str(symbol["name"]) in dynamic_symbols:
                raise VerificationError(f"private TLS root escaped into dynsym: {root_name}")
            section_name = sections.get(str(symbol["section_index"]), "")
            if root_name in NONZERO_INITIAL_ROOTS:
                expected_prefix = ".tdata"
            elif root_name in ZERO_INITIAL_ROOTS:
                expected_prefix = ".tbss"
            else:
                raise VerificationError(f"unclassified TLS root initializer: {root_name}")
            if not section_name.startswith(expected_prefix):
                raise VerificationError(
                    f"{root_name} is in {section_name!r}, expected {expected_prefix} initial image"
                )
            symbol["section"] = section_name

            root_relocations = [
                line for line in relocations.splitlines() if str(symbol["name"]) in line
            ]
            for expected_relocation in EXPECTED_TLS_RELOCATIONS:
                if not any(expected_relocation in line for line in root_relocations):
                    raise VerificationError(
                        f"{root_name} lacks initial-exec relocation {expected_relocation}"
                    )

        witness_disassembly: dict[str, str] = {}
        for witness in WITNESSES:
            section = f".text.{witness}"
            disassembly = run([objdump, "-dr", "--section", section, str(object_path)])
            if witness not in disassembly:
                raise VerificationError(f"missing codegen witness section: {witness}")
            if "tpidr_el0" not in disassembly:
                raise VerificationError(f"{witness} does not directly read the AArch64 thread pointer")
            has_tlsie = any(
                relocation in disassembly for relocation in EXPECTED_TLS_RELOCATIONS
            )
            if witness in DIRECT_ROOT_WITNESSES and not has_tlsie:
                raise VerificationError(f"{witness} has no initial-exec TLS relocation")
            if witness == "crabc_mimalloc_tls_probe_identity_get" and has_tlsie:
                raise VerificationError(
                    "selected Linux/AArch64 identity unexpectedly accesses a TLS variable"
                )
            reject_forbidden_tls_forms(disassembly)
            witness_disassembly[witness] = disassembly.replace(
                str(object_path), "<probe-object>"
            )

        reject_forbidden_tls_forms(symbol_table + relocations)

        # The production target configuration now deliberately makes
        # initial-exec ambient for every native runtime crate. Clear Cargo's
        # encoded rustflags only for this negative control so it measures the
        # pinned compiler default rather than accidentally inheriting the
        # production policy. Keep the contrast executable: a future toolchain
        # must not silently make the explicit runtime model look optional or
        # replace it with an unreviewed access form.
        default_model_environment = environment.copy()
        default_model_environment["CARGO_ENCODED_RUSTFLAGS"] = ""
        default_model_command = cargo_base_command + [
            *common_codegen_flags,
            "-Cmetadata=crabc_mimalloc_tls_default_control",
        ]
        default_cargo_output = run(default_model_command, env=default_model_environment)
        default_archive = artifact_from_cargo_output(default_cargo_output)
        default_object_path = temporary_root / "crabc_mimalloc_tls_default_control.o"
        default_archive_member = extract_single_object(
            ar, default_archive, default_object_path
        )
        default_symbol_table = run([readelf, "-sW", str(default_object_path)])
        default_relocations = run([readelf, "-rW", str(default_object_path)])
        default_symbols = root_symbols(default_symbol_table)
        for root_name, symbol in default_symbols.items():
            root_relocations = [
                line
                for line in default_relocations.splitlines()
                if str(symbol["name"]) in line
            ]
            if not any("R_AARCH64_TLSDESC_CALL" in line for line in root_relocations):
                raise VerificationError(
                    f"pinned-nightly default-model control no longer emits TLSDESC for {root_name}"
                )

        report = {
            "schema_version": 1,
            "status": "pass",
            "target": "aarch64-unknown-linux-musl",
            "tls_model": "initial-exec",
            "rustc": rustc_version.strip(),
            "cargo_command": cargo_command,
            "artifact": {
                "archive_member": archive_member,
                "object_sha256": sha256(object_path),
                "file": normalized_file_output.strip(),
            },
            "default_model_control": {
                "cargo_command": default_model_command,
                "environment_override": {"CARGO_ENCODED_RUSTFLAGS": ""},
                "archive_member": default_archive_member,
                "object_sha256": sha256(default_object_path),
                "observed_root_access": "R_AARCH64_TLSDESC_* including R_AARCH64_TLSDESC_CALL",
                "initial_exec_flag_required": True,
            },
            "root_symbols": symbols,
            "witnesses": {
                name: {
                    "disassembly_sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "direct_thread_pointer": True,
                    "tlsie_relocation": name in DIRECT_ROOT_WITNESSES,
                }
                for name, text in witness_disassembly.items()
            },
            "forbidden_tls_forms": [],
            "codegen_scope": (
                "test-only crabc-mimalloc probe feature; production integration must apply "
                "the initial-exec setting target-wide and audit the installed runtime images"
            ),
        }

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        "allocator compiler TLS: PASS "
        f"({len(ROOT_NAMES)} private roots, {len(WITNESSES)} codegen witnesses)"
    )
    print(f"report: {REPORT}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"allocator compiler TLS: FAIL: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
