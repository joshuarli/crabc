#!/usr/bin/env python3
"""Prove crabc-mimalloc's private x86-64 compiler-TLS access model.

This is a deliberately separate native x86-64 judge.  The sibling
``run.py`` is the AArch64 judge; keeping the ELF and register expectations
target-specific prevents one architecture's evidence from accidentally
accepting the other's object.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[3]
REPORT = ROOT / "compat/reports/allocator/tls-codegen-x86_64.json"
TARGET = "x86_64-unknown-linux-musl"

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
IDENTITY_WITNESS = "crabc_mimalloc_tls_probe_identity_get"
TLS_ROOT_WITNESSES = frozenset(WITNESSES) - {IDENTITY_WITNESS}
FORBIDDEN_TLS_FORMS = (
    "__tls_get_addr",
    "TLSDESC",
    "TLSGD",
    "TLSLD",
    "DTPMOD",
    "DTPREL",
)
# x86-64 initial-exec uses a GOT entry containing the negative TP offset.
# The access itself then adds that offset to the native FS base in the
# generated instruction sequence.
EXPECTED_TLS_RELOCATION = "R_X86_64_GOTTPOFF"
FS_SEGMENT_ACCESS = re.compile(r"\bfs\s*:", re.IGNORECASE)
# GNU objdump normally renders the identity load as ``%fs:0x0``. Accept the
# equivalent Intel spelling as well, but do not mistake an FS-relative TLS
# access such as ``%fs:(%rax)`` for the direct thread-pointer identity load.
FS_ZERO_ACCESS = re.compile(
    r"\bfs\s*:\s*(?:0x0+|0+)(?=\b|[,\)])|\bfs\s*:\s*\[\s*(?:0x0+|0+)\s*\]",
    re.IGNORECASE,
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
    destination.write_bytes(run([ar, "p", str(archive), objects[0]], binary=True))
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


def witness_access_evidence(witness: str, disassembly: str) -> dict[str, bool | str]:
    """Validate the target-specific access proof for one retained witness.

    The selected Linux/musl identity path is a literal load from the TCB self
    pointer at ``%fs:0`` and must not acquire a TLS relocation. The other
    witnesses access private compiler-TLS roots, for which initial-exec code
    uses an FS-segment addressing instruction together with a
    ``R_X86_64_GOTTPOFF`` relocation. A register-derived FS offset is expected
    for those roots and is intentionally not represented as an exact zero
    offset.
    """
    if not FS_SEGMENT_ACCESS.search(disassembly):
        raise VerificationError(f"{witness} has no x86-64 %fs-segment access")

    has_tlsie = EXPECTED_TLS_RELOCATION in disassembly
    if witness == IDENTITY_WITNESS:
        if not FS_ZERO_ACCESS.search(disassembly):
            raise VerificationError(
                f"{witness} does not directly read the x86-64 %fs:0 identity word"
            )
        if has_tlsie:
            raise VerificationError(
                "selected Linux/x86-64 identity unexpectedly accesses a TLS variable"
            )
        return {
            "access_model": "direct-thread-pointer-fs-zero",
            "exact_fs_zero_read": True,
            "fs_segment_access": True,
            "tlsie_relocation": False,
        }

    if witness not in TLS_ROOT_WITNESSES:
        raise VerificationError(f"unclassified x86-64 TLS codegen witness: {witness}")
    if not has_tlsie:
        raise VerificationError(f"{witness} has no x86-64 initial-exec TLS relocation")
    return {
        "access_model": "initial-exec-tls-fs-segment-gottpoff",
        "fs_segment_access": True,
        "tlsie_relocation": True,
    }


def require_native_x86_execution_provenance() -> None:
    # Guest `uname` cannot distinguish Docker's native amd64 execution from
    # QEMU emulation. The canonical dispatcher carries its host observation
    # into the container; require that evidence before writing a report that
    # calls this x86-64 codegen result native.
    execution_mode = os.environ.get("CRABC_EXECUTION_MODE")
    host_arch = os.environ.get("CRABC_HOST_ARCH")
    if execution_mode != "native" or host_arch not in {"x86_64", "amd64"}:
        raise VerificationError(
            "TLS codegen evidence requires canonical native x86-64 provenance "
            "(CRABC_EXECUTION_MODE=native and CRABC_HOST_ARCH=x86_64)"
        )


def require_native_x86_host(rustc: str) -> str:
    require_native_x86_execution_provenance()
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64"}:
        raise VerificationError(
            f"TLS codegen evidence must run natively on x86-64, not {machine!r}"
        )
    rustc_version = run([rustc, "-vV"])
    if f"host: {TARGET}" not in rustc_version:
        raise VerificationError(
            f"TLS codegen evidence requires native {TARGET} rustc host"
        )
    return rustc_version


def main() -> int:
    require_native_x86_execution_provenance()
    cargo = require_tool("cargo")
    rustc = require_tool("rustc")
    ar = require_tool("ar")
    readelf = require_tool("readelf")
    objdump = require_tool("objdump")
    file_tool = require_tool("file")
    rustc_version = require_native_x86_host(rustc)

    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-tls-x86_64-") as temporary:
        temporary_root = Path(temporary)
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(temporary_root / "target")
        cargo_base_command = [
            cargo,
            "rustc",
            "--offline",
            "-p",
            "crabc-mimalloc",
            "--lib",
            "--features",
            "tls-codegen-probe",
            "--target",
            TARGET,
            "--message-format=json-render-diagnostics",
            "--",
        ]
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
        archive = artifact_from_cargo_output(run(cargo_command, env=environment))
        object_path = temporary_root / "crabc_mimalloc_tls_probe.o"
        archive_member = extract_single_object(ar, archive, object_path)

        file_output = run([file_tool, str(object_path)])
        if not re.search(r"ELF 64-bit LSB.*relocatable.*x86-64", file_output):
            raise VerificationError(
                f"probe object is not a native x86-64 relocatable ELF: {file_output.strip()}"
            )
        normalized_file_output = file_output.replace(str(object_path), "<probe-object>")
        elf_header = run([readelf, "-hW", str(object_path)])
        if not re.search(r"Class:\s+ELF64", elf_header) or not re.search(
            r"Data:\s+2's complement, little endian", elf_header
        ):
            raise VerificationError("probe object is not ELF64 little-endian")
        if not re.search(r"Machine:\s+Advanced Micro Devices X86-64", elf_header):
            raise VerificationError("probe object ELF machine is not x86-64")

        symbol_table = run([readelf, "-sW", str(object_path)])
        dynamic_symbols = run([readelf, "--dyn-syms", "-W", str(object_path)])
        relocations = run([readelf, "-rW", str(object_path)])
        sections = section_names(run([readelf, "-SW", str(object_path)]))
        symbols = root_symbols(symbol_table)

        for root_name, symbol in symbols.items():
            observed = (symbol["type"], symbol["binding"], symbol["visibility"], symbol["size"])
            expected = ("TLS", "GLOBAL", "HIDDEN", 8)
            if observed != expected:
                raise VerificationError(
                    f"{root_name} has {observed}, expected private x86-64 TLS {expected}"
                )
            if str(symbol["name"]) in dynamic_symbols:
                raise VerificationError(f"private TLS root escaped into dynsym: {root_name}")
            section_name = sections.get(str(symbol["section_index"]), "")
            expected_prefix = ".tdata" if root_name in NONZERO_INITIAL_ROOTS else ".tbss"
            if root_name not in NONZERO_INITIAL_ROOTS | ZERO_INITIAL_ROOTS:
                raise VerificationError(f"unclassified TLS root initializer: {root_name}")
            if not section_name.startswith(expected_prefix):
                raise VerificationError(
                    f"{root_name} is in {section_name!r}, expected {expected_prefix} initial image"
                )
            symbol["section"] = section_name
            root_relocations = [
                line for line in relocations.splitlines() if str(symbol["name"]) in line
            ]
            if not any(EXPECTED_TLS_RELOCATION in line for line in root_relocations):
                raise VerificationError(
                    f"{root_name} lacks x86-64 initial-exec relocation {EXPECTED_TLS_RELOCATION}"
                )
            symbol["relocations"] = [
                line.strip() for line in root_relocations if line.strip()
            ]

        witness_disassembly: dict[str, str] = {}
        witness_accesses: dict[str, dict[str, bool | str]] = {}
        for witness in WITNESSES:
            section = f".text.{witness}"
            disassembly = run([objdump, "-dr", "--section", section, str(object_path)])
            if witness not in disassembly:
                raise VerificationError(f"missing codegen witness section: {witness}")
            witness_accesses[witness] = witness_access_evidence(witness, disassembly)
            reject_forbidden_tls_forms(disassembly)
            witness_disassembly[witness] = disassembly.replace(
                str(object_path), "<probe-object>"
            )

        reject_forbidden_tls_forms(symbol_table + relocations)

        report = {
            "schema_version": 1,
            "status": "pass",
            "target": TARGET,
            "host_machine": platform.machine(),
            "tls_model": "initial-exec",
            "rustc": rustc_version.strip(),
            "cargo_command": cargo_command,
            "artifact": {
                "archive_member": archive_member,
                "object_sha256": sha256(object_path),
                "file": normalized_file_output.strip(),
                "elf_machine": "x86-64",
            },
            "root_symbols": symbols,
            "witnesses": {
                name: {
                    "disassembly_sha256": hashlib.sha256(text.encode()).hexdigest(),
                    **witness_accesses[name],
                }
                for name, text in witness_disassembly.items()
            },
            "tls_relocation": EXPECTED_TLS_RELOCATION,
            "forbidden_tls_forms": [],
            "codegen_scope": (
                "test-only crabc-mimalloc probe feature; production integration must apply "
                "the same per-crate -Ztls-model=initial-exec setting"
            ),
        }

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        "allocator compiler TLS x86-64: PASS "
        f"({len(ROOT_NAMES)} private roots, {len(WITNESSES)} codegen witnesses)"
    )
    print(f"report: {REPORT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"allocator compiler TLS x86-64: FAIL: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
