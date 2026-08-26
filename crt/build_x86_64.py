#!/usr/bin/env python3
"""Build and audit the bounded Linux/x86-64 static-PIE CRT foundation.

This is deliberately not a target switch for ``build.py``. It produces only
the target-specific static-PIE objects: ``rcrt1.o``, ``crti.o``, and
``crtn.o``. Dynamic CRT objects and sysroot installation remain outside this
native-evidence slice.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
CRT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = CRT_ROOT / "src"
TARGET = "x86_64-unknown-linux-musl"
PINNED_TOOLCHAIN = "nightly-2026-07-24"
DEFAULT_OUTPUT = ROOT / "target" / "crt-x86_64-static-pie"

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_REL = 1
EM_X86_64 = 62
SHT_SYMTAB = 2
SHT_RELA = 4
SHF_EXECINSTR = 0x4
STB_GLOBAL = 1
STT_FUNC = 2
STV_DEFAULT = 0
SHN_UNDEF = 0
R_X86_64_PLT32 = 4
R_X86_64_GOTPCREL = 9
EARLY_ENTRY_FORBIDDEN_RELOCATIONS = frozenset(
    {
        R_X86_64_GOTPCREL,
        16,  # R_X86_64_DTPMOD64
        17,  # R_X86_64_DTPOFF64
        18,  # R_X86_64_TPOFF64
        19,  # R_X86_64_TLSGD
        20,  # R_X86_64_TLSLD
        22,  # R_X86_64_GOTTPOFF
        23,  # R_X86_64_TPOFF32
        34,  # R_X86_64_GOTPC32_TLSDESC
        35,  # R_X86_64_TLSDESC_CALL
        36,  # R_X86_64_TLSDESC
        41,  # R_X86_64_GOTPCRELX
        42,  # R_X86_64_REX_GOTPCRELX
    }
)


class BuildError(RuntimeError):
    """A deterministic x86-64 CRT build or ELF-contract failure."""


@dataclass(frozen=True)
class ObjectSpec:
    name: str
    source_name: str
    code_sections: tuple[str, ...]
    defined_symbols: tuple[str, ...]
    undefined_symbols: tuple[str, ...]


STATIC_PIE_BOUNDARIES = (
    "__libc_start_main",
    "main",
    "_init",
    "_fini",
    "__preinit_array_start",
    "__preinit_array_end",
    "__init_array_start",
    "__init_array_end",
    "__fini_array_start",
    "__fini_array_end",
)

OBJECTS = (
    ObjectSpec(
        "rcrt1.o",
        "x86_64_rcrt1.rs",
        (".text._start",),
        ("_start",),
        STATIC_PIE_BOUNDARIES,
    ),
    ObjectSpec("crti.o", "x86_64_crti.rs", (".init", ".fini"), ("_init", "_fini"), ()),
    ObjectSpec("crtn.o", "x86_64_crtn.rs", (".init", ".fini"), (), ()),
)


@dataclass(frozen=True)
class Section:
    name: str
    section_type: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    entry_size: int


@dataclass(frozen=True)
class Symbol:
    name: str
    binding: int
    symbol_type: int
    visibility: int
    section_index: int
    value: int
    size: int


@dataclass(frozen=True)
class Relocation:
    target_section_index: int
    offset: int
    relocation_type: int


@dataclass(frozen=True)
class ElfObject:
    sections: tuple[Section, ...]
    symbols: tuple[Symbol, ...]
    relocations: tuple[Relocation, ...]

    @property
    def relocation_types(self) -> tuple[int, ...]:
        return tuple(relocation.relocation_type for relocation in self.relocations)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--llvm-objdump", default="llvm-objdump")
    return parser.parse_args()


def source_path(name: str) -> Path:
    path = (SOURCE_ROOT / name).resolve()
    if not path.is_file():
        raise BuildError(f"x86-64 CRT source is missing: {path}")
    return path


def output_directory(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(CRT_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise BuildError("--out-dir must not place generated CRT objects under crt/")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def default_rustc_command() -> list[str]:
    rustup = shutil.which("rustup")
    if rustup is None:
        raise BuildError("rustup is required to select the pinned nightly toolchain")
    return [rustup, "run", PINNED_TOOLCHAIN, "rustc"]


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise BuildError(f"required host tool is unavailable: {name}")
    return resolved


def deterministic_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "SOURCE_DATE_EPOCH": "0",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    for key in ("RUSTUP_HOME", "CARGO_HOME"):
        if key in os.environ:
            environment[key] = os.environ[key]
    return environment


def run_command(command: list[str], environment: dict[str, str]) -> dict[str, Any]:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout.decode("utf-8", errors="replace"),
        "stderr": result.stderr.decode("utf-8", errors="replace"),
    }


def write_json(path: Path, value: object) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        stream.write(encoded)
        temporary = Path(stream.name)
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_range(data: bytes, offset: int, size: int, context: str) -> bytes:
    end = offset + size
    if offset < 0 or size < 0 or end < offset or end > len(data):
        raise BuildError(f"{context}: range is outside the ELF object")
    return data[offset:end]


def c_string(data: bytes, offset: int, context: str) -> str:
    if offset < 0 or offset >= len(data):
        raise BuildError(f"{context}: string offset outside string table: {offset}")
    end = data.find(b"\0", offset)
    if end < 0:
        raise BuildError(f"{context}: unterminated string table entry")
    return data[offset:end].decode("utf-8", errors="replace")


def parse_elf_object(path: Path) -> ElfObject:
    data = path.read_bytes()
    if len(data) < 64:
        raise BuildError(f"{path}: too short for ELF64 header")
    ident = data[:16]
    if ident[:4] != ELF_MAGIC or ident[4] != ELFCLASS64 or ident[5] != ELFDATA2LSB:
        raise BuildError(f"{path}: expected little-endian ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    elf_type, machine = header[1], header[2]
    section_offset, header_size = header[6], header[8]
    section_entry_size, section_count, string_index = header[11], header[12], header[13]
    if elf_type != ET_REL or machine != EM_X86_64:
        raise BuildError(f"{path}: expected ELFREL/x86-64, got type={elf_type} machine={machine}")
    if header_size != 64 or section_entry_size != 64 or section_count == 0 or string_index >= section_count:
        raise BuildError(f"{path}: malformed ELF64 section-header table")

    raw_sections: list[tuple[int, int, int, int, int, int, int, int]] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        fields = struct.unpack("<IIQQQQIIQQ", checked_range(data, offset, 64, f"{path}: section {index}"))
        raw_sections.append((fields[0], fields[1], fields[2], fields[4], fields[5], fields[6], fields[7], fields[9]))
    _, _, _, string_offset, string_size, _, _, _ = raw_sections[string_index]
    names = checked_range(data, string_offset, string_size, f"{path}: section-name table")
    sections = tuple(
        Section(
            c_string(names, name, f"{path}: section {index}"),
            section_type,
            flags,
            offset,
            size,
            link,
            info,
            entry_size,
        )
        for index, (name, section_type, flags, offset, size, link, info, entry_size) in enumerate(raw_sections)
    )

    symbols: list[Symbol] = []
    relocations: list[Relocation] = []
    for section in sections:
        if section.section_type == SHT_SYMTAB:
            if section.entry_size != 24 or section.link >= len(sections) or section.size % section.entry_size != 0:
                raise BuildError(f"{path}: malformed symbol table {section.name}")
            strings = sections[section.link]
            string_data = checked_range(data, strings.offset, strings.size, f"{path}: symbol strings")
            for offset in range(section.offset, section.offset + section.size, section.entry_size):
                name, info, other, section_index, value, size = struct.unpack(
                    "<IBBHQQ", checked_range(data, offset, 24, f"{path}: symbol entry")
                )
                symbols.append(
                    Symbol(
                        c_string(string_data, name, f"{path}: symbol name") if name else "",
                        info >> 4,
                        info & 0x0F,
                        other & 0x03,
                        section_index,
                        value,
                        size,
                    )
                )
        elif section.section_type == SHT_RELA:
            if section.entry_size != 24 or section.size % section.entry_size != 0:
                raise BuildError(f"{path}: malformed RELA section {section.name}")
            for offset in range(section.offset, section.offset + section.size, section.entry_size):
                relocation_offset, info, _ = struct.unpack(
                    "<QQq", checked_range(data, offset, 24, f"{path}: relocation entry")
                )
                relocations.append(Relocation(section.info, relocation_offset, info & 0xFFFFFFFF))
    return ElfObject(tuple(sections), tuple(symbols), tuple(relocations))


def symbol_map(symbols: Iterable[Symbol]) -> dict[str, list[Symbol]]:
    mapped: dict[str, list[Symbol]] = {}
    for symbol in symbols:
        mapped.setdefault(symbol.name, []).append(symbol)
    return mapped


def portable_rustc_command(command: list[str], source: Path, destination: Path) -> list[str]:
    portable: list[str] = []
    for index, argument in enumerate(command):
        if index == 0:
            portable.append("rustup")
        elif argument == str(source):
            portable.append(f"/crabc/crt/src/{source.name}")
        elif argument == str(destination):
            portable.append(f"$CRABC_CRT_X86_64_OUT/{destination.name}")
        elif argument == f"{ROOT}=/crabc":
            portable.append("$CRABC_SOURCE=/crabc")
        else:
            portable.append(argument)
    return portable


def inspect_object(spec: ObjectSpec, path: Path) -> dict[str, object]:
    elf = parse_elf_object(path)
    sections = {section.name: section for section in elf.sections}
    metadata_sections = sorted(section.name for section in elf.sections if section.name.startswith(".rustc"))
    if metadata_sections:
        raise BuildError(f"{path}: Rust metadata-only sections are not valid CRT output: {metadata_sections}")
    stack = sections.get(".note.GNU-stack")
    if stack is None or stack.flags & SHF_EXECINSTR:
        raise BuildError(f"{path}: CRT object must declare a non-executable GNU stack")
    for name in spec.code_sections:
        section = sections.get(name)
        if section is None or section.size == 0 or section.flags & SHF_EXECINSTR == 0:
            raise BuildError(f"{path}: missing executable section {name}")
    symbols = symbol_map(elf.symbols)
    for name in spec.defined_symbols:
        candidates = [item for item in symbols.get(name, []) if item.section_index != SHN_UNDEF]
        if not any(
            item.binding == STB_GLOBAL and item.symbol_type == STT_FUNC and item.visibility == STV_DEFAULT
            for item in candidates
        ):
            raise BuildError(f"{path}: {name} must be a default-visible global function")
    for name in spec.undefined_symbols:
        if not any(item.section_index == SHN_UNDEF for item in symbols.get(name, [])):
            raise BuildError(f"{path}: missing required unresolved CRT boundary {name}")
    unresolved = {item.name for item in elf.symbols if item.name and item.section_index == SHN_UNDEF}
    unexpected = sorted(unresolved.difference(spec.undefined_symbols))
    if unexpected:
        raise BuildError(f"{path}: unexpected runtime dependency symbols: {unexpected}")
    return {
        "path": path.name,
        "sha256": sha256_file(path),
        "sections": [section.name for section in elf.sections],
        "defined_symbols": sorted(item.name for item in elf.symbols if item.name and item.section_index != SHN_UNDEF),
        "undefined_symbols": sorted(item.name for item in elf.symbols if item.name and item.section_index == SHN_UNDEF),
        "relocation_types": sorted(set(elf.relocation_types)),
    }


def audit_entry_machine_code(path: Path, objdump: str, environment: dict[str, str]) -> tuple[dict[str, object], dict[str, object]]:
    command = [objdump, "-d", "--disassemble-symbols=_start", str(path)]
    result = run_command(command, environment)
    normalized = result["stdout"].replace(str(path), f"$CRABC_CRT_X86_64_OUT/{path.name}")
    normalized_stderr = result["stderr"].replace(str(path), f"$CRABC_CRT_X86_64_OUT/{path.name}")
    machine_record = {
        "kind": "machine_entry_audit",
        "object": path.name,
        "command": [Path(objdump).name, "-d", "--disassemble-symbols=_start", f"$CRABC_CRT_X86_64_OUT/{path.name}"],
        "returncode": result["returncode"],
        "stdout_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(normalized_stderr.encode()).hexdigest(),
    }
    if result["returncode"] != 0:
        raise BuildError(f"{path}: llvm-objdump could not disassemble _start: {result['stderr']}")
    elf = parse_elf_object(path)
    starts = [item for item in elf.symbols if item.name == "_start" and item.section_index != SHN_UNDEF]
    if len(starts) != 1 or starts[0].size == 0:
        raise BuildError(f"{path}: expected one bounded _start symbol for machine audit")
    start = starts[0]
    section = elf.sections[start.section_index]
    entry_bytes = checked_range(
        path.read_bytes(),
        section.offset + start.value,
        start.size,
        f"{path}: _start instruction range",
    )
    required_machine_sequences = {
        "mov r15, rsp": b"\x49\x89\xe7",
        "and rsp, -16": b"\x48\x83\xe4\xf0",
        "syscall": b"\x0f\x05",
    }
    missing = [
        instruction
        for instruction, sequence in required_machine_sequences.items()
        if sequence not in entry_bytes
    ]
    if missing:
        raise BuildError(f"{path}: emitted _start is missing required instruction encodings: {missing}")
    entry_end = start.value + start.size
    relocation_types = sorted(
        item.relocation_type
        for item in elf.relocations
        if item.target_section_index == start.section_index and start.value <= item.offset < entry_end
    )
    forbidden = sorted(set(relocation_types).intersection(EARLY_ENTRY_FORBIDDEN_RELOCATIONS))
    if forbidden:
        raise BuildError(f"{path}: early entry has forbidden GOT/TLS relocations: {forbidden}")
    if R_X86_64_PLT32 not in relocation_types:
        raise BuildError(f"{path}: static-PIE entry lacks its direct post-relocation handoff")
    return (
        {
            "status": "verified",
            "disassembly_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
            "required_instructions": list(required_machine_sequences),
            "entry_symbol_size": start.size,
            "entry_relocation_types": relocation_types,
            "no_early_got_or_tls_relocation": True,
            "stack_alignment_before_direct_handoff": True,
        },
        machine_record,
    )


def build(args: argparse.Namespace) -> dict[str, object]:
    output = output_directory(args.out_dir)
    rustc = default_rustc_command()
    objdump = require_tool(args.llvm_objdump)
    environment = deterministic_environment()
    records: list[dict[str, Any]] = []
    commands_path = output / "commands.json"

    version = run_command(rustc + ["-Vv"], environment)
    records.append({"kind": "toolchain", **version})
    write_json(commands_path, records)
    if version["returncode"] != 0:
        raise BuildError(f"unable to execute pinned rustc: {version['stderr']}")
    version_text = str(version["stdout"])
    if "rustc 1.99.0-nightly" not in version_text or "commit-date: 2026-07-23" not in version_text:
        raise BuildError("x86-64 CRT builder requires rust-toolchain.toml's pinned nightly-2026-07-24 rustc")

    object_records: dict[str, dict[str, object]] = {}
    try:
        for spec in OBJECTS:
            source = source_path(spec.source_name)
            destination = output / spec.name
            command = rustc + [
                "--edition=2021",
                "--crate-type=lib",
                "--emit=obj",
                "--target",
                TARGET,
                "-C",
                "panic=abort",
                "-C",
                "force-unwind-tables=no",
                "-C",
                "debuginfo=0",
                "-C",
                "opt-level=2",
                "-C",
                "overflow-checks=off",
                "-C",
                "debug-assertions=off",
                "-C",
                "relocation-model=pic",
                "-C",
                "code-model=small",
                "-C",
                "link-dead-code=no",
                "--remap-path-prefix",
                f"{ROOT}=/crabc",
                "--crate-name",
                "crabc_x86_64_" + spec.name.removesuffix(".o").replace(".", "_"),
                str(source),
                "-o",
                str(destination),
            ]
            record = run_command(command, environment)
            records.append(
                {
                    "kind": "compile",
                    "object": spec.name,
                    **record,
                    "command": portable_rustc_command(command, source, destination),
                }
            )
            write_json(commands_path, records)
            if record["returncode"] != 0:
                raise BuildError(f"rustc failed while building {spec.name}: {record['stderr']}")
            if not destination.is_file():
                raise BuildError(f"rustc reported success but did not create {destination}")
            inspection = inspect_object(spec, destination)
            if spec.name == "rcrt1.o":
                machine_contract, machine_record = audit_entry_machine_code(destination, objdump, environment)
                records.append(machine_record)
                write_json(commands_path, records)
                inspection["entry_machine_contract"] = machine_contract
            inspection.update(
                {
                    "source": "/crabc/crt/src/" + spec.source_name,
                    "source_languages": ["Rust"],
                    "producer": portable_rustc_command(command, source, destination),
                }
            )
            object_records[spec.name] = inspection
    except Exception:
        write_json(commands_path, records)
        raise

    report = {
        "schema": 1,
        "target": TARGET,
        "scope": "bounded-static-pie-bootstrap",
        "toolchain": PINNED_TOOLCHAIN,
        "objects": object_records,
        "commands": {"name": commands_path.name, "sha256": sha256_file(commands_path)},
    }
    write_json(output / "objects.json", report)
    return report


def main() -> int:
    try:
        report = build(parse_args())
    except BuildError as error:
        print(f"crabc x86-64 static-PIE CRT build failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
