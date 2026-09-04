#!/usr/bin/env python3
"""Build and audit crabc's Rust-owned AArch64 application CRT objects.

This is intentionally a small direct-rustc builder instead of a Cargo build
script. Cargo's ordinary archive products do not express the C linker's five
independently ordered start/end objects. The builder is stdlib-only, invokes
the repository-pinned nightly toolchain, and performs its own ELF64/AArch64
inspection so a generated object cannot be accepted merely because rustc
returned success.
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
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
CRT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = CRT_ROOT / "src"
TARGET = "aarch64-unknown-linux-musl"
PINNED_TOOLCHAIN = "nightly-2026-07-24"
DEFAULT_OUTPUT = ROOT / "target" / "crt"

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_REL = 1
EM_AARCH64 = 183
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_NOTE = 7
SHF_EXECINSTR = 0x4
STB_GLOBAL = 1
STT_FUNC = 2
STV_DEFAULT = 0
SHN_UNDEF = 0
R_AARCH64_ADR_GOT_PAGE = 311
R_AARCH64_LD64_GOT_LO12_NC = 312
R_AARCH64_JUMP26 = 282
EARLY_ENTRY_FORBIDDEN_RELOCATIONS = frozenset(
    {
        # GOT indirections are invalid before rcrt1 has applied its own
        # relocations. TLS access is also forbidden before libc's initial
        # thread state exists. The direct branch relocation to the shared
        # post-relocation Rust handoff is separately allowed below.
        R_AARCH64_ADR_GOT_PAGE,
        R_AARCH64_LD64_GOT_LO12_NC,
        512,  # R_AARCH64_TLSGD_ADR_PREL21
        513,  # R_AARCH64_TLSGD_ADR_PAGE21
        514,  # R_AARCH64_TLSGD_ADD_LO12_NC
        541,  # R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21
        542,  # R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
        562,  # R_AARCH64_TLSDESC_ADR_PAGE21
        563,  # R_AARCH64_TLSDESC_LD64_LO12
        564,  # R_AARCH64_TLSDESC_ADD_LO12
        569,  # R_AARCH64_TLSDESC_CALL
    }
)


class BuildError(RuntimeError):
    """A deterministic CRT build or ELF-contract failure."""


@dataclass(frozen=True)
class ObjectSpec:
    name: str
    source_name: str
    relocation_model: str
    code_sections: tuple[str, ...]
    defined_symbols: tuple[str, ...]
    undefined_symbols: tuple[str, ...]


OBJECTS = (
    # libc's musl-shaped startup entry never returns and owns normal `exit`
    # processing.  The CRT therefore imports only `__libc_start_main`, rather
    # than retaining a second direct `exit` path that LLVM can legitimately
    # optimize away.
    ObjectSpec(
        "crt1.o",
        "crt1.rs",
        "static",
        (".text",),
        ("_start",),
        (
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
        ),
    ),
    ObjectSpec(
        "Scrt1.o",
        "Scrt1.rs",
        "pic",
        (".text",),
        ("_start",),
        (
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
        ),
    ),
    ObjectSpec(
        "rcrt1.o",
        "rcrt1.rs",
        "pic",
        (".text._start",),
        ("_start",),
        (
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
        ),
    ),
    ObjectSpec("crti.o", "crti.rs", "static", (".init", ".fini"), ("_init", "_fini"), ()),
    ObjectSpec("crtn.o", "crtn.rs", "static", (".init", ".fini"), (), ()),
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
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="generated object directory (default: %(default)s)",
    )
    parser.add_argument(
        "--llvm-objdump",
        default="llvm-objdump",
        help="LLVM disassembler used to audit emitted early-entry instructions",
    )
    return parser.parse_args()


def source_path(name: str) -> Path:
    path = (SOURCE_ROOT / name).resolve()
    if not path.is_file():
        raise BuildError(f"CRT source is missing: {path}")
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
        raise BuildError("rustup is required to select the repository-pinned nightly toolchain")
    return [rustup, "run", PINNED_TOOLCHAIN, "rustc"]


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise BuildError(f"required host tool is unavailable: {name}")
    return resolved


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


def c_string(data: bytes, offset: int, context: str) -> str:
    if offset < 0 or offset >= len(data):
        raise BuildError(f"{context}: string offset outside string table: {offset}")
    end = data.find(b"\0", offset)
    if end < 0:
        raise BuildError(f"{context}: unterminated string table entry")
    return data[offset:end].decode("utf-8", errors="replace")


def checked_range(data: bytes, offset: int, size: int, context: str) -> bytes:
    end = offset + size
    if offset < 0 or size < 0 or end < offset or end > len(data):
        raise BuildError(f"{context}: range is outside the ELF object")
    return data[offset:end]


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
    if elf_type != ET_REL or machine != EM_AARCH64:
        raise BuildError(f"{path}: expected ELFREL/AArch64, got type={elf_type} machine={machine}")
    if header_size != 64 or section_entry_size != 64 or section_count == 0:
        raise BuildError(f"{path}: malformed ELF64 section-header table")
    if string_index >= section_count:
        raise BuildError(f"{path}: section-name string-table index is invalid")

    raw_sections: list[tuple[int, int, int, int, int, int, int, int]] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        fields = struct.unpack("<IIQQQQIIQQ", checked_range(data, offset, 64, f"{path}: section {index}"))
        raw_sections.append((fields[0], fields[1], fields[2], fields[4], fields[5], fields[6], fields[7], fields[9]))

    name_offset, _, _, string_offset, string_size, _, _, _ = raw_sections[string_index]
    del name_offset
    section_names = checked_range(data, string_offset, string_size, f"{path}: section-name table")
    sections = tuple(
        Section(
            c_string(section_names, name, f"{path}: section {index}"),
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
    for index, section in enumerate(sections):
        if section.section_type == SHT_SYMTAB:
            if section.entry_size != 24 or section.link >= len(sections):
                raise BuildError(f"{path}: malformed symbol table section {section.name}")
            strings = sections[section.link]
            string_data = checked_range(data, strings.offset, strings.size, f"{path}: symbol strings")
            if section.size % section.entry_size != 0:
                raise BuildError(f"{path}: symbol table is not entry aligned")
            for symbol_offset in range(section.offset, section.offset + section.size, section.entry_size):
                name, info, other, section_index, value, size = struct.unpack(
                    "<IBBHQQ", checked_range(data, symbol_offset, 24, f"{path}: symbol entry")
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
            for relocation_offset in range(section.offset, section.offset + section.size, section.entry_size):
                relocation_offset_value, info, _ = struct.unpack(
                    "<QQq", checked_range(data, relocation_offset, 24, f"{path}: relocation entry")
                )
                relocations.append(Relocation(section.info, relocation_offset_value, info & 0xFFFFFFFF))

    return ElfObject(sections=sections, symbols=tuple(symbols), relocations=tuple(relocations))


def symbol_map(symbols: Iterable[Symbol]) -> dict[str, list[Symbol]]:
    mapped: dict[str, list[Symbol]] = {}
    for symbol in symbols:
        mapped.setdefault(symbol.name, []).append(symbol)
    return mapped


def portable_objdump_command(objdump: str, destination: Path) -> list[str]:
    """Record a disassembly command without its disposable output directory."""

    return [
        Path(objdump).name,
        "-d",
        "--disassemble-symbols=_start",
        f"$CRABC_CRT_OUT/{destination.name}",
    ]


def audit_entry_machine_code(
    spec: ObjectSpec,
    path: Path,
    objdump: str,
    environment: dict[str, str],
) -> tuple[dict[str, object], dict[str, object]]:
    """Inspect the emitted pre-libc entry sequence, not merely its Rust text.

    The normal CRT entries are naked assembly and the static-PIE entry is
    Rust-hosted global assembly.  This disassembly check binds their critical
    frame/stack/no-return contract to the actual AArch64 object bytes before
    the objects are allowed into the installed sysroot.
    """

    command = [objdump, "-d", "--disassemble-symbols=_start", str(path)]
    result = run_command(command, environment)
    normalized = result["stdout"].replace(str(path), f"$CRABC_CRT_OUT/{path.name}")
    normalized_stderr = str(result["stderr"]).replace(str(path), f"$CRABC_CRT_OUT/{path.name}")
    machine_record = {
        "kind": "machine_entry_audit",
        "object": spec.name,
        "command": portable_objdump_command(objdump, path),
        "returncode": result["returncode"],
        "stdout_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(normalized_stderr.encode("utf-8")).hexdigest(),
    }
    if result["returncode"] != 0:
        raise BuildError(f"{path}: llvm-objdump could not disassemble _start: {result['stderr']}")

    text = " ".join(normalized.lower().split())
    common = ("mov x29, xzr", "mov x30, xzr")
    if spec.name == "crt1.o":
        required = ("mov x9, sp", *common, "and sp, x9", "mov x0, x9", "mov x1, xzr")
    elif spec.name == "Scrt1.o":
        required = ("mov x9, sp", "mov x10, x0", *common, "and sp, x9", "mov x0, x9", "mov x1, x10")
    elif spec.name == "rcrt1.o":
        required = ("mov x15, sp", *common, "and sp, x15", "svc #0")
    else:
        return ({"status": "not_applicable"}, machine_record)
    missing = [instruction for instruction in required if instruction not in text]
    if missing:
        raise BuildError(f"{path}: emitted _start is missing required early-entry instructions: {missing}")
    if " ret" in f" {text}" or " bl " in f" {text}":
        raise BuildError(f"{path}: emitted _start must not return or call ordinary code before its handoff")
    if "mrs " in text:
        raise BuildError(f"{path}: emitted _start reads system/TLS state before libc startup")

    elf = parse_elf_object(path)
    starts = [symbol for symbol in elf.symbols if symbol.name == "_start" and symbol.section_index != SHN_UNDEF]
    if len(starts) != 1:
        raise BuildError(f"{path}: expected exactly one defined _start symbol for machine audit")
    start = starts[0]
    entry_relocation_types: list[int] = []
    if start.size:
        entry_end = start.value + start.size
        entry_relocation_types = sorted(
            relocation.relocation_type
            for relocation in elf.relocations
            if relocation.target_section_index == start.section_index
            and start.value <= relocation.offset < entry_end
        )
    elif spec.name == "rcrt1.o":
        raise BuildError(f"{path}: rcrt1 _start has no bounded symbol extent for pre-relocation audit")
    if spec.name == "rcrt1.o":
        forbidden = sorted(set(entry_relocation_types).intersection(EARLY_ENTRY_FORBIDDEN_RELOCATIONS))
        if forbidden:
            raise BuildError(f"{path}: rcrt1 pre-relocation entry has forbidden GOT/TLS relocation types: {forbidden}")
        if R_AARCH64_JUMP26 not in entry_relocation_types:
            raise BuildError(f"{path}: rcrt1 entry does not branch through the direct post-relocation handoff")
    return (
        {
            "status": "verified",
            "disassembly_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            "required_instructions": list(required),
            "entry_symbol_size": start.size,
            "entry_relocation_types": entry_relocation_types,
            "no_return_or_call_before_handoff": True,
            "no_early_system_or_tls_register_read": True,
        },
        machine_record,
    )


def inspect_object(spec: ObjectSpec, path: Path) -> dict[str, object]:
    elf = parse_elf_object(path)
    sections = {section.name: section for section in elf.sections}
    metadata_sections = sorted(
        section.name
        for section in elf.sections
        if section.name == ".rustc" or section.name.startswith(".rustc")
    )
    if metadata_sections:
        raise BuildError(f"{path}: Rust metadata-only sections are not valid CRT object output: {metadata_sections}")
    if ".note.GNU-stack" not in sections or sections[".note.GNU-stack"].flags & SHF_EXECINSTR:
        raise BuildError(f"{path}: CRT object must declare a non-executable GNU stack")
    for name in spec.code_sections:
        if name == ".text":
            matching_sections = [
                section
                for section in elf.sections
                if section.name.startswith(".text")
                and section.size != 0
                and section.flags & SHF_EXECINSTR
            ]
            if not matching_sections:
                raise BuildError(f"{path}: missing executable Rust text section")
            continue
        section = sections.get(name)
        if section is None or section.size == 0 or section.flags & SHF_EXECINSTR == 0:
            raise BuildError(f"{path}: missing executable section {name}")

    symbols = symbol_map(elf.symbols)
    for name in spec.defined_symbols:
        candidates = [entry for entry in symbols.get(name, []) if entry.section_index != SHN_UNDEF]
        if not candidates:
            raise BuildError(f"{path}: missing defined symbol {name}")
        if not any(
            entry.binding == STB_GLOBAL
            and entry.symbol_type == STT_FUNC
            and entry.visibility == STV_DEFAULT
            for entry in candidates
        ):
            raise BuildError(f"{path}: {name} must be a default-visible global function")
    for name in spec.undefined_symbols:
        if not any(entry.section_index == SHN_UNDEF for entry in symbols.get(name, [])):
            raise BuildError(f"{path}: missing required unresolved CRT boundary {name}")
    unresolved = {
        symbol.name
        for symbol in elf.symbols
        if symbol.name and symbol.section_index == SHN_UNDEF
    }
    unexpected_unresolved = sorted(unresolved.difference(spec.undefined_symbols))
    if unexpected_unresolved:
        raise BuildError(f"{path}: unexpected runtime dependency symbols: {unexpected_unresolved}")

    if spec.name == "Scrt1.o":
        got_relocations = {R_AARCH64_ADR_GOT_PAGE, R_AARCH64_LD64_GOT_LO12_NC}
        if not got_relocations.intersection(elf.relocation_types):
            raise BuildError(f"{path}: PIC startup object has no AArch64 GOT relocation")
        owned_note = sections.get(".note.crabc.owned-crt")
        if owned_note is None or owned_note.section_type != SHT_NOTE:
            raise BuildError(f"{path}: Scrt1.o lacks the owned-CRT ELF note")
        expected_note = (
            struct.pack("<III", 6, 4, 0x43525401)
            + b"CRABC\0\0\0"
            + struct.pack("<I", 1)
        )
        actual_note = checked_range(
            path.read_bytes(),
            owned_note.offset,
            owned_note.size,
            f"{path}: owned-CRT note",
        )
        if actual_note != expected_note:
            raise BuildError(f"{path}: owned-CRT ELF note has an unexpected wire value")

    return {
        # This record is installed into the relocatable sysroot.  Keep the
        # object identity without embedding the disposable builder directory.
        "path": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "sections": [section.name for section in elf.sections],
        "defined_symbols": sorted(
            symbol.name for symbol in elf.symbols if symbol.name and symbol.section_index != SHN_UNDEF
        ),
        "undefined_symbols": sorted(
            symbol.name for symbol in elf.symbols if symbol.name and symbol.section_index == SHN_UNDEF
        ),
        "relocation_types": sorted(set(elf.relocation_types)),
        "owned_lifecycle_note": spec.name == "Scrt1.o",
    }


def portable_rustc_command(command: Sequence[str], source: Path, destination: Path) -> list[str]:
    """Retain an installed producer record without a disposable build path."""

    portable: list[str] = []
    for index, argument in enumerate(command):
        if index == 0:
            portable.append("rustup")
        elif argument == str(source):
            portable.append(f"/crabc/crt/src/{source.name}")
        elif argument == str(destination):
            portable.append(f"$CRABC_CRT_OUT/{destination.name}")
        elif argument == f"{ROOT}=/crabc":
            portable.append("$CRABC_SOURCE=/crabc")
        else:
            portable.append(argument)
    return portable


def deterministic_environment(temporary_directory: Path) -> dict[str, str]:
    # Direct rustc invocation does not use Cargo's linker configuration. Keep
    # only process discovery state and establish reproducible diagnostic/time
    # inputs explicitly; no ambient target include/library path is consulted.
    temporary_directory = temporary_directory.expanduser().resolve()
    temporary_directory.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "SOURCE_DATE_EPOCH": "0",
        "LC_ALL": "C",
        # Rustc may use a temporary directory for intermediates. This builder
        # owns its output parent, so retain that state beside the generated
        # objects rather than allowing the platform default such as /tmp.
        "TMPDIR": str(temporary_directory),
        "TZ": "UTC",
    }
    for key in ("RUSTUP_HOME", "CARGO_HOME"):
        if key in os.environ:
            environment[key] = os.environ[key]
    return environment


def build(args: argparse.Namespace) -> dict[str, object]:
    output = output_directory(args.out_dir)
    rustc = default_rustc_command()
    objdump = require_tool(args.llvm_objdump)
    environment = deterministic_environment(output.parent / ".crabc-crt-tmp")
    records: list[dict[str, Any]] = []
    commands_path = output / "commands.json"

    version = run_command(rustc + ["-Vv"], environment)
    records.append({"kind": "toolchain", **version})
    write_json(commands_path, records)
    if version["returncode"] != 0:
        raise BuildError(f"unable to execute pinned rustc: {version['stderr']}")
    version_text = str(version["stdout"])
    if "rustc 1.99.0-nightly" not in version_text or "commit-date: 2026-07-23" not in version_text:
        raise BuildError(
            "CRT builder requires rust-toolchain.toml's pinned nightly-2026-07-24 rustc"
        )

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
                "relocation-model=" + spec.relocation_model,
                "-C",
                "code-model=small",
                "-C",
                "link-dead-code=no",
                "--remap-path-prefix",
                f"{ROOT}=/crabc",
                "--crate-name",
                "crabc_" + spec.name.removesuffix(".o").replace(".", "_"),
                str(source),
                "-o",
                str(destination),
            ]
            if spec.name == "Scrt1.o":
                # Linux's dynamic-loader entry ABI carries the loader fini
                # callback in x0. Static crt1 has no register input at entry.
                command[command.index(str(source)) : command.index(str(source))] = [
                    "--cfg",
                    "crabc_dynamic_startup",
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
            machine_contract, machine_record = audit_entry_machine_code(spec, destination, objdump, environment)
            records.append(machine_record)
            write_json(commands_path, records)
            inspection.update(
                {
                    "source": "/crabc/crt/src/" + spec.source_name,
                    "source_languages": ["Rust"],
                    "producer": portable_rustc_command(command, source, destination),
                    "entry_machine_contract": machine_contract,
                }
            )
            object_records[spec.name] = inspection

        if object_records["crt1.o"]["sha256"] == object_records["Scrt1.o"]["sha256"]:
            raise BuildError("crt1.o and Scrt1.o are byte-identical; PIE requires a distinct PIC object")
    except Exception:
        write_json(commands_path, records)
        raise

    report = {
        "schema": 1,
        "target": TARGET,
        "toolchain": PINNED_TOOLCHAIN,
        "objects": object_records,
        "commands": {"name": commands_path.name, "sha256": sha256_file(commands_path)},
    }
    write_json(output / "objects.json", report)
    return report


def main() -> int:
    args = parse_args()
    try:
        report = build(args)
    except BuildError as error:
        print(f"crabc CRT build failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
