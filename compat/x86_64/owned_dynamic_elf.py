"""Pre-execution ELF inspection for installed-driver dynamic link outputs.

The installed dynamic driver declares a link plan and validates LLD's input
trace. This module is the independent reader of the resulting file: it parses
the final ELF64 x86-64 image directly (no ambient ``readelf`` text), records
the facts the owned dynamic product contract names, and rejects an output
whose interpreter, dependencies, search path, binding, relocations, symbols,
TLS, stack, or RELRO shape differs from the declared mode before anything can
execute it. It is standard-library-only so the same code runs inside the
installed product and in host-side qualification replay.

The admitted dynamic relocation kinds are the ones the owned loader's general
graph applies (``ldso/src/x86_64_general_relocation.rs``, after musl 1.2.6
``arch/x86_64/reloc.h``): NONE, 64, COPY, GLOB_DAT, JUMP_SLOT, RELATIVE,
DTPMOD64, DTPOFF64 and TPOFF64, plus packed DT_RELR relative entries. A kind
outside that set, such as TLSDESC or IRELATIVE, is not an owned-runtime input.

An output with a non-empty ``.eh_frame`` must carry exactly one
``PT_GNU_EH_FRAME``: unwinders, including Rust's, find a module's frame
descriptors only through that segment reported by ``dl_iterate_phdr``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
from typing import Any, Callable, Mapping

SCHEMA = "crabc.x86_64-owned-dynamic-elf-inspection/v2"

ET_EXEC, ET_DYN = 2, 3
EM_X86_64 = 62
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_TLS = 1, 2, 3, 7
PT_GNU_EH_FRAME, PT_GNU_STACK, PT_GNU_RELRO = 0x6474E550, 0x6474E551, 0x6474E552
SHT_NOBITS = 8
PF_X, PF_W, PF_R = 1, 2, 4
DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 1, 2, 4, 5, 6
DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT = 7, 8, 9, 10, 11
DT_SONAME, DT_RPATH, DT_REL, DT_RELSZ, DT_PLTREL, DT_TEXTREL = 14, 15, 17, 18, 20, 22
DT_JMPREL, DT_BIND_NOW, DT_RUNPATH, DT_FLAGS = 23, 24, 29, 30
DT_RELRSZ, DT_RELR, DT_RELRENT = 35, 36, 37
DT_GNU_HASH, DT_VERSYM, DT_VERDEF, DT_VERNEED = 0x6FFFFEF5, 0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFE
DT_FLAGS_1 = 0x6FFFFFFB
DF_TEXTREL, DF_BIND_NOW, DF_STATIC_TLS = 0x4, 0x8, 0x10
DF_1_NOW, DF_1_PIE = 0x1, 0x08000000
STB_WEAK = 2
STT_GNU_IFUNC = 10
SHN_UNDEF = 0

RELOCATION_NAMES = {
    0: "R_X86_64_NONE", 1: "R_X86_64_64", 5: "R_X86_64_COPY", 6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT", 8: "R_X86_64_RELATIVE", 16: "R_X86_64_DTPMOD64",
    17: "R_X86_64_DTPOFF64", 18: "R_X86_64_TPOFF64",
}
EXECUTABLE_ONLY_RELOCATIONS = frozenset({"R_X86_64_COPY"})
MODES = {
    "pie": {"elf_type": "ET_DYN", "interpreter": True},
    "exec": {"elf_type": "ET_EXEC", "interpreter": True},
    "shared": {"elf_type": "ET_DYN", "interpreter": False},
}


class InspectionError(ValueError):
    """A final ELF is malformed or differs from its declared link contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InspectionError(message)


@dataclass(frozen=True)
class Expectation:
    """The declared link contract one final output must physically satisfy."""

    mode: str
    interpreter: str
    needed: tuple[str, ...]
    soname: str | None
    search_kind: str
    search_path: str
    binding: str
    hash_style: str
    runtime_imports: frozenset[str]
    # The driver knows every declared provider at link time. A retained
    # sidecar replay has no provider tables and passes None to check only the
    # recorded physical facts; it never widens the link-time decision.
    provided_symbols: frozenset[str] | None


class _Image:
    """Bounds-checked little-endian reads over one immutable file image."""

    def __init__(self, data: bytes):
        self.data = data

    def unpack(self, layout: str, offset: int) -> tuple[Any, ...]:
        size = struct.calcsize(layout)
        _require(0 <= offset and offset + size <= len(self.data), "ELF read is outside the file")
        return struct.unpack_from(layout, self.data, offset)

    def string(self, offset: int, limit: int) -> str:
        _require(0 <= offset < limit <= len(self.data), "ELF string is outside its table")
        end = self.data.find(b"\0", offset, limit)
        _require(end >= 0, "ELF string is unterminated")
        try:
            return self.data[offset:end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise InspectionError("ELF string is not UTF-8") from error


def _file_offset(loads: list[tuple[int, int, int, int]], address: int, size: int) -> int:
    """Translate one loaded virtual range to the file bytes that initialize it."""

    for offset, vaddr, filesz, _ in loads:
        if vaddr <= address and address + size <= vaddr + filesz:
            return offset + address - vaddr
    raise InspectionError(f"dynamic address 0x{address:x} is not file-backed by a PT_LOAD")


def _symbol_count(image: _Image, loads, tags: Mapping[int, list[int]]) -> int:
    """Return the dynamic symbol count from the hash table the loader uses."""

    if DT_HASH in tags:
        offset = _file_offset(loads, tags[DT_HASH][0], 8)
        _, chains = image.unpack("<II", offset)
        return chains
    if DT_GNU_HASH not in tags:
        return 0
    offset = _file_offset(loads, tags[DT_GNU_HASH][0], 16)
    buckets, first, bloom_words, _ = image.unpack("<IIII", offset)
    bucket_offset = offset + 16 + 8 * bloom_words
    highest = 0
    for index in range(buckets):
        highest = max(highest, image.unpack("<I", bucket_offset + 4 * index)[0])
    if highest < first:
        return first
    chain_offset = bucket_offset + 4 * buckets
    while True:
        value = image.unpack("<I", chain_offset + 4 * (highest - first))[0]
        if value & 1:
            return highest + 1
        highest += 1


def _relocations(image: _Image, loads, tags: Mapping[int, list[int]], address_tag: int,
                 size_tag: int) -> list[str]:
    if address_tag not in tags:
        _require(size_tag not in tags, "relocation size has no table")
        return []
    _require(size_tag in tags and len(tags[address_tag]) == len(tags[size_tag]) == 1,
             "relocation table is not uniquely sized")
    size = tags[size_tag][0]
    _require(size % 24 == 0, "RELA table size is not a whole number of entries")
    offset = _file_offset(loads, tags[address_tag][0], size)
    kinds = []
    for index in range(size // 24):
        _, info, _ = image.unpack("<QQq", offset + 24 * index)
        kind = info & 0xFFFFFFFF
        _require(kind in RELOCATION_NAMES, f"unadmitted dynamic relocation kind {kind}")
        kinds.append(RELOCATION_NAMES[kind])
    return kinds


def _has_eh_frame(image: _Image, shoff: int, shentsize: int, shnum: int, shstrndx: int) -> bool:
    """Whether the section table names a non-empty, file-backed ``.eh_frame``."""

    if shnum == 0:
        return False
    _require(shentsize == 64 and shstrndx < shnum, "section header table is invalid")
    names_offset, names_size = image.unpack("<QQ", shoff + 64 * shstrndx + 24)
    found = False
    for index in range(shnum):
        name, kind, _, _, _, size = image.unpack("<IIQQQQ", shoff + 64 * index)
        if image.string(names_offset + name, names_offset + names_size) == ".eh_frame":
            _require(not found, "output has more than one .eh_frame section")
            found = kind != SHT_NOBITS and size > 0
    return found


def unwind_table_facts(path: Path) -> dict[str, Any]:
    """Return whether an ELF64 image has ``.eh_frame`` and its PT_GNU_EH_FRAME count."""

    data = Path(path).read_bytes()
    image = _Image(data)
    _require(len(data) >= 64 and data[:4] == b"\x7fELF" and data[4:7] == b"\x02\x01\x01",
             "image is not ELF64 little-endian version 1")
    phoff, shoff = image.unpack("<QQ", 32)
    phentsize, phnum, shentsize, shnum, shstrndx = image.unpack("<HHHHH", 54)
    _require(phentsize == 56, "program header table is invalid")
    headers = sum(image.unpack("<I", phoff + index * phentsize)[0] == PT_GNU_EH_FRAME for index in range(phnum))
    return {"eh_frame": _has_eh_frame(image, shoff, shentsize, shnum, shstrndx),
            "eh_frame_hdr_segments": headers}


def require_unwind_table_header(facts: Mapping[str, Any]) -> None:
    """Require one PT_GNU_EH_FRAME exactly when the image has ``.eh_frame``."""

    _require(facts["eh_frame_hdr_segments"] == (1 if facts["eh_frame"] else 0),
             "output with .eh_frame lacks exactly one PT_GNU_EH_FRAME (link with --eh-frame-hdr)"
             if facts["eh_frame"] else "output without .eh_frame has a PT_GNU_EH_FRAME")


def inspect(path: Path) -> dict[str, Any]:
    """Return the canonical structural facts of one final ELF64 x86-64 image."""

    data = Path(path).read_bytes()
    image = _Image(data)
    _require(len(data) >= 64 and data[:4] == b"\x7fELF", "output is not ELF")
    _require(data[4] == 2 and data[5] == 1 and data[6] == 1, "output is not ELF64 little-endian version 1")
    (elf_type, machine, _, entry, phoff, _, _, header_size, phentsize, phnum,
     _, _, _) = image.unpack("<HHIQQQIHHHHHH", 16)
    _require(machine == EM_X86_64, "output is not EM_X86_64")
    _require(elf_type in (ET_EXEC, ET_DYN), "output is neither ET_EXEC nor ET_DYN")
    _require(header_size == 64 and phentsize == 56 and phnum > 0, "program header table is invalid")

    loads: list[tuple[int, int, int, int]] = []
    interpreters: list[str] = []
    dynamics: list[tuple[int, int]] = []
    tls: list[dict[str, int]] = []
    stacks: list[int] = []
    relro = 0
    writable_executable = 0
    for index in range(phnum):
        (kind, flags, offset, vaddr, _, filesz, memsz, align) = image.unpack(
            "<IIQQQQQQ", phoff + index * phentsize)
        if kind == PT_LOAD:
            _require(filesz <= memsz and offset + filesz <= len(data), "PT_LOAD exceeds the file")
            loads.append((offset, vaddr, filesz, flags))
            writable_executable += bool(flags & PF_W and flags & PF_X)
        elif kind == PT_INTERP:
            interpreters.append(image.string(offset, offset + filesz))
        elif kind == PT_DYNAMIC:
            dynamics.append((offset, filesz))
        elif kind == PT_TLS:
            tls.append({"filesz": filesz, "memsz": memsz, "align": align})
        elif kind == PT_GNU_STACK:
            stacks.append(flags)
        elif kind == PT_GNU_RELRO:
            relro += 1
    _require(len(dynamics) == 1, "output must have exactly one PT_DYNAMIC")
    _require(len(interpreters) <= 1 and len(tls) <= 1, "duplicate PT_INTERP or PT_TLS")

    tags: dict[int, list[int]] = {}
    dynamic_offset, dynamic_size = dynamics[0]
    for index in range(dynamic_size // 16):
        tag, value = image.unpack("<qQ", dynamic_offset + 16 * index)
        if tag == DT_NULL:
            break
        tags.setdefault(tag, []).append(value)
    else:
        raise InspectionError("dynamic section has no DT_NULL terminator")
    for singleton in (DT_STRTAB, DT_STRSZ, DT_SYMTAB, DT_FLAGS, DT_FLAGS_1, DT_SONAME,
                      DT_RUNPATH, DT_RPATH, DT_PLTREL, DT_HASH, DT_GNU_HASH):
        _require(len(tags.get(singleton, [])) <= 1, f"duplicate dynamic tag {singleton:#x}")
    _require(DT_STRTAB in tags and DT_STRSZ in tags and DT_SYMTAB in tags,
             "dynamic section lacks its string or symbol table")
    string_offset = _file_offset(loads, tags[DT_STRTAB][0], tags[DT_STRSZ][0])
    string_limit = string_offset + tags[DT_STRSZ][0]

    def name(value: int) -> str:
        return image.string(string_offset + value, string_limit)

    flags = tags.get(DT_FLAGS, [0])[0]
    flags_1 = tags.get(DT_FLAGS_1, [0])[0]
    _require(DT_REL not in tags and DT_RELSZ not in tags, "REL relocations are not the x86-64 ABI form")
    _require(tags.get(DT_PLTREL, [DT_RELA]) == [DT_RELA], "PLT relocations are not RELA")
    _require(tags.get(DT_SYMENT, [24]) == [24] and tags.get(DT_RELAENT, [24]) == [24],
             "dynamic entry sizes differ from ELF64")
    ordinary = _relocations(image, loads, tags, DT_RELA, DT_RELASZ)
    plt = _relocations(image, loads, tags, DT_JMPREL, DT_PLTRELSZ)
    _require(all(kind == "R_X86_64_JUMP_SLOT" for kind in plt), "PLT table has a non-JUMP_SLOT relocation")
    relr_entries = 0
    if DT_RELR in tags or DT_RELRSZ in tags:
        _require(tags.get(DT_RELRENT, [8]) == [8] and len(tags.get(DT_RELRSZ, [])) == 1,
                 "RELR table is not uniquely sized")
        relr_entries = tags[DT_RELRSZ][0] // 8
    counts: dict[str, int] = {}
    for kind in ordinary + plt:
        counts[kind] = counts.get(kind, 0) + 1

    symbol_offset = _file_offset(loads, tags[DT_SYMTAB][0], 24)
    undefined, weak_undefined, defined, ifunc = set(), set(), set(), set()
    for index in range(1, _symbol_count(image, loads, tags)):
        st_name, info, _, section, _, _ = image.unpack("<IBBHQQ", symbol_offset + 24 * index)
        symbol = name(st_name)
        binding, kind = info >> 4, info & 0xF
        if kind == STT_GNU_IFUNC:
            ifunc.add(symbol)
        if section == SHN_UNDEF:
            (weak_undefined if binding == STB_WEAK else undefined).add(symbol)
        else:
            defined.add(symbol)

    return {
        "schema": SCHEMA,
        "elf_type": "ET_EXEC" if elf_type == ET_EXEC else "ET_DYN",
        "machine": "EM_X86_64",
        "entry": entry,
        "interpreter": interpreters[0] if interpreters else None,
        "needed": [name(value) for value in tags.get(DT_NEEDED, [])],
        "soname": name(tags[DT_SONAME][0]) if DT_SONAME in tags else None,
        "runpath": name(tags[DT_RUNPATH][0]) if DT_RUNPATH in tags else None,
        "rpath": name(tags[DT_RPATH][0]) if DT_RPATH in tags else None,
        "textrel": DT_TEXTREL in tags or bool(flags & DF_TEXTREL),
        "bind_now": bool(flags & DF_BIND_NOW or DT_BIND_NOW in tags),
        "flags_1_now": bool(flags_1 & DF_1_NOW),
        "flags_1_pie": bool(flags_1 & DF_1_PIE),
        "static_tls": bool(flags & DF_STATIC_TLS),
        "hash_tables": sorted(label for tag, label in ((DT_HASH, "sysv"), (DT_GNU_HASH, "gnu")) if tag in tags),
        "symbol_versioning": any(tag in tags for tag in (DT_VERSYM, DT_VERDEF, DT_VERNEED)),
        "gnu_stack_flags": stacks,
        "relro_segments": relro,
        "writable_executable_loads": writable_executable,
        "load_segments": len(loads),
        "tls": tls[0] if tls else None,
        "relocations": dict(sorted(counts.items())),
        "relr_entries": relr_entries,
        "undefined_symbols": sorted(undefined),
        "weak_undefined_symbols": sorted(weak_undefined),
        "defined_symbol_count": len(defined),
        "ifunc_symbols": sorted(ifunc),
        **unwind_table_facts(path),
    }


def require_expected(facts: Mapping[str, Any], expected: Expectation) -> None:
    """Reject a final output whose physical facts differ from its link plan."""

    mode = MODES.get(expected.mode)
    _require(mode is not None, f"unknown dynamic mode {expected.mode!r}")
    _require(facts.get("schema") == SCHEMA, "inspection schema differs")
    _require(facts["elf_type"] == mode["elf_type"], f"{expected.mode} output is not {mode['elf_type']}")
    if mode["interpreter"]:
        _require(facts["interpreter"] == expected.interpreter,
                 f"executable interpreter is not the canonical {expected.interpreter}")
        _require(facts["entry"] != 0, "executable has no entry point")
    else:
        _require(facts["interpreter"] is None, "shared object has an interpreter")
    _require(facts["needed"] == list(expected.needed),
             f"DT_NEEDED differs from the declared inputs: {facts['needed']}")
    _require(facts["soname"] == expected.soname, "DT_SONAME differs from the declared output")
    declared = {"runpath": None, "rpath": None, expected.search_kind: expected.search_path}
    _require(set(declared) == {"runpath", "rpath"}, "unknown declared search kind")
    _require(facts["runpath"] == declared["runpath"] and facts["rpath"] == declared["rpath"],
             "runtime search path differs from the declared application search path")
    _require(not facts["textrel"], "output has text relocations")
    now = expected.binding == "now"
    _require(expected.binding in ("now", "lazy"), "unknown declared binding")
    _require(facts["bind_now"] is now and facts["flags_1_now"] is now,
             f"output binding differs from declared {expected.binding}")
    _require(facts["flags_1_pie"] is (expected.mode == "pie"), "DF_1_PIE differs from the declared mode")
    hash_tables = {"sysv": ["sysv"], "gnu": ["gnu"], "both": ["gnu", "sysv"]}.get(expected.hash_style)
    _require(facts["hash_tables"] == hash_tables, "hash tables differ from the declared hash style")
    _require(not facts["symbol_versioning"] and not facts["ifunc_symbols"],
             "symbol versioning and IFUNC are not admitted")
    _require(facts["gnu_stack_flags"] == [PF_R | PF_W], "output stack is not exactly one non-executable GNU_STACK")
    _require(facts["relro_segments"] == 1, "output lacks exactly one PT_GNU_RELRO")
    _require(facts["writable_executable_loads"] == 0, "output has a writable executable PT_LOAD")
    require_unwind_table_header(facts)
    if expected.mode == "shared":
        _require(not EXECUTABLE_ONLY_RELOCATIONS & set(facts["relocations"]),
                 "shared object has an executable-only COPY relocation")
    if expected.provided_symbols is not None:
        unresolved = set(facts["undefined_symbols"]) - expected.provided_symbols
        _require(unresolved == set(expected.runtime_imports),
                 f"unresolved dynamic imports differ from the declared contract: {sorted(unresolved)}")


def record(path: Path, facts: Mapping[str, Any], expected: Expectation, *, output_format: str,
           link_map: Path) -> dict[str, Any]:
    """Bind accepted facts to the output bytes, declaration and retained map."""

    def sha256(target: Path) -> str:
        digest = hashlib.sha256()
        with Path(target).open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    return {
        "schema": SCHEMA,
        "format": output_format,
        "output_path": str(Path(path).resolve()),
        "output_sha256": sha256(path),
        "declared": {
            "mode": expected.mode,
            "interpreter": expected.interpreter if MODES[expected.mode]["interpreter"] else None,
            "needed": list(expected.needed),
            "soname": expected.soname,
            "search": {"kind": expected.search_kind, "path": expected.search_path},
            "binding": expected.binding,
            "hash_style": expected.hash_style,
            "runtime_imports": sorted(expected.runtime_imports),
        },
        "facts": dict(facts),
        "link_map": {"path": str(Path(link_map).resolve()), "sha256": sha256(link_map)},
    }


def validate_record(value: Mapping[str, Any], path: Path, *, output_format: str,
                    fail: Callable[[str], None],
                    recorded_path: Callable[[Path], str] = lambda local: str(local.resolve())
                    ) -> Mapping[str, Any]:
    """Replay one retained sidecar against its physical output and link map.

    ``path`` is the retained output as seen by this reader; its map is the
    fixed sidecar beside it. ``recorded_path`` maps a local path to the
    spelling the producer recorded, such as a container source mount.
    """

    def check(condition: bool, message: str) -> None:
        if not condition:
            fail(message)
            raise AssertionError("inspection failure callback returned")

    check(type(value) is dict and set(value) == {"schema", "format", "output_path", "output_sha256",
                                                  "declared", "facts", "link_map"},
          "ELF inspection sidecar fields differ")
    check(value["schema"] == SCHEMA and value["format"] == output_format, "ELF inspection identity differs")
    try:
        facts = inspect(path)
    except (InspectionError, OSError) as error:
        check(False, f"retained output cannot be inspected: {error}")
    check(value["facts"] == facts, "ELF inspection sidecar differs from the retained output")
    declared = value["declared"]
    link_map = sidecar_paths(path)[1]
    try:
        expected = Expectation(
            mode=declared["mode"], interpreter=declared["interpreter"] or "",
            needed=tuple(declared["needed"]), soname=declared["soname"],
            search_kind=declared["search"]["kind"], search_path=declared["search"]["path"],
            binding=declared["binding"], hash_style=declared["hash_style"],
            runtime_imports=frozenset(declared["runtime_imports"]), provided_symbols=None,
        )
        require_expected(facts, expected)
        replay = record(path, facts, expected, output_format=output_format, link_map=link_map)
    except (InspectionError, KeyError, TypeError, OSError) as error:
        check(False, f"retained ELF inspection does not replay: {error}")
    replay["output_path"] = recorded_path(path)
    replay["link_map"]["path"] = recorded_path(link_map)
    check(replay == value, "ELF inspection sidecar differs from its replayed declaration, output or map")
    return facts


def sidecar_paths(output: Path) -> tuple[Path, Path]:
    """Return the fixed inspection and link-map sidecars beside one output."""

    return Path(str(output) + ".crabc-elf.json"), Path(str(output) + ".crabc-link.map")
