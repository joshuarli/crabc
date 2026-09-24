#!/usr/bin/env python3
"""Owned x86-64 dynamic CRT startup evidence through one installed product.

This is the executing gate for the `crt.dynamic-startup` family obligation:
installed dynamic-PIE `Scrt1.o` and dynamic non-PIE `crt1.o` entry, the
libc `__libc_start_main` handoff, main-image preinit/init/fini lifecycle and
process finalization, the compiler-helper archive, and the deterministic link
interface of the installed driver. A separate wide graph (43 initial images
with more than 32 initial TLS modules, more than twenty DT_NEEDED edges per
image and 24-entry init/fini arrays in the executable, a dependency and a
runtime plugin) checks that startup, TLS and finalization are not bounded by
a small fixed loader table. It consumes a
supplied materialized product and never builds, repairs, or substitutes a
runtime.

Pinned musl 1.2.6 is the behavior oracle. The same fixture sources are built
by the oracle compiler profile and executed as separate processes. The only
admitted transcript difference is the owned CRT's leading executable preinit
marker `P`: musl's dynamic linker never dispatches a main DT_PREINIT_ARRAY.

Run it in the pinned native image as
``python3 -B crt/x86_64_owned_dynamic_startup.py PRODUCT`` with TMPDIR below
this checkout's `.work`. Raw inputs, commands, streams and a `report.json`
stay in one fresh evidence directory named on the final line.
"""

from __future__ import annotations

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


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crt" / "fixtures"
MAIN_SOURCE = FIXTURES / "owned_dynamic_startup_main.c"
DEPENDENCY_SOURCE = FIXTURES / "owned_dynamic_startup_dependency.c"
PLUGIN_SOURCE = FIXTURES / "owned_dynamic_startup_plugin.c"
WIDE_SOURCE = FIXTURES / "owned_dynamic_startup_wide.c"
NAMES_SOURCE = FIXTURES / "owned_dynamic_startup_names.c"
DEPENDENCY = "libowned-startup-dependency.so"
PLUGIN = "libowned-startup-plugin.so"
SCHEMA = "crabc.x86_64-owned-crt-dynamic-startup/v1"

INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
ORACLE_COMPILER = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
ORACLE_INTERPRETER = Path("/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1")
CHROOT = "/usr/sbin/chroot"
TIMEOUT = "/usr/bin/timeout"
# Frame pointers make each callback's own frame alignment observable.
FIXTURE_FLAGS = ("-O1", "-fno-omit-frame-pointer")
ARGUMENTS = ("first", "second")

# Driver mode flag, installed entry object, and required ELF type per mode.
MODES = {
    "dynamic-pie": ("--dynamic-pie", "Scrt1.o", 3, ("-fPIE", "-pie")),
    "dynamic-non-pie": ("--dynamic-non-pie", "crt1.o", 2, ("-fno-pie", "-no-pie")),
}
ENTRIES = ("kernel", "direct")

# Executable unsigned/signed quotient and remainder, then the plugin quotient.
EXECUTABLE_HELPERS = (
    "0000000000000000123456789abcdefc;0000000000000000083fb72ea61d951c;"
    "ffffffffffffffffedcba98765432104;fffffffffffffffff7c048d159e26ae4;"
)
PLUGIN_HELPER = "0000000000000000123456789abcdefc;"
# Musl transcripts for each scenario; `M` stands for main plus its AT_ENTRY
# observation (see ENTRY_MARKERS). `m`/`f` are buffered stdio bytes and
# must follow every finalizer; `_Exit` discards them. Constructors after an
# exit never run, and an object whose construction did not complete is never
# finalized. A runtime object whose construction began after main's is
# finalized before main; one constructed during a dependency constructor is
# finalized after main but before that dependency.
SCENARIOS = {
    "ordinary": ("DAIMLalFZdmf", 7),
    "exit": ("DAIMLalFZdmf", 11),
    "immediate-exit": ("DAIM", 5),
    "helpers": ("DAIM" + EXECUTABLE_HELPERS + "L" + PLUGIN_HELPER + "alFZdmf", 7),
    "exit-in-main-constructor": ("DAad", 29),
    "exit-in-dependency-constructor": ("D", 23),
    "dlopen-in-main-constructor": ("DAILMalFZdmf", 7),
    "dlopen-in-dependency-constructor": ("DLAIMaFZldmf", 7),
}
OWNED_PREINIT = "P"

# The wide graph (see WIDE_SOURCE) has no admitted difference and no preinit.
# Its executable names the hub plus one group of leaves, the hub another group
# and the runtime plugin a third, so the initial graph holds 43 images.
WIDE_FANOUT = 20
WIDE_CALLBACKS = 24
WIDE_HUB = "libowned-startup-wide-hub.so"
WIDE_PLUGIN = "libowned-startup-wide-plugin.so"
WIDE_STATUS = 7
WIDE_VALUES = "|1420,2210,3630,1|"


# The names graph (see NAMES_SOURCE) has no admitted difference. Each arm lays
# out one tree below its own root; every path below has the same length in
# both arms, so the transcripts compare byte for byte.
NAMES_STATUS = 7
NAMES_SEARCH = "libowned-startup-name-search.so"
NAMES_LEAF = "libowned-startup-name-leaf.so"
NAMES_DEEP = "libowned-startup-name-deep.so"
# Musl composes search candidates in char[2*NAME_MAX+2].
NAMES_SEARCH_BUFFER = 512
# Case, the executable's path length and whether it reads the long preloads
# or the long library path.
NAMES_CASES = {"initial": 600, "dlopen": 3000, "search": 3000, "preload": 3000}


def names_path(root: str, group: str, total: int, filename: str) -> str:
    """`root/names/group/.../filename`, padded to exactly `total` bytes.

    Padding directories are at most 200 bytes, below NAME_MAX.
    """

    head = f"{root}/names/{group}"
    room = total - len(head) - 1 - len(filename)
    require(room >= 2, f"names path {group} cannot reach {total} bytes")
    segments = []
    while room > 0:
        size = min(200, room - 1)
        if room - (size + 1) == 1:
            size -= 1
        segments.append(group[0] * size)
        room -= size + 1
    path = "/".join([head, *segments, filename])
    require(len(path) == total, f"names path {group} has {len(path)} bytes, not {total}")
    return path


def names_layout(root: str) -> dict[str, str]:
    """Every name-bearing path of one arm below `root` (empty in the chroot)."""

    # An ordinary directory, padded like every other path.
    short = names_path(root, "short", 200, "x")[:-2]
    layout = {
        "a": names_path(root, "a", 600, "libowned-startup-name-a.so"),
        "b": names_path(root, "b", 3000, "libowned-startup-name-b.so"),
        "c": names_path(root, "c", 600, "libowned-startup-name-c.so"),
        "d": names_path(root, "d", 3000, "libowned-startup-name-d.so"),
        "e": names_path(root, "e", 3000, "libowned-startup-name-e.so"),
        "f": names_path(root, "f", 3000, "libowned-startup-name-f.so"),
        "leaf": f"{short}/{NAMES_LEAF}",
        "deep": f"{short}/{NAMES_DEEP}",
        # Two 3000-byte directories and one whose candidate is exactly the
        # buffer size are skipped; the 511-byte candidate fits and is opened.
        "search-long-1": names_path(root, "long", 3000, NAMES_SEARCH),
        "search-long-2": names_path(root, "longer", 3000, NAMES_SEARCH),
        "search-skipped": names_path(root, "skipped", NAMES_SEARCH_BUFFER, NAMES_SEARCH),
        "search": names_path(root, "fits", NAMES_SEARCH_BUFFER - 1, NAMES_SEARCH),
        # Two $ORIGIN expansions of a ~3000-byte directory exceed any fixed
        # path buffer and each candidate exceeds musl's; the last component
        # is an ordinary directory.
        "runpath": f"$ORIGIN:${{ORIGIN}}:{short}",
    }
    for mode in MODES:
        for length in sorted(set(NAMES_CASES.values())):
            layout[f"program-{mode}-{length}"] = names_path(root, f"program{length}", length, f"main-names-{mode}")
    return layout


def names_environment(layout: dict[str, str], mode: str, case: str) -> dict[str, str]:
    environment = {"NAMES_CASE": case, "NAMES_PROGRAM": layout[f"program-{mode}-{NAMES_CASES[case]}"],
                   "NAMES_A": layout["a"], "NAMES_B": layout["b"], "NAMES_LEAF": layout["leaf"]}
    if case == "dlopen":
        environment.update(NAMES_C=layout["c"], NAMES_D=layout["d"], NAMES_DEEP=layout["deep"])
    elif case == "search":
        directories = [layout[key].rpartition("/")[0]
                       for key in ("search-long-1", "search-long-2", "search-skipped", "search")]
        environment.update(LD_LIBRARY_PATH=":".join(directories), NAMES_SEARCH=layout["search"])
    elif case == "preload":
        environment.update(LD_PRELOAD=f"{layout['e']}:{layout['f']}", NAMES_E=layout["e"], NAMES_F=layout["f"])
    return environment


def wide_leaf(group: str, index: int) -> str:
    return f"libowned-startup-wide-{group}{index}.so"


def wide_markers() -> list[str]:
    """Every two-byte callback marker the wide graph must emit exactly once."""

    markers = [group + chr(ord(case) + index)
               for group in "wdp" for index in range(1, WIDE_FANOUT + 1) for case in "Aa"]
    markers += [role + chr(ord(case) + index)
                for role in "HQM" for index in range(WIDE_CALLBACKS) for case in "Aa"]
    return markers
# After kernel entry, AT_ENTRY must name the executable's own `_start`. A
# direct interpreter command's auxv rewrite is loader policy, not CRT
# behavior: pinned musl leaves the kernel vector untouched while the owned
# interpreter rewrites it, so that observation is not requested there.
ENTRY_MARKERS = {"kernel": "Me", "direct": "M"}

# The one compiler-helper archive member supplies every two-word helper the
# fixtures use; libc.so keeps its private copy local.
HELPER_SYMBOLS = ("__udivti3", "__umodti3", "__divti3", "__modti3")
OWNED_CRT_NOTE = struct.pack("<III", 6, 4, 0x43525401) + b"CRABC\0\0\0" + struct.pack("<I", 1)

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
PF_X = 1
DT_NEEDED, DT_INIT, DT_FINI, DT_SONAME, DT_TEXTREL = 1, 12, 13, 14, 22
DT_INIT_ARRAY, DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ = 25, 26, 27, 28
DT_FLAGS, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_FLAGS_1 = 30, 32, 33, 0x6FFFFFFB
DT_STRTAB = 5
DF_BIND_NOW, DF_TEXTREL, DF_1_NOW = 0x8, 0x4, 0x1
SHT_SYMTAB, SHT_DYNSYM = 2, 11
STT_FUNC = 2


class EvidenceError(RuntimeError):
    """The installed product violated the dynamic CRT startup contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


@dataclass(frozen=True)
class Symbol:
    name: str
    binding: int
    symbol_type: int
    section: int
    value: int


@dataclass(frozen=True)
class ElfImage:
    """The loader-visible and link-visible facts this gate inspects."""

    elf_type: int
    machine: int
    entry: int
    segments: tuple[tuple[int, int, int, int, int, int], ...]
    dynamic: tuple[tuple[int, int], ...]
    needed: tuple[str, ...]
    soname: str | None
    interpreter: bytes | None
    notes: tuple[bytes, ...]
    symtab: tuple[Symbol, ...]
    dynsym: tuple[Symbol, ...]

    def tags(self, tag: int) -> list[int]:
        return [value for key, value in self.dynamic if key == tag]


def _string(data: bytes, offset: int) -> str:
    end = data.index(b"\0", offset)
    return data[offset:end].decode()


def _offset_for_address(segments, address: int) -> int:
    for kind, _flags, offset, vaddr, filesz, _memsz in segments:
        if kind == PT_LOAD and vaddr <= address < vaddr + filesz:
            return offset + address - vaddr
    raise EvidenceError(f"virtual address {address:#x} is outside every file-backed load")


def parse_elf(path: Path) -> ElfImage:
    """Parse one final little-endian ELF64 image without external tools."""

    data = path.read_bytes()
    require(data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1, f"{path.name}: not ELF64 LSB")
    (elf_type, machine, _version, entry, phoff, shoff, _flags, _ehsize,
     phentsize, phnum, shentsize, shnum, _shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    require(phentsize == 56 and shentsize == 64, f"{path.name}: unexpected ELF header entry sizes")
    segments = []
    for index in range(phnum):
        kind, flags, offset, vaddr, _paddr, filesz, memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * 56)
        segments.append((kind, flags, offset, vaddr, filesz, memsz))
    interpreters = [data[offset:offset + size] for kind, _f, offset, _v, size, _m in segments if kind == PT_INTERP]
    require(len(interpreters) <= 1, f"{path.name}: more than one PT_INTERP")
    notes = tuple(data[offset:offset + size] for kind, _f, offset, _v, size, _m in segments if kind == PT_NOTE)
    dynamics = [(offset, size) for kind, _f, offset, _v, size, _m in segments if kind == PT_DYNAMIC]
    require(len(dynamics) == 1, f"{path.name}: expected exactly one PT_DYNAMIC")
    dynamic = []
    offset, size = dynamics[0]
    for cursor in range(offset, offset + size, 16):
        tag, value = struct.unpack_from("<qQ", data, cursor)
        if tag == 0:
            break
        dynamic.append((tag, value))
    strtabs = [value for tag, value in dynamic if tag == DT_STRTAB]
    require(len(strtabs) == 1, f"{path.name}: expected one DT_STRTAB")
    strings = _offset_for_address(segments, strtabs[0])
    needed = tuple(_string(data, strings + value) for tag, value in dynamic if tag == DT_NEEDED)
    sonames = [_string(data, strings + value) for tag, value in dynamic if tag == DT_SONAME]
    require(len(sonames) <= 1, f"{path.name}: more than one DT_SONAME")

    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * 64) for index in range(shnum)]

    def symbols(section_type: int) -> tuple[Symbol, ...]:
        result = []
        for _name, kind, _flags, _addr, offset, size, link, _info, _align, entsize in sections:
            if kind != section_type:
                continue
            string_offset = sections[link][4]
            for cursor in range(offset, offset + size, entsize):
                name, info, _other, shndx, value, _size = struct.unpack_from("<IBBHQQ", data, cursor)
                result.append(Symbol(_string(data, string_offset + name), info >> 4, info & 15, shndx, value))
        return tuple(result)

    return ElfImage(elf_type, machine, entry, tuple(segments), tuple(dynamic), needed,
                    sonames[0] if sonames else None, interpreters[0] if interpreters else None,
                    notes, symbols(SHT_SYMTAB), symbols(SHT_DYNSYM))


def require_hardened_dynamic_image(path: Path, image: ElfImage) -> None:
    """Every installed-driver output keeps RELRO, NOW, no TEXTREL and a NX stack."""

    require(image.machine == 62, f"{path.name}: not EM_X86_64")
    stacks = [flags for kind, flags, *_rest in image.segments if kind == PT_GNU_STACK]
    require(len(stacks) == 1 and stacks[0] & PF_X == 0, f"{path.name}: executable or missing GNU stack")
    require(any(kind == PT_GNU_RELRO for kind, *_rest in image.segments), f"{path.name}: missing GNU RELRO")
    require(not image.tags(DT_TEXTREL) and not any(value & DF_TEXTREL for value in image.tags(DT_FLAGS)),
            f"{path.name}: text relocation")
    require(any(value & DF_BIND_NOW for value in image.tags(DT_FLAGS))
            or any(value & DF_1_NOW for value in image.tags(DT_FLAGS_1)),
            f"{path.name}: installed default binding is not NOW")


def require_owned_helpers(path: Path, image: ElfImage) -> None:
    """Compiler helpers are ordinary archive definitions, never runtime imports."""

    for name in HELPER_SYMBOLS:
        defined = [item for item in image.symtab if item.name == name and item.section != 0]
        require(len(defined) == 1 and defined[0].symbol_type == STT_FUNC,
                f"{path.name}: {name} is not defined once from the helper archive")
        require(not any(item.name == name and item.section == 0 for item in image.dynsym),
                f"{path.name}: {name} remains a dynamic import")


def check_executable(path: Path, mode: str) -> dict[str, object]:
    _flag, entry_object, elf_type, _oracle = MODES[mode]
    image = parse_elf(path)
    require(image.elf_type == elf_type, f"{path.name}: {mode} has ELF type {image.elf_type}")
    require(image.interpreter == INTERPRETER.encode() + b"\0", f"{path.name}: PT_INTERP is not the owned interpreter")
    require(image.needed == (DEPENDENCY, "libc.so"), f"{path.name}: DT_NEEDED differs: {image.needed}")
    for tag in (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_INIT, DT_FINI, DT_INIT_ARRAY,
                DT_INIT_ARRAYSZ, DT_FINI_ARRAY, DT_FINI_ARRAYSZ):
        values = image.tags(tag)
        require(len(values) == 1 and values[0] != 0, f"{path.name}: lifecycle tag {tag} is absent or empty")
    starts = [item for item in image.symtab if item.name == "_start" and item.section != 0]
    require(len(starts) == 1 and starts[0].binding == 1 and starts[0].symbol_type == STT_FUNC,
            f"{path.name}: expected one global installed-CRT _start")
    require(image.entry == starts[0].value, f"{path.name}: ELF entry is not the installed CRT _start")
    for name in ("_init", "_fini", "__crabc_x86_64_dynamic_start"):
        require(sum(item.name == name and item.section != 0 for item in image.symtab) == 1,
                f"{path.name}: {name} is not defined once by the installed CRT")
    require(any(OWNED_CRT_NOTE in note for note in image.notes), f"{path.name}: owned CRT note is not in a PT_NOTE")
    require_hardened_dynamic_image(path, image)
    require_owned_helpers(path, image)
    return {"entry_object": entry_object, "elf_type": elf_type, "needed": list(image.needed)}


def check_shared_object(path: Path, name: str, helpers: bool) -> list[str]:
    """Check an application DSO and return the helper names it exports.

    The export list is an observed open condition, not an accepted contract:
    musl's libgcc.a helpers are hidden, while the owned archive's are
    GLOBAL DEFAULT and therefore leave the extracting DSO's dynsym.
    """

    image = parse_elf(path)
    require(image.elf_type == 3 and image.interpreter is None, f"{path.name}: not an interpreter-free ET_DYN")
    require(image.soname == name and image.needed == ("libc.so",), f"{path.name}: SONAME/DT_NEEDED differs")
    require_hardened_dynamic_image(path, image)
    if helpers:
        require_owned_helpers(path, image)
    return sorted(item.name for item in image.dynsym
                  if item.section != 0 and item.name.startswith("__") and item.symbol_type == STT_FUNC
                  and item.name.endswith(("ti2", "ti3", "ti4", "di2", "si2", "dc3")))


def check_link_receipt(product: Path, output: Path, mode: str, objects: list[Path],
                       dsos: list[Path]) -> dict[str, object]:
    """Require the installed driver's exact deterministic link interface."""

    receipt = json.loads(Path(str(output) + ".crabc-link.json").read_text())
    library = product / "usr/lib"
    archive = library / "libcrabc-builtins.a"
    if mode == "dynamic-shared-object":
        runtime = ["crti.o", "libc.so", "crtn.o", "libcrabc-builtins.a"]
        ordered = [library / "crti.o", *objects, *dsos, library / "libc.so", archive, library / "crtn.o"]
    else:
        entry = MODES[mode][1]
        runtime = [entry, "crabc-dynamic-attach.o", "crti.o", "libc.so", "crtn.o", "libcrabc-builtins.a"]
        ordered = [library / entry, library / "crabc-dynamic-attach.o", library / "crti.o", *objects,
                   *dsos, library / "libc.so", archive, library / "crtn.o"]
    require(receipt.get("output_sha256") == sha256(output), f"{output.name}: receipt does not bind the output")
    require(receipt.get("owned_runtime_inputs") == sorted(f"usr/lib/{name}" for name in runtime),
            f"{output.name}: owned runtime input roster differs")
    command = receipt.get("link_command")
    require(isinstance(command, list) and command[-2:] == ["-o", str(output)], f"{output.name}: link command shape")
    positional = [item for item in command if item.startswith("/") and Path(item) in set(ordered)]
    require(positional == [str(path) for path in ordered], f"{output.name}: link input order differs: {positional}")
    if mode != "dynamic-shared-object":
        require(command[command.index("--dynamic-linker") + 1] == INTERPRETER, f"{output.name}: dynamic linker")
    # LLD's trace names the extracted helper member at the archive's position;
    # any other input, or a missing extraction, changes this exact sequence.
    trace = receipt.get("link_trace")
    member = f"{archive}(crabc-builtins.o)"
    expected_trace = [member if path == archive else str(path) for path in ordered]
    require(trace == expected_trace, f"{output.name}: link trace differs: {trace}")
    return {"runtime_inputs": receipt["owned_runtime_inputs"], "link_command": command, "link_trace": trace}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Recorder:
    """Run commands with retained argv and streams under one evidence root."""

    def __init__(self, work: Path) -> None:
        self.work = work
        self.raw = work / "raw"
        self.raw.mkdir()
        self.count = 0

    def run(self, label: str, command: list[str], *, environment: dict[str, str] | None = None,
            expect_success: bool = True) -> subprocess.CompletedProcess[bytes]:
        self.count += 1
        stem = self.raw / f"{self.count:03d}-{label}"
        stem.with_suffix(".argv.json").write_text(json.dumps(command, indent=1) + "\n")
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, check=False)
        stem.with_suffix(".stdout").write_bytes(completed.stdout)
        stem.with_suffix(".stderr").write_bytes(completed.stderr)
        stem.with_suffix(".status").write_text(f"{completed.returncode}\n")
        if expect_success and completed.returncode != 0:
            raise EvidenceError(f"{label} failed ({completed.returncode}): "
                                f"{completed.stderr.decode(errors='replace')[-2000:]}")
        return completed


def evidence_root() -> Path:
    temporary = Path(os.environ.get("TMPDIR", ""))
    require(temporary.is_absolute() and temporary.is_dir() and temporary.resolve() == temporary
            and temporary.is_relative_to(ROOT / ".work"),
            "TMPDIR must be a physical directory below this checkout's .work")
    work = Path(tempfile.mkdtemp(prefix="owned-crt-dynamic-startup.", dir=temporary))
    # Retained evidence is host-inspectable; runtime modes are unaffected.
    work.chmod(0o755)
    return work


def build(recorder: Recorder, product: Path, work: Path) -> dict[str, object]:
    driver = str(product / "bin/crabc-cc-dynamic")
    oracle = work / "oracle"
    oracle.mkdir()
    candidate = work / "candidate"
    candidate.mkdir()
    dependency = candidate / DEPENDENCY
    plugin = candidate / PLUGIN
    report: dict[str, object] = {"shared_objects": {}, "executables": {}}
    for source, target, helpers in ((DEPENDENCY_SOURCE, dependency, False), (PLUGIN_SOURCE, plugin, True)):
        obj = target.with_suffix(".o")
        recorder.run(f"compile-{target.name}", [driver, "--dynamic-shared-object", "-c", *FIXTURE_FLAGS,
                                                str(source), "-o", str(obj)])
        recorder.run(f"link-{target.name}", [driver, "--dynamic-shared-object", str(obj), "-o", str(target)])
        exported = check_shared_object(target, target.name, helpers)
        if helpers:
            report["shared_objects"][target.name] = check_link_receipt(
                product, target, "dynamic-shared-object", [obj], [])
            report["open_conditions"] = {"application_dso_exported_helpers": exported}
        recorder.run(f"oracle-{target.name}", [str(ORACLE_COMPILER), "-fPIC", "-shared", *FIXTURE_FLAGS,
                                               "-fstack-protector-strong", str(source),
                                               f"-Wl,-soname,{target.name}", "-o", str(oracle / target.name)])
    for mode, (flag, _entry, _type, oracle_flags) in MODES.items():
        # A caller-owned object keeps the complete link command replayable
        # for the helper-archive control below.
        obj = candidate / f"main-{mode}.o"
        recorder.run(f"compile-{mode}", [driver, flag, "-c", *FIXTURE_FLAGS, str(MAIN_SOURCE), "-o", str(obj)])
        outputs = []
        for copy in ("", "-repeat"):
            output = candidate / f"main-{mode}{copy}"
            recorder.run(f"link-{mode}{copy}", [driver, flag, str(obj), "--application-dso", str(dependency),
                                                "-o", str(output)])
            outputs.append(output)
        require(outputs[0].read_bytes() == outputs[1].read_bytes(),
                f"{mode}: two links of one object through the installed driver differ")
        facts = check_executable(outputs[0], mode)
        facts["link"] = check_link_receipt(product, outputs[0], mode, [obj], [dependency])
        facts["reproducible_link_sha256"] = sha256(outputs[0])
        # Removing only the owned helper archive must leave the executable's
        # own two-word helper references unresolved; no other input may supply them.
        command = [item for item in facts["link"]["link_command"]
                   if item != str(product / "usr/lib/libcrabc-builtins.a")]
        command[-1] = str(candidate / f"main-{mode}-without-helpers")
        missing = recorder.run(f"link-{mode}-without-helpers", command, expect_success=False)
        diagnostic = missing.stderr.decode(errors="replace")
        require(missing.returncode != 0 and "__udivti3" in diagnostic,
                f"{mode}: link without libcrabc-builtins.a did not fail on __udivti3")
        facts["without_helper_archive"] = {"status": missing.returncode}
        report["executables"][mode] = facts
        recorder.run(f"oracle-{mode}", [str(ORACLE_COMPILER), *oracle_flags, *FIXTURE_FLAGS,
                                        "-fstack-protector-strong", str(MAIN_SOURCE),
                                        str(oracle / DEPENDENCY), f"-Wl,-rpath,{oracle}",
                                        "-o", str(oracle / f"main-{mode}")])
    return report


def build_wide(recorder: Recorder, product: Path, work: Path) -> dict[str, object]:
    """Build the wide graph through the installed driver and pinned musl."""

    driver = str(product / "bin/crabc-cc-dynamic")
    candidate = work / "candidate" / "wide"
    oracle = work / "oracle" / "wide"
    candidate.mkdir()
    oracle.mkdir()

    def shared(name: str, defines: list[str], dependencies: list[str]) -> None:
        obj = candidate / f"{name}.o"
        recorder.run(f"compile-{name}", [driver, "--dynamic-shared-object", "-c", *FIXTURE_FLAGS, *defines,
                                         str(WIDE_SOURCE), "-o", str(obj)])
        declared = [item for dependency in dependencies for item in ("--application-dso", str(candidate / dependency))]
        recorder.run(f"link-{name}", [driver, "--dynamic-shared-object", str(obj), *declared,
                                      "-o", str(candidate / name)])
        recorder.run(f"oracle-{name}", [str(ORACLE_COMPILER), "-fPIC", "-shared", *FIXTURE_FLAGS, *defines,
                                        str(WIDE_SOURCE), f"-Wl,-soname,{name}", f"-Wl,-rpath,{oracle}",
                                        "-Wl,--no-as-needed", *(str(oracle / item) for item in dependencies),
                                        "-o", str(oracle / name)])

    groups = {group: [wide_leaf(group, index) for index in range(1, WIDE_FANOUT + 1)] for group in "wdp"}
    for group, names in groups.items():
        for index, name in enumerate(names, 1):
            shared(name, ["-DWIDE_LEAF", f"-DWIDE_GROUP={group}", f"-DWIDE_ID={index}"], [])
    shared(WIDE_HUB, ["-DWIDE_HUB"], groups["d"])
    shared(WIDE_PLUGIN, ["-DWIDE_PLUGIN"], groups["p"])
    direct = [WIDE_HUB, *groups["w"]]
    report: dict[str, object] = {}
    for mode, (flag, _entry, elf_type, oracle_flags) in MODES.items():
        output = candidate / f"main-wide-{mode}"
        transitive = [item for name in groups["d"] for item in ("--transitive-application-dso", str(candidate / name))]
        recorder.run(f"link-wide-{mode}", [driver, flag, *FIXTURE_FLAGS, str(WIDE_SOURCE),
                                           *(item for name in direct for item in ("--application-dso", str(candidate / name))),
                                           *transitive, "-o", str(output)])
        image = parse_elf(output)
        require(image.elf_type == elf_type and image.needed == (*direct, "libc.so"),
                f"{output.name}: wide DT_NEEDED differs: {image.needed}")
        require(len(image.tags(DT_INIT_ARRAYSZ)) == 1 and image.tags(DT_INIT_ARRAYSZ)[0] >= 8 * WIDE_CALLBACKS
                and len(image.tags(DT_FINI_ARRAYSZ)) == 1 and image.tags(DT_FINI_ARRAYSZ)[0] >= 8 * WIDE_CALLBACKS,
                f"{output.name}: wide callback arrays are smaller than {WIDE_CALLBACKS} entries")
        report[mode] = {"needed": list(image.needed), "init_array_bytes": image.tags(DT_INIT_ARRAYSZ)[0],
                        "fini_array_bytes": image.tags(DT_FINI_ARRAYSZ)[0]}
        recorder.run(f"oracle-wide-{mode}", [str(ORACLE_COMPILER), *oracle_flags, *FIXTURE_FLAGS,
                                             "-fstack-protector-strong", str(WIDE_SOURCE), f"-Wl,-rpath,{oracle}",
                                             "-Wl,--no-as-needed", *(str(oracle / name) for name in direct),
                                             "-o", str(oracle / f"main-wide-{mode}")])
    report["shared_objects"] = sorted(path.name for path in candidate.glob("*.so"))
    return report


def execute_wide(recorder: Recorder, root: Path, work: Path) -> list[dict[str, object]]:
    """Compare the complete wide transcript and status with pinned musl."""

    candidate = work / "candidate" / "wide"
    oracle = work / "oracle" / "wide"
    for path in candidate.glob("*.so"):
        shutil.copy2(path, root / "usr/lib" / path.name)
    markers = wide_markers()
    cells = []
    for mode in MODES:
        shutil.copy2(candidate / f"main-wide-{mode}", root / f"main-wide-{mode}")
        for entry in ENTRIES:
            prefix = [INTERPRETER] if entry == "direct" else []
            observed = recorder.run(f"candidate-wide-{mode}-{entry}",
                                    [TIMEOUT, "20", CHROOT, str(root), *prefix, f"/main-wide-{mode}"],
                                    environment={}, expect_success=False)
            oracle_prefix = [str(ORACLE_INTERPRETER)] if entry == "direct" else []
            reference = recorder.run(f"oracle-wide-{mode}-{entry}",
                                     [TIMEOUT, "20", *oracle_prefix, str(oracle / f"main-wide-{mode}")],
                                     environment={}, expect_success=False)
            label = f"wide/{mode}/{entry}"
            transcript = observed.stdout.decode(errors="replace")
            oracle_transcript = reference.stdout.decode(errors="replace")
            before, separator, after = oracle_transcript.partition(WIDE_VALUES)
            pairs = [(before + after)[index:index + 2] for index in range(0, len(before + after), 2)]
            require(reference.returncode == WIDE_STATUS and separator and reference.stderr == b""
                    and sorted(pairs) == sorted(markers),
                    f"{label}: pinned musl oracle observed {oracle_transcript!r} status {reference.returncode}")
            require(observed.returncode == WIDE_STATUS and transcript == oracle_transcript and observed.stderr == b"",
                    f"{label}: owned {transcript!r} status {observed.returncode} "
                    f"{observed.stderr.decode(errors='replace')!r}; musl {oracle_transcript!r}")
            cells.append({"mode": mode, "entry": entry, "scenario": "wide-graph", "status": WIDE_STATUS,
                          "candidate": transcript, "oracle": oracle_transcript})
    return cells


# Image roster of the names graph: role defines, the exported identifier and
# its value, the bare-named dependency, and whether the SONAME is the image's
# own absolute path (so the executable records a pathname DT_NEEDED).
# Dependencies precede their dependents.
NAMES_IMAGES = {
    "leaf": ("leaf", "names_leaf_value", 3, None, False),
    "deep": ("leaf", "names_deep_value", 4, None, False),
    "a": ("leaf", "names_a_value", 1, None, True),
    "b": ("origin", "names_b_value", 200, "leaf", True),
    "c": ("leaf", "names_c_value", 5, None, False),
    "d": ("origin", "names_d_value", 400, "deep", False),
    "e": ("leaf", "names_e_value", 6, None, False),
    "f": ("leaf", "names_f_value", 7, None, False),
    "search-long-1": ("leaf", "names_search_value", 8, None, False),
    "search-long-2": ("leaf", "names_search_value", 8, None, False),
    "search-skipped": ("leaf", "names_search_value", 8, None, False),
    "search": ("leaf", "names_search_value", 9, None, False),
}
DEPENDENCY_SYMBOL = {"leaf": "names_leaf_value", "deep": "names_deep_value"}


def names_defines(key: str) -> list[str]:
    role, symbol, value, dependency, _pathname = NAMES_IMAGES[key]
    defines = [f"-DNAMES_SYMBOL={symbol}", f"-DNAMES_ID={value}"]
    if role == "leaf":
        return ["-DNAMES_LEAF", *defines]
    return ["-DNAMES_ORIGIN", *defines, f"-DNAMES_LEAF_SYMBOL={DEPENDENCY_SYMBOL[dependency]}"]


def replay_link(recorder: Recorder, label: str, linked: Path, output: Path, *, soname: str | None = None,
                runpath: str | None = None, inputs: dict[Path, Path] | None = None) -> None:
    """Relink through the installed driver's recorded LLD command.

    The installed driver deliberately refuses pathname SONAMEs, pathname
    DT_NEEDED entries and `$ORIGIN` search paths in application images. Only
    those name-bearing arguments of its exact recorded command change here.
    """

    command = json.loads(Path(str(linked) + ".crabc-link.json").read_text())["link_command"]
    require(command[-2:] == ["-o", str(linked)], f"{label}: recorded link command shape")
    command = [str(inputs.get(Path(item), item)) if inputs else item for item in command[:-1]] + [str(output)]
    for flag, value in (("-soname", soname), ("-rpath", runpath)):
        if value is not None:
            require(command.count(flag) == 1, f"{label}: recorded link command has no single {flag}")
            command[command.index(flag) + 1] = value
    output.parent.mkdir(parents=True, exist_ok=True)
    recorder.run(label, command)


def build_names(recorder: Recorder, product: Path, work: Path) -> dict[str, object]:
    """Build the names graph through the installed driver and pinned musl."""

    driver = str(product / "bin/crabc-cc-dynamic")
    candidate = work / "candidate" / "names"
    oracle_root = work / "oracle" / "names-root"
    candidate_layout = names_layout("")
    oracle_layout = names_layout(str(oracle_root))
    normal: dict[str, Path] = {}
    final: dict[str, Path] = {}
    for key, (_role, _symbol, _value, dependency, pathname) in NAMES_IMAGES.items():
        defines = names_defines(key)
        basename = candidate_layout[key].rpartition("/")[2]
        directory = candidate / key
        directory.mkdir(parents=True)
        obj = directory / f"{basename}.o"
        recorder.run(f"compile-names-{key}", [driver, "--dynamic-shared-object", "-c", *FIXTURE_FLAGS, *defines,
                                              str(NAMES_SOURCE), "-o", str(obj)])
        declared = ["--application-dso", str(normal[dependency])] if dependency else []
        normal[key] = directory / basename
        recorder.run(f"link-names-{key}", [driver, "--dynamic-shared-object", str(obj), *declared,
                                           "-o", str(normal[key])])
        final[key] = normal[key]
        if pathname or dependency:
            final[key] = directory / "final" / basename
            replay_link(recorder, f"relink-names-{key}", normal[key], final[key],
                        soname=candidate_layout[key] if pathname else None,
                        runpath=candidate_layout["runpath"] if dependency else None)
        oracle_output = Path(oracle_layout[key])
        oracle_output.parent.mkdir(parents=True, exist_ok=True)
        soname = oracle_layout[key] if pathname else basename
        search = ["-Wl,--enable-new-dtags", f"-Wl,-rpath,{oracle_layout['runpath']}", "-Wl,--no-as-needed",
                  oracle_layout[dependency]] if dependency else []
        recorder.run(f"oracle-names-{key}", [str(ORACLE_COMPILER), "-fPIC", "-shared", *FIXTURE_FLAGS, *defines,
                                             str(NAMES_SOURCE), f"-Wl,-soname,{soname}", *search,
                                             "-o", str(oracle_output)])
    report: dict[str, object] = {}
    for mode, (flag, _entry, elf_type, oracle_flags) in MODES.items():
        obj = candidate / f"main-names-{mode}.o"
        recorder.run(f"compile-names-{mode}", [driver, flag, "-c", *FIXTURE_FLAGS, str(NAMES_SOURCE), "-o", str(obj)])
        linked = candidate / f"main-names-{mode}"
        recorder.run(f"link-names-{mode}", [driver, flag, str(obj), "--application-dso", str(normal["a"]),
                                            "--application-dso", str(normal["b"]),
                                            "--transitive-application-dso", str(normal["leaf"]), "-o", str(linked)])
        output = candidate / "final" / f"main-names-{mode}"
        replay_link(recorder, f"relink-names-{mode}", linked, output,
                    inputs={normal["a"]: final["a"], normal["b"]: final["b"]})
        image = parse_elf(output)
        expected = (candidate_layout["a"], candidate_layout["b"], "libc.so")
        require(image.elf_type == elf_type and image.needed == expected,
                f"{output.name}: names DT_NEEDED differs: {[len(name) for name in image.needed]}")
        report[mode] = {"needed_lengths": [len(name) for name in image.needed]}
        for length in sorted(set(NAMES_CASES.values())):
            program = Path(oracle_layout[f"program-{mode}-{length}"])
            program.parent.mkdir(parents=True, exist_ok=True)
            recorder.run(f"oracle-names-{mode}-{length}",
                         [str(ORACLE_COMPILER), *oracle_flags, *FIXTURE_FLAGS, "-fstack-protector-strong",
                          str(NAMES_SOURCE), "-Wl,--no-as-needed", oracle_layout["a"], oracle_layout["b"],
                          "-o", str(program)])
    report["images"] = {key: str(path.relative_to(candidate)) for key, path in final.items()}
    return report


def execute_names(recorder: Recorder, root: Path, work: Path) -> list[dict[str, object]]:
    """Compare every names case's transcript and status with pinned musl."""

    candidate = work / "candidate" / "names"
    candidate_layout = names_layout("")
    oracle_layout = names_layout(str(work / "oracle" / "names-root"))
    for key in NAMES_IMAGES:
        built = candidate / key / "final" if (candidate / key / "final").is_dir() else candidate / key
        target = root / candidate_layout[key].lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built / target.name, target)
    for mode in MODES:
        for length in sorted(set(NAMES_CASES.values())):
            target = root / candidate_layout[f"program-{mode}-{length}"].lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(candidate / "final" / f"main-names-{mode}", target)
    cells = []
    for mode in MODES:
        for entry in ENTRIES:
            for case in NAMES_CASES:
                environment = names_environment(candidate_layout, mode, case)
                prefix = [INTERPRETER] if entry == "direct" else []
                observed = recorder.run(f"candidate-names-{mode}-{entry}-{case}",
                                        [TIMEOUT, "20", CHROOT, str(root), *prefix, environment["NAMES_PROGRAM"]],
                                        environment=environment, expect_success=False)
                oracle_environment = names_environment(oracle_layout, mode, case)
                oracle_prefix = [str(ORACLE_INTERPRETER)] if entry == "direct" else []
                reference = recorder.run(f"oracle-names-{mode}-{entry}-{case}",
                                         [TIMEOUT, "20", *oracle_prefix, oracle_environment["NAMES_PROGRAM"]],
                                         environment=oracle_environment, expect_success=False)
                label = f"names/{mode}/{entry}/{case}"
                transcript = observed.stdout.decode(errors="replace")
                oracle_transcript = reference.stdout.decode(errors="replace")
                # Every stored name the oracle reports must match all three views.
                reports = [item.rpartition(":")[2] for item in oracle_transcript.split(";") if item.count(":") == 2]
                require(reference.returncode == NAMES_STATUS and reference.stderr == b"" and reports
                        and all(item == "111" for item in reports) and "dlopen-failed" not in oracle_transcript,
                        f"{label}: pinned musl oracle observed {oracle_transcript!r} status {reference.returncode} "
                        f"{reference.stderr.decode(errors='replace')!r}")
                require(observed.returncode == NAMES_STATUS and transcript == oracle_transcript
                        and observed.stderr == b"",
                        f"{label}: owned {transcript!r} status {observed.returncode} "
                        f"{observed.stderr.decode(errors='replace')!r}; musl {oracle_transcript!r}")
                cells.append({"mode": mode, "entry": entry, "scenario": f"names-{case}", "status": NAMES_STATUS,
                              "candidate": transcript, "oracle": oracle_transcript})
    return cells


def execute(recorder: Recorder, product: Path, work: Path) -> list[dict[str, object]]:
    root = work / "execution-root"
    shutil.copytree(product, root, symlinks=True)
    candidate = work / "candidate"
    for name in (DEPENDENCY, PLUGIN):
        shutil.copy2(candidate / name, root / "usr/lib" / name)
    for mode in MODES:
        shutil.copy2(candidate / f"main-{mode}", root / f"main-{mode}")
    oracle = work / "oracle"
    cells = []
    for mode in MODES:
        for entry in ENTRIES:
            for scenario, (template, status) in SCENARIOS.items():
                expected = template.replace("M", ENTRY_MARKERS[entry], 1)
                environment = {"CRABC_CRT_CASE": scenario}
                if entry == "kernel":
                    environment["CRABC_CRT_ENTRY_AUXV"] = "1"
                program = f"/main-{mode}"
                prefix = [INTERPRETER] if entry == "direct" else []
                observed = recorder.run(
                    f"candidate-{mode}-{entry}-{scenario}",
                    [TIMEOUT, "20", CHROOT, str(root), *prefix, program, *ARGUMENTS],
                    environment=environment, expect_success=False)
                oracle_prefix = [str(ORACLE_INTERPRETER)] if entry == "direct" else []
                reference = recorder.run(
                    f"oracle-{mode}-{entry}-{scenario}",
                    [TIMEOUT, "20", *oracle_prefix, str(oracle / f"main-{mode}"), *ARGUMENTS],
                    environment=environment, expect_success=False)
                transcript = observed.stdout.decode(errors="replace")
                oracle_transcript = reference.stdout.decode(errors="replace")
                label = f"{mode}/{entry}/{scenario}"
                require(reference.returncode == status and oracle_transcript == expected,
                        f"{label}: pinned musl oracle observed {oracle_transcript!r} status {reference.returncode}")
                require(observed.stderr == b"" and reference.stderr == b"", f"{label}: unexpected diagnostics")
                require(observed.returncode == status and transcript == OWNED_PREINIT + oracle_transcript,
                        f"{label}: owned {transcript!r} status {observed.returncode}; "
                        f"musl {oracle_transcript!r} status {reference.returncode}")
                cells.append({"mode": mode, "entry": entry, "scenario": scenario, "status": status,
                              "candidate": transcript, "oracle": oracle_transcript})
    return cells + execute_wide(recorder, root, work) + execute_names(recorder, root, work)


def product_identity(product: Path) -> str:
    return sha256(product / "share/crabc/manifest.json")


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print("usage: x86_64_owned_dynamic_startup.py INSTALLED_DYNAMIC_SYSROOT", file=sys.stderr)
        return 2
    product = Path(arguments[0])
    try:
        require(product.is_absolute() and (product / "bin/crabc-cc-dynamic").is_file(),
                "supply an absolute installed owned dynamic sysroot")
        require(ORACLE_COMPILER.is_file() and ORACLE_INTERPRETER.is_file(), "pinned musl oracle is unavailable")
        work = evidence_root()
        before = product_identity(product)
        recorder = Recorder(work)
        report = {"schema": SCHEMA, "product_manifest_sha256": before,
                  "fixtures": {path.name: sha256(path)
                               for path in (MAIN_SOURCE, DEPENDENCY_SOURCE, PLUGIN_SOURCE, WIDE_SOURCE, NAMES_SOURCE)},
                  "admitted_difference": "owned executable DT_PREINIT_ARRAY dispatch (leading P)"}
        report.update(build(recorder, product, work))
        report["wide"] = build_wide(recorder, product, work)
        report["names"] = build_names(recorder, product, work)
        report["cells"] = execute(recorder, product, work)
        require(product_identity(product) == before, "installed product manifest changed during evidence")
        report["family_completion"] = False
        (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    except (EvidenceError, OSError, ValueError, KeyError) as error:
        print(f"owned dynamic CRT startup: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"owned dynamic CRT startup: PASS ({len(report['cells'])} musl-differential cells, "
          f"PIE and non-PIE link interface); evidence: {work}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
