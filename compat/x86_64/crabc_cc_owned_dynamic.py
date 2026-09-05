#!/usr/bin/env python3
"""Sealed materialized dynamic driver (not campaign completion).

The static driver's input/ELF/tool checks are reused verbatim from the installed
package. This owner adds only dynamic linkage and explicit application DSOs.
The interpreter name is canonical; run applications in the installed root.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager, nullcontext

# Installed tools are immutable payload, including when callers do not set a
# Python environment policy. Importing the shared checks must not create a
# bytecode cache inside the validated installation.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "share/crabc"))
import crabc_cc_static as shared

FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
ALIASES = {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}
REQUIRED = {"usr/lib/libc.so", "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/crti.o", "usr/lib/crtn.o",
            "usr/lib/crabc-dynamic-attach.o", "usr/lib/libcrabc-builtins.a", "lib/ld-crabc-x86_64.so.1"}


@contextmanager
def reserve_receipt(path: Path):
    """Claim a new sidecar before tools; never replace an existing inode.

    The held descriptor is the write authority. A failed invocation removes
    only its own still-empty reservation, not a pathname replaced by another
    publisher. Existing files, symlinks and hardlinks fail with EEXIST.
    """
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except OSError as error:
        raise shared.DriverError(f"cannot reserve dynamic link receipt: {path}: {error}") from error
    identity = os.fstat(descriptor)
    complete = False
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        def publish(payload: str):
            nonlocal complete
            current = path.lstat()
            if (current.st_dev, current.st_ino, current.st_nlink) != (identity.st_dev, identity.st_ino, 1):
                raise shared.DriverError("dynamic receipt reservation identity changed")
            stream.write(payload)
            stream.flush()
            complete = True
        try:
            yield publish
        finally:
            if not complete:
                try:
                    current = path.lstat()
                    if (current.st_dev, current.st_ino, current.st_nlink) == (identity.st_dev, identity.st_ino, 1):
                        path.unlink()
                except FileNotFoundError:
                    pass


def validate(root: Path) -> dict:
    manifest = root / "share/crabc/manifest.json"
    shared.require_regular(manifest, "dynamic manifest")
    try:
        record = json.loads(manifest.read_text())
    except (ValueError, OSError) as error:
        raise shared.DriverError(f"invalid dynamic manifest: {error}") from error
    if not isinstance(record, dict) or type(record.get("schema")) is not int or record.get("schema") != 1 or record.get("format") != FORMAT or record.get("target") != shared.TARGET or record.get("symlinks") != ALIASES:
        raise shared.DriverError("wrong installed dynamic product contract")
    files = record.get("files")
    if not isinstance(files, dict) or not REQUIRED <= files.keys():
        raise shared.DriverError("incomplete installed dynamic payload")
    observed = set()
    aliases = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            aliases[relative] = os.readlink(path)
        elif path.is_file():
            if relative != "share/crabc/manifest.json":
                observed.add(relative)
        elif not path.is_dir():
            raise shared.DriverError(f"nonregular installed payload: {relative}")
    if observed != files.keys() or aliases != ALIASES:
        raise shared.DriverError("installed payload differs from exact manifest roster")
    for relative, digest in files.items():
        if Path(relative).is_absolute() or ".." in Path(relative).parts or not re.fullmatch("[0-9a-f]{64}", str(digest)):
            raise shared.DriverError("unsafe manifest payload entry")
        if shared.sha256_file(root / relative) != digest:
            raise shared.DriverError(f"installed payload hash mismatch: {relative}")
    return record


def run(command: list[str], temporary: Path) -> str:
    environment = shared.clean_environment()
    environment["TMPDIR"] = str(temporary)
    result = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise shared.DriverError(f"command failed: {command[0]}\n{result.stdout}{result.stderr}")
    return result.stdout


def dso_metadata(path: Path, temporary: Path) -> tuple[str, list[str]]:
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01" or int.from_bytes(data[16:18], "little") != 3 or int.from_bytes(data[18:20], "little") != 62:
        raise shared.DriverError(f"application DSO is not native ET_DYN: {path}")
    segments = run(["/usr/bin/readelf", "-lW", str(path)], temporary)
    dynamic = run(["/usr/bin/readelf", "-dW", str(path)], temporary)
    if "INTERP" in segments or "TEXTREL" in dynamic or "(RPATH)" in dynamic:
        raise shared.DriverError("application DSO contains forbidden interpreter/textrel/RPATH")
    sonames = re.findall(r"\(SONAME\).*\[([^\]]+)\]", dynamic)
    if sonames != [path.name] or "/" in path.name:
        raise shared.DriverError("application DSO must own exactly its basename SONAME")
    needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)
    if any("/" in name for name in needed):
        raise shared.DriverError("application DSO contains pathname DT_NEEDED")
    runpaths = re.findall(r"\(RUNPATH\).*\[([^\]]*)\]", dynamic)
    if runpaths not in ([], ["/usr/lib"]):
        receipt = Path(str(path) + ".crabc-link.json")
        shared.require_regular(receipt, "application search path receipt")
        try:
            record = json.loads(receipt.read_text())
        except (ValueError, OSError) as error:
            raise shared.DriverError(f"invalid application search path receipt: {error}") from error
        if (not isinstance(record, dict) or record.get("format") != FORMAT or record.get("output_sha256") != shared.sha256_file(path)
                or record.get("output_path") != str(path.resolve())
                or runpaths != [record.get("application_runpath")]):
            raise shared.DriverError("application DSO has an undeclared runtime search path")
    return path.name, needed


def dynamic_symbols(path: Path, temporary: Path, *, object_symbols: bool = False) -> tuple[set[str], set[str]]:
    definitions, required = set(), set()
    for line in run(["/usr/bin/readelf", "--symbols" if object_symbols else "--dyn-syms", "-W", str(path)], temporary).splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"): continue
        kind, binding, visibility, section, name = fields[3:8]
        if binding not in ("GLOBAL", "WEAK"): continue
        if "@" in name or kind == "IFUNC":
            raise shared.DriverError("symbol versions and IFUNC are not admitted by this initial product")
        if section == "UND":
            if binding == "GLOBAL": required.add(name)
        elif object_symbols or visibility in ("DEFAULT", "PROTECTED"):
            definitions.add(name)
    return definitions, required


def execute(root: Path, arguments: list[str]) -> None:
    validate(root)
    mode = None
    binding = None
    application_runpath = None
    runtime_imports = set()
    dsos = []
    common = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in ("--dynamic-pie", "-pie", "--dynamic-non-pie", "-no-pie", "--dynamic-shared-object", "-shared"):
            if mode is not None: raise shared.DriverError("select exactly one dynamic mode")
            mode = ("shared" if argument in ("-shared", "--dynamic-shared-object") else
                    "exec" if argument in ("--dynamic-non-pie", "-no-pie") else "pie")
        elif argument in ("--binding", "--runtime-import"):
            index += 1
            if index == len(arguments): raise shared.DriverError(f"missing {argument} value")
            value = arguments[index]
            if argument == "--binding":
                if binding is not None or value not in ("now", "lazy"):
                    raise shared.DriverError("select one binding: now or lazy")
                binding = value
            else:
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", value) or value in runtime_imports:
                    raise shared.DriverError("invalid or duplicate runtime import")
                runtime_imports.add(value)
        elif argument == "--application-runpath":
            index += 1
            if index == len(arguments) or application_runpath is not None:
                raise shared.DriverError("select one application RUNPATH")
            application_runpath = arguments[index]
            if not application_runpath or len(application_runpath.encode()) >= 4096 or "\0" in application_runpath:
                raise shared.DriverError("invalid application RUNPATH")
        elif argument == "--application-dso":
            index += 1
            if index == len(arguments): raise shared.DriverError("missing application DSO")
            path = Path(arguments[index])
            if path.suffix != ".so" or shared.rejects_runtime_object(path) or path.name == "libc.so":
                raise shared.DriverError("unowned application DSO")
            dsos.append(path)
        elif argument in ("-static", "--static-et-exec", "-static-pie", "--static-pie"):
            raise shared.DriverError("static linkage is not a dynamic mode")
        else:
            common.append(argument)
        index += 1
    if mode is None: raise shared.DriverError("select --dynamic-pie, --dynamic-non-pie or --dynamic-shared-object")
    application_runpath = application_runpath if application_runpath is not None else "/usr/lib"
    binding = binding or "now"
    if runtime_imports and (mode != "shared" or binding != "lazy"):
        raise shared.DriverError("runtime imports require a lazy shared object")
    invocation = shared.parse_invocation(common)
    if invocation.compile_only and application_runpath != "/usr/lib":
        raise shared.DriverError("compile-only accepts no application RUNPATH")
    if invocation.compile_only and (runtime_imports or binding != "now"):
        raise shared.DriverError("compile-only accepts no binding/import contract")
    if invocation.compile_only and dsos: raise shared.DriverError("compile-only accepts no DSO")
    if invocation.link_receipt is not None:
        raise shared.DriverError("dynamic link receipt path is derived from -o")
    library = root / "usr/lib"
    link = [shared.linker(), *(["-shared"] if mode == "shared" else ["-pie"] if mode == "pie" else []), "--hash-style=sysv",
            "-z", "relro", "-z", binding, "-z", "noexecstack", "-z", "text", *([] if runtime_imports else ["--no-undefined"]),
            "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", application_runpath]
    entry_object = "Scrt1.o" if mode == "pie" else "crt1.o"
    if mode != "shared":
        link += ["--dynamic-linker", INTERPRETER, str(library / entry_object),
                 str(library / "crabc-dynamic-attach.o")]
    if invocation.print_link_plan:
        if dsos: raise shared.DriverError("link plan accepts no application inputs")
        print(json.dumps({"format": FORMAT, "mode": mode, "binding": binding,
                          "runtime_imports": sorted(runtime_imports), "application_runpath": application_runpath, "linker": link,
                          "campaign_complete": False}, sort_keys=True))
        return
    output = (invocation.output or Path("a.out")).absolute()
    shared.validate_application_output(root, output)
    shared.validate_application_output_disjoint(output, invocation.sources + invocation.objects + tuple(dsos))
    receipt = Path(str(output) + ".crabc-link.json")
    shared.validate_application_output(root, receipt)
    shared.validate_application_output_disjoint(receipt, invocation.sources + invocation.objects + tuple(dsos) + (output,))
    output.parent.mkdir(parents=True, exist_ok=True)
    with (nullcontext(None) if invocation.compile_only else reserve_receipt(receipt)) as receipt_stream, tempfile.TemporaryDirectory(prefix="crabc-dynamic-link.", dir=output.parent) as temporary_name:
        temporary = Path(temporary_name)
        objects = [shared.require_x86_64_relocatable_object(root, path) for path in invocation.objects]
        for index, source in enumerate(invocation.sources):
            source = shared.require_application_file(root, source, "source")
            obj = output if invocation.compile_only else temporary / f"source-{index}.o"
            run([shared.compiler(), "-nostdinc", "-isystem", str(root / "usr/include"),
                 "-ffreestanding", "-fno-builtin", "-fstack-protector-strong",
                 *invocation.compiler_flags, "-fPIC" if mode == "shared" else "-fPIE" if mode == "pie" else "-fno-pie",
                 "-c", str(source), "-o", str(obj)], temporary)
            objects.append(obj)
        if invocation.compile_only:
            return
        declared = {}
        for path in dsos:
            path = shared.require_application_file(root, path, "DSO")
            name, needed = dso_metadata(path, temporary)
            if name in declared: raise shared.DriverError("duplicate application SONAME")
            declared[name] = (path, needed)
        for path, needed in declared.values():
            if not set(needed) <= {"libc.so", *declared.keys()}:
                raise shared.DriverError(f"undeclared transitive dependency of {path}")
        provided, _ = dynamic_symbols(library / "libc.so", temporary)
        requirements = set()
        for path, _ in declared.values():
            definitions, required = dynamic_symbols(path, temporary)
            provided.update(definitions)
            requirements.update(required)
        if requirements - provided:
            raise shared.DriverError(f"application DSOs have unresolved runtime imports: {sorted(requirements - provided)}")
        if runtime_imports:
            # Removing --no-undefined is authorized only by an exact symbol
            # contract, checked against all owned objects before linking. No
            # incidental missing import or ambient provider is accepted.
            # ELF x86 PIC objects name this linker-synthesized table anchor;
            # it is not an import from a target runtime library.
            object_provided, object_required = {*provided, "_GLOBAL_OFFSET_TABLE_"}, set()
            for path in [*objects, library / "libcrabc-builtins.a"]:
                definitions, required = dynamic_symbols(path, temporary, object_symbols=True)
                object_provided.update(definitions)
                if path in objects: object_required.update(required)
            if object_required - object_provided != runtime_imports:
                raise shared.DriverError(f"runtime imports differ from exact unresolved object symbols: {sorted(object_required - object_provided)}")
        if mode == "shared": link += ["-soname", output.name]
        link += [str(library / "crti.o"), *(str(path) for path in objects),
                 *(str(path) for path, _ in declared.values()), str(library / "libc.so"),
                 str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", str(output)]
        trace = run([*link[:-2], "--trace", *link[-2:]], temporary).splitlines()
        runtime = [library / name for name in ("crti.o", "libc.so", "crtn.o")]
        if mode != "shared": runtime += [library / entry_object, library / "crabc-dynamic-attach.o"]
        direct = [*runtime, *objects, *(path for path, _ in declared.values())]
        archive = library / "libcrabc-builtins.a"
        # LLD may not extract an archive member. Every other input must appear,
        # and no ambient startup, library, script or helper input is permitted.
        seen = set()
        for line in trace:
            if line in {str(path) for path in direct}:
                seen.add(line)
            elif line == str(archive) or (line.startswith(str(archive) + "(") and line.endswith(")")):
                continue
            else:
                raise shared.DriverError(f"unadmitted dynamic link trace input: {line}")
        if seen != {str(path) for path in direct}:
            raise shared.DriverError("dynamic link trace omitted an explicit input")
        if runtime_imports:
            _, output_required = dynamic_symbols(output, temporary)
            if output_required - provided != runtime_imports:
                raise shared.DriverError("linked runtime imports differ from declared contract")
        record = {"schema": 1, "format": FORMAT, "mode": mode, "binding": binding,
                  "runtime_imports": sorted(runtime_imports), "application_runpath": application_runpath,
                  "output_path": str(output.resolve()),
                  "output_sha256": shared.sha256_file(output),
                  "manifest_sha256": shared.sha256_file(root / "share/crabc/manifest.json"),
                  "application_dsos": {name: shared.sha256_file(path) for name, (path, _) in declared.items()},
                  "owned_runtime_inputs": sorted(path.relative_to(root).as_posix() for path in [*runtime, archive]),
                  "input_receipts": [{"path": str(path), "sha256": shared.sha256_file(path)} for path in [*direct, archive]],
                  "resolved_linker": {"path": link[0], "sha256": shared.sha256_file(Path(link[0]))},
                  "link_command": link, "link_trace": trace, "campaign_complete": False}
        receipt_stream(json.dumps(record, indent=2, sort_keys=True) + "\n")


def main() -> int:
    try:
        execute(ROOT, sys.argv[1:])
    except (shared.DriverError, OSError) as error:
        print(f"crabc-cc-dynamic: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
