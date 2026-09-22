#!/usr/bin/env python3
"""Link one owned Rust executable while isolating Cargo host build scripts.

``owned_cleanup.py`` is the sole caller.  Rust invokes this program as its
linker, but it cannot select a linker search path or a native fallback: this
file replaces Rust's target ``libunwind``/compiler-builtins inputs and native
``-l`` requests with the explicitly supplied provider and product files.

Cargo's host and requested target triples are both x86_64-musl in the native
image. Cargo therefore applies the target linker override to build-script
executables as well as the final target artifact. A narrowly identified
``build_script_build-*`` output below the separately declared Cargo host-build
root delegates to the pinned container GCC and writes one exclusive receipt.
The runner later requires exact closure between those receipts and Cargo's
machine-readable custom-build artifact records. Every application and cdylib
output still takes the closed owned-runtime path below.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Iterable


TARGET = "x86_64-unknown-linux-musl"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
STOCK_RUST_UNWIND_ARCHIVE = re.compile(r"libunwind-[0-9a-f]+\.rlib\Z")
COMPILER_BUILTINS_ARCHIVE = re.compile(r"libcompiler_builtins-[0-9a-f]+\.rlib\Z")
FALLBACK_REQUESTS = frozenset({"-lgcc", "-lgcc_s", "-lunwind"})
NATIVE_REQUESTS = frozenset({"-lc", *FALLBACK_REQUESTS, "-lpthread", "-lm", "-ldl", "-lrt", "-lutil"})
CANONICAL_FLAGS = frozenset({
    "-m64", "-nodefaultlibs", "-Wl,--as-needed", "-Wl,-Bstatic", "-Wl,-Bdynamic",
    "-Wl,--eh-frame-hdr", "-Wl,-z,noexecstack", "-Wl,--gc-sections",
    "-Wl,-z,relro,-z,now", "-Wl,-O1", "-Wl,--strip-debug",
})
METADATA_MEMBERS = frozenset({"lib.rmeta", "lib.rmeta-link"})
RUST_CDYLIB_EXPORTS = (
    "crabc_owned_cleanup_dso",
    "crabc_owned_cleanup_dso_ready",
    "crabc_owned_cleanup_dso_release",
)
HOST_BUILD_SCRIPT_OUTPUT = re.compile(r"build_script_build-[0-9a-f]+\Z")
SOURCE_LTO_UNWIND_ABI_ENV = "CRABC_OWNED_RUST_SOURCE_LTO_UNWIND_ABI"


class LinkError(RuntimeError):
    """Rust requested a link input outside the owned consumer boundary."""


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def physical_regular(path: Path, description: str) -> Path:
    """Reject every symlinked component, not only a symlink final input."""

    if ".." in path.parts:
        raise LinkError(f"{description} has parent traversal: {path}")
    candidate = _absolute(path)
    current = Path(candidate.anchor)
    try:
        for component in candidate.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                raise LinkError(f"{description} traverses a symlink: {path}")
        if not stat.S_ISREG(candidate.lstat().st_mode):
            raise LinkError(f"{description} is not a regular file: {path}")
    except OSError as error:
        raise LinkError(f"{description} is unreadable: {path}") from error
    return candidate


def physical_directory(path: Path, description: str) -> Path:
    if ".." in path.parts:
        raise LinkError(f"{description} has parent traversal: {path}")
    candidate = _absolute(path)
    current = Path(candidate.anchor)
    try:
        for component in candidate.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                raise LinkError(f"{description} traverses a symlink: {path}")
        if not stat.S_ISDIR(candidate.lstat().st_mode):
            raise LinkError(f"{description} is not a directory: {path}")
    except OSError as error:
        raise LinkError(f"{description} is unreadable: {path}") from error
    return candidate


def confined(path: str, roots: Iterable[Path], description: str, *, directory: bool = False) -> Path:
    candidate = _absolute(Path(path))
    checked = physical_directory(candidate, description) if directory else physical_regular(candidate, description)
    if not any(checked.is_relative_to(root) for root in roots):
        raise LinkError(f"{description} is outside the declared Rust roots: {path}")
    return checked


def confined_output(path: str, root: Path) -> Path:
    """Accept one not-yet-created output below an already-physical root."""

    candidate = _absolute(Path(path))
    if ".." in Path(path).parts or not candidate.is_relative_to(root):
        raise LinkError(f"Rust output is outside the declared application root: {path}")
    physical_directory(candidate.parent, "Rust output parent")
    return candidate


def host_build_script_output(arguments: list[str], host_build_root: Path) -> Path | None:
    """Return the one Cargo host build-script output, if this is one.

    The source-built consumer names a fresh physical ``target/release/build``
    root.  Only Cargo's hash-named build-script executable may be linked
    outside the final target release root.  This prevents the same-triple host
    exception from admitting a second application or cdylib link path.
    """

    output: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        index += 1
        if argument != "-o":
            continue
        if index == len(arguments) or output is not None:
            raise LinkError("Cargo host build-script link has an invalid output")
        output = arguments[index]
        index += 1
    if output is None:
        return None
    candidate = _absolute(Path(output))
    if not candidate.is_relative_to(host_build_root):
        return None
    if ".." in Path(output).parts:
        raise LinkError(f"Cargo host build-script output has parent traversal: {output}")
    physical_directory(candidate.parent, "Cargo host build-script output parent")
    if HOST_BUILD_SCRIPT_OUTPUT.fullmatch(candidate.name) is None:
        raise LinkError(f"Cargo host build-script output is not an admitted build script: {output}")
    if candidate.exists() or candidate.is_symlink():
        raise LinkError(f"Cargo host build-script output must be fresh: {output}")
    return candidate


def is_foreign_native_runtime(argument: str) -> bool:
    name = Path(argument).name
    if argument.startswith("-l:"):
        name = argument.removeprefix("-l:")
    elif argument.startswith("-l") and len(argument) > 2:
        name = argument.removeprefix("-l")
    return (
        name.startswith(("libgcc", "gcc"))
        or name == "unwind" or name.startswith("unwind.")
        or name == "libunwind" or name.startswith(("libunwind-", "libunwind."))
    )


def _reject_linker_escape(argument: str) -> None:
    if argument.startswith("@") or (
        argument.startswith("-Wl,") and any(item.startswith("@") for item in argument.split(",")[1:])
    ):
        raise LinkError(f"response file is not admitted: {argument}")
    if argument in {"-l", "-Xlinker"}:
        raise LinkError(f"alternate linker library spelling is not admitted: {argument}")
    if argument.startswith("-Wl,"):
        options = argument.split(",")[1:]
        if any(is_foreign_native_runtime(item) for item in options):
            raise LinkError(f"foreign native runtime linker option: {argument}")


def _stock_archive(path: Path, stock_root: Path, expression: re.Pattern[str]) -> bool:
    return path.parent == stock_root and expression.fullmatch(path.name) is not None


def _linker_option_value(argument: str, name: str) -> str | None:
    """Read the two finite GCC spellings Rust emits for one linker option."""

    equals = f"-Wl,{name}="
    comma = f"-Wl,{name},"
    if argument.startswith(equals):
        return argument.removeprefix(equals)
    if argument.startswith(comma):
        return argument.removeprefix(comma)
    return None


def audit_rust_cdylib_export_script(path: Path) -> None:
    """Keep the plugin's Rust-generated export policy as one finite input."""

    try:
        contents = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise LinkError(f"Rust cdylib export script is unreadable: {path}") from error
    if len(contents) > 4096:
        raise LinkError("Rust cdylib export script is too large")
    without_comments = re.sub(r"/\*.*?\*/", "", contents, flags=re.DOTALL)
    exports = "\\s*;\\s*".join(RUST_CDYLIB_EXPORTS)
    expected = rf"\s*\{{\s*global\s*:\s*{exports}\s*;\s*local\s*:\s*\*\s*;\s*\}}\s*;\s*"
    if re.fullmatch(expected, without_comments) is None:
        raise LinkError("Rust cdylib export script differs from the cleanup plugin contract")


def parse_arguments(
    arguments: list[str], application_root: Path, stock_root: Path | None,
    source_built_root: Path | None = None, toolchain_search_root: Path | None = None,
) -> dict[str, object]:
    """Parse the finite rustc linker dialect without forwarding any raw flag."""

    source_built = source_built_root is not None
    if source_built:
        # Cargo unconditionally passes its target-libdir with ``-L`` even
        # though the source graph supplied its Rust archives before fat LTO
        # emitted this final object. Admit only that declared directory as a
        # *search* path; no archive input may use it and ``link_command`` never
        # forwards any search path to LLD.
        search_roots = [application_root, source_built_root]
        if toolchain_search_root is not None:
            search_roots.append(toolchain_search_root)
        archive_roots = [source_built_root]
        archive_description = "source-built Rust archive"
    else:
        if stock_root is None:
            raise LinkError("missing stock Rust target library root")
        search_roots = [application_root, stock_root]
        archive_roots = search_roots
        archive_description = "Rust archive"
    objects: list[Path] = []
    archives: list[Path] = []
    search_paths: list[Path] = []
    native_requests: list[str] = []
    stock_unwind: Path | None = None
    compiler_builtins: Path | None = None
    output: Path | None = None
    rust_mode: str | None = None
    shared_soname: str | None = None
    version_script: Path | None = None
    export_dynamic = False
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        index += 1
        _reject_linker_escape(argument)
        if argument in {"-o", "-L"}:
            if index == len(arguments):
                raise LinkError(f"missing value for {argument}")
            value = arguments[index]
            index += 1
            if argument == "-o":
                if output is not None:
                    raise LinkError("duplicate output")
                output = confined_output(value, application_root)
            else:
                search_paths.append(confined(value, search_roots, "Rust search path", directory=True))
        elif argument in {"-pie", "-no-pie", "-shared"}:
            if rust_mode is not None:
                raise LinkError("duplicate or conflicting Rust executable mode")
            rust_mode = argument.removeprefix("-")
        elif argument == "-Wl,--export-dynamic":
            export_dynamic = True
        elif (value := _linker_option_value(argument, "-soname")) is not None:
            if not value or "/" in value or "\0" in value or shared_soname is not None:
                raise LinkError("Rust shared-object SONAME is invalid")
            shared_soname = value
        elif (value := _linker_option_value(argument, "--version-script")) is not None:
            if not value or version_script is not None:
                raise LinkError("Rust cdylib export script is invalid")
            version_script = confined(value, [application_root], "Rust cdylib export script")
        elif argument in NATIVE_REQUESTS:
            native_requests.append(argument)
        elif argument in CANONICAL_FLAGS:
            pass
        elif argument.endswith(".rlib"):
            archive = confined(argument, archive_roots, archive_description)
            runtime_root = source_built_root if source_built else stock_root
            assert runtime_root is not None
            if _stock_archive(archive, runtime_root, STOCK_RUST_UNWIND_ARCHIVE):
                if source_built:
                    raise LinkError("source-built Rust libunwind archive must not enter the final owned link")
                if stock_unwind is not None:
                    raise LinkError("duplicate stock Rust libunwind archive")
                stock_unwind = archive
            elif _stock_archive(archive, runtime_root, COMPILER_BUILTINS_ARCHIVE):
                if compiler_builtins is not None:
                    raise LinkError("duplicate source-built Rust compiler-builtins archive" if source_built else
                                    "duplicate Rust compiler-builtins archive")
                compiler_builtins = archive
            elif is_foreign_native_runtime(str(archive)):
                raise LinkError(f"foreign native runtime archive: {archive}")
            else:
                archives.append(archive)
        elif argument.endswith(".o"):
            objects.append(confined(argument, [application_root], "Rust application object"))
        elif is_foreign_native_runtime(argument):
            raise LinkError(f"foreign native runtime input: {argument}")
        else:
            raise LinkError(f"unrecognized Rust link argument: {argument}")
    if output is None or rust_mode is None or not objects:
        raise LinkError("expected output, Rust link mode, and Rust application objects")
    if not source_built and stock_unwind is None:
        raise LinkError("missing exact stock Rust libunwind archive")
    if compiler_builtins is None:
        raise LinkError("missing exact source-built Rust compiler-builtins archive" if source_built else
                        "missing exact Rust compiler-builtins archive")
    if "-lc" not in native_requests or not set(native_requests) & {"-lgcc", "-lgcc_s"}:
        raise LinkError("missing Rust libc or libgcc request")
    if (shared_soname is not None or version_script is not None) and rust_mode != "shared":
        raise LinkError("Rust shared-object option used for a non-shared link")
    if rust_mode == "shared":
        if shared_soname is not None and shared_soname != output.name:
            raise LinkError("Rust shared-object SONAME differs from its output")
        if source_built and version_script is None:
            raise LinkError("source-built Rust cdylib lacks its export script")
        if version_script is not None:
            audit_rust_cdylib_export_script(version_script)
    if source_built:
        # Fat LTO consumes the source-built standard libraries and the Cargo
        # provider through rustc's --extern graph, then emits one fused object
        # for this native link. A direct rlib here would bypass that graph and
        # make archive ordering decide which Rust implementation owns an ABI.
        if archives:
            raise LinkError("source-built Cargo fat-LTO final link carries a direct Rust archive")
        if len(objects) != 1:
            raise LinkError("source-built Cargo fat-LTO final link must contain one fused Rust object")
    all_inputs = [*objects, *archives]
    if output in all_inputs or len(all_inputs) != len(set(all_inputs)):
        raise LinkError("output aliases or Rust repeats an application input")
    return {
        "objects": objects,
        "archives": archives,
        "search_paths": search_paths,
        "native_requests": native_requests,
        "stock_unwind": stock_unwind,
        "compiler_builtins": compiler_builtins,
        "output": output,
        "rust_mode": rust_mode,
        "export_dynamic": export_dynamic,
        "rust_library_origin": "source-built" if source_built else "stock",
        "source_built_unwind": None,
        "source_built_compiler_builtins": compiler_builtins if source_built else None,
        "shared_soname": shared_soname,
        "version_script": version_script,
    }


def run(command: list[str | Path]) -> str:
    environment = dict(os.environ)
    environment.pop("CARGO_MAKEFLAGS", None)
    environment.pop("MAKEFLAGS", None)
    result = subprocess.run([str(item) for item in command], env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise LinkError(f"link editor exited {result.returncode}: {result.stdout}")
    return result.stdout


def source_lto_object_receipt(objects: list[Path], nm: Path) -> dict[str, object]:
    """Prove the fused Cargo object retains the provider ABI before LLD.

    Fat LTO intentionally removes Rust standard-library and provider rlibs
    from the native argv. The runner supplies the precise ABI from the pinned
    provider contract; its reader compares this record with that contract.
    """

    encoded = os.environ.get(SOURCE_LTO_UNWIND_ABI_ENV)
    if encoded is None:
        raise LinkError("missing source-built Cargo LTO unwind ABI")
    try:
        expected_value = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise LinkError("source-built Cargo LTO unwind ABI is not JSON") from error
    if (
        not isinstance(expected_value, list) or not expected_value
        or any(not isinstance(symbol, str) or re.fullmatch(r"_Unwind_[A-Za-z0-9_]+", symbol) is None
               for symbol in expected_value)
        or len(set(expected_value)) != len(expected_value)
    ):
        raise LinkError("source-built Cargo LTO unwind ABI is malformed")
    if len(objects) != 1:
        raise LinkError("source-built Cargo fat-LTO final link must contain one fused Rust object")
    symbols = {
        line.split()[-1]
        for line in run([nm, "--defined-only", objects[0]]).splitlines()
        if len(line.split()) >= 3
    }
    defined_unwind = sorted(symbol for symbol in symbols if symbol.startswith("_Unwind_"))
    if set(defined_unwind) != set(expected_value):
        raise LinkError("source-built Cargo LTO object does not retain the declared unwind ABI")
    if "rust_eh_personality" not in symbols:
        raise LinkError("source-built Cargo LTO object lacks rust_eh_personality")
    return {
        "object": _record_input(objects[0]),
        "defined_unwind_abi": defined_unwind,
        "rust_eh_personality": True,
    }


def delegate_host_build_script(arguments: list[str], output: Path) -> None:
    """Run one explicitly separated Cargo host build-script link and retain it.

    This route exists only because the pinned native toolchain's host and
    requested target have the same Rust triple.  It is a build-tool executable,
    not a target consumer input, and cannot share the owned final-link receipt.
    """

    linker_value = os.environ.get("CRABC_OWNED_RUST_HOST_BUILD_LINKER")
    receipts_value = os.environ.get("CRABC_OWNED_RUST_HOST_BUILD_RECEIPTS")
    if not linker_value or not receipts_value:
        raise LinkError("missing owned Rust host build-script linker evidence")
    linker = physical_regular(Path(linker_value), "pinned Cargo host build-script linker")
    receipts = physical_directory(Path(receipts_value), "Cargo host build-script receipt root")
    environment = dict(os.environ)
    environment.pop("CARGO_MAKEFLAGS", None)
    environment.pop("MAKEFLAGS", None)
    completed = subprocess.run(
        [str(linker), *arguments], env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if completed.returncode:
        raise LinkError(f"Cargo host build-script linker exited {completed.returncode}: {completed.stdout}")
    output = physical_regular(output, "Cargo host build-script output")
    record = {
        "schema": 1,
        "kind": "cargo-host-build-script",
        "linker": {"path": str(linker), "sha256": sha256(linker)},
        "command": [str(linker), *arguments],
        "output": {"path": str(output), "sha256": sha256(output)},
    }
    receipt = receipts / f"{hashlib.sha256(str(output).encode()).hexdigest()}.json"
    if receipt.exists() or receipt.is_symlink():
        raise LinkError(f"Cargo host build-script receipt must be fresh: {receipt}")
    with receipt.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.write("\n")


def audit_rust_archive(path: Path, ar: Path) -> list[str]:
    physical_regular(path, "Rust archive")
    members = run([ar, "t", path]).splitlines()
    if not members or any(member not in METADATA_MEMBERS and not member.endswith(".rcgu.o") for member in members):
        raise LinkError(f"Rust archive contains an unadmitted native member: {path}")
    return members


def _read_product(root: Path, mode: str) -> tuple[Path, dict[str, str]]:
    compat = Path(__file__).resolve().parent.parent / "compat/x86_64"
    if str(compat) not in sys.path:
        sys.path.insert(0, str(compat))
    import owned_posix_product_evidence as product  # pylint: disable=import-outside-toplevel

    root = physical_directory(root, f"owned {mode} product root")
    try:
        if mode == "static":
            return product._validate_static_product(root)
        return product._validate_dynamic_product(root)
    except product.ProductEvidenceError as error:
        raise LinkError(f"invalid owned {mode} product: {error}") from error


def _product_inputs(root: Path, mode: str) -> list[Path]:
    library = root / "usr/lib"
    if mode == "static":
        return [
            library / "crt1.o", library / "crti.o", library / "libc.a",
            library / "libcrabc-builtins.a", library / "crtn.o",
        ]
    return [
        library / "Scrt1.o", library / "crti.o", library / "crabc-dynamic-attach.o",
        library / "libc.so", library / "libcrabc-builtins.a", library / "crtn.o",
    ]


def link_command(
    *, linker: Path, root: Path, mode: str, provider: Path | None, objects: list[Path], archives: list[Path], output: Path,
    export_dynamic: bool, rust_mode: str = "executable", version_script: Path | None = None,
) -> list[str]:
    """Return the entire native command; there are no library-search holes."""

    runtime = _product_inputs(root, mode)
    rust_inputs = [*map(str, archives), *( [str(provider)] if provider is not None else [] )]
    if rust_mode == "shared":
        if mode != "dynamic":
            raise LinkError("a Rust shared object requires the owned dynamic product")
        return [
            str(linker), "-shared", "-soname", output.name, "--hash-style=sysv", "--eh-frame-hdr", "--gc-sections",
            "--no-undefined", "--allow-shlib-undefined", "-z", "text", "-z", "noexecstack", "-z", "relro", "-z", "now",
            *( ["--version-script", str(version_script)] if version_script is not None else [] ),
            "--trace", "-o", str(output), str(runtime[1]), *map(str, objects), *rust_inputs,
            str(runtime[3]), str(runtime[4]), str(runtime[5]),
        ]
    if rust_mode not in {"executable", "pie", "no-pie"}:
        raise LinkError(f"unsupported Rust link mode: {rust_mode}")
    if mode == "static":
        return [
            str(linker), "-static", "--no-dynamic-linker", "--no-undefined", "--eh-frame-hdr",
            "--gc-sections", "-z", "noexecstack", "-z", "relro", "-z", "now", "-e", "_start",
            "--trace", "-o", str(output), str(runtime[0]), str(runtime[1]),
            *map(str, objects), *rust_inputs, str(runtime[2]), str(runtime[3]), str(runtime[4]),
        ]
    return [
        str(linker), "-pie", "--hash-style=sysv", "--eh-frame-hdr", "--gc-sections", "--no-undefined",
        "--allow-shlib-undefined", "-z", "text", "-z", "noexecstack", "-z", "relro", "-z", "now",
        "--dynamic-linker", INTERPRETER, *( ["--export-dynamic"] if export_dynamic else [] ),
        "--trace", "-o", str(output), str(runtime[0]), str(runtime[1]), str(runtime[2]),
        *map(str, objects), *rust_inputs, str(runtime[3]), str(runtime[4]), str(runtime[5]),
    ]


def _trace_input(line: str) -> str:
    return line.split("(", 1)[0]


def validate_trace(trace: str, admitted: set[Path]) -> None:
    paths = {str(path) for path in admitted}
    for line in trace.splitlines():
        if not line:
            continue
        input_path = _trace_input(line)
        if input_path not in paths:
            raise LinkError(f"link trace names an unowned input: {line}")
        if is_foreign_native_runtime(input_path):
            raise LinkError(f"link trace admits ambient native runtime: {line}")


def _elf_facts(output: Path, mode: str, rust_mode: str) -> tuple[str, str]:
    dynamic = run(["readelf", "-dW", output])
    segments = run(["readelf", "-lW", output])
    if "GNU_EH_FRAME" not in segments or "GNU_RELRO" not in segments:
        raise LinkError("owned Rust executable lacks EH-frame header or RELRO")
    if rust_mode == "shared":
        needed = re.findall(r"\(NEEDED\).*\[([^]]+)\]", dynamic)
        sonames = re.findall(r"\(SONAME\).*\[([^]]+)\]", dynamic)
        if mode != "dynamic" or "INTERP" in segments or needed != ["libc.so"] or sonames != [output.name] or "TEXTREL" in dynamic:
            raise LinkError("owned Rust shared object has unapproved runtime dependencies")
    elif mode == "static":
        if "INTERP" in segments or "(NEEDED)" in dynamic:
            raise LinkError("static owned Rust executable admits an interpreter or DSO")
    else:
        needed = re.findall(r"\(NEEDED\).*\[([^]]+)\]", dynamic)
        if INTERPRETER not in segments or needed != ["libc.so"] or "TEXTREL" in dynamic:
            raise LinkError("dynamic owned Rust executable has unapproved runtime dependencies")
    return dynamic, segments


def _record_input(path: Path, *, members: list[str] | None = None) -> dict[str, object]:
    record: dict[str, object] = {"path": str(path), "sha256": sha256(path)}
    if members is not None:
        record["members"] = members
    return record


def link(arguments: list[str]) -> None:
    """Entry point used by rustc after the runner declares every input root."""

    required = ("CRABC_OWNED_RUST_LINK_MODE", "CRABC_OWNED_RUST_PRODUCT", "CRABC_OWNED_RUST_APPLICATION_ROOT")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise LinkError(f"missing owned Rust linker environment: {missing[0]}")
    mode = os.environ["CRABC_OWNED_RUST_LINK_MODE"]
    if mode not in {"static", "dynamic"}:
        raise LinkError(f"unsupported owned Rust link mode: {mode}")
    root = physical_directory(Path(os.environ["CRABC_OWNED_RUST_PRODUCT"]), "owned product root")
    application_root = physical_directory(Path(os.environ["CRABC_OWNED_RUST_APPLICATION_ROOT"]), "Rust application root")
    source_built_value = os.environ.get("CRABC_OWNED_RUST_SOURCE_BUILT_LIBDIR")
    source_built_root = (
        physical_directory(Path(source_built_value), "source-built Rust target library root")
        if source_built_value else None
    )
    toolchain_search_root: Path | None = None
    if source_built_root is not None:
        toolchain_search_value = os.environ.get("CRABC_OWNED_RUST_TOOLCHAIN_SEARCH_ROOT")
        if not toolchain_search_value:
            raise LinkError("missing owned Rust toolchain search root")
        toolchain_search_root = physical_directory(
            Path(toolchain_search_value), "declared Rust toolchain search root",
        )
        host_build_value = os.environ.get("CRABC_OWNED_RUST_HOST_BUILD_ROOT")
        if not host_build_value:
            raise LinkError("missing owned Rust host build-script root")
        host_build_root = physical_directory(Path(host_build_value), "Cargo host build-script root")
        host_output = host_build_script_output(arguments, host_build_root)
        if host_output is not None:
            delegate_host_build_script(arguments, host_output)
            return
    if source_built_root is None:
        stock_value = os.environ.get("CRABC_OWNED_RUST_STOCK_LIBDIR")
        if not stock_value:
            raise LinkError("missing owned Rust linker environment: CRABC_OWNED_RUST_STOCK_LIBDIR")
        stock_root: Path | None = physical_directory(Path(stock_value), "stock Rust target library root")
    else:
        stock_root = None
    provider: Path | None = None
    if source_built_root is None:
        provider_value = os.environ.get("CRABC_OWNED_RUST_PROVIDER")
        if not provider_value:
            raise LinkError("missing owned Rust linker environment: CRABC_OWNED_RUST_PROVIDER")
        provider = physical_regular(Path(provider_value), "selected unwind provider")
    elif os.environ.get("CRABC_OWNED_RUST_PROVIDER"):
        raise LinkError("source-built Rust link must not receive a standalone unwind provider")
    manifest, manifest_files = _read_product(root, mode)
    parsed = parse_arguments(
        arguments, application_root, stock_root, source_built_root,
        toolchain_search_root=toolchain_search_root,
    )
    output = parsed["output"]
    assert isinstance(output, Path)
    if output.exists() or output.is_symlink():
        raise LinkError(f"owned Rust output must be fresh: {output}")
    receipt = Path(str(output) + ".crabc-owned-rust-link.json")
    if receipt.exists() or receipt.is_symlink():
        raise LinkError(f"owned Rust link receipt must be fresh: {receipt}")
    rust_sysroot = Path(run(["rustup", "run", os.environ["CRABC_OWNED_RUST_CHANNEL"], "rustc", "--print", "sysroot"]).strip())
    linker = physical_regular(rust_sysroot / "lib/rustlib" / TARGET / "bin/gcc-ld/ld.lld", "pinned Rust LLD")
    ar = physical_regular(rust_sysroot / "lib/rustlib" / TARGET / "bin/llvm-ar", "pinned Rust llvm-ar")
    nm = physical_regular(rust_sysroot / "lib/rustlib" / TARGET / "bin/llvm-nm", "pinned Rust llvm-nm")
    objects = parsed["objects"]
    archives = parsed["archives"]
    rust_mode = parsed["rust_mode"]
    version_script = parsed["version_script"]
    assert isinstance(objects, list) and isinstance(archives, list) and isinstance(rust_mode, str)
    assert version_script is None or isinstance(version_script, Path)
    input_records: list[dict[str, object]] = []
    for object_path in objects:
        if object_path.read_bytes()[:20][18:20] != b"\x3e\x00":
            raise LinkError(f"Rust application object is not x86-64 ELF: {object_path}")
        input_records.append(_record_input(object_path))
    for archive in archives:
        input_records.append(_record_input(archive, members=audit_rust_archive(archive, ar)))
    source_lto_object: dict[str, object] | None = None
    if source_built_root is not None:
        source_lto_object = source_lto_object_receipt(objects, nm)
    command = link_command(
        linker=linker, root=root, mode=mode, provider=provider, objects=objects, archives=archives,
        output=output, export_dynamic=bool(parsed["export_dynamic"]), rust_mode=rust_mode,
        version_script=version_script,
    )
    trace = run(command)
    runtime = _product_inputs(root, mode)
    validate_trace(trace, {*objects, *archives, *runtime, *( [provider] if provider is not None else [] )})
    dynamic, segments = _elf_facts(output, mode, rust_mode)
    record = {
        "schema": 3 if source_built_root is not None else 1,
        "format": "crabc-owned-rust-source-build-link/v2" if source_built_root is not None else "crabc-owned-rust-std-link/v1",
        "target": TARGET,
        "mode": mode,
        "rust_requested_mode": parsed["rust_mode"],
        "product": {"root": str(root), "manifest": _record_input(manifest), "files": manifest_files},
        "rust_library_origin": parsed["rust_library_origin"],
        "replaced_native_requests": parsed["native_requests"],
        "unused_search_paths": [str(path) for path in parsed["search_paths"]],
        "application_inputs": input_records,
        "resolved_linker": _record_input(linker),
        "command": command,
        "resolved_input_trace": trace,
        "dynamic": dynamic,
        "segments": segments,
        "output": _record_input(output),
        "qualified": False,
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }
    if source_built_root is None:
        assert provider is not None
        record["provider_archive"] = _record_input(provider)
        record["omitted_stock_rust_unwind"] = _record_input(parsed["stock_unwind"])
        record["omitted_compiler_builtins"] = _record_input(parsed["compiler_builtins"])
    else:
        source_compiler_builtins = parsed["source_built_compiler_builtins"]
        assert isinstance(source_compiler_builtins, Path) and source_lto_object is not None
        record["source_built_target_library_root"] = str(source_built_root)
        assert toolchain_search_root is not None
        record["declared_toolchain_search_root"] = str(toolchain_search_root)
        # Cargo builds libunwind for build-std but does not pass it to the
        # final normal Cargo graph. The source provider supplies the approved
        # unwind ABI, so admitting libunwind here would create a second owner.
        record["omitted_source_built_compiler_builtins"] = _record_input(source_compiler_builtins)
        record["source_lto_object"] = source_lto_object
    if version_script is not None:
        record["rust_cdylib_export_script"] = _record_input(version_script)
    with receipt.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main() -> int:
    try:
        link(sys.argv[1:])
    except (LinkError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"crabc-owned-rust-link: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
