#!/usr/bin/env python3
"""Link one stock-Rust executable only against declared owned runtime inputs.

``owned_cleanup.py`` is the sole caller.  Rust invokes this program as its
linker, but it cannot select a linker search path or a native fallback: this
file replaces Rust's target ``libunwind``/compiler-builtins inputs and native
``-l`` requests with the explicitly supplied provider and product files.
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
    """Accept one not-yet-created output without permitting symlink traversal."""

    candidate = _absolute(Path(path))
    if ".." in Path(path).parts or not candidate.is_relative_to(root):
        raise LinkError(f"Rust output is outside the declared application root: {path}")
    if candidate.parent != root:
        physical_directory(candidate.parent, "Rust output parent")
    return candidate


def is_foreign_native_runtime(argument: str) -> bool:
    name = Path(argument).name
    if argument.startswith("-l:"):
        name = argument.removeprefix("-l:")
    elif argument.startswith("-l") and len(argument) > 2:
        name = argument.removeprefix("-l")
    return name.startswith(("libgcc", "libunwind", "gcc", "unwind"))


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


def parse_arguments(arguments: list[str], application_root: Path, stock_root: Path) -> dict[str, object]:
    """Parse the finite rustc linker dialect without forwarding any raw flag."""

    objects: list[Path] = []
    archives: list[Path] = []
    search_paths: list[Path] = []
    native_requests: list[str] = []
    stock_unwind: Path | None = None
    compiler_builtins: Path | None = None
    output: Path | None = None
    rust_mode: str | None = None
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
                search_paths.append(confined(value, [application_root, stock_root], "Rust search path", directory=True))
        elif argument in {"-pie", "-no-pie"}:
            if rust_mode is not None:
                raise LinkError("duplicate or conflicting Rust executable mode")
            rust_mode = argument.removeprefix("-")
        elif argument == "-Wl,--export-dynamic":
            export_dynamic = True
        elif argument in NATIVE_REQUESTS:
            native_requests.append(argument)
        elif argument in CANONICAL_FLAGS:
            pass
        elif argument.endswith(".rlib"):
            archive = confined(argument, [application_root, stock_root], "Rust archive")
            if _stock_archive(archive, stock_root, STOCK_RUST_UNWIND_ARCHIVE):
                if stock_unwind is not None:
                    raise LinkError("duplicate stock Rust libunwind archive")
                stock_unwind = archive
            elif _stock_archive(archive, stock_root, COMPILER_BUILTINS_ARCHIVE):
                if compiler_builtins is not None:
                    raise LinkError("duplicate Rust compiler-builtins archive")
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
        raise LinkError("expected output, executable mode, and Rust application objects")
    if stock_unwind is None:
        raise LinkError("missing exact stock Rust libunwind archive")
    if compiler_builtins is None:
        raise LinkError("missing exact Rust compiler-builtins archive")
    if "-lc" not in native_requests or not set(native_requests) & {"-lgcc", "-lgcc_s"}:
        raise LinkError("missing Rust libc or libgcc request")
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
    *, linker: Path, root: Path, mode: str, provider: Path, objects: list[Path], archives: list[Path], output: Path,
    export_dynamic: bool,
) -> list[str]:
    """Return the entire native command; there are no library-search holes."""

    runtime = _product_inputs(root, mode)
    if mode == "static":
        return [
            str(linker), "-static", "--no-dynamic-linker", "--no-undefined", "--eh-frame-hdr",
            "--gc-sections", "-z", "noexecstack", "-z", "relro", "-z", "now", "-e", "_start",
            "--trace", "-o", str(output), str(runtime[0]), str(runtime[1]),
            *map(str, objects), *map(str, archives), str(provider), str(runtime[2]), str(runtime[3]), str(runtime[4]),
        ]
    return [
        str(linker), "-pie", "--hash-style=sysv", "--eh-frame-hdr", "--gc-sections", "--no-undefined",
        "--allow-shlib-undefined", "-z", "text", "-z", "noexecstack", "-z", "relro", "-z", "now",
        "--dynamic-linker", INTERPRETER, *( ["--export-dynamic"] if export_dynamic else [] ),
        "--trace", "-o", str(output), str(runtime[0]), str(runtime[1]), str(runtime[2]),
        *map(str, objects), *map(str, archives), str(provider), str(runtime[3]), str(runtime[4]), str(runtime[5]),
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


def _elf_facts(output: Path, mode: str) -> tuple[str, str]:
    dynamic = run(["readelf", "-dW", output])
    segments = run(["readelf", "-lW", output])
    if "GNU_EH_FRAME" not in segments or "GNU_RELRO" not in segments:
        raise LinkError("owned Rust executable lacks EH-frame header or RELRO")
    if mode == "static":
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

    required = (
        "CRABC_OWNED_RUST_LINK_MODE", "CRABC_OWNED_RUST_PRODUCT", "CRABC_OWNED_RUST_PROVIDER",
        "CRABC_OWNED_RUST_STOCK_LIBDIR", "CRABC_OWNED_RUST_APPLICATION_ROOT",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise LinkError(f"missing owned Rust linker environment: {missing[0]}")
    mode = os.environ["CRABC_OWNED_RUST_LINK_MODE"]
    if mode not in {"static", "dynamic"}:
        raise LinkError(f"unsupported owned Rust link mode: {mode}")
    root = physical_directory(Path(os.environ["CRABC_OWNED_RUST_PRODUCT"]), "owned product root")
    application_root = physical_directory(Path(os.environ["CRABC_OWNED_RUST_APPLICATION_ROOT"]), "Rust application root")
    stock_root = physical_directory(Path(os.environ["CRABC_OWNED_RUST_STOCK_LIBDIR"]), "stock Rust target library root")
    provider = physical_regular(Path(os.environ["CRABC_OWNED_RUST_PROVIDER"]), "selected unwind provider")
    manifest, manifest_files = _read_product(root, mode)
    parsed = parse_arguments(arguments, application_root, stock_root)
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
    objects = parsed["objects"]
    archives = parsed["archives"]
    assert isinstance(objects, list) and isinstance(archives, list)
    input_records: list[dict[str, object]] = []
    for object_path in objects:
        if object_path.read_bytes()[:20][18:20] != b"\x3e\x00":
            raise LinkError(f"Rust application object is not x86-64 ELF: {object_path}")
        input_records.append(_record_input(object_path))
    for archive in archives:
        input_records.append(_record_input(archive, members=audit_rust_archive(archive, ar)))
    command = link_command(
        linker=linker, root=root, mode=mode, provider=provider, objects=objects, archives=archives,
        output=output, export_dynamic=bool(parsed["export_dynamic"]),
    )
    trace = run(command)
    runtime = _product_inputs(root, mode)
    validate_trace(trace, {provider, *objects, *archives, *runtime})
    dynamic, segments = _elf_facts(output, mode)
    record = {
        "schema": 1,
        "format": "crabc-owned-rust-std-link/v1",
        "target": TARGET,
        "mode": mode,
        "rust_requested_mode": parsed["rust_mode"],
        "product": {"root": str(root), "manifest": _record_input(manifest), "files": manifest_files},
        "provider_archive": _record_input(provider),
        "omitted_stock_rust_unwind": _record_input(parsed["stock_unwind"]),
        "omitted_compiler_builtins": _record_input(parsed["compiler_builtins"]),
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
