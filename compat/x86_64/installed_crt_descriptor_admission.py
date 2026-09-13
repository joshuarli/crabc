#!/usr/bin/env python3
"""Finite negative admission control for the private main-image TLS descriptor.

This is development evidence over one caller-supplied materialized dynamic
product.  It builds a current-source interpreter, reuses one supplied owned
main byte-for-byte for four exact ELF mutations, and links one source-shaped
weak DSO request through the supplied driver.  It has no product or campaign
qualification authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-installed-crt-descriptor-admission/v1"
DESCRIPTOR = "__crabc_x86_64_loader_tls_runtime_v1"
IMAGE = "CRABC_X86_PUBLIC_DATA_IMAGE_ID"
SOURCE_ROOT = "ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs"
SOURCES = (
    SOURCE_ROOT,
    "ldso/src/x86_64_initial_graph.rs",
    "ldso/src/x86_64_general_relocation.rs",
    "ldso/src/x86_64_general_initial_graph.rs",
    "ldso/src/x86_64_general_initial_lifecycle.rs",
    "ldso/src/x86_64_general_initial_tls_state.rs",
    "ldso/src/x86_64_general_relocation_tests.rs",
    "compat/x86_64/installed-crt-startup.toml",
    "compat/x86_64/installed-crt-startup.md",
    "compat/x86_64/installed-crt-descriptor-admission.md",
    "compat/x86_64/installed_crt_descriptor_admission.py",
    "compat/x86_64/installed_crt_descriptor_admission_dso.c",
    "compat/x86_64/installed_crt_descriptor_admission_main.c",
    "compat/x86_64/tests/test_installed_crt_descriptor_admission.py",
)
if len(SOURCES) != len(set(SOURCES)):
    raise RuntimeError("descriptor collector source roster repeats a path")
CASES = {
    "wrong-symbol-type": ("symbol-info", 0x21),
    "wrong-binding": ("symbol-info", 0x10),
    "wrong-relocation-kind": ("relocation-kind", 7),
    "wrong-addend": ("addend", 1),
}
LIMITS = [
    "READY release ordering",
    "descriptor lifetime",
    "generation transitions",
    "fork",
]


class DescriptorAdmissionError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DescriptorAdmissionError(message)


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"not a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(path: Path) -> dict[str, object]:
    mode = stat.S_IMODE(path.lstat().st_mode)
    return {"path": str(path.resolve()), "sha256": digest(path), "size": path.stat().st_size, "mode": mode}


def write_json(path: Path, value: object) -> None:
    require(not path.exists() and not path.is_symlink(), f"refusing to replace {path}")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise DescriptorAdmissionError(f"invalid JSON: {path}") from error


def same_identity(path: Path, recorded: object, label: str) -> None:
    require(type(recorded) is dict and recorded == identity(path), f"{label} identity differs")


def output_identity(output: Path, path: Path) -> dict[str, object]:
    relative = path.resolve().relative_to(output.resolve()).as_posix()
    result = identity(path)
    result["path"] = relative
    return result


def output_file(output: Path, recorded: object, relative: str, label: str) -> Path:
    require(type(recorded) is dict and set(recorded) == {"path", "sha256", "size", "mode"}, f"{label} identity shape differs")
    require(recorded["path"] == relative, f"{label} path differs")
    path = output / relative
    require(not path.is_symlink() and path.resolve() == output / relative, f"{label} path differs")
    actual = output_identity(output, path)
    require(recorded == actual, f"{label} identity differs")
    return path


def source_identities(root: Path) -> dict[str, dict[str, object]]:
    result = {}
    for name in SOURCES:
        record = identity(root / name)
        record["path"] = name
        result[name] = record
    require(set(result) == set(SOURCES), "descriptor source roster differs")
    return result


def tree(path: Path) -> dict[str, dict[str, object]]:
    require(path.is_dir() and not path.is_symlink(), "dynamic product is not a physical directory")
    result: dict[str, dict[str, object]] = {}
    for item in sorted(path.rglob("*"), key=lambda value: value.as_posix()):
        relative = item.relative_to(path).as_posix()
        metadata = item.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            result[relative] = {"kind": "directory", "mode": mode}
        elif stat.S_ISREG(metadata.st_mode):
            result[relative] = {"kind": "file", "mode": mode, "size": metadata.st_size, "sha256": digest(item)}
        elif stat.S_ISLNK(metadata.st_mode):
            result[relative] = {"kind": "symlink", "mode": mode, "target": os.readlink(item)}
        else:
            raise DescriptorAdmissionError(f"dynamic product has unsupported node: {relative}")
    return result


def _elf_descriptor(data: bytes | bytearray) -> tuple[int, int, int]:
    """Return the descriptor dynsym record, linked RELA record, and r_info."""
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "main is not ELF64 little-endian")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    shoff, shentsize, shnum = header[6], header[11], header[12]
    require(shentsize == 64 and shoff + shentsize * shnum <= len(data), "ELF section table differs")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize) for index in range(shnum)]
    names: list[tuple[int, int, int]] = []
    for section_index, section in enumerate(sections):
        if section[1] != 11:
            continue
        offset, size, entry, strings = section[4], section[5], section[9], section[6]
        require(entry == 24 and size % entry == 0 and offset + size <= len(data) and strings < len(sections), "dynsym layout differs")
        string = sections[strings]
        require(string[4] + string[5] <= len(data), "dynstr layout differs")
        for record in range(offset, offset + size, entry):
            name_offset = struct.unpack_from("<I", data, record)[0]
            require(name_offset < string[5], "dynsym name leaves string table")
            start = string[4] + name_offset
            end = data.find(b"\0", start, string[4] + string[5])
            require(end >= 0, "dynsym name is unterminated")
            if bytes(data[start:end]) == DESCRIPTOR.encode():
                names.append((section_index, record, (record - offset) // entry))
    require(len(names) == 1, "descriptor dynsym roster differs")
    section_index, symbol, symbol_index = names[0]
    relocations: list[tuple[int, int]] = []
    for section in sections:
        if section[1] != 4 or section[6] != section_index:
            continue
        offset, size, entry = section[4], section[5], section[9]
        require(entry == 24 and size % entry == 0 and offset + size <= len(data), "RELA layout differs")
        for record in range(offset, offset + size, entry):
            info = struct.unpack_from("<Q", data, record + 8)[0]
            if info >> 32 == symbol_index:
                relocations.append((record, info))
    require(len(relocations) == 1, "descriptor relocation roster differs")
    relocation, info = relocations[0]
    require(data[symbol + 4] == 0x20 and data[symbol + 5] & 3 == 0
            and struct.unpack_from("<H", data, symbol + 6)[0] == 0
            and info & 0xffffffff == 6 and struct.unpack_from("<q", data, relocation + 16)[0] == 0,
            "descriptor positive admission shape differs")
    return symbol, relocation, info


def mutate_main(source: Path, destination: Path, label: str) -> dict[str, object]:
    require(label in CASES, "descriptor mutation label differs")
    before = source.read_bytes()
    data = bytearray(before)
    symbol, relocation, info = _elf_descriptor(data)
    field, value = CASES[label]
    if field == "symbol-info":
        data[symbol + 4] = value
    elif field == "relocation-kind":
        struct.pack_into("<Q", data, relocation + 8, (info & ~0xffffffff) | value)
    else:
        struct.pack_into("<q", data, relocation + 16, value)
    destination.write_bytes(data)
    destination.chmod(source.stat().st_mode & 0o777)
    return {"case": label, "input": identity(source), "output": identity(destination),
            "symbol_file_offset": symbol, "rela_file_offset": relocation,
            "field": field, "expected_value": value}


def run(output: Path, label: str, argv: list[str], *, required: bool) -> dict[str, object]:
    raw = output / "raw"
    raw.mkdir(exist_ok=True)
    command, stdout, stderr, status = (raw / f"{label}.{suffix}" for suffix in ("command.json", "stdout", "stderr", "status"))
    write_json(command, argv)
    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    stdout.write_bytes(completed.stdout)
    stderr.write_bytes(completed.stderr)
    status.write_text(f"{completed.returncode}\n", encoding="ascii")
    if required:
        require(completed.returncode == 0 and completed.stderr == b"", f"descriptor command failed: {label}")
    return {"label": label, "argv": argv, "command": output_identity(output, command), "stdout": output_identity(output, stdout),
            "stderr": output_identity(output, stderr), "status": output_identity(output, status), "returncode": completed.returncode}


def contract() -> dict[str, object]:
    return {"descriptor": DESCRIPTOR, "positive": {"type": "NOTYPE", "binding": "WEAK", "kind": "GLOB_DAT", "addend": 0},
            "negative_cases": list(CASES), "endpoints": ["main-image", "dso"], "modes": ["kernel", "direct"],
            "no_application_main_on_rejection": True, "qualification": False}


def collect(root: Path, output: Path, dynamic: Path, main: Path) -> Path:
    root, output, dynamic, main = root.resolve(), output.resolve(), dynamic.resolve(), main.resolve()
    require(sys.platform == "linux" and os.uname().machine == "x86_64" and os.geteuid() == 0, "native root x86-64 collection required")
    require(os.environ.get("LC_ALL") == "C" and os.environ.get(IMAGE, "").startswith("crabc-core-evidence@sha256:"), "pinned C-locale collection required")
    require(output.parent == root / ".work" / "x86_64" and not output.exists(), "fresh descriptor output must be under .work/x86_64")
    require((dynamic / "bin/crabc-cc-dynamic").is_file() and (dynamic / "lib/ld-crabc-x86_64.so.1").is_file(), "supplied dynamic product differs")
    require(main.is_file() and not main.is_symlink(), "supplied owned main differs")
    source_before, product_before, main_before = source_identities(root), tree(dynamic), identity(main)
    output.mkdir(parents=True)
    try:
        execution = output / "execution-root"
        shutil.copytree(dynamic, execution, symlinks=True)
        loader_archive, loader = output / "loader.a", output / "ld-crabc-x86_64.so.1"
        rust = ["rustc", "--edition=2021", "--crate-type", "staticlib", "-C", "panic=abort", "-C", "relocation-model=pic",
                "--cfg", "crabc_general_initial_graph", "--cfg", "crabc_general_initial_lifecycle",
                "--cfg", "crabc_general_initial_tls_materialization_v1", "--cfg", "crabc_general_loader_libc_tls_runtime_v1",
                "--cfg", "crabc_dynamic_main_thread_runtime_v1", "--cfg", 'feature="x86_64-owned-dynamic-runtime"',
                str(root / SOURCE_ROOT), "-o", str(loader_archive)]
        commands = [run(output, "build-loader-archive", rust, required=True)]
        commands.append(run(output, "build-loader", ["cc", "-nostdlib", "-shared", "-Wl,-e,_start", "-Wl,-Bsymbolic", "-Wl,-z,now", "-Wl,--no-undefined", "-Wl,--whole-archive", str(loader_archive), "-Wl,--no-whole-archive", "-o", str(loader)], required=True))
        shutil.copy2(loader, execution / "lib/ld-crabc-x86_64.so.1")
        driver = dynamic / "bin/crabc-cc-dynamic"
        rogue, endpoint = output / "libdescriptor-rogue.so", output / "dso-endpoint"
        commands.append(run(output, "build-dso", [str(driver), "--dynamic-shared-object", str(root / "compat/x86_64/installed_crt_descriptor_admission_dso.c"), "-o", str(rogue)], required=True))
        commands.append(run(output, "build-dso-endpoint", [str(driver), "--dynamic-pie", "--application-dso", str(rogue), str(root / "compat/x86_64/installed_crt_descriptor_admission_main.c"), "-o", str(endpoint)], required=True))
        shutil.copy2(rogue, execution / "usr/lib/libdescriptor-rogue.so")
        shutil.copy2(endpoint, execution / "dso-endpoint")
        shutil.copy2(main, execution / "control")
        mutations = {label: mutate_main(main, execution / label, label) for label in CASES}
        for mutation in mutations.values():
            mutation["output"] = output_identity(output, execution / str(mutation["case"]))
        for mode in ("kernel", "direct"):
            prefix = ["/usr/sbin/chroot", str(execution)]
            for label in ("control", *CASES, "dso-endpoint"):
                argv = ["/usr/bin/env", "-i", "CRABC_STARTUP=yes", *prefix]
                if mode == "direct":
                    argv.append("/lib/ld-crabc-x86_64.so.1")
                argv.extend(["/" + label, "owned"] if label != "dso-endpoint" else ["/dso-endpoint"])
                commands.append(run(output, f"{label}-{mode}", argv, required=False))
        report = {"schema": SCHEMA, "contract": contract(), "image": os.environ[IMAGE], "status": {"qualification": False, "public_support": False},
                  "source": source_before, "inputs": {"dynamic_product": {"path": str(dynamic), "tree": product_before}, "owned_main": main_before},
                  "generated": {"loader": output_identity(output, loader), "rogue_dso": output_identity(output, rogue), "dso_endpoint": output_identity(output, endpoint)},
                  "mutations": mutations, "execution_tree": tree(execution), "commands": commands,
                  "limits": LIMITS}
        _validate_report(root, output, report)
        write_json(output / "report.json", report)
        require(source_before == source_identities(root) and product_before == tree(dynamic) and main_before == identity(main), "supplied input changed during collection")
    finally:
        for path in output.rglob("*"):
            if path.is_file() and not path.is_symlink(): path.chmod(path.stat().st_mode | 0o444)
    validate_report(root, output / "report.json")
    return output / "report.json"


def _validate_report(root: Path, output: Path, report: object) -> None:
    require(type(report) is dict and set(report) == {"schema", "contract", "image", "status", "source", "inputs", "generated", "mutations", "execution_tree", "commands", "limits"}, "descriptor report fields differ")
    require(report["schema"] == SCHEMA and report["contract"] == contract()
            and report["status"] == {"qualification": False, "public_support": False}
            and report["limits"] == LIMITS, "descriptor report contract differs")
    require(type(report["image"]) is str and report["image"].startswith("crabc-core-evidence@sha256:"), "descriptor image identity differs")
    require(report["source"] == source_identities(root), "descriptor collector source differs")
    inputs = report["inputs"]
    require(type(inputs) is dict and set(inputs) == {"dynamic_product", "owned_main"}, "descriptor input roster differs")
    dynamic = inputs["dynamic_product"]
    require(type(dynamic) is dict and set(dynamic) == {"path", "tree"}, "descriptor dynamic input differs")
    dynamic_path = Path(dynamic["path"])
    require(dynamic_path.is_absolute() and dynamic["tree"] == tree(dynamic_path), "descriptor dynamic product differs")
    owned_main = inputs["owned_main"]
    require(type(owned_main) is dict and set(owned_main) == {"path", "sha256", "size", "mode"}, "descriptor main input differs")
    main_path = Path(owned_main["path"])
    require(main_path.is_absolute() and not main_path.is_symlink(), "descriptor main input path differs")
    same_identity(main_path, owned_main, "descriptor main input")
    symbol, relocation, info = _elf_descriptor(main_path.read_bytes())
    generated = report["generated"]
    require(type(generated) is dict and set(generated) == {"loader", "rogue_dso", "dso_endpoint"}, "descriptor generated roster differs")
    output_file(output, generated["loader"], "ld-crabc-x86_64.so.1", "descriptor loader")
    rogue = output_file(output, generated["rogue_dso"], "libdescriptor-rogue.so", "descriptor rogue DSO")
    endpoint = output_file(output, generated["dso_endpoint"], "dso-endpoint", "descriptor DSO endpoint")
    # The application driver retains its own canonical main slot.  Reparse it
    # and the dependency separately, so the DSO negative control cannot pass
    # merely because the link stopped emitting the dependency's weak request.
    _elf_descriptor(rogue.read_bytes())
    _elf_descriptor(endpoint.read_bytes())
    require(type(report["mutations"]) is dict and set(report["mutations"]) == set(CASES), "descriptor mutation roster differs")
    for label, (field, value) in CASES.items():
        mutation = report["mutations"][label]
        require(type(mutation) is dict and set(mutation) == {"case", "input", "output", "symbol_file_offset", "rela_file_offset", "field", "expected_value"}, "descriptor mutation shape differs")
        require(mutation["case"] == label and mutation["input"] == owned_main
                and mutation["symbol_file_offset"] == symbol and mutation["rela_file_offset"] == relocation
                and mutation["field"] == field and mutation["expected_value"] == value,
                "descriptor mutation contract differs")
        mutated = output_file(output, mutation["output"], "execution-root/" + label, "descriptor " + label)
        expected = bytearray(main_path.read_bytes())
        if field == "symbol-info":
            expected[symbol + 4] = value
        elif field == "relocation-kind":
            struct.pack_into("<Q", expected, relocation + 8, (info & ~0xffffffff) | value)
        else:
            struct.pack_into("<q", expected, relocation + 16, value)
        require(mutated.read_bytes() == expected, "descriptor mutation bytes differ")
    execution = output / "execution-root"
    require(report["execution_tree"] == tree(execution), "descriptor execution tree differs")
    commands = report["commands"]
    require(type(commands) is list and len(commands) == 16, "descriptor command roster differs")
    rows = {row["label"]: row for row in commands if type(row) is dict}
    require(len(rows) == len(commands), "descriptor command labels differ")
    expected_labels = {"build-loader-archive", "build-loader", "build-dso", "build-dso-endpoint"}
    expected_labels.update(label + "-" + mode for label in ("control", *CASES, "dso-endpoint") for mode in ("kernel", "direct"))
    require(set(rows) == expected_labels, "descriptor command labels differ")
    for label, row in rows.items():
        require(set(row) == {"label", "argv", "command", "stdout", "stderr", "status", "returncode"}
                and row["label"] == label and type(row["argv"]) is list
                and all(type(value) is str for value in row["argv"])
                and type(row["returncode"]) is int, "descriptor command shape differs")
        command = output_file(output, row["command"], "raw/" + label + ".command.json", "descriptor command")
        require(read_json(command) == row["argv"], "descriptor command argv differs")
        output_file(output, row["stdout"], "raw/" + label + ".stdout", "descriptor stdout")
        output_file(output, row["stderr"], "raw/" + label + ".stderr", "descriptor stderr")
        status = output_file(output, row["status"], "raw/" + label + ".status", "descriptor status")
        require(status.read_text(encoding="ascii") == str(row["returncode"]) + "\n", "descriptor status bytes differ")
    for label in ("build-loader-archive", "build-loader", "build-dso", "build-dso-endpoint"):
        require(rows.get(label, {}).get("returncode") == 0, "descriptor build outcome differs")
    for mode in ("kernel", "direct"):
        control = rows.get("control-" + mode, {})
        require(control.get("returncode") == 0
                and (output / control["stdout"]["path"]).read_bytes() == b"PICOMAFL\n"
                and (output / control["stderr"]["path"]).read_bytes() == b"", "descriptor positive control differs")
        for label in (*CASES, "dso-endpoint"):
            row = rows.get(label + "-" + mode, {})
            require(row.get("returncode") == 127
                    and (output / row["stdout"]["path"]).read_bytes() == b""
                    and (output / row["stderr"]["path"]).read_bytes() == b"reloc\n",
                    "descriptor rejection outcome differs")


def validate_report(root: Path, report_path: Path) -> None:
    root = root.resolve()
    require(report_path.is_file() and not report_path.is_symlink(), "descriptor report is not a regular file")
    report_path = report_path.resolve()
    require(report_path.parent.parent == root / ".work" / "x86_64", "descriptor report escapes .work/x86_64")
    _validate_report(root, report_path.parent, read_json(report_path))


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    options = [value.split("=", 1)[0] for value in values if value.startswith("--")]
    require(len(options) == len(set(options)), "duplicate descriptor option")
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("mode", choices=("collect", "validate-report"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dynamic-product", type=Path)
    parser.add_argument("--owned-main", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(values)
    if args.mode == "collect":
        require(args.output is not None and args.dynamic_product is not None and args.owned_main is not None and args.report is None, "descriptor collect arguments differ")
        path = collect(ROOT, args.output, args.dynamic_product, args.owned_main)
    else:
        require(args.report is not None and args.output is None and args.dynamic_product is None and args.owned_main is None, "descriptor replay arguments differ")
        validate_report(ROOT, args.report); path = args.report
    print(json.dumps({"schema": SCHEMA, "report": str(path), "sha256": digest(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DescriptorAdmissionError, OSError, subprocess.SubprocessError) as error:
        print(f"installed CRT descriptor admission: {error}", file=sys.stderr)
        raise SystemExit(2)
