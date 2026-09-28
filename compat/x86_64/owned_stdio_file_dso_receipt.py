#!/usr/bin/env python3
"""Collect and reread byte, cookie and wide FILE handoffs across a DSO.

The executable owns pathname and cookie FILEs used by its DSO. The DSO also
creates a cookie FILE whose callbacks it owns while main uses and closes it.
The DSO sets wide orientation on a main-owned pathname FILE, then main reads
the same non-ASCII character. Static links run the same functions in one image
as a baseline; only dynamic cells prove the cross-image handoffs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import core_image
import owned_posix_product_evidence as products
import owned_posix_static_products as static_products
import owned_pthread_alias_contract_reader as pthread_receipt

SCHEMA = "crabc.x86_64-owned-stdio-file-dso/v1"
SOURCES = (
    "compat/x86_64/owned_stdio_file_dso_main_probe.c",
    "compat/x86_64/owned_stdio_file_dso_library_probe.c",
    "compat/x86_64/owned_stdio_file_dso_probe.h",
    "compat/x86_64/owned_stdio_file_dso_receipt.py",
)
EXPECTED_STDOUT = b"stdio-file-dso-wide-ok\n"
ORACLE_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
ORACLE_ARCHIVE = Path("/opt/musl-1.2.6/lib/libc.a")
ORACLE_LIBC = Path("/opt/musl-1.2.6/lib/libc.so")
TOOLS = {
    "ar": Path("/usr/bin/ar"), "nm": Path("/usr/bin/nm"),
    "readelf": Path("/usr/bin/readelf"), "strace": Path("/usr/bin/strace"),
    "chroot": Path("/usr/sbin/chroot"),
}
CASES = (
    "oracle-static-process", "candidate-static-process", "candidate-static-pie-process",
    "oracle-pie-kernel", "oracle-pie-direct", "oracle-non-pie-kernel", "oracle-non-pie-direct",
    "candidate-pie-kernel", "candidate-pie-direct", "candidate-non-pie-kernel", "candidate-non-pie-direct",
)
ELFS = (
    "oracle-static", "candidate-static", "candidate-static-pie",
    "oracle-libfile-dso.so", "candidate-libfile-dso.so",
    "oracle-pie", "oracle-non-pie", "candidate-pie", "candidate-non-pie",
)
STRACE_FILTER = "trace=open,openat,unlink,unlinkat,close,fcntl,fstat,newfstatat,read,write,writev,pwrite64"


class ReceiptError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ReceiptError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> object:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate receipt key: {path}: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def same(left: object, right: object) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def write_new(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")


def physical(root: Path, path: Path, description: str, *, directory: bool = False) -> Path:
    require(path.is_absolute() and ".." not in path.parts and path.is_relative_to(root / ".work"),
            f"{description} must be a physical checkout .work path")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        require(not current.is_symlink(), f"{description} traverses a symlink")
    require(path.is_dir() if directory else path.is_file(), f"{description} is missing")
    return path


def file_identity(root: Path, path: Path) -> dict[str, object]:
    require(path.is_file() and not path.is_symlink(), f"artifact is not a regular file: {path}")
    return {"path": path.relative_to(root).as_posix(), "size": path.stat().st_size,
            "mode": stat.S_IMODE(path.stat().st_mode), "sha256": digest(path)}


def source_copies(root: Path, work: Path, *, capture: bool) -> dict[str, object]:
    result = {}
    for name in SOURCES:
        source = root / name
        retained = work / "inputs/source" / name
        if capture:
            retained.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, retained)
        require(retained.read_bytes() == source.read_bytes(), f"selected source changed: {name}")
        result[name] = file_identity(root, retained)
    return result


def oracle_copies(root: Path, work: Path, *, capture: bool) -> dict[str, object]:
    result = {}
    for name, source in (("compiler", ORACLE_CC), ("archive", ORACLE_ARCHIVE), ("libc", ORACLE_LIBC),
                         *((name, path) for name, path in TOOLS.items())):
        retained = work / "inputs/oracle" / name
        if capture:
            retained.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, retained)
        require(retained.read_bytes() == source.read_bytes(), f"pinned image input changed: {name}")
        result[name] = file_identity(root, retained)
    return result


def selected_products(root: Path, preparation: Path, static: Path, dynamic: Path) -> dict[str, object]:
    preparation = physical(root, preparation, "static preparation")
    static = physical(root, static, "static product", directory=True)
    dynamic = physical(root, dynamic, "dynamic product", directory=True)
    require(preparation.name == "preparation.json" and static == preparation.parent / "products/primary",
            "static product is not the prepared primary")
    source = static_products.source_identity(root)
    prepared = read_json(preparation)
    require(prepared["schema"] == static_products.SCHEMA and prepared["source"] == source,
            "static preparation source differs")
    for name in ("source-before.json", "source-after.json"):
        require(same(read_json(preparation.parent / name), source), "static source seal differs")
    static_manifest, _ = products._validate_static_product(static)
    dynamic_manifest, dynamic_files = products._validate_dynamic_product(dynamic)
    require(same(static_products.tree_identity(static), prepared["products"]["primary"]["tree"]),
            "prepared static product bytes differ")
    pthread_receipt._validate_dynamic_materialization_state(
        read_json(dynamic / "share/crabc/dynamic-product-state.json"), source["content_sha256"],
        dynamic_files, "FILE DSO dynamic product")
    static_command = read_json(static / "share/crabc/build.commands.json")["commands"]["libc"]
    dynamic_command = read_json(dynamic / "share/crabc/libc-shared.provenance.json")["libc_command"]
    for command, feature in ((static_command, "x86-owned-static-runtime"),
                             (dynamic_command, "x86-owned-dynamic-runtime")):
        require(command.count("--features") == 1 and command[command.index("--features") + 1] == feature,
                "selected libc feature differs")
    return {
        "source": source, "preparation": file_identity(root, preparation),
        "static": {"path": static.relative_to(root).as_posix(), "manifest": file_identity(root, static_manifest),
                   "archive": file_identity(root, static / "usr/lib/libc.a"),
                   "driver": file_identity(root, static / "bin/crabc-cc")},
        "dynamic": {"path": dynamic.relative_to(root).as_posix(), "manifest": file_identity(root, dynamic_manifest),
                    "state": file_identity(root, dynamic / "share/crabc/dynamic-product-state.json"),
                    "libc": file_identity(root, dynamic / "usr/lib/libc.so"),
                    "loader": file_identity(root, dynamic / "lib/ld-crabc-x86_64.so.1"),
                    "driver": file_identity(root, dynamic / "bin/crabc-cc-dynamic")},
    }


def commands(root: Path, work: Path, static: Path, dynamic: Path) -> dict[str, list[str]]:
    main = root / SOURCES[0]
    library = root / SOURCES[1]
    main_object, library_object = work / "main.o", work / "library.o"
    oracle_dso, candidate_dso = work / "oracle/libfile-dso.so", work / "candidate/libfile-dso.so"
    oracle = str(ORACLE_CC)
    static_driver = str(static / "bin/crabc-cc")
    dynamic_driver = str(dynamic / "bin/crabc-cc-dynamic")
    common = ["-std=c11", "-D_GNU_SOURCE", "-fno-builtin", "-fno-stack-protector"]
    result = {
        "main-compile": [dynamic_driver, "--dynamic-pie", *common, "-c", str(main), "-o", str(main_object)],
        "library-compile": [dynamic_driver, "--dynamic-shared-object", *common, "-c", str(library), "-o", str(library_object)],
        "oracle-static-link": [oracle, "-static", "-fno-pie", "-no-pie", str(main_object), str(library_object),
                               "-o", str(work / "oracle-static")],
        "candidate-static-link": [static_driver, "-static", "--link-receipt", "candidate-static.link.json",
                                  str(main_object), str(library_object), "-o", str(work / "candidate-static")],
        "candidate-static-pie-link": [static_driver, "-static-pie", "--link-receipt", "candidate-static-pie.link.json",
                                      str(main_object), str(library_object), "-o", str(work / "candidate-static-pie")],
        "oracle-dso-link": [oracle, "-shared", "-fPIC", "-Wl,-soname,libfile-dso.so", str(library_object),
                            "-o", str(oracle_dso)],
        "candidate-dso-link": [dynamic_driver, "--dynamic-shared-object", str(library_object),
                               "-o", str(candidate_dso)],
    }
    for mode, oracle_flags in (("pie", ["-fPIE", "-pie"]), ("non-pie", ["-fno-pie", "-no-pie"])):
        result[f"oracle-{mode}-link"] = [oracle, *oracle_flags,
            "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1", str(main_object),
            "-L" + str(oracle_dso.parent), "-Wl,-rpath,/usr/lib", "-l:libfile-dso.so",
            "-o", str(work / f"oracle-{mode}")]
        result[f"candidate-{mode}-link"] = [dynamic_driver, "--dynamic-" + mode,
            str(main_object), "--application-dso", str(candidate_dso),
            "-o", str(work / f"candidate-{mode}")]
    result["oracle-archive-members"] = [str(TOOLS["ar"]), "t", str(ORACLE_ARCHIVE)]
    result["candidate-archive-members"] = [str(TOOLS["ar"]), "t", str(static / "usr/lib/libc.a")]
    result["oracle-archive-symbols"] = [str(TOOLS["nm"]), "-A", "--defined-only", str(ORACLE_ARCHIVE)]
    result["candidate-archive-symbols"] = [str(TOOLS["nm"]), "-A", "--defined-only", str(static / "usr/lib/libc.a")]
    for role in ELFS:
        artifact = (work / role if not role.endswith(".so") else
                    work / role.split("-", 1)[0] / "libfile-dso.so")
        for option, suffix in (("-hW", "header"), ("-lW", "segments"),
                               ("-dW", "dynamic"), ("-sW", "symbols")):
            result[f"{role}-{suffix}"] = [str(TOOLS["readelf"]), option, str(artifact)]
    return result


def case_program(work: Path, case: str) -> Path:
    return work / case.rsplit("-", 1)[0]


def case_command(work: Path, case: str) -> list[str]:
    root = work / "execution-roots" / case
    entry = case.rsplit("-", 1)[1]
    if entry == "direct":
        interpreter = ("/lib/ld-musl-x86_64.so.1" if case.startswith("oracle-") else
                       "/lib/ld-crabc-x86_64.so.1")
        target = [str(TOOLS["chroot"]), str(root), interpreter, "/consumer", "/scratch/stream"]
    else:
        target = [str(TOOLS["chroot"]), str(root), "/consumer", "/scratch/stream"]
    return [str(TOOLS["strace"]), "-f", "-qq", "-x", "-s", "256", "-e", STRACE_FILTER,
            "-o", str(work / "raw" / (case + ".strace")), *target]


def capture(work: Path, label: str, argv: list[str]) -> None:
    raw = work / "raw"
    raw.mkdir(exist_ok=True)
    write_new(raw / f"{label}.argv.json", argv)
    try:
        result = subprocess.run(argv, cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=45, check=False)
        status, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        status, stdout, stderr = 124, error.stdout or b"", error.stderr or b""
    (raw / f"{label}.stdout").write_bytes(stdout)
    (raw / f"{label}.stderr").write_bytes(stderr)
    (raw / f"{label}.status").write_text(f"{status}\n", encoding="ascii")
    require(status == 0, f"{label} exited {status}; raw evidence: {work}")


def make_root(work: Path, case: str, dynamic: Path) -> None:
    execution = work / "execution-roots" / case
    owner = case.split("-", 1)[0]
    mode = case.rsplit("-", 1)[0].split("-", 1)[1]
    if owner == "candidate" and mode in ("pie", "non-pie"):
        shutil.copytree(dynamic, execution, symlinks=True)
        shutil.copy2(work / "candidate/libfile-dso.so", execution / "usr/lib/libfile-dso.so")
    else:
        execution.mkdir(parents=True)
        if owner == "oracle" and mode in ("pie", "non-pie"):
            (execution / "lib").mkdir()
            (execution / "usr/lib").mkdir(parents=True)
            for directory in (execution / "lib", execution / "usr", execution / "usr/lib"):
                directory.chmod(0o755)
            shutil.copy2(ORACLE_LIBC, execution / "lib/ld-musl-x86_64.so.1")
            (execution / "lib/libc.so").symlink_to("ld-musl-x86_64.so.1")
            shutil.copy2(work / "oracle/libfile-dso.so", execution / "usr/lib/libfile-dso.so")
    (execution / "scratch").mkdir()
    (execution / "scratch").chmod(0o755)
    shutil.copy2(case_program(work, case), execution / "consumer")


def tree(path: Path) -> dict[str, object]:
    result = {}
    for current, directories, files in os.walk(path, followlinks=False):
        base = Path(current)
        for name in sorted([*directories, *files]):
            item = base / name
            relative = item.relative_to(path).as_posix()
            mode = item.lstat().st_mode
            if stat.S_ISLNK(mode):
                result[relative] = {"kind": "symlink", "target": os.readlink(item)}
            elif stat.S_ISDIR(mode):
                result[relative] = {"kind": "directory", "mode": stat.S_IMODE(mode)}
            else:
                require(stat.S_ISREG(mode), f"non-regular evidence artifact: {item}")
                result[relative] = {"kind": "file", "mode": stat.S_IMODE(mode),
                                    "size": item.stat().st_size, "sha256": digest(item)}
        directories[:] = [name for name in directories if not (base / name).is_symlink()]
    return result


def expected_root(work: Path, case: str, dynamic: Path) -> dict[str, object]:
    owner = case.split("-", 1)[0]
    mode = case.rsplit("-", 1)[0].split("-", 1)[1]
    if owner == "candidate" and mode in ("pie", "non-pie"):
        expected = tree(dynamic)
        dso = work / "candidate/libfile-dso.so"
        expected["usr/lib/libfile-dso.so"] = {"kind": "file", "mode": stat.S_IMODE(dso.stat().st_mode),
                                             "size": dso.stat().st_size, "sha256": digest(dso)}
    elif owner == "oracle" and mode in ("pie", "non-pie"):
        libc = work / "inputs/oracle/libc"
        dso = work / "oracle/libfile-dso.so"
        expected = {"lib": {"kind": "directory", "mode": 0o755},
                    "usr": {"kind": "directory", "mode": 0o755},
                    "usr/lib": {"kind": "directory", "mode": 0o755},
                    "lib/libc.so": {"kind": "symlink", "target": "ld-musl-x86_64.so.1"},
                    "lib/ld-musl-x86_64.so.1": {"kind": "file", "mode": 0o755,
                        "size": libc.stat().st_size, "sha256": digest(libc)},
                    "usr/lib/libfile-dso.so": {"kind": "file", "mode": stat.S_IMODE(dso.stat().st_mode),
                        "size": dso.stat().st_size, "sha256": digest(dso)}}
    else:
        expected = {}
    program = case_program(work, case)
    expected["consumer"] = {"kind": "file", "mode": stat.S_IMODE(program.stat().st_mode),
                            "size": program.stat().st_size, "sha256": digest(program)}
    expected["scratch"] = {"kind": "directory", "mode": 0o755}
    return expected


def files(work: Path) -> dict[str, object]:
    return {name: value for name, value in tree(work).items() if name != "report.json"}


def audit_runtime(work: Path, dynamic: Path) -> None:
    raw = work / "raw"
    for case in CASES:
        require((raw / f"{case}.status").read_bytes() == b"0\n", f"{case} status differs")
        require((raw / f"{case}.stdout").read_bytes() == EXPECTED_STDOUT, f"{case} stdout differs")
        require((raw / f"{case}.stderr").read_bytes() == b"", f"{case} stderr differs")
        require(read_json(raw / f"{case}.scratch-before.json") == []
                and read_json(raw / f"{case}.scratch-after.json") == []
                and not any((work / "execution-roots" / case / "scratch").iterdir()),
                f"{case} pathname cleanup differs")
        trace = (raw / f"{case}.strace").read_text(encoding="utf-8")
        require(re.search(r'unlink\("/scratch/stream"\)\s+=\s+0', trace) is not None,
                f"{case} did not unlink the main-owned pathname")
        require(re.search(r'fcntl\([0-9]+, F_GETFD\)\s+=\s+-1 EBADF', trace) is not None,
                f"{case} did not observe a closed descriptor")
        require(re.search(r'(?:write|writev|pwrite64)\([^\n]*"\\xe2\\x82\\xac"[^\n]*\)\s+=\s+3\b', trace) is not None,
                f"{case} did not write the selected UTF-8 bytes")
        execution = work / "execution-roots" / case
        require(same(tree(execution), expected_root(work, case, dynamic)),
                f"{case} execution root differs from its selected product")


def audit_elf(work: Path) -> None:
    raw = work / "raw"
    for role in ELFS:
        path = work / role if not role.endswith(".so") else work / role.split("-", 1)[0] / "libfile-dso.so"
        for option, suffix in (("-hW", "header"), ("-lW", "segments"),
                               ("-dW", "dynamic"), ("-sW", "symbols")):
            observed = subprocess.check_output([str(TOOLS["readelf"]), option, str(path)])
            require(observed == (raw / f"{role}-{suffix}.stdout").read_bytes(),
                    f"{role} retained ELF {suffix} differs")
        header = (raw / f"{role}-header.stdout").read_text()
        segments = (raw / f"{role}-segments.stdout").read_text()
        dynamic = (raw / f"{role}-dynamic.stdout").read_text()
        symbols = (raw / f"{role}-symbols.stdout").read_text()
        dynamic_main = role in {"oracle-pie", "oracle-non-pie", "candidate-pie", "candidate-non-pie"}
        elf_type = "EXEC" if role in {"oracle-static", "candidate-static", "oracle-non-pie",
                                       "candidate-non-pie"} else "DYN"
        require(re.search(r"Type:\s+" + elf_type + r"\b", header) is not None,
                f"{role} ELF type differs")
        if dynamic_main and role.startswith("oracle-"):
            require("/lib/ld-musl-x86_64.so.1" in segments, f"{role} musl interpreter differs")
        elif dynamic_main and role.startswith("candidate-"):
            require("/lib/ld-crabc-x86_64.so.1" in segments, f"{role} owned interpreter differs")
        else:
            require("Requesting program interpreter" not in segments, f"{role} acquired an interpreter")
        if role.endswith(".so"):
            require(re.search(r"\(SONAME\).*\[libfile-dso\.so\]", dynamic) is not None,
                    f"{role} SONAME differs")
            require(re.search(r"\(NEEDED\).*\[libc\.so\]", dynamic) is not None,
                    f"{role} libc dependency differs")
            for entry in ("crabc_file_dso_transfer", "crabc_cookie_dso_transfer",
                          "crabc_cookie_dso_open", "crabc_cookie_dso_check",
                          "crabc_file_dso_write_wide"):
                require(re.search(r"\bFUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+" + entry + r"\b", symbols) is not None,
                        f"{role} lacks {entry}")
        elif dynamic_main:
            require(re.search(r"\(NEEDED\).*\[libfile-dso\.so\]", dynamic) is not None
                    and re.search(r"\(NEEDED\).*\[libc\.so\]", dynamic) is not None,
                    f"{role} DSO/libc dependencies differ")
            for entry in ("crabc_file_dso_transfer", "crabc_cookie_dso_transfer",
                          "crabc_cookie_dso_open", "crabc_cookie_dso_check",
                          "crabc_file_dso_write_wide"):
                require(re.search(r"\bFUNC\s+GLOBAL\s+DEFAULT\s+UND\s+" + entry + r"\b", symbols) is not None,
                        f"{role} does not import {entry}")
        else:
            require("(NEEDED)" not in dynamic, f"{role} static baseline gained a shared dependency")


def audit_links(work: Path, static: Path, dynamic: Path) -> None:
    library = work / "candidate/libfile-dso.so"
    libc_sha = digest(dynamic / "usr/lib/libc.so")
    for role in ("candidate-libfile-dso.so", "candidate-pie", "candidate-non-pie"):
        path = library if role.endswith(".so") else work / role
        receipt = read_json(Path(str(path) + ".crabc-link.json"))
        require(receipt["output_sha256"] == digest(path), f"{role} link output differs")
        require(any(item["sha256"] == libc_sha and item["path"] == str(dynamic / "usr/lib/libc.so")
                    for item in receipt["input_receipts"]), f"{role} did not link selected libc")
        if role.endswith(".so"):
            require(receipt["mode"] == "shared" and receipt["application_dsos"] == {},
                    "candidate DSO link differs")
        else:
            require(receipt["mode"] == ("pie" if role == "candidate-pie" else "exec")
                    and receipt["application_dsos"] == {"libfile-dso.so": digest(library)},
                    f"{role} did not link the selected application DSO")
    for mode in ("static", "static-pie"):
        receipt = read_json(work / f"candidate-{mode}.link.json")
        require(receipt["output"]["sha256"] == digest(work / f"candidate-{mode}"),
                f"candidate {mode} output differs")
        applications = [item for item in receipt["input_receipts"] if item["role"] == "application"]
        require({(item["path"], item["sha256"]) for item in applications} ==
                {(str(work / "main.o"), digest(work / "main.o")),
                 (str(work / "library.o"), digest(work / "library.o"))},
                f"candidate {mode} baseline input objects differ")
    for owner, archive in (("oracle", ORACLE_ARCHIVE), ("candidate", static / "usr/lib/libc.a")):
        for operation, argument in (("members", [str(TOOLS["ar"]), "t", str(archive)]),
                                    ("symbols", [str(TOOLS["nm"]), "-A", "--defined-only", str(archive)])):
            observed = subprocess.check_output(argument)
            require(observed == (work / "raw" / f"{owner}-archive-{operation}.stdout").read_bytes(),
                    f"{owner} archive {operation} differs")


def validate(root: Path, report_path: Path) -> dict[str, object]:
    report_path = physical(root, report_path, "FILE DSO receipt")
    work = report_path.parent
    report = read_json(report_path)
    require(set(report) == {"schema", "status", "image", "inputs", "source_files", "oracle_files",
                            "plan", "files"}, "FILE DSO receipt fields differ")
    require(report["schema"] == SCHEMA and report["status"] == "component-verified"
            and report["image"] == core_image.CORE_IMAGE_REFERENCE,
            "FILE DSO receipt status or pinned image differs")
    selected = report["inputs"]
    preparation = root / selected["preparation"]["path"]
    static = root / selected["static"]["path"]
    dynamic = root / selected["dynamic"]["path"]
    require(same(selected, selected_products(root, preparation, static, dynamic)),
            "selected source/product seal differs")
    require(same(report["source_files"], source_copies(root, work, capture=False)),
            "selected probe source bytes differ")
    require(same(report["oracle_files"], oracle_copies(root, work, capture=False)),
            "pinned compiler/runtime/tool bytes differ")
    plan = commands(root, work, static, dynamic)
    plan.update({case: case_command(work, case) for case in CASES})
    require(report["plan"] == list(plan), "FILE DSO command roster differs")
    for label, argv in plan.items():
        require(read_json(work / "raw" / f"{label}.argv.json") == argv
                and (work / "raw" / f"{label}.status").read_bytes() == b"0\n",
                f"{label} retained command or status differs")
    require(same(report["files"], files(work)), "FILE DSO artifact roster or bytes differ")
    audit_runtime(work, dynamic)
    audit_elf(work)
    audit_links(work, static, dynamic)
    return report


def collect(root: Path, output: Path, preparation: Path, static: Path, dynamic: Path) -> Path:
    require(sys.platform == "linux" and os.uname().machine == "x86_64", "native x86-64 required")
    require(os.environ.get("LC_ALL") == "C", "C locale required")
    require(os.environ.get("CRABC_X86_PUBLIC_DATA_IMAGE_ID") == core_image.CORE_IMAGE_REFERENCE,
            "pinned core image identity required")
    require(output.is_absolute() and ".." not in output.parts
            and output.is_relative_to(root / ".work") and not output.exists()
            and output.parent.is_dir() and not output.parent.is_symlink(), "fresh checkout output required")
    selected = selected_products(root, preparation, static, dynamic)
    output.mkdir()
    (output / "oracle").mkdir()
    (output / "candidate").mkdir()
    sources = source_copies(root, output, capture=True)
    oracle = oracle_copies(root, output, capture=True)
    plan = commands(root, output, static, dynamic)
    for label, argv in plan.items():
        capture(output, label, argv)
    for case in CASES:
        make_root(output, case, dynamic)
        scratch = output / "execution-roots" / case / "scratch"
        write_new(output / "raw" / f"{case}.scratch-before.json", sorted(item.name for item in scratch.iterdir()))
        capture(output, case, case_command(output, case))
        write_new(output / "raw" / f"{case}.scratch-after.json", sorted(item.name for item in scratch.iterdir()))
    require(same(selected, selected_products(root, preparation, static, dynamic)),
            "selected source/product changed during execution")
    static_products.make_retained_evidence_readable(output)
    complete_plan = list(plan) + list(CASES)
    write_new(output / "report.json", {"schema": SCHEMA, "status": "component-verified",
        "image": core_image.CORE_IMAGE_REFERENCE, "inputs": selected, "source_files": sources,
        "oracle_files": oracle, "plan": complete_plan, "files": files(output)})
    validate(root, output / "report.json")
    return output / "report.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--collect", action="store_true")
    modes.add_argument("--validate-report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--static-preparation", type=Path)
    parser.add_argument("--static-product", type=Path)
    parser.add_argument("--dynamic-product", type=Path)
    args = parser.parse_args()
    try:
        if args.collect:
            require(all(value is not None for value in (args.output, args.static_preparation,
                    args.static_product, args.dynamic_product)), "collection needs four supplied paths")
            report = collect(ROOT, args.output, args.static_preparation, args.static_product, args.dynamic_product)
        else:
            require(all(value is None for value in (args.output, args.static_preparation,
                    args.static_product, args.dynamic_product)), "replay accepts only a report")
            report = args.validate_report
            validate(ROOT, report)
        print(json.dumps({"schema": SCHEMA, "report": str(report), "sha256": digest(report),
                          "cases": list(CASES), "status": "component-verified"}, sort_keys=True))
        return 0
    except (ReceiptError, OSError, KeyError, TypeError, json.JSONDecodeError,
            products.ProductEvidenceError, static_products.PreparationError,
            pthread_receipt.ReceiptError, subprocess.CalledProcessError) as error:
        print(f"owned stdio FILE DSO receipt: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
