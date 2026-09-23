#!/usr/bin/env python3
"""Reconstruct the bounded installed FILE-engine receipt from retained bytes.

This reader deliberately validates seven existing FILE-engine probes as separate
installed-header objects.  It does not add a stdio API, infer symbols from a
report, or treat an earlier static-only run as six-mode product evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import owned_crypt_runtime_evidence as copies
import owned_posix_product_evidence as products

SCHEMA = "crabc.x86_64-owned-stdio-file-engine/v1"
ORACLE_COMPILER = "/usr/local/bin/crabc-x86_64-musl-gcc"
COPIES_PATH = HERE / "owned_crypt_runtime_evidence.py"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
# The process probe needs a shell.  These are explicit pinned-image control
# inputs, resolved to physical files before any receipt validation; they never
# stand in for a supplied product loader or libc.
CONTROL_BUSYBOX = Path(os.path.realpath("/bin/busybox"))
CONTROL_LOADER = Path(os.path.realpath("/lib/ld-musl-x86_64.so.1"))
CONTROL_APPLETS = ("sh", "cat", "sleep")
# The mount helpers are invoked through their fixed applet paths.  The separate
# physical identities below bind the resolved bytes (BusyBox provides these
# applets in the pinned image), while the receipt preserves the literal argv.
CONTROL_PROC_MOUNT_COMMAND = Path("/bin/mount")
CONTROL_PROC_UMOUNT_COMMAND = Path("/bin/umount")
CONTROL_PROC_MOUNT = Path(os.path.realpath("/bin/mount"))
CONTROL_PROC_UMOUNT = Path(os.path.realpath("/bin/umount"))
CONTROL_HEADERS = ("unistd.h", "features.h", "bits/alltypes.h")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
EXECUTION_CELLS = (
    "static", "static-pie", "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)

# The role labels describe only behavior observed by the named, pre-existing
# probe.  They are closed receipt values, not an attempt to enumerate stdio.
ROLES: dict[str, dict[str, object]] = {
    "stdio.file-backends": {
        "source": "compat/x86_64/owned_stdio_backends_probe.c",
        "behavior": "descriptor-memory-cookie-and-ordinary-exit",
        "headers": ("stdio.h", "stdlib.h", "string.h", "stdint.h", "errno.h", "unistd.h",
                    "sys/resource.h", "fcntl.h", "features.h", "bits/alltypes.h"),
        "flags": (), "side_effect": b"backend-exit\n",
    },
    "stdio.process-streams": {
        "source": "compat/x86_64/owned_stdio_process_probe.c",
        "behavior": "popen-pclose-system-and-failure-cleanup",
        "headers": ("stdio.h", "stdlib.h", "string.h", "errno.h", "fcntl.h", "signal.h",
                    "unistd.h", "sys/wait.h", "sys/resource.h", "pthread.h", "features.h", "bits/alltypes.h"),
        "flags": (), "side_effect": None,
    },
    "stdio.wide-stream": {
        "source": "compat/x86_64/owned_wide_stdio_probe.c",
        "behavior": "orientation-locale-decoding-and-wide-memstream",
        "headers": ("stdio.h", "wchar.h", "locale.h", "errno.h", "stdlib.h", "string.h",
                    "unistd.h", "stdint.h", "pthread.h", "features.h", "bits/alltypes.h"),
        "flags": (), "side_effect": None,
    },
    "stdio.wide-format": {
        "source": "compat/x86_64/owned_wide_format_probe.c",
        "behavior": "wide-format-scan-conversion-varargs-and-standard-streams",
        "headers": ("stdio.h", "wchar.h", "locale.h", "stdlib.h", "string.h", "errno.h",
                    "stdarg.h", "fenv.h", "float.h", "math.h", "unistd.h", "features.h", "bits/alltypes.h"),
        "flags": (), "side_effect": None,
    },
    "stdio.file-extensions": {
        "source": "compat/x86_64/owned_stdio_extensions_probe.c",
        "behavior": "stdio-ext-state-views-buffering-purge-and-unlocked-entries",
        "headers": ("stdio.h", "stdio_ext.h", "stdlib.h", "string.h", "errno.h", "unistd.h",
                    "wchar.h", "locale.h", "features.h", "bits/alltypes.h"),
        "flags": (), "side_effect": None,
    },
    "stdio.printf-float": {
        "source": "compat/x86_64/owned_static_printf_float_probe.c",
        "behavior": "float-format-rounding-fenv-and-four-destinations",
        "headers": ("stdio.h", "stdlib.h", "stdint.h", "stdarg.h", "string.h", "unistd.h",
                    "errno.h", "float.h", "math.h", "fenv.h", "limits.h", "features.h", "bits/alltypes.h"),
        "flags": (), "side_effect": None,
    },
    "stdio.scanf": {
        "source": "compat/x86_64/owned_static_scanf_probe.c",
        "behavior": "scan-grammar-lookahead-fenv-and-m-allocation",
        "headers": ("stdio.h", "stdlib.h", "string.h", "stdarg.h", "stdint.h", "errno.h",
                    "fenv.h", "unistd.h", "sys/resource.h", "features.h", "bits/alltypes.h"),
        "flags": ("-DCRABC_OWNED_SCANF",), "side_effect": None,
    },
}
SCOPE = tuple(ROLES)
COMMON_FLAGS = ("-std=c11", "-D_GNU_SOURCE", "-pthread", "-fno-builtin", "-fno-stack-protector")
CONTROL_COMPILE_FLAGS = ("-std=c11", "-fno-builtin", "-fno-stack-protector")


def control_launcher_source(applet: str) -> bytes:
    """Fixed applet launcher source; the applet is never caller selected."""
    require(applet in CONTROL_APPLETS, "unknown control applet")
    return (f"""#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{{
    char *command[argc + 3];
    command[0] = "/control/ld-musl-x86_64.so.1";
    command[1] = "/control/busybox";
    command[2] = "{applet}";
    for (int index = 1; index < argc; index++)
        command[index + 2] = argv[index];
    command[argc + 2] = NULL;
    execve(command[0], command, environ);
    return 127;
}}
""").encode("utf-8")


class ReceiptError(RuntimeError):
    """The retained FILE-engine evidence cannot establish its closed observation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def same(left: object, right: object, message: str) -> None:
    require(json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False)
            == json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False), message)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def physical(path: Path, label: str) -> Path:
    """Reject a symlink hop before resolving or opening a receipt input."""
    if ".." in path.parts:
        raise ReceiptError(f"{label} has lexical parent traversal: {path}")
    result = Path(os.path.abspath(path))
    current = Path(result.anchor)
    try:
        for part in result.parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ReceiptError(f"{label} traverses a symlink: {path}")
        result.lstat()
    except OSError as error:
        raise ReceiptError(f"{label} is unreadable: {path}") from error
    return result


def directory(path: Path, label: str) -> Path:
    path = physical(path, label)
    require(stat.S_ISDIR(path.lstat().st_mode), f"{label} is not a physical directory")
    return path


def regular(path: Path, label: str) -> Path:
    path = physical(path, label)
    require(stat.S_ISREG(path.lstat().st_mode), f"{label} is not a physical regular file")
    return path


def digest(path: Path) -> str:
    path = regular(path, "hashed receipt artifact")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def identity(root: Path, path: Path) -> dict[str, object]:
    root = directory(root, "receipt root")
    path = regular(path, "receipt artifact")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise ReceiptError("receipt artifact escapes its root") from error
    metadata = path.stat()
    return {"path": relative, "sha256": digest(path), "size": metadata.st_size,
            "mode": stat.S_IMODE(metadata.st_mode)}


def check_identity(root: Path, value: object, label: str) -> Path:
    require(type(value) is dict and set(value) == {"path", "sha256", "size", "mode"},
            f"{label} identity fields drifted")
    relative, expected, size, mode = value["path"], value["sha256"], value["size"], value["mode"]
    require(type(relative) is str and relative and not Path(relative).is_absolute()
            and ".." not in Path(relative).parts, f"{label} identity path is invalid")
    require(type(expected) is str and SHA256.fullmatch(expected) is not None, f"{label} identity digest is invalid")
    require(type(size) is int and size >= 0 and type(mode) is int and 0 <= mode <= 0o777,
            f"{label} identity metadata is invalid")
    path = regular(root / relative, label)
    same(identity(root, path), value, f"{label} differs from physical retained bytes")
    return path


def strict_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(regular(path, label).read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{label} is not strict JSON") from error
    require(type(value) is dict, f"{label} must be a JSON object")
    return value


def tree_identity(root: Path) -> dict[str, object]:
    root = directory(root, "sealed product")
    result: dict[str, object] = {}
    pending = [root]
    while pending:
        parent = pending.pop()
        for path in sorted(parent.iterdir()):
            mode = path.lstat().st_mode
            relative = path.relative_to(root).as_posix()
            metadata = path.stat(follow_symlinks=False)
            entry: dict[str, object] = {"mode": stat.S_IMODE(mode), "uid": metadata.st_uid,
                                        "gid": metadata.st_gid, "links": metadata.st_nlink}
            if stat.S_ISDIR(mode):
                entry["kind"] = "directory"
                pending.append(directory(path, "sealed product directory"))
            elif stat.S_ISREG(mode):
                entry.update(kind="file", size=metadata.st_size, sha256=digest(path))
            elif stat.S_ISLNK(mode):
                entry.update(kind="symlink", target=os.readlink(path))
            else:
                raise ReceiptError("sealed product contains a non-file entry")
            result[relative] = entry
    require(bool(result), "sealed product tree is empty")
    return result


def source_identity(checkout: Path, path: Path) -> dict[str, object]:
    value = identity(checkout, path)
    return {"path": value["path"], "sha256": value["sha256"], "mode": value["mode"]}


def source_file(checkout: Path, value: object, expected: str, label: str) -> Path:
    require(type(value) is dict and set(value) == {"path", "sha256", "mode"}, f"{label} fields drifted")
    require(value["path"] == expected, f"{label} path differs")
    path = regular(checkout / expected, label)
    same(source_identity(checkout, path), value, f"{label} differs from physical bytes")
    return path


def product_seal(value: object, product: Path, label: str) -> None:
    require(type(value) is dict and set(value) == {"path", "manifest", "tree"}, f"{label} product seal fields drifted")
    require(value["path"] == str(product), f"{label} product seal path differs")
    manifest = product / "share/crabc/manifest.json"
    require(type(value["manifest"]) is dict and set(value["manifest"]) == {"path", "sha256", "size"},
            f"{label} product manifest fields drifted")
    manifest_value = value["manifest"]
    actual = {"path": str(regular(manifest, label + " product manifest")), "sha256": digest(manifest),
              "size": manifest.stat().st_size}
    same(actual, manifest_value, f"{label} product manifest differs")
    require(type(value["tree"]) is dict and value["tree"], f"{label} product seal tree is empty")
    same(tree_identity(product), value["tree"], f"{label} product seal tree differs")


def source_map(checkout: Path, sources: Mapping[str, Path]) -> dict[str, object]:
    return {name: identity(checkout, path) for name, path in sources.items()}


def validate_source_product_seals(checkout: Path, work: Path, report: Mapping[str, Any]) -> dict[str, Path]:
    seals = report["seals"]
    before = check_identity(work, seals["source-product-before"], "source/product before seal")
    after = check_identity(work, seals["source-product-after"], "source/product after seal")
    before_value, after_value = strict_json(before, "source/product before seal"), strict_json(after, "source/product after seal")
    same(before_value, after_value, "source/product seals differ")
    require(set(before_value) == {"sources", "static", "dynamic"}, "source/product seal fields drifted")
    raw_sources = before_value["sources"]
    expected_names = {"runner", "reader", *SCOPE}
    require(type(raw_sources) is dict and set(raw_sources) == expected_names, "source seal roster differs")
    sources = {role: source_file(checkout, raw_sources[role], str(ROLES[role]["source"]), role + " source")
               for role in SCOPE}
    runner = source_file(checkout, raw_sources["runner"], "compat/x86_64/run_owned_stdio_file_engine.sh", "FILE engine runner")
    reader = source_file(checkout, raw_sources["reader"], "compat/x86_64/owned_stdio_file_engine_receipt.py", "FILE engine reader")
    all_sources = {**sources, "runner": runner, "reader": reader}
    require(type(report["source"]) is dict, "report source mapping differs")
    same(source_map(checkout, all_sources), report["source"], "report source mapping differs from sealed sources")
    product_paths = report["products"]
    require(type(product_paths) is dict and set(product_paths) == {"static", "dynamic"}, "report product roster differs")
    static_product = directory(Path(product_paths["static"]), "static product")
    dynamic_product = directory(Path(product_paths["dynamic"]), "dynamic product")
    product_seal(before_value["static"], static_product, "static")
    product_seal(before_value["dynamic"], dynamic_product, "dynamic")
    try:
        products._validate_static_product(static_product)
        products._validate_dynamic_product(dynamic_product)
    except Exception as error:
        raise ReceiptError("supplied product validation failed") from error
    return all_sources


def dynamic_helper_tools(dynamic: Path) -> dict[str, Path]:
    helper = regular(dynamic / "share/crabc/crabc_cc_static.py", "installed compiler helper")
    name = "owned_stdio_file_engine_helper"
    specification = importlib.util.spec_from_file_location(name, helper)
    require(specification is not None and specification.loader is not None, "installed compiler helper cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    try:
        specification.loader.exec_module(module)
        require(type(getattr(module, "__file__", None)) is str
                and regular(Path(module.__file__), "loaded compiler helper") == helper,
                "installed compiler helper origin differs")
        selected: dict[str, Path] = {}
        for role in ("compiler", "linker"):
            selector = getattr(module, role, None)
            require(callable(selector), f"installed compiler helper lacks {role} selector")
            candidate = selector(dynamic) if role == "linker" else selector()
            require(type(candidate) is str and Path(candidate).is_absolute(),
                    f"installed compiler helper {role} path is invalid")
            selected[role] = regular(Path(candidate), f"installed helper {role}")
        return selected
    except ReceiptError:
        raise
    except Exception as error:
        raise ReceiptError("installed compiler helper cannot resolve fixed tools") from error
    finally:
        sys.modules.pop(name, None)


def validate_tools(work: Path, report: Mapping[str, Any]) -> dict[str, dict[str, object]]:
    before_path = check_identity(work, report["seals"]["tools-before"], "tools before seal")
    after_path = check_identity(work, report["seals"]["tools-after"], "tools after seal")
    before, after = strict_json(before_path, "tools before seal"), strict_json(after_path, "tools after seal")
    same(before, after, "tool seals differ")
    expected = {"oracle", "static_driver", "dynamic_driver", "compiler", "linker", "control_busybox", "control_loader",
                "control_mount", "control_umount"}
    require(set(before) == expected, "tool roster differs")
    result: dict[str, dict[str, object]] = {}
    for role in expected:
        value = before[role]
        require(type(value) is dict and set(value) == {"path", "sha256", "size", "mode"},
                f"{role} tool fields drifted")
        path_text = value["path"]
        require(type(path_text) is str and Path(path_text).is_absolute(), f"{role} tool path is invalid")
        path = regular(Path(path_text), role + " tool")
        actual = {"path": str(path), "sha256": digest(path), "size": path.stat().st_size,
                  "mode": stat.S_IMODE(path.stat().st_mode)}
        same(actual, value, f"{role} tool differs from physical bytes")
        result[role] = value
    require(result["oracle"]["path"] == ORACLE_COMPILER, "oracle tool path differs from pinned musl compiler")
    require(result["control_busybox"]["path"] == str(regular(CONTROL_BUSYBOX, "pinned control BusyBox")),
            "control BusyBox tool path differs")
    require(result["control_loader"]["path"] == str(regular(CONTROL_LOADER, "pinned control musl loader")),
            "control loader tool path differs")
    require(result["control_mount"]["path"] == str(regular(CONTROL_PROC_MOUNT, "pinned proc mount")),
            "control proc mount tool path differs")
    require(result["control_umount"]["path"] == str(regular(CONTROL_PROC_UMOUNT, "pinned proc unmount")),
            "control proc unmount tool path differs")
    static_product = directory(Path(report["products"]["static"]), "static product")
    dynamic_product = directory(Path(report["products"]["dynamic"]), "dynamic product")
    require(result["static_driver"]["path"] == str(regular(static_product / "bin/crabc-cc", "static driver")),
            "static driver tool path differs")
    require(result["dynamic_driver"]["path"] == str(regular(dynamic_product / "bin/crabc-cc-dynamic", "dynamic driver")),
            "dynamic driver tool path differs")
    for role, path in dynamic_helper_tools(dynamic_product).items():
        require(result[role]["path"] == str(path), f"{role} tool path differs from sealed helper")
    return result



def _same_bytes_metadata(left: Path, right: Path, label: str) -> None:
    require(digest(left) == digest(right) and left.stat().st_size == right.stat().st_size
            and stat.S_IMODE(left.stat().st_mode) == stat.S_IMODE(right.stat().st_mode), label + " differs")


def _control_root(work: Path, linkage: str) -> Path:
    """Retained fixture copies, separate from audited dynamic execution roots."""
    names = {
        "oracle": "process-control-oracle-stage",
        "static": "process-control-static-stage",
        "static-pie": "process-control-static-pie-stage",
        "pie": "process-control-pie-stage",
        "non-pie": "process-control-non-pie-stage",
    }
    return work / names[linkage]


def _process_root(work: Path, linkage: str) -> Path:
    names = {
        "oracle": "process-oracle-root",
        "static": "process-static-root",
        "static-pie": "process-static-pie-root",
        "pie": "dynamic-stdio.process-streams-pie-root",
        "non-pie": "dynamic-stdio.process-streams-non-pie-root",
        "wide-format-pie": "dynamic-stdio.wide-format-pie-root",
        "wide-format-non-pie": "dynamic-stdio.wide-format-non-pie-root",
    }
    return work / names[linkage]


def validate_control_material(work: Path, report: Mapping[str, Any], tools: Mapping[str, Mapping[str, object]]) -> dict[str, dict[str, Path]]:
    """Bind fixed control source, objects, linkage-specific launchers, and stages."""
    value = report["control"]
    require(type(value) is dict and set(value) == {"sources", "objects", "launchers", "links", "staged"},
            "process control fields differ")
    source_values, object_values = value["sources"], value["objects"]
    require(type(source_values) is dict and set(source_values) == set(CONTROL_APPLETS),
            "process control source roster differs")
    require(type(object_values) is dict and set(object_values) == set(CONTROL_APPLETS),
            "process control object roster differs")
    sources: dict[str, Path] = {}
    objects: dict[str, Path] = {}
    for applet in CONTROL_APPLETS:
        source = check_identity(work, source_values[applet], "control " + applet + " source")
        require(source == work / ("control-" + applet + ".c"), "control " + applet + " source path differs")
        require(source.read_bytes() == control_launcher_source(applet), "control " + applet + " source differs")
        object_path = check_identity(work, object_values[applet], "control " + applet + " object")
        require(object_path == work / ("control-" + applet + ".o"), "control " + applet + " object path differs")
        sources[applet], objects[applet] = source, object_path

    launchers_value, links_value = value["launchers"], value["links"]
    require(type(launchers_value) is dict and set(launchers_value) == set(CONTROL_APPLETS),
            "process control launcher roster differs")
    require(type(links_value) is dict and set(links_value) == set(CONTROL_APPLETS),
            "process control link roster differs")
    launchers: dict[str, dict[str, Path]] = {}
    for applet in CONTROL_APPLETS:
        item = launchers_value[applet]
        require(type(item) is dict and set(item) == {"oracle", "static", "static-pie", "pie", "non-pie"},
                "control " + applet + " launcher modes differ")
        paths: dict[str, Path] = {}
        for linkage in item:
            binary = check_identity(work, item[linkage], "control " + applet + " " + linkage + " launcher")
            require(binary == work / ("control-" + applet + "-" + linkage),
                    "control " + applet + " " + linkage + " launcher path differs")
            paths[linkage] = binary
        launchers[applet] = paths
        link_items = links_value[applet]
        require(type(link_items) is dict and set(link_items) == {"static", "static-pie", "pie", "non-pie"},
                "control " + applet + " product link modes differ")
        for linkage in link_items:
            link = check_identity(work, link_items[linkage], "control " + applet + " " + linkage + " product link")
            require(link == work / ("control-" + applet + "-" + linkage + ".product-link.json"),
                    "control " + applet + " " + linkage + " product link path differs")

    stages = value["staged"]
    required_stage_keys = {"oracle", "static", "static-pie", "pie", "non-pie"}
    require(type(stages) is dict and set(stages) == required_stage_keys, "process control stage roster differs")
    for linkage in required_stage_keys:
        root = directory(_control_root(work, linkage), "process control " + linkage + " root")
        stage = stages[linkage]
        require(type(stage) is dict and set(stage) == {"busybox", "loader", *CONTROL_APPLETS},
                "process control " + linkage + " stage fields differ")
        busybox = check_identity(work, stage["busybox"], "control " + linkage + " BusyBox stage")
        loader = check_identity(work, stage["loader"], "control " + linkage + " loader stage")
        require(busybox == root / "control/busybox", "control " + linkage + " BusyBox stage path differs")
        require(loader == root / "control/ld-musl-x86_64.so.1", "control " + linkage + " loader stage path differs")
        _same_bytes_metadata(busybox, regular(Path(str(tools["control_busybox"]["path"])), "pinned control BusyBox"),
                             "control " + linkage + " BusyBox stage")
        _same_bytes_metadata(loader, regular(Path(str(tools["control_loader"]["path"])), "pinned control loader"),
                             "control " + linkage + " loader stage")
        for applet in CONTROL_APPLETS:
            stage_path = check_identity(work, stage[applet], "control " + linkage + " " + applet + " stage")
            require(stage_path == root / "bin" / applet, "control " + linkage + " " + applet + " stage path differs")
            _same_bytes_metadata(stage_path, launchers[applet][linkage],
                                 "control " + linkage + " " + applet + " stage")
    return {"sources": sources, "objects": objects, "launchers": launchers}


def _expected_control_header_argv(compiler: str, dynamic: Path, source: Path) -> list[str]:
    return [compiler, "-nostdinc", "-isystem", str(dynamic / "usr/include"), *CONTROL_COMPILE_FLAGS,
            "-E", "-H", str(source)]


def _expected_control_compile_argv(driver: str, source: Path, object_path: Path) -> list[str]:
    return [driver, "--dynamic-pie", *CONTROL_COMPILE_FLAGS, "-c", str(source), "-o", str(object_path)]


def _validate_control_link(work: Path, commands: Mapping[str, Mapping[str, object]], control: Mapping[str, dict[str, Path]],
                           report: Mapping[str, Any], tools: Mapping[str, Mapping[str, object]], applet: str, linkage: str, product: Path) -> None:
    object_path, binary = control["objects"][applet], control["launchers"][applet][linkage]
    stem = "control-" + applet + "-" + linkage
    command = commands[stem + "-link"]
    if linkage == "oracle":
        require_argv(command, [str(tools["oracle"]["path"]), "-static", "-fno-pie", "-no-pie",
                               str(object_path), "-o", str(binary)], stem + " link")
    else:
        link = check_identity(work, report["control"]["links"][applet][linkage], stem + " product link")
        receipt = (work / (stem + ".crabc-link.json"))
        receipt = regular(receipt, stem + " link receipt")
        try:
            actual = products.validate_link(product, object_path, binary, receipt, linkage)
        except Exception as error:
            raise ReceiptError(stem + " link validation failed") from error
        require(canonical(actual) == link.read_bytes(), stem + " link identity differs")
        driver = str(product / ("bin/crabc-cc" if linkage.startswith("static") else "bin/crabc-cc-dynamic"))
        expected = ([driver, "-" + linkage, "--link-receipt", receipt.name, str(object_path), "-o", str(binary)]
                    if linkage.startswith("static") else
                    [driver, "--dynamic-" + linkage, *CONTROL_COMPILE_FLAGS, str(object_path), "-o", str(binary)])
        require_argv(command, expected, stem + " link")
    require(command["stdout"].read_bytes() == b"" and command["stderr"].read_bytes() == b"",
            stem + " link raw output differs")  # type: ignore[union-attr]


def validate_control_commands(work: Path, report: Mapping[str, Any], commands: Mapping[str, Mapping[str, object]],
                              control: Mapping[str, dict[str, Path]], tools: Mapping[str, Mapping[str, object]]) -> set[str]:
    """Validate the fixed control sources before their launcher bytes can be trusted."""
    static_product = directory(Path(report["products"]["static"]), "static product")
    dynamic_product = directory(Path(report["products"]["dynamic"]), "dynamic product")
    stems: set[str] = set()
    for applet in CONTROL_APPLETS:
        source, object_path = control["sources"][applet], control["objects"][applet]
        header_stem, compile_stem = "control-" + applet + "-header", "control-" + applet + "-compile"
        header, compile_command = commands[header_stem], commands[compile_stem]
        stems.update((header_stem, compile_stem, "control-" + applet + "-oracle-link"))
        require_argv(header, _expected_control_header_argv(str(tools["compiler"]["path"]), dynamic_product, source),
                     "control " + applet + " header")
        _header_trace(header["stderr"], dynamic_product / "usr/include", CONTROL_HEADERS, "control " + applet)  # type: ignore[arg-type]
        require(f'# 0 "{source}"'.encode() in header["stdout"].read_bytes(),
                "control " + applet + " preprocessed source differs")  # type: ignore[union-attr]
        require_argv(compile_command, _expected_control_compile_argv(str(tools["dynamic_driver"]["path"]), source, object_path),
                     "control " + applet + " compile")
        require(compile_command["stdout"].read_bytes() == b"" and compile_command["stderr"].read_bytes() == b"",
                "control " + applet + " compile raw output differs")  # type: ignore[union-attr]
        _validate_control_link(work, commands, control, report, tools, applet, "oracle", dynamic_product)
        for linkage, product in (("static", static_product), ("static-pie", static_product),
                                 ("pie", dynamic_product), ("non-pie", dynamic_product)):
            stems.add("control-" + applet + "-" + linkage + "-link")
            _validate_control_link(work, commands, control, report, tools, applet, linkage, product)
    return stems

def command_files(work: Path, value: object, stem: str) -> dict[str, object]:
    require(type(value) is dict and set(value) == {"argv", "stdout", "stderr", "status"},
            f"{stem} command fields drifted")
    paths = {kind: check_identity(work, value[kind], f"{stem} {kind}") for kind in value}
    for kind, suffix in (("argv", ".argv.json"), ("stdout", ".stdout"), ("stderr", ".stderr"), ("status", ".status")):
        require(paths[kind].name == stem + suffix, f"{stem} {kind} filename differs")
    try:
        argv = json.loads(paths["argv"].read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{stem} argv is not strict JSON") from error
    require(type(argv) is list and all(type(item) is str for item in argv), f"{stem} argv is invalid")
    require(paths["status"].read_bytes() == b"0\n", f"{stem} status is not successful")
    paths["parsed_argv"] = argv  # type: ignore[assignment]
    return paths


def require_argv(files: Mapping[str, object], expected: list[str], label: str) -> None:
    same(files["parsed_argv"], expected, label + " argv differs")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def row_value(role: str) -> dict[str, object]:
    metadata = ROLES[role]
    return {"source": metadata["source"], "behavior": metadata["behavior"],
            "runtime_cells": list(EXECUTION_CELLS)}


def _header_trace(trace: Path, root: Path, headers: tuple[str, ...], role: str) -> None:
    seen: list[Path] = []
    for line in trace.read_text(errors="replace").splitlines():
        match = re.fullmatch(r"\.+\s+(.+)", line)
        if match is None:
            continue
        candidate = Path(match.group(1))
        require(candidate.is_absolute() and ".." not in candidate.parts and candidate.is_relative_to(root),
                role + " header trace escapes installed include tree")
        # A syntactically in-tree trace can still use an installed-header
        # symlink to read ambient bytes. The sealed product supplies headers
        # as physical files, so reject that hop before accepting the trace.
        seen.append(regular(candidate, role + " header trace"))
    require(all(root / name in seen for name in headers), role + " header trace omits required installed header")


def _expected_header_argv(compiler: str, dynamic: Path, source: Path, flags: tuple[str, ...]) -> list[str]:
    return [compiler, "-nostdinc", "-isystem", str(dynamic / "usr/include"), *COMMON_FLAGS, *flags,
            "-E", "-H", str(source)]


def _expected_compile_argv(driver: str, source: Path, object_path: Path, flags: tuple[str, ...]) -> list[str]:
    return [driver, "--dynamic-pie", *COMMON_FLAGS, *flags, "-c", str(source), "-o", str(object_path)]


def _expected_run(executable: Path, scratch: Path) -> list[str]:
    return ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", str(executable), str(scratch)]


def validate_object_seals(work: Path, report: Mapping[str, Any], sources: Mapping[str, Path],
                          control: Mapping[str, dict[str, Path]]) -> dict[str, Path]:
    workloads_value = report["workloads"]
    require(type(workloads_value) is dict and set(workloads_value) == set(SCOPE), "workload roster differs")
    workloads = {role: check_identity(work, workloads_value[role], role + " workload") for role in SCOPE}
    records = report["object_seals"]
    require(type(records) is dict and set(records) == {"before", "after"}, "object seal roster differs")
    before = check_identity(work, records["before"], "object before seal")
    after = check_identity(work, records["after"], "object after seal")
    sealed = [*(sources[role] for role in SCOPE), sources["runner"],
              *(control["sources"][applet] for applet in CONTROL_APPLETS),
              *(workloads[role] for role in SCOPE),
              *(control["objects"][applet] for applet in CONTROL_APPLETS)]
    expected_before = "".join(f"{digest(path)}  {path}\n" for path in sealed).encode("ascii")
    expected_after = "".join(f"{path}: OK\n" for path in sealed).encode("utf-8")
    require(before.read_bytes() == expected_before, "object before seal differs")
    require(after.read_bytes() == expected_after, "object after seal differs")
    return workloads


def validate_link(work: Path, commands: Mapping[str, Mapping[str, object]], links: Mapping[str, object],
                  role: str, linkage: str, product: Path, workload: Path, executable: Path) -> None:
    stem = f"{role}-{linkage}"
    link_file = check_identity(work, links[stem], stem + " product link")
    receipt = (work / f"{role}-{linkage}.crabc-link.json") if linkage.startswith("static") else executable.with_name(executable.name + ".crabc-link.json")
    receipt = regular(receipt, stem + " link receipt")
    try:
        actual = products.validate_link(product, workload, executable, receipt, linkage)
    except Exception as error:
        raise ReceiptError(stem + " link validation failed") from error
    require(canonical(actual) == link_file.read_bytes(), stem + " link identity differs")
    files = commands[stem + "-link"]
    driver = (str(product / "bin/crabc-cc") if linkage.startswith("static")
              else str(product / "bin/crabc-cc-dynamic"))
    expected = ([driver, "-" + linkage, "--link-receipt", receipt.name, str(workload), "-o", str(executable)]
                if linkage.startswith("static") else
                [driver, "--dynamic-" + linkage, *COMMON_FLAGS, str(workload), "-o", str(executable)])
    require_argv(files, expected, stem + " link")
    require(files["stdout"].read_bytes() == b"" and files["stderr"].read_bytes() == b"",
            stem + " link raw output differs")  # type: ignore[union-attr]


def payload_audit(work: Path, command: Mapping[str, object], product: Path, root: Path, source: Path,
                  consumer: Path, record: Path, label: str) -> None:
    try:
        actual = copies.audit_execution_payload(product, root, source, consumer, record)
    except Exception as error:
        raise ReceiptError(label + " payload audit failed") from error
    stdout = command["stdout"]
    require(isinstance(stdout, Path) and stdout.read_bytes() == canonical(actual), label + " payload audit differs")



def _snapshot(value: object, raw: bytes, label: str) -> None:
    require(type(value) is dict and set(value) == {"byte_length", "sha256", "text"}, label + " fields differ")
    expected = {"byte_length": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "text": raw.decode("utf-8", errors="replace")}
    same(value, expected, label + " differs")


def validate_process_proc(work: Path, report: Mapping[str, Any], tools: Mapping[str, Mapping[str, object]]) -> None:
    """Validate tracked private-proc lifecycles before examining their roots."""
    values = report["process_proc"]
    expected_modes = ("oracle", "static", "static-pie", "pie", "non-pie", "wide-format-pie", "wide-format-non-pie")
    require(type(values) is dict and set(values) == set(expected_modes), "process proc roster differs")
    for linkage in expected_modes:
        value = values[linkage]
        require(type(value) is dict and set(value) == {"receipt", "mountinfo"},
                "process " + linkage + " proc fields differ")
        receipt_path = check_identity(work, value["receipt"], "process " + linkage + " proc receipt")
        mountinfo = check_identity(work, value["mountinfo"], "process " + linkage + " proc mountinfo")
        require(receipt_path == work / ("process-" + linkage + "-private-proc.json"),
                "process " + linkage + " proc receipt path differs")
        require(mountinfo == work / ("process-" + linkage + "-proc-mountinfo.txt"),
                "process " + linkage + " proc mountinfo path differs")
        private = strict_json(receipt_path, "process " + linkage + " proc receipt")
        root = directory(_process_root(work, linkage), "process " + linkage + " root")
        target = root / "proc"
        require(set(private) == {"schema", "mountpoint", "reservation", "mount", "namespace", "unmount"},
                "process " + linkage + " proc receipt fields differ")
        require(private["schema"] == "crabc.x86_64-owned-os-test-private-proc/v1"
                and private["mountpoint"] == str(target) and private["reservation"] == {"empty": True, "mode": 0o755},
                "process " + linkage + " proc reservation differs")
        mount = private["mount"]
        require(type(mount) is dict and set(mount) == {"command", "status", "stdout", "stderr", "target"},
                "process " + linkage + " proc mount fields differ")
        same([mount["command"], mount["status"], mount["target"]],
             [[str(CONTROL_PROC_MOUNT_COMMAND), "-t", "proc", "-o", "ro,nosuid,nodev,noexec", "proc", str(target)], 0, str(target)],
             "process " + linkage + " proc mount command differs")
        _snapshot(mount["stdout"], b"", "process " + linkage + " proc mount stdout")
        _snapshot(mount["stderr"], b"", "process " + linkage + " proc mount stderr")
        namespace = private["namespace"]
        require(type(namespace) is dict and set(namespace) == {"outside", "inside", "matched"},
                "process " + linkage + " proc namespace fields differ")
        outside = namespace["outside"]
        require(type(outside) is str and re.fullmatch(r"pid:\[[0-9]+\]", outside) is not None,
                "process " + linkage + " proc outside namespace differs")
        inside = namespace["inside"]
        require(type(inside) is dict and set(inside) == {"command", "status", "stdout", "stderr"},
                "process " + linkage + " proc inside namespace fields differ")
        same([inside["command"], inside["status"], namespace["matched"]],
             [["/usr/sbin/chroot", str(root), "/control/ld-musl-x86_64.so.1", "/control/busybox", "readlink", "/proc/self/ns/pid"], 0, True],
             "process " + linkage + " proc namespace command differs")
        _snapshot(inside["stdout"], (outside + "\n").encode(), "process " + linkage + " proc namespace stdout")
        _snapshot(inside["stderr"], b"", "process " + linkage + " proc namespace stderr")
        unmount = private["unmount"]
        require(type(unmount) is dict and set(unmount) == {"command", "status", "stdout", "stderr"},
                "process " + linkage + " proc unmount fields differ")
        same([unmount["command"], unmount["status"]], [[str(CONTROL_PROC_UMOUNT_COMMAND), str(target)], 0],
             "process " + linkage + " proc unmount command differs")
        _snapshot(unmount["stdout"], b"", "process " + linkage + " proc unmount stdout")
        _snapshot(unmount["stderr"], b"", "process " + linkage + " proc unmount stderr")
        raw_mountinfo = mountinfo.read_bytes()
        require(str(target).encode() in raw_mountinfo and b" - proc proc " in raw_mountinfo
                and b"ro,nosuid,nodev,noexec" in raw_mountinfo,
                "process " + linkage + " proc mountinfo differs")

def validate_commands(checkout: Path, work: Path, report: Mapping[str, Any], sources: Mapping[str, Path],
                      workloads: Mapping[str, Path], tools: Mapping[str, Mapping[str, object]],
                      control: Mapping[str, dict[str, Path]]) -> None:
    values = report["commands"]
    require(type(values) is dict, "command roster differs")
    commands = {stem: command_files(work, value, stem) for stem, value in values.items()}
    static_product = directory(Path(report["products"]["static"]), "static product")
    dynamic_product = directory(Path(report["products"]["dynamic"]), "dynamic product")
    expected_stems = validate_control_commands(work, report, commands, control, tools)
    links = report["links"]
    require(type(links) is dict and set(links) == {f"{role}-{linkage}" for role in SCOPE
            for linkage in ("static", "static-pie", "pie", "non-pie")}, "link roster differs")
    payloads = report["execution_payloads"]
    require(type(payloads) is dict and set(payloads) == set(SCOPE), "execution payload roster differs")
    side_effects = report["side_effects"]
    require(type(side_effects) is dict and set(side_effects) == {"stdio.file-backends"}, "side-effect roster differs")
    backend_effects = side_effects["stdio.file-backends"]
    require(type(backend_effects) is dict and set(backend_effects) == set(EXECUTION_CELLS), "backend side-effect cells differ")

    for role in SCOPE:
        metadata = ROLES[role]
        source, workload = sources[role], workloads[role]
        flags = tuple(metadata["flags"])
        header = commands[f"{role}-header"]
        compile_command = commands[f"{role}-compile"]
        expected_stems.update((f"{role}-header", f"{role}-compile", f"{role}-oracle-link", f"{role}-oracle-run"))
        require_argv(header, _expected_header_argv(str(tools["compiler"]["path"]), dynamic_product, source, flags),
                     role + " header")
        _header_trace(header["stderr"], dynamic_product / "usr/include", tuple(metadata["headers"]), role)  # type: ignore[arg-type]
        marker = f'# 0 "{source}"'.encode()
        require(marker in header["stdout"].read_bytes(), role + " preprocessed source differs")  # type: ignore[union-attr]
        require_argv(compile_command, _expected_compile_argv(str(tools["dynamic_driver"]["path"]), source, workload, flags),
                     role + " compile")
        require(compile_command["stdout"].read_bytes() == b"" and compile_command["stderr"].read_bytes() == b"",
                role + " compile raw output differs")  # type: ignore[union-attr]
        oracle = work / f"oracle-{role}"
        oracle_link = commands[f"{role}-oracle-link"]
        require_argv(oracle_link,
                     [str(tools["oracle"]["path"]), "-std=c11", "-static", "-fno-pie", "-no-pie",
                      str(workload), "-o", str(oracle)], role + " oracle link")
        require(oracle_link["stdout"].read_bytes() == b"" and oracle_link["stderr"].read_bytes() == b"",
                role + " oracle link raw output differs")  # type: ignore[union-attr]
        oracle_run = commands[f"{role}-oracle-run"]
        if role == "stdio.process-streams":
            oracle_root = directory(_process_root(work, "oracle"), "process oracle root")
            oracle_scratch = oracle_root / "scratch/stream"
            require_argv(oracle_run, ["chroot", str(oracle_root), "/consumer", "/scratch/stream"], role + " oracle run")
        else:
            oracle_scratch = work / f"oracle-{role}-stream"
            require_argv(oracle_run, _expected_run(oracle, oracle_scratch), role + " oracle run")
        require(oracle_run["stderr"].read_bytes() == b"", role + " oracle stderr differs")  # type: ignore[union-attr]

        for linkage, cell in (("static", "static"), ("static-pie", "static-pie")):
            executable = work / f"{role}-{linkage}"
            validate_link(work, commands, links, role, linkage, static_product, workload, executable)
            run = commands[f"{role}-{linkage}-run"]
            expected_stems.update((f"{role}-{linkage}-link", f"{role}-{linkage}-run"))
            if role == "stdio.process-streams":
                root = directory(_process_root(work, linkage), "process " + linkage + " root")
                scratch = root / "scratch/stream"
                require_argv(run, ["chroot", str(root), "/consumer", "/scratch/stream"], f"{role} {linkage} run")
            else:
                scratch = work / f"{role}-{linkage}-stream"
                require_argv(run, _expected_run(executable, scratch), f"{role} {linkage} run")
            require(run["stdout"].read_bytes() == oracle_run["stdout"].read_bytes()
                    and run["stderr"].read_bytes() == oracle_run["stderr"].read_bytes(),
                    f"{role} {linkage} raw output differs from pinned musl")  # type: ignore[union-attr]
            if metadata["side_effect"] is None:
                cleanup = commands[f"{role}-{linkage}-cleanup"]
                expected_stems.add(f"{role}-{linkage}-cleanup")
                require_argv(cleanup, ["test", "!", "-e", str(scratch)], f"{role} {linkage} cleanup")
            else:
                effect = check_identity(work, backend_effects[cell], f"{role} {cell} side effect")
                expected_effect = work / f"stdio.file-backends-{cell}-exit"
                require(effect == expected_effect and effect.read_bytes() == metadata["side_effect"],
                        f"{role} {cell} ordinary-exit side effect differs")

        role_payloads = payloads[role]
        require(type(role_payloads) is dict and set(role_payloads) == {"pie", "non-pie"}, role + " payload modes differ")
        for linkage in ("pie", "non-pie"):
            executable = work / f"dynamic-{role}-{linkage}"
            validate_link(work, commands, links, role, linkage, dynamic_product, workload, executable)
            expected_stems.add(f"{role}-{linkage}-link")
            value = role_payloads[linkage]
            require(type(value) is dict and set(value) == {"record", "before", "after"},
                    f"{role} dynamic {linkage} payload fields differ")
            root = directory(work / f"dynamic-{role}-{linkage}-root", f"{role} dynamic {linkage} execution root")
            record = check_identity(work, value["record"], f"{role} dynamic {linkage} payload record")
            before = commands[f"{role}-{linkage}-copy-audit-before"]
            after = commands[f"{role}-{linkage}-copy-audit-after"]
            expected_stems.update((f"{role}-{linkage}-copy-before", f"{role}-{linkage}-copy-audit-before",
                                   f"{role}-{linkage}-copy-audit-after", f"{role}-{linkage}-kernel",
                                   f"{role}-{linkage}-direct"))
            consumer = root / "consumer"
            record_command = commands[f"{role}-{linkage}-copy-before"]
            record_argv = ["python3", "-B", str(COPIES_PATH), "record", "--product", str(dynamic_product),
                          "--execution-root", str(root), "--source-consumer", str(executable),
                          "--execution-consumer", str(consumer), "--record", str(record)]
            require_argv(record_command, record_argv, f"{role} dynamic {linkage} payload record")
            require(record_command["stdout"].read_bytes() == b"" and record_command["stderr"].read_bytes() == b"",
                    f"{role} dynamic {linkage} payload record output differs")  # type: ignore[union-attr]
            audit_argv = ["python3", "-B", str(COPIES_PATH), "audit", "--product", str(dynamic_product),
                          "--execution-root", str(root), "--source-consumer", str(executable),
                          "--execution-consumer", str(consumer), "--record", str(record)]
            for phase, command in (("before", before), ("after", after)):
                require_argv(command, audit_argv, f"{role} dynamic {linkage} payload {phase} audit")
            payload_audit(work, before, dynamic_product, root, executable, consumer, record,
                          f"{role} dynamic {linkage} before")
            for entry, cell in (("kernel", f"dynamic-{linkage}-kernel"), ("direct", f"dynamic-{linkage}-direct")):
                run = commands[f"{role}-{linkage}-{entry}"]
                scratch = root / "scratch/stream"
                argv = (["chroot", str(root), "/consumer", "/scratch/stream"] if entry == "kernel" else
                        ["chroot", str(root), INTERPRETER, "/consumer", "/scratch/stream"])
                require_argv(run, argv, f"{role} dynamic {linkage} {entry} run")
                require(run["stdout"].read_bytes() == oracle_run["stdout"].read_bytes()
                        and run["stderr"].read_bytes() == oracle_run["stderr"].read_bytes(),
                        f"{role} dynamic {linkage} {entry} raw output differs from pinned musl")  # type: ignore[union-attr]
                if metadata["side_effect"] is not None:
                    effect = check_identity(work, backend_effects[cell], f"{role} {cell} side effect")
                    expected_effect = work / f"stdio.file-backends-{cell}-exit"
                    require(effect == expected_effect and effect.read_bytes() == metadata["side_effect"],
                            f"{role} {cell} ordinary-exit side effect differs")
            payload_audit(work, after, dynamic_product, root, executable, consumer, record,
                          f"{role} dynamic {linkage} after")
            if metadata["side_effect"] is None:
                cleanup = commands[f"{role}-{linkage}-cleanup"]
                expected_stems.add(f"{role}-{linkage}-cleanup")
                require_argv(cleanup, ["test", "!", "-e", str(root / "scratch/stream")],
                             f"{role} dynamic {linkage} cleanup")
    require(set(commands) == expected_stems, "command roster differs")


def validate_report(path: Path, checkout: Path, *, require_static: bool = True) -> dict[str, object]:
    """Validate a full supplied-product FILE-engine receipt without executing it."""
    require(require_static is True, "FILE engine requires supplied-static admission")
    checkout = directory(checkout, "checkout")
    report_path = regular(path, "FILE engine report")
    work = directory(report_path.parent, "FILE engine work")
    require(work.is_relative_to(checkout / ".work"), "FILE engine report escapes checkout .work")
    report = strict_json(report_path, "FILE engine report")
    expected_fields = {"schema", "scope", "rows", "source", "workloads", "products", "seals", "object_seals",
                       "commands", "links", "execution_payloads", "side_effects", "control", "process_proc", "family_completion",
                       "promotion_ready", "public_support"}
    require(set(report) == expected_fields, "report fields differ")
    require(report["schema"] == SCHEMA, "report schema differs")
    same(report["scope"], list(SCOPE), "report scope differs")
    require(type(report["rows"]) is dict and set(report["rows"]) == set(SCOPE), "report row roster differs")
    same(report["rows"], {role: row_value(role) for role in SCOPE}, "report rows differ")
    require(report["family_completion"] is False and report["promotion_ready"] is False
            and report["public_support"] is False, "FILE engine flags differ")
    require(type(report["seals"]) is dict and set(report["seals"]) == {
        "source-product-before", "source-product-after", "tools-before", "tools-after"}, "seal roster differs")
    sources = validate_source_product_seals(checkout, work, report)
    tools = validate_tools(work, report)
    control = validate_control_material(work, report, tools)
    validate_process_proc(work, report, tools)
    workloads = validate_object_seals(work, report, sources, control)
    validate_commands(checkout, work, report, sources, workloads, tools, control)
    return {
        "schema": SCHEMA,
        "matrix": "supplied-static",
        "cells": 6,
        "execution_cells": list(EXECUTION_CELLS),
        "scope": list(SCOPE),
        "rows": report["rows"],
        "products": report["products"],
        "source": report["source"],
        "source_product_seal": report["seals"]["source-product-before"],
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--require-static", action="store_true")
    arguments = parser.parse_args()
    print(json.dumps(validate_report(arguments.report, arguments.checkout, require_static=arguments.require_static),
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
