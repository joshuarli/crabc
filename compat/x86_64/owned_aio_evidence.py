#!/usr/bin/env python3
"""Seal and replay installed owned-AIO product evidence.

The shell runner owns the behavior.  This helper is intentionally narrow: it
records the inputs before the runner consumes them and later reconstructs the
fixed AIO object, link, command, and chroot-root roster from those inputs.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import owned_crypt_runtime_evidence as copies
import owned_posix_product_evidence as products
import owned_dynamic_qualification as qualification
import run_qualification_manifest as native_qualification

SCHEMA = "crabc.x86_64-owned-aio-receipts/v1"
EXPECTED_SCHEMA = "crabc.x86_64-owned-aio-expected-native-inputs/v1"
SOURCE_MOUNT = "/workspace"
ENVIRONMENT = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1", "TZ": "UTC"}
PROBES = {
    "workload": "compat/x86_64/owned_aio_probe.c",
    "behavior": "compat/x86_64/owned_aio_behavior_probe.c",
    "fd-reuse": "compat/x86_64/owned_aio_fd_reuse_probe.c",
    "lio-create-failure": "compat/x86_64/owned_aio_lio_create_failure_probe.c",
    "suspend-wake": "compat/x86_64/owned_aio_suspend_wake_probe.c",
    "queued-cancel": "compat/x86_64/owned_aio_cancel_defect_probe.c",
    "cancel-cursor": "compat/x86_64/owned_aio_cancel_cursor_probe.c",
    "submit-cancel": "compat/x86_64/owned_aio_submit_cancel_probe.c",
    "fresh-signal": "compat/x86_64/owned_aio_fresh_signal_probe.c",
}
OBJECTS = {key: f"{key if key != 'workload' else 'workload'}-workload.o" for key in PROBES}
OBJECTS["workload"] = "workload.o"
CONSUMERS = {
    "workload": "consumer", "behavior": "behavior", "fd-reuse": "fd-reuse",
    "lio-create-failure": "lio-create-failure", "suspend-wake": "suspend-wake",
    "queued-cancel": "queued-cancel", "cancel-cursor": "cancel-cursor",
    "submit-cancel": "submit-cancel", "fresh-signal": "fresh-signal",
}
ORACLE_CASES = ("workload", "behavior", "fd-reuse", "lio-create-failure", "suspend-wake")
STATIC_MODES = (("static", "static"), ("static-pie", "static-pie"))
DYNAMIC_MODES = (("dynamic-pie", "pie"), ("dynamic-non-pie", "non-pie"))
ROUTES = ("kernel", "direct")
HEADERS = ("aio.h", "signal.h", "time.h", "features.h", "bits/alltypes.h")
STANDARD_TRANSCRIPTS = {
    "workload": b"owned-aio basic ok\n",
    "behavior": b"owned-aio behavior positioned/nonseekable/append/cancel/partial-sigevent/notify/list/suspend/fork=ok\n",
    "lio-create-failure": b"lio-create-failure-mask-retained=ok\n",
    "suspend-wake": b"aio-suspend wake-all single/list=ok\n",
}
FD_REUSE_SUCCESS = b"fd-reuse-regular-to-pipe=ok\n"
FD_REUSE_ESPIPE = re.compile(
    rb"fd-reuse-failure step=[A-Za-z0-9-]+ attempt=[1-9][0-9]* regular=[0-9]+ "
    rb"pipe-read=-?[0-9]+ pipe-write=-?[0-9]+ positioned-submit=-?[0-9]+ "
    rb"positioned-error=-?[0-9]+ positioned-return=-?[0-9]+ pipe-submit=0 "
    rb"pipe-error=29 pipe-return=-1 byte=-?[0-9]+ errno=29\n\Z"
)
SOURCES = tuple(PROBES.values()) + (
    "compat/x86_64/run_owned_aio.sh", "compat/x86_64/owned_aio_evidence.py",
    "compat/x86_64/owned_posix_product_evidence.py", "compat/x86_64/owned_crypt_runtime_evidence.py",
    "compat/x86_64/owned_dynamic_qualification.py", "compat/x86_64/run_qualification_manifest.py",
    "compat/upstreams.toml", "docker/x86_64-musl-oracle-gcc", "docs/evidence/x86-owned-aio.md",
)
TOOL_NAMES = ("dynamic-driver", "compiler", "linker", "oracle-compiler", "chroot", "timeout")

class EvidenceError(RuntimeError):
    pass

def fail(message: str) -> None:
    raise EvidenceError(message)

def _physical(path: Path, description: str, *, directory: bool | None = None) -> Path:
    if ".." in path.parts:
        fail(f"{description} has lexical parent traversal: {path}")
    value = Path(os.path.abspath(path))
    current = Path(value.anchor)
    try:
        for piece in value.parts[1:]:
            current /= piece
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{description} traverses a symlink: {path}")
        mode = value.lstat().st_mode
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {path}") from error
    if directory is True and not stat.S_ISDIR(mode):
        fail(f"{description} is not a physical directory: {path}")
    if directory is False and not stat.S_ISREG(mode):
        fail(f"{description} is not a physical regular file: {path}")
    return value

def supplied_product(root: Path, raw: Path, family: str) -> str:
    """Validate the original spelling before canonicalization can hide aliases."""
    root = _physical(root, "checkout", directory=True)
    product = _physical(raw, f"supplied {family} product", directory=True)
    work = _physical(root / ".work", "checkout .work", directory=True)
    if not product.is_relative_to(work):
        fail(f"supplied {family} product physically escapes checkout .work")
    try:
        if family == "dynamic":
            products._validate_dynamic_product(product)
        elif family == "static":
            products._validate_static_product(product)
        else:
            fail("unknown supplied product family")
    except products.ProductEvidenceError as error:
        raise EvidenceError(f"supplied {family} product is invalid: {error}") from error
    return str(product)

def _sha(path: Path) -> str:
    path = _physical(path, "hashed artifact", directory=False)
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def _mode(path: Path) -> int:
    return stat.S_IMODE(_physical(path, "mode artifact").lstat().st_mode)

def _mounted(root: Path, path: Path) -> str:
    path = _physical(path, "checkout artifact")
    try:
        return str(Path(SOURCE_MOUNT) / path.relative_to(root))
    except ValueError as error:
        raise EvidenceError(f"artifact escapes checkout: {path}") from error

def _local(root: Path, mounted: object, description: str, *, directory: bool | None = None) -> Path:
    if not isinstance(mounted, str) or not mounted.startswith(SOURCE_MOUNT + "/"):
        fail(f"{description} does not use the fixed source mount")
    relative = Path(mounted).relative_to(SOURCE_MOUNT)
    if any(item in {"", ".", ".."} for item in relative.parts):
        fail(f"{description} has an unsafe source-mounted path")
    return _physical(root / relative, description, directory=directory)

def _identity(root: Path, path: Path, description: str) -> dict[str, Any]:
    path = _physical(path, description, directory=False)
    return {"path": _mounted(root, path), "sha256": _sha(path), "mode": _mode(path)}

def _tool(path: Path, description: str) -> dict[str, Any]:
    # Commands in the pinned image can be aliases; retain the physical image
    # executable while recorded argv preserves the invoked path separately.
    value = _physical(Path(os.path.realpath(path)), description, directory=False)
    return {"path": str(value), "sha256": _sha(value), "mode": _mode(value)}

def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        fail(f"refusing to replace retained evidence: {path}")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush(); os.fsync(stream.fileno())

def _read(path: Path, description: str) -> Any:
    try:
        return json.loads(_physical(path, description, directory=False).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{description} is not JSON") from error

def _exact(value: object, fields: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{description} fields drifted")
    return value

def _driver_tools(dynamic: Path, static: Path | None) -> dict[str, Any]:
    helper = _physical(dynamic / "share/crabc/crabc_cc_static.py", "installed compiler helper", directory=False)
    spec = importlib.util.spec_from_file_location("owned_aio_compiler_helper", helper)
    if spec is None or spec.loader is None:
        fail("installed compiler helper cannot load")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        compiler, linker = Path(module.compiler()), Path(module.linker())
    except (AttributeError, OSError, RuntimeError) as error:
        raise EvidenceError("installed compiler helper cannot resolve tools") from error
    finally:
        sys.modules.pop(spec.name, None)
    result = {
        "dynamic-driver": _tool(dynamic / "bin/crabc-cc-dynamic", "installed dynamic driver"),
        "compiler": _tool(compiler, "installed compiler"),
        "linker": _tool(linker, "installed linker"),
        "oracle-compiler": _tool(Path("/usr/local/bin/crabc-x86_64-musl-gcc"), "pinned musl compiler"),
        "chroot": _tool(Path("/usr/sbin/chroot"), "chroot"),
        "timeout": _tool(Path("/usr/bin/timeout"), "timeout"),
    }
    if static is not None:
        result["static-driver"] = _tool(static / "bin/crabc-cc", "installed static driver")
    return result

def _product(root: Path, path: Path, family: str) -> dict[str, Any]:
    path = _physical(path, f"{family} product", directory=True)
    try:
        manifest, files = (products._validate_dynamic_product(path) if family == "dynamic" else products._validate_static_product(path))
    except products.ProductEvidenceError as error:
        raise EvidenceError(f"{family} product validation failed: {error}") from error
    return {"root": _mounted(root, path), "manifest": _identity(root, manifest, f"{family} product manifest"),
            "files": dict(sorted(files.items()))}

def _oracle(root: Path, work: Path) -> dict[str, Any]:
    try:
        qualified = qualification.capture_oracle(work)
        qualification.require_live_oracle(work, qualified)
    except qualification.QualificationError as error:
        raise EvidenceError(f"pinned musl qualification input unavailable: {error}") from error
    libc_a = Path("/opt/musl-1.2.6/lib/libc.a")
    loader = Path(native_qualification.MUSL_RUNTIME_PATHS["loader"])
    return {"qualification": qualified, "static-libc": _tool(libc_a, "pinned musl static libc"),
            "loader": _tool(loader, "pinned musl loader")}

def _oracle_after(work: Path, before: Mapping[str, Any]) -> dict[str, Any]:
    """Re-observe native oracle bytes without replacing the retained copy."""
    try:
        qualification.require_live_oracle(work, dict(before["qualification"]))
    except qualification.QualificationError as error:
        raise EvidenceError(f"pinned musl oracle changed during AIO collection: {error}") from error
    return {"qualification": before["qualification"],
            "static-libc": _tool(Path("/opt/musl-1.2.6/lib/libc.a"), "post-run pinned musl static libc"),
            "loader": _tool(Path(native_qualification.MUSL_RUNTIME_PATHS["loader"]), "post-run pinned musl loader")}

def _input(root: Path, work: Path, dynamic: Path, static: Path | None, tools: Mapping[str, Any], oracle: Mapping[str, Any]) -> dict[str, Any]:
    return {"sources": {name: _identity(root, root / name, f"AIO source {name}") for name in SOURCES},
            "products": {"dynamic": _product(root, dynamic, "dynamic"),
                         "static": _product(root, static, "static") if static is not None else None},
            "tools": dict(tools), "oracle": dict(oracle)}

def command_environment(root: Path, work: Path) -> dict[str, str]:
    """The complete scrubbed environment actually passed to each command."""
    return {**ENVIRONMENT, "TMPDIR": _mounted(root, work)}

def expected_native_input(tools: Mapping[str, Any], oracle: Mapping[str, Any]) -> dict[str, Any]:
    expected = {name: tools[name] for name in TOOL_NAMES}
    return {"schema": EXPECTED_SCHEMA, "target": "x86_64-unknown-linux-musl", "tools": expected,
            "oracle": {"qualification": oracle["qualification"], "static-libc": oracle["static-libc"], "loader": oracle["loader"]}}

def _same_expected(expected: object, tools: Mapping[str, Any], oracle: Mapping[str, Any]) -> None:
    value = _exact(expected, {"schema", "target", "tools", "oracle"}, "external native input seal")
    if value["schema"] != EXPECTED_SCHEMA or value["target"] != "x86_64-unknown-linux-musl":
        fail("external native input identity differs")
    if value != expected_native_input(tools, oracle):
        fail("report native tool or oracle identity differs from external input seal")

def seal_inputs(root: Path, work: Path, dynamic: Path, static: Path | None) -> Path:
    root = _physical(root, "checkout", directory=True); work = _physical(work, "AIO work", directory=True)
    dynamic = _physical(dynamic, "dynamic product", directory=True)
    static = _physical(static, "static product", directory=True) if static is not None else None
    tools = _driver_tools(dynamic, static); oracle = _oracle(root, work)
    before = _input(root, work, dynamic, static, tools, oracle)
    _write(work / "aio-inputs-before.json", before)
    _write(work / "expected-native-inputs.json", expected_native_input(tools, oracle))
    return work / "expected-native-inputs.json"

def capture_expected(root: Path, work: Path, dynamic: Path, static: Path | None) -> Path:
    root = _physical(root, "checkout", directory=True); work = _physical(work, "AIO expected input work", directory=True)
    dynamic = _physical(dynamic, "dynamic product", directory=True)
    static = _physical(static, "static product", directory=True) if static is not None else None
    result = expected_native_input(_driver_tools(dynamic, static), _oracle(root, work))
    path = work / "expected-native-inputs.json"; _write(path, result); return path

def tool_path(dynamic: Path, static: Path | None, name: str) -> str:
    tools = _driver_tools(_physical(dynamic, "dynamic product", directory=True),
                          _physical(static, "static product", directory=True) if static is not None else None)
    if name not in tools:
        fail(f"unknown installed tool: {name}")
    return str(tools[name]["path"])

def record_command(root: Path, work: Path, label: str, argv: list[str], cwd: Path, stdout: Path, stderr: Path, status: Path) -> Path:
    if not label or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in label):
        fail("command label is unsafe")
    if not argv or not all(isinstance(item, str) for item in argv):
        fail("retained command must have a nonempty argv")
    root = _physical(root, "checkout", directory=True); work = _physical(work, "AIO work", directory=True)
    cwd = _physical(cwd, "AIO command cwd", directory=True)
    if not cwd.is_relative_to(root):
        fail("AIO command cwd escapes checkout")
    record = {"argv": argv, "cwd": _mounted(root, cwd), "environment": command_environment(root, work),
              "stdout": _identity(root, stdout, f"{label} stdout"),
              "stderr": _identity(root, stderr, f"{label} stderr"),
              "status": _identity(root, status, f"{label} status")}
    path = work / "commands" / f"{label}.json"; _write(path, record); return path

def _identity_current(root: Path, value: object, expected: Path, description: str) -> Path:
    value = _exact(value, {"path", "sha256", "mode"}, description)
    path = _local(root, value["path"], description, directory=False)
    if path != _physical(expected, f"{description} expected", directory=False) or value != _identity(root, path, description):
        fail(f"{description} identity differs")
    return path

def _source_record(root: Path, record: object) -> None:
    record = _exact(record, {"sources", "products", "tools", "oracle"}, "AIO input seal")
    if not isinstance(record["sources"], dict) or set(record["sources"]) != set(SOURCES):
        fail("AIO source roster differs")
    for name in SOURCES:
        _identity_current(root, record["sources"][name], root / name, f"AIO source {name}")

def _tool_record(value: object, description: str) -> dict[str, Any]:
    value = _exact(value, {"path", "sha256", "mode"}, description)
    if not isinstance(value["path"], str) or not Path(value["path"]).is_absolute() or ".." in Path(value["path"]).parts:
        fail(f"{description} path differs")
    if not isinstance(value["sha256"], str) or len(value["sha256"]) != 64 or type(value["mode"]) is not int:
        fail(f"{description} identity differs")
    return value

def _check_input(root: Path, work: Path, value: object, *, after: bool) -> tuple[Path, Path | None, dict[str, Any], dict[str, Any]]:
    _source_record(root, value)
    products_record = _exact(value["products"], {"dynamic", "static"}, "AIO input products")
    dynamic = _local(root, _exact(products_record["dynamic"], {"root", "manifest", "files"}, "dynamic product record")["root"], "dynamic product", directory=True)
    if products_record["dynamic"] != _product(root, dynamic, "dynamic"):
        fail("dynamic product input differs")
    static: Path | None = None
    if products_record["static"] is not None:
        record = _exact(products_record["static"], {"root", "manifest", "files"}, "static product record")
        static = _local(root, record["root"], "static product", directory=True)
        if record != _product(root, static, "static"):
            fail("static product input differs")
    tools = value["tools"]
    expected_names = set(TOOL_NAMES) | ({"static-driver"} if static is not None else set())
    if not isinstance(tools, dict) or set(tools) != expected_names:
        fail("AIO tool roster differs")
    for name in sorted(expected_names):
        _tool_record(tools[name], f"AIO tool {name}")
    driver_paths: list[tuple[str, Path]] = [("dynamic-driver", dynamic / "bin/crabc-cc-dynamic")]
    if static is not None:
        driver_paths.append(("static-driver", static / "bin/crabc-cc"))
    for name, product_path in driver_paths:
        expected_driver = {"path": _mounted(root, product_path), "sha256": _sha(product_path), "mode": _mode(product_path)}
        if tools[name] != expected_driver:
            fail(f"AIO installed {name} differs from selected product")
    oracle = value["oracle"]
    if not isinstance(oracle, dict) or set(oracle) != {"qualification", "static-libc", "loader"}:
        fail("AIO oracle roster differs")
    # Retained qualification bytes and caller pins bind source identity without
    # consulting qualification.ROOT from a different worker checkout.
    qualification_value = oracle["qualification"]
    if not isinstance(qualification_value, dict) or set(qualification_value) != {"version", "runtime_sha256", "compiler_wrapper_sha256", "pins_sha256", "files"}:
        fail("AIO retained musl qualification roster differs")
    files = qualification_value["files"]
    if not isinstance(files, dict) or set(files) != set(qualification.ORACLE_FILES):
        fail("AIO retained musl qualification files differ")
    oracle_dir = _physical(work / "qualification-oracle", "retained musl qualification directory", directory=True)
    if {entry.name for entry in oracle_dir.iterdir()} != set(files):
        fail("AIO retained musl qualification file roster differs")
    for name, digest in files.items():
        if not isinstance(digest, str) or len(digest) != 64 or _sha(oracle_dir / name) != digest:
            fail("AIO retained musl qualification bytes differ")
    pins = _physical(root / "compat/upstreams.toml", "caller musl pins", directory=False)
    wrapper = _physical(root / "docker/x86_64-musl-oracle-gcc", "caller oracle wrapper", directory=False)
    if qualification_value["pins_sha256"] != _sha(pins) or qualification_value["compiler_wrapper_sha256"] != _sha(wrapper):
        fail("AIO retained musl qualification pin differs")
    try:
        musl = tomllib.loads(pins.read_text(encoding="utf-8"))["musl"]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError) as error:
        raise EvidenceError("caller musl pins are malformed") from error
    manifest = ("format=crabc-pinned-musl-oracle-v1\n" f"version={musl['version']}\nsource_sha256={musl['sha256']}\n"
                f"fallback_revision={musl['fallback_revision']}\narchitecture=x86_64\n")
    if (oracle_dir / "source_manifest").read_text(encoding="utf-8") != manifest:
        fail("AIO retained musl source manifest differs")
    _tool_record(oracle["static-libc"], "AIO retained static musl oracle")
    _tool_record(oracle["loader"], "AIO retained musl loader")
    return dynamic, static, dict(tools), dict(oracle)

def _command(root: Path, work: Path, label: str, expected_argv: list[str], expected_status: set[bytes],
             *, cwd: Path | None = None) -> dict[str, Any]:
    record = _read(work / "commands" / f"{label}.json", f"AIO command {label}")
    record = _exact(record, {"argv", "cwd", "environment", "stdout", "stderr", "status"}, f"AIO command {label}")
    cwd = root if cwd is None else _physical(cwd, f"AIO command {label} cwd", directory=True)
    if (record["argv"] != expected_argv or record["cwd"] != _mounted(root, cwd)
            or record["environment"] != command_environment(root, work)):
        fail(f"AIO command {label} differs from canonical invocation")
    status = _identity_current(root, record["status"], work / f"{label}.status", f"AIO command {label} status")
    if status.read_bytes() not in expected_status:
        fail(f"AIO command {label} raw status differs")
    for key, suffix in (("stdout", "stdout"), ("stderr", "stderr")):
        _identity_current(root, record[key], work / f"{label}.{suffix}", f"AIO command {label} {key}")
    return record

def _expected_root(root: Path, work: Path, mode: str, dynamic: Path | None) -> tuple[Path, dict[str, Path], dict[str, Path], dict[str, str]]:
    if mode == "oracle":
        execution = work / "oracle-root"; candidates = {key: work / f"oracle-{key}" if key != "workload" else work / "oracle" for key in ORACLE_CASES}
        return execution, candidates, {}, {}
    if mode in {"static", "static-pie"}:
        execution = work / f"{mode}-root"; candidates = {key: work / (mode if key == "workload" else f"{mode}-{key}") for key in CONSUMERS}
        return execution, candidates, {}, {}
    if dynamic is None: fail("dynamic execution root has no selected product")
    execution = work / f"{mode}-root"; base = mode.removeprefix("dynamic-")
    candidates = {key: work / f"dynamic-{base}" if key == "workload" else work / f"dynamic-{base}-{key}" for key in CONSUMERS}
    _, manifest, files, aliases = copies.dynamic_product(dynamic)
    expected = {"share/crabc/manifest.json": manifest}
    expected.update({name: dynamic / name for name in files})
    return execution, candidates, expected, aliases

def _walk(root: Path) -> tuple[set[str], set[str], set[str]]:
    regular, aliases, devices = set(), set(), set()
    for entry in sorted(root.rglob("*")):
        name = entry.relative_to(root).as_posix(); mode = entry.lstat().st_mode
        if stat.S_ISDIR(mode): continue
        if stat.S_ISREG(mode): regular.add(name)
        elif stat.S_ISLNK(mode): aliases.add(name)
        elif stat.S_ISCHR(mode): devices.add(name)
        else: fail(f"AIO execution root has unsupported entry: {name}")
    return regular, aliases, devices

def assert_execution_tree(root: Path, regular_sources: Mapping[str, Path], aliases: Mapping[str, str],
                          device: tuple[str, int, int, int] | None) -> None:
    """Bind every copied runtime/consumer byte and retained root entry.

    ``regular_sources`` names the independent product/link source for each
    in-root regular file. A report cannot re-sign an execution copy because
    this comparison never takes expected bytes from the execution record.
    """
    root = _physical(root, "AIO execution root", directory=True)
    if not regular_sources or len(set(regular_sources)) != len(regular_sources):
        fail("AIO execution regular roster is malformed")
    regular, actual_aliases, devices = _walk(root)
    expected_devices = {device[0]} if device is not None else set()
    if regular != set(regular_sources) or actual_aliases != set(aliases) or devices != expected_devices:
        fail("AIO execution root roster differs")
    for relative, source in regular_sources.items():
        destination = _physical(root / relative, f"AIO execution copy {relative}", directory=False)
        if _sha(destination) != _sha(source) or _mode(destination) != _mode(source):
            fail(f"AIO execution copy differs for {relative}")
    for relative, target in aliases.items():
        if os.readlink(root / relative) != target:
            fail(f"AIO execution alias differs: {relative}")
    if device is not None:
        relative, mode, major, minor = device
        entry = root / relative
        observed = entry.lstat()
        if not stat.S_ISCHR(observed.st_mode) or (stat.S_IMODE(observed.st_mode), os.major(observed.st_rdev), os.minor(observed.st_rdev)) != (mode, major, minor):
            fail("AIO execution null device differs")

def _execution(root: Path, work: Path, mode: str, dynamic: Path | None) -> dict[str, Any]:
    execution, consumers, product_files, aliases = _expected_root(root, work, mode, dynamic)
    execution = _physical(execution, f"AIO {mode} execution root", directory=True)
    regular_sources = {CONSUMERS[name]: source for name, source in consumers.items()}
    regular_sources.update(product_files)
    assert_execution_tree(execution, regular_sources, aliases, ("dev/null", 0o644, 1, 3))
    regular, actual_aliases, _ = _walk(execution)
    null = execution / "dev/null"; null_stat = null.lstat()
    return {"root": _mounted(root, execution), "mode": mode,
            "regular": {name: _identity(root, execution / name, f"AIO {mode} execution {name}") for name in sorted(regular)},
            "aliases": {name: os.readlink(execution / name) for name in sorted(actual_aliases)},
            "null": {"path": _mounted(root, null), "mode": stat.S_IMODE(null_stat.st_mode), "major": os.major(null_stat.st_rdev), "minor": os.minor(null_stat.st_rdev)}}

def _validate_execution_record(root: Path, work: Path, mode: str, dynamic: Path | None, value: object) -> None:
    replay = _execution(root, work, mode, dynamic)
    if value != replay: fail(f"AIO {mode} execution record differs")

def _link(root: Path, work: Path, product: Path, obj: Path, binary: Path, receipt: Path, linkage: str,
          tools: Mapping[str, Any], *, retained: bool) -> dict[str, Any]:
    try:
        receipt_value = _read(receipt, "AIO link receipt")
        actual_linker = receipt_value.get("resolved_linker") if isinstance(receipt_value, dict) else None
        sealed_linker = {"path": tools["linker"]["path"], "sha256": tools["linker"]["sha256"]}
        if actual_linker != sealed_linker:
            fail("AIO link receipt selected an unsealed linker")
        if retained:
            reader = getattr(products, "validate_retained_link", None)
            if reader is None:
                fail("AIO host replay requires the shared retained-link reader")
            value = reader(root, SOURCE_MOUNT, product, obj, binary, receipt, linkage, actual_linker)
        else:
            value = products.validate_link(product, obj, binary, receipt, linkage)
    except (products.ProductEvidenceError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"AIO sealed {linkage} link differs: {error}") from error
    value = dict(value)
    value["product"] = _mounted(root, product)
    return {**value, "object": _identity(root, obj, "AIO workload object"),
            "binary": _identity(root, binary, "AIO linked consumer"), "linker": sealed_linker}

def _status_text(root: Path, command: Mapping[str, Any]) -> bytes:
    return _local(root, command["status"]["path"], "AIO command status", directory=False).read_bytes()

def _streams(root: Path, command: Mapping[str, Any], description: str) -> tuple[bytes, bytes]:
    stdout = _local(root, command["stdout"]["path"], f"{description} stdout", directory=False).read_bytes()
    stderr = _local(root, command["stderr"]["path"], f"{description} stderr", directory=False).read_bytes()
    return stdout, stderr

def assert_success_transcript(root: Path, command: Mapping[str, Any], expected: bytes, description: str) -> tuple[bytes, bytes]:
    """Require one completed AIO workload's full, quiet transcript."""
    stdout, stderr = _streams(root, command, description)
    if stdout != expected or stderr != b"":
        fail(f"{description} transcript differs")
    return stdout, stderr

def assert_matched_transcript(root: Path, oracle: Mapping[str, Any], candidate: Mapping[str, Any], description: str) -> None:
    if _streams(root, oracle, f"{description} oracle") != _streams(root, candidate, f"{description} candidate"):
        fail(f"{description} candidate differs from pinned-musl transcript")

def assert_oracle_fd_reuse(root: Path, command: Mapping[str, Any]) -> None:
    """Accept only the observed success or the pinned stale-queue ESPIPE form."""
    status, (stdout, stderr) = _status_text(root, command), _streams(root, command, "pinned musl fd-reuse")
    if status == b"0\n":
        if stdout != FD_REUSE_SUCCESS or stderr != b"":
            fail("pinned musl fd-reuse success transcript differs")
    elif status == b"1\n":
        if stdout != b"" or FD_REUSE_ESPIPE.fullmatch(stderr) is None:
            fail("pinned musl fd-reuse failure is not the stale-queue ESPIPE observation")
    else:
        fail("pinned musl fd-reuse status differs")

def _candidate_expected(consumer: str, arguments: str) -> bytes:
    if consumer in STANDARD_TRANSCRIPTS:
        return STANDARD_TRANSCRIPTS[consumer]
    if consumer == "fd-reuse":
        return FD_REUSE_SUCCESS
    if consumer == "queued-cancel":
        return f"queued-cancel-{arguments}=ok\n".encode("ascii")
    if consumer == "cancel-cursor":
        return f"cancel-cursor-{arguments}=ok\n".encode("ascii")
    if consumer == "submit-cancel":
        return b"submit-handoff-cancellation=deferred\n"
    if consumer == "fresh-signal":
        return b"fresh-signal-handler-close-pending=not-observed\n"
    fail(f"unknown AIO candidate consumer: {consumer}")

def _validate_header(root: Path, work: Path, dynamic: Path, tools: Mapping[str, Any]) -> dict[str, Any]:
    expected = [tools["compiler"]["path"], "-nostdinc", "-isystem", _mounted(root, dynamic / "usr/include"),
                "-ffreestanding", "-fno-builtin", "-fstack-protector-strong", "-fPIE", "-std=c11", "-D_GNU_SOURCE",
                "-E", "-H", _mounted(root, root / PROBES["workload"])]
    record = _command(root, work, "installed-header-trace", expected, {b"0\n"})
    trace = _local(root, record["stderr"]["path"], "installed header trace", directory=False).read_text(encoding="utf-8")
    for header in HEADERS:
        if _mounted(root, dynamic / "usr/include" / header) not in trace:
            fail(f"AIO installed header trace omits {header}")
    return record

def _compile_commands(root: Path, work: Path, dynamic: Path, tools: Mapping[str, Any]) -> dict[str, Any]:
    result = {}
    for key, source in PROBES.items():
        output = work / OBJECTS[key]
        argv = [tools["dynamic-driver"]["path"], "--dynamic-pie", "-std=c11", "-fno-builtin", "-c", _mounted(root, root / source), "-o", _mounted(root, output)]
        result[key] = _command(root, work, f"compile-{key}", argv, {b"0\n"})
        _physical(output, f"AIO installed header object {key}", directory=False)
    return result

def _cell_specs(static: Path | None) -> list[tuple[str, str, str, str, str]]:
    """(label, root mode, consumer, route, program arguments)."""
    values: list[tuple[str, str, str, str, str]] = []
    if static is not None:
        for mode, _ in STATIC_MODES:
            for key in CONSUMERS:
                if key == "queued-cancel":
                    values.extend(((f"{mode}-queued-cancel-target", mode, key, "", "target"), (f"{mode}-queued-cancel-all", mode, key, "", "all")))
                elif key == "cancel-cursor":
                    values.extend((f"{mode}-cancel-cursor-{case}", mode, key, "", case) for case in ("target-target", "all-target", "late"))
                elif key == "submit-cancel": values.append((f"{mode}-submit-cancel", mode, key, "", "c 128"))
                else: values.append((mode if key == "workload" else f"{mode}-{key}", mode, key, "", ""))
    for mode, _ in DYNAMIC_MODES:
        for route in ROUTES:
            rootmode = mode
            for key in CONSUMERS:
                prefix = f"{mode}-{route}"
                if key == "queued-cancel":
                    values.extend(((f"{prefix}-queued-cancel-target", rootmode, key, route, "target"), (f"{prefix}-queued-cancel-all", rootmode, key, route, "all")))
                elif key == "cancel-cursor":
                    values.extend((f"{prefix}-cancel-cursor-{case}", rootmode, key, route, case) for case in ("target-target", "all-target", "late"))
                elif key == "submit-cancel": values.append((f"{prefix}-submit-cancel", rootmode, key, route, "c 128"))
                else: values.append((prefix if key == "workload" else f"{prefix}-{key}", rootmode, key, route, ""))
    return values

def _mode_claims(static: Path | None) -> list[str]:
    claims: list[str] = []
    if static is not None:
        claims += ["static-et-exec", "static-pie"]
    claims += ["dynamic-pie-kernel", "dynamic-pie-direct", "dynamic-non-pie-kernel", "dynamic-non-pie-direct"]
    return claims

def _execution_argv(root: Path, work: Path, rootmode: str, consumer: str, route: str, arguments: str) -> list[str]:
    execution = work / f"{rootmode}-root"
    mounted = _mounted(root, execution); program = "/" + CONSUMERS[consumer]
    argv = ["/usr/bin/timeout", "30", "/usr/sbin/chroot", mounted]
    if rootmode.startswith("dynamic-") and route == "direct":
        argv += ["/lib/ld-crabc-x86_64.so.1", program]
    else: argv.append(program)
    if arguments: argv += arguments.split()
    if consumer == "fd-reuse": argv.append("512")
    return argv

def validate_report(root: Path, report_path: Path, expected: object, *, live: bool = False) -> dict[str, Any]:
    root = _physical(root, "caller checkout", directory=True); report_path = _physical(report_path, "AIO report", directory=False)
    report = _read(report_path, "AIO report")
    report = _exact(report, {"schema", "source_mount", "status", "modes", "inputs", "header_trace", "compiles", "links", "executions", "commands"}, "AIO report")
    if report["schema"] != SCHEMA or report["source_mount"] != SOURCE_MOUNT or report["status"] != "component-verified-not-family-qualified": fail("AIO report identity differs")
    work = _local(root, report["commands"], "AIO command work", directory=True)
    inputs = _exact(report["inputs"], {"before", "after", "expected_native_inputs"}, "AIO report inputs")
    dynamic, static, tools, oracle = _check_input(root, work, inputs["before"], after=False)
    if report["modes"] != _mode_claims(static):
        fail("AIO successful mode claims differ from the selected products")
    _same_expected(expected, tools, oracle)
    _same_expected(_read(_local(root, inputs["expected_native_inputs"], "retained expected native inputs", directory=False), "retained expected native inputs"), tools, oracle)
    header = _validate_header(root, work, dynamic, tools)
    if report["header_trace"] != header:
        fail("AIO installed-header trace record differs")
    compiles = _compile_commands(root, work, dynamic, tools)
    if report["compiles"] != compiles: fail("AIO compile records differ")
    source_links = [
        ("source-link-queued-cancel", root / PROBES["queued-cancel"], work / "oracle-queued-cancel"),
        ("source-link-submit-cancel", root / PROBES["submit-cancel"], work / "oracle-submit-cancel"),
        ("source-link-workload", work / OBJECTS["workload"], work / "oracle"),
        ("source-link-behavior", work / OBJECTS["behavior"], work / "oracle-behavior"),
        ("source-link-fd-reuse", work / OBJECTS["fd-reuse"], work / "oracle-fd-reuse"),
        ("source-link-lio-create-failure", work / OBJECTS["lio-create-failure"], work / "oracle-lio-create-failure"),
        ("source-link-suspend-wake", work / OBJECTS["suspend-wake"], work / "oracle-suspend-wake"),
    ]
    for label, input_path, output_path in source_links:
        _command(root, work, label, [tools["oracle-compiler"]["path"], "-static", "-fno-pie", "-no-pie", "-pthread",
                                     _mounted(root, input_path), "-o", _mounted(root, output_path)], {b"0\n"})
    # Source-known cancellation remains a raw pin observation and cannot be
    # promoted into a positive oracle comparison.
    defect_binary = work / "oracle-queued-cancel"
    for case in ("target", "all"):
        label = f"oracle-queued-cancel-{case}"
        _command(root, work, label, ["/usr/bin/timeout", "-k", "1", "5", _mounted(root, defect_binary), case], {b"124\n", b"137\n"})
    submit = _command(root, work, "oracle-submit-cancel", ["/usr/bin/timeout", "60", _mounted(root, work / "oracle-submit-cancel"), "s"], {b"0\n"})
    assert_success_transcript(root, submit, b"submit-handoff-cancellation=observed\n", "source submit cancellation")
    oracle_commands: dict[str, Any] = {}
    for key in ORACLE_CASES:
        binary = work / ("oracle" if key == "workload" else f"oracle-{key}")
        argv = ["/usr/bin/timeout", "30", "/usr/sbin/chroot", _mounted(root, work / "oracle-root"), "/" + CONSUMERS[key]]
        if key == "fd-reuse": argv.append("512")
        statuses = {b"0\n", b"1\n"} if key == "fd-reuse" else {b"0\n"}
        oracle_commands[key] = _command(root, work, f"oracle-{key}" if key != "workload" else "oracle", argv, statuses)
        if key == "fd-reuse":
            assert_oracle_fd_reuse(root, oracle_commands[key])
        else:
            assert_success_transcript(root, oracle_commands[key], STANDARD_TRANSCRIPTS[key], f"pinned musl {key}")
    links: dict[str, Any] = {}
    if static is not None:
        for mode, linkage in STATIC_MODES:
            for key in CONSUMERS:
                binary = work / (mode if key == "workload" else f"{mode}-{key}")
                receipt = work / f"{binary.name}.receipt.json"
                label = f"link-{mode}-{key}"
                expected_argv = [tools["static-driver"]["path"], f"-{mode}", "--link-receipt", receipt.name,
                                 _mounted(root, work / OBJECTS[key]), "-o", _mounted(root, binary)]
                _command(root, work, label, expected_argv, {b"0\n"}, cwd=work)
                links[label] = _link(root, work, static, work / OBJECTS[key], binary, receipt, linkage, tools, retained=not live)
    for mode, linkage in DYNAMIC_MODES:
        short = mode.removeprefix("dynamic-")
        for key in CONSUMERS:
            binary = work / (f"dynamic-{short}" if key == "workload" else f"dynamic-{short}-{key}")
            label = f"link-{mode}-{key}"
            expected_argv = [tools["dynamic-driver"]["path"], f"--dynamic-{short}", _mounted(root, work / OBJECTS[key]), "-o", _mounted(root, binary)]
            _command(root, work, label, expected_argv, {b"0\n"}, cwd=work)
            links[label] = _link(root, work, dynamic, work / OBJECTS[key], binary, binary.with_name(binary.name + ".crabc-link.json"), linkage, tools, retained=not live)
    if report["links"] != links: fail("AIO sealed link records differ")
    executions = {"oracle": _execution(root, work, "oracle", None)}
    if static is not None:
        executions.update({mode: _execution(root, work, mode, None) for mode, _ in STATIC_MODES})
    executions.update({mode: _execution(root, work, mode, dynamic) for mode, _ in DYNAMIC_MODES})
    if report["executions"] != executions: fail("AIO execution root records differ")
    for label, rootmode, consumer, route, arguments in _cell_specs(static):
        candidate = _command(root, work, label, _execution_argv(root, work, rootmode, consumer, route, arguments), {b"0\n"})
        assert_success_transcript(root, candidate, _candidate_expected(consumer, arguments), f"owned {label}")
        if consumer in STANDARD_TRANSCRIPTS:
            assert_matched_transcript(root, oracle_commands[consumer], candidate, f"owned {label}")
    expected_labels = {"installed-header-trace", *{f"compile-{key}" for key in PROBES},
                       *{label for label, _, _ in source_links}, "oracle-queued-cancel-target",
                       "oracle-queued-cancel-all", "oracle-submit-cancel", "oracle", "oracle-behavior",
                       "oracle-fd-reuse", "oracle-lio-create-failure", "oracle-suspend-wake"}
    if static is not None:
        expected_labels |= {f"link-{mode}-{key}" for mode, _ in STATIC_MODES for key in CONSUMERS}
    expected_labels |= {f"link-{mode}-{key}" for mode, _ in DYNAMIC_MODES for key in CONSUMERS}
    expected_labels |= {label for label, _, _, _, _ in _cell_specs(static)}
    observed_labels = {entry.stem for entry in (work / "commands").glob("*.json")}
    if observed_labels != expected_labels:
        fail("AIO retained command roster differs")
    after_dynamic, after_static, after_tools, after_oracle = _check_input(root, work, inputs["after"], after=True)
    if (dynamic, static, tools, oracle) != (after_dynamic, after_static, after_tools, after_oracle) or inputs["before"] != inputs["after"]:
        fail("AIO source, product, tool, or oracle changed during collection")
    return report

def finalize(root: Path, work: Path, expected_path: Path) -> Path:
    root = _physical(root, "checkout", directory=True); work = _physical(work, "AIO work", directory=True)
    before = _read(work / "aio-inputs-before.json", "AIO before input seal")
    dynamic, static, tools, oracle = _check_input(root, work, before, after=False)
    after = _input(root, work, dynamic, static, _driver_tools(dynamic, static), _oracle_after(work, oracle))
    commands = _mounted(root, work)
    report = {"schema": SCHEMA, "source_mount": SOURCE_MOUNT, "status": "component-verified-not-family-qualified",
              "modes": _mode_claims(static),
              "inputs": {"before": before, "after": after, "expected_native_inputs": _mounted(root, expected_path)},
              "header_trace": _read(work / "commands/installed-header-trace.json", "header trace command"),
              "compiles": {key: _read(work / f"commands/compile-{key}.json", f"compile {key}") for key in PROBES},
              "links": {}, "executions": {}, "commands": commands}
    # The reader reconstructs all links and roots; persist only their resulting
    # records after live product validation, never an arbitrary supplied map.
    for mode, linkage in STATIC_MODES:
        if static is None: continue
        for key in CONSUMERS:
            binary = work / (mode if key == "workload" else f"{mode}-{key}")
            report["links"][f"link-{mode}-{key}"] = _link(root, work, static, work / OBJECTS[key], binary, work / f"{binary.name}.receipt.json", linkage, tools, retained=False)
    for mode, linkage in DYNAMIC_MODES:
        short = mode.removeprefix("dynamic-")
        for key in CONSUMERS:
            binary = work / (f"dynamic-{short}" if key == "workload" else f"dynamic-{short}-{key}")
            report["links"][f"link-{mode}-{key}"] = _link(root, work, dynamic, work / OBJECTS[key], binary, binary.with_name(binary.name + ".crabc-link.json"), linkage, tools, retained=False)
    report["executions"]["oracle"] = _execution(root, work, "oracle", None)
    if static is not None:
        for mode, _ in STATIC_MODES: report["executions"][mode] = _execution(root, work, mode, None)
    for mode, _ in DYNAMIC_MODES: report["executions"][mode] = _execution(root, work, mode, dynamic)
    report_path = work / "owned-aio-receipts.json"; _write(report_path, report)
    expected = _read(expected_path, "AIO native input seal")
    validate_report(root, report_path, expected, live=True)
    return report_path

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest="action", required=True)
    supplied = sub.add_parser("supplied-product"); supplied.add_argument("--root", type=Path, required=True); supplied.add_argument("--family", choices=("static", "dynamic"), required=True); supplied.add_argument("path", type=Path)
    path = sub.add_parser("tool-path"); path.add_argument("--dynamic", type=Path, required=True); path.add_argument("--static", type=Path); path.add_argument("--name", required=True)
    seal = sub.add_parser("seal-inputs"); seal.add_argument("--root", type=Path, required=True); seal.add_argument("--work", type=Path, required=True); seal.add_argument("--dynamic", type=Path, required=True); seal.add_argument("--static", type=Path)
    external = sub.add_parser("capture-expected-inputs"); external.add_argument("--root", type=Path, required=True); external.add_argument("--work", type=Path, required=True); external.add_argument("--dynamic", type=Path, required=True); external.add_argument("--static", type=Path)
    command = sub.add_parser("record-command"); command.add_argument("--root", type=Path, required=True); command.add_argument("--work", type=Path, required=True); command.add_argument("--label", required=True); command.add_argument("--cwd", type=Path, required=True); command.add_argument("--stdout", type=Path, required=True); command.add_argument("--stderr", type=Path, required=True); command.add_argument("--status", type=Path, required=True); command.add_argument("argv", nargs=argparse.REMAINDER)
    finish = sub.add_parser("finalize"); finish.add_argument("--root", type=Path, required=True); finish.add_argument("--work", type=Path, required=True); finish.add_argument("--expected-inputs", type=Path, required=True)
    validate = sub.add_parser("validate"); validate.add_argument("--root", type=Path, required=True); validate.add_argument("--report", type=Path, required=True); validate.add_argument("--expected-inputs", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "supplied-product": print(supplied_product(args.root, args.path, args.family))
        elif args.action == "tool-path": print(tool_path(args.dynamic, args.static, args.name))
        elif args.action == "seal-inputs": print(seal_inputs(args.root, args.work, args.dynamic, args.static))
        elif args.action == "capture-expected-inputs": print(capture_expected(args.root, args.work, args.dynamic, args.static))
        elif args.action == "record-command":
            argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
            print(record_command(args.root, args.work, args.label, argv, args.cwd, args.stdout, args.stderr, args.status))
        elif args.action == "finalize": print(finalize(args.root, args.work, args.expected_inputs))
        else: validate_report(args.root, args.report, _read(args.expected_inputs, "external AIO native input seal"))
    except EvidenceError as error:
        print(f"owned aio evidence: {error}", file=sys.stderr); return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
