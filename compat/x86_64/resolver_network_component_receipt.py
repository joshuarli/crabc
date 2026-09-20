#!/usr/bin/env python3
"""Read one retained physical receipt from the native resolver-network gate.

This reader is deliberately narrower than ``compat.resolver-network`` family
admission.  It reconstructs the existing two-arm, twelve-candidate execution
from a public report and its retained execution root.  It never builds or runs
the workload, and it does not grant resolver-family, Rust-foundation, promotion,
or public-support credit.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_MOUNT = "/workspace"
PINNED_IMAGE = "crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
IMAGE_MANIFEST = "compat/x86_64/owned_utmpx_image_inputs.json"
RECEIPT_SCHEMA = "crabc.x86_64-resolver-network-physical/v2"
SCOPE = ("libc.resolver",)
EXECUTION_MODE = "two-arms-twelve-candidate-modes"
RUNNER = "crabc-resolver-network-native-x86"
ARTIFACT_MODES = ("static-et-exec", "static-pie", "dynamic-pie", "dynamic-non-pie")
ARMS = ("installed", "extracted")
DYNAMIC_INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
MUSL_ROOT = Path("/opt/musl-1.2.6")
MUSL_INCLUDE = MUSL_ROOT / "include"
HEADER_TRACE_PATH = re.compile(r"^\.+ (/.+)$")
COMPILER_ORACLE_INPUTS = {
    "gcc": Path("/usr/bin/gcc"),
    "assembler": Path("/usr/bin/as"),
    "linker": Path("/usr/bin/ld"),
    "cc1": Path("/usr/libexec/gcc/x86_64-alpine-linux-musl/15.2.0/cc1"),
    "collect2": Path("/usr/libexec/gcc/x86_64-alpine-linux-musl/15.2.0/collect2"),
    "lto_plugin": Path("/usr/libexec/gcc/x86_64-alpine-linux-musl/15.2.0/liblto_plugin.so"),
    "specs": MUSL_ROOT / "lib/musl-gcc.specs",
    "libc_archive": MUSL_ROOT / "lib/libc.a",
    "libc_shared": MUSL_ROOT / "lib/libc.so",
}
EXPECTED_STDOUT = (
    b"resolver.a=198.51.100.42\n"
    b"resolver.aaaa=2001:db8::42\n"
    b"resolver.nxdomain=HOST_NOT_FOUND\n"
    b"resolver.nodata=NO_DATA\n"
    b"resolver.malformed-wrong-id=accepted-valid\n"
    b"resolver.cname=target.example.test\n"
    b"resolver.tc-tcp=accepted-over-tcp\n"
    b"resolver.search=searchhost.search.test\n"
    b"resolver.fallback=second-server\n"
    b"network.tcp4=loopback\n"
    b"network.tcp6=loopback\n"
    b"network.udp4=loopback\n"
    b"network.udp6=loopback\n"
    b"network.socketpair-sendmsg-recvmsg=ok\n"
    b"network.ancillary-scm-rights=ok\n"
    b"network.epoll=readiness\n"
    b"network.shutdown-half-close=eof\n"
    b"network.partial-send=short-write\n"
    b"network.socket-timeout=EAGAIN\n"
    b"network.eintr=EINTR\n"
    b"network.nonblocking-recv=EAGAIN\n"
    b"network.poll-select=readiness\n"
)
REQUIRED_SERVER_NAMES = {
    "a.example.test.", "aaaa.example.test.", "nxdomain.example.test.",
    "nodata.example.test.", "malformed.example.test.", "alias.example.test.",
    "tc.example.test.", "searchhost.search.test.", "fallback.example.test.",
}
SOURCE_PATHS = {
    "runner": "compat/resolver-network/run_x86_64.py",
    "workload": "compat/resolver-network/workload.c",
    "dns_fixture": "compat/resolver-network/dns_server.py",
    "dynamic_receipt_contract": "compat/x86_64/owned_dynamic_receipt.py",
    "reader": "compat/x86_64/resolver_network_component_receipt.py",
    "image_manifest": IMAGE_MANIFEST,
}


class ReceiptError(RuntimeError):
    """The retained resolver-network component evidence cannot be replayed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json_bytes(value: bytes, description: str) -> object:
    try:
        return json.loads(value.decode("utf-8"), object_pairs_hook=no_duplicate_pairs)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{description} is not valid JSON") from error


def physical_directory(path: Path, description: str) -> Path:
    """Return a directory only when every path component is non-symlinked."""

    try:
        result = Path(os.path.abspath(path))
        require(result.exists() and result.is_dir() and not result.is_symlink(),
                f"{description} is not a physical directory: {path}")
        current = Path(result.anchor)
        for part in result.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return result
    except OSError as error:
        raise ReceiptError(f"{description} is unreadable: {path}") from error


def physical_file(path: Path, description: str) -> Path:
    """Return a regular file only when it has no symlinked path component."""

    try:
        result = Path(os.path.abspath(path))
        require(result.exists() and not result.is_symlink() and stat.S_ISREG(result.lstat().st_mode),
                f"{description} is not a physical regular file: {path}")
        current = Path(result.anchor)
        for part in result.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return result
    except OSError as error:
        raise ReceiptError(f"{description} is unreadable: {path}") from error


def digest(path: Path) -> str:
    path = physical_file(path, "hashed artifact")
    value = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def stream_record(value: bytes) -> dict[str, object]:
    return {
        "byte_length": len(value),
        "sha256": sha256(value).hexdigest(),
        "text": value.decode("utf-8", errors="replace"),
    }


def safe_relative(value: object, description: str) -> Path:
    require(isinstance(value, str) and value, f"{description} path is absent")
    candidate = Path(value)
    require(not candidate.is_absolute() and candidate.parts and
            all(part not in {"", ".", ".."} for part in candidate.parts),
            f"{description} path is unsafe")
    return candidate


def mounted_path(root: Path, value: object, description: str, *, directory: bool = False) -> Path:
    require(isinstance(value, str) and value.startswith(SOURCE_MOUNT + "/"),
            f"{description} is not below the pinned {SOURCE_MOUNT} mount")
    path = root / safe_relative(value.removeprefix(SOURCE_MOUNT + "/"), description)
    return physical_directory(path, description) if directory else physical_file(path, description)


def path_from_record(root: Path, value: object, description: str) -> Path:
    require(isinstance(value, str) and value, f"{description} identity path is absent")
    if value.startswith(SOURCE_MOUNT + "/"):
        return mounted_path(root, value, description)
    candidate = Path(value)
    require(candidate.is_absolute(), f"{description} identity path is not absolute")
    return physical_file(candidate, description)


def file_identity(root: Path, path: Path) -> dict[str, object]:
    path = physical_file(path, "receipt artifact")
    rendered = str(path)
    if path.is_relative_to(root):
        rendered = str(Path(SOURCE_MOUNT) / path.relative_to(root))
    return {"path": rendered, "sha256": digest(path), "byte_length": path.stat().st_size}


def receipt_file_identity(root: Path, path: Path) -> dict[str, object]:
    """Bind receipt artifacts' bytes and permission mode without changing summaries."""

    path = physical_file(path, "receipt artifact")
    return {**file_identity(root, path), "mode": stat.S_IMODE(path.lstat().st_mode)}


def assert_file_identity(root: Path, value: object, description: str, *, expected: Path | None = None) -> Path:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "byte_length"},
            f"{description} identity fields differ")
    path = path_from_record(root, value["path"], description)
    if expected is not None:
        require(path == physical_file(expected, description), f"{description} identity path differs")
    require(value == file_identity(root, path), f"{description} identity differs from physical artifact")
    return path


def assert_receipt_file_identity(root: Path, value: object, description: str, *, expected: Path | None = None) -> Path:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "byte_length", "mode"},
            f"{description} identity fields differ")
    path = path_from_record(root, value["path"], description)
    if expected is not None:
        require(path == physical_file(expected, description), f"{description} identity path differs")
    require(value == receipt_file_identity(root, path), f"{description} identity differs from physical artifact")
    return path


def tree_identity(root: Path, *, excluded: frozenset[str] = frozenset()) -> dict[str, object]:
    """Match the producer's no-follow tree digest for products and chroots."""

    root = physical_directory(root, "tree root")
    records: list[dict[str, object]] = []
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        if relative in excluded:
            continue
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode):
            records.append({"path": relative, "kind": "symlink", "target": os.readlink(entry)})
        elif stat.S_ISDIR(mode):
            records.append({"path": relative, "kind": "directory"})
        elif stat.S_ISREG(mode):
            records.append({"path": relative, "kind": "regular", "sha256": digest(entry)})
        else:
            raise ReceiptError(f"tree contains an unsafe entry: {entry}")
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"entry_count": len(records), "sha256": sha256(encoded).hexdigest()}


def receipt_tree_identity(root: Path, *, excluded: frozenset[str] = frozenset()) -> dict[str, object]:
    """Match the producer's mode-aware no-follow physical receipt tree digest."""

    root = physical_directory(root, "tree root")
    records: list[dict[str, object]] = [{
        "path": ".",
        "kind": "directory",
        "mode": stat.S_IMODE(root.lstat().st_mode),
    }]
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        if relative in excluded:
            continue
        mode = entry.lstat().st_mode
        permissions = stat.S_IMODE(mode)
        if stat.S_ISLNK(mode):
            records.append({"path": relative, "kind": "symlink", "mode": permissions, "target": os.readlink(entry)})
        elif stat.S_ISDIR(mode):
            records.append({"path": relative, "kind": "directory", "mode": permissions})
        elif stat.S_ISREG(mode):
            records.append({"path": relative, "kind": "regular", "mode": permissions, "sha256": digest(entry)})
        else:
            raise ReceiptError(f"tree contains an unsafe entry: {entry}")
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"entry_count": len(records), "sha256": sha256(encoded).hexdigest()}


def assert_tree_identity(
    root: Path, value: object, description: str, expected: Path, *, excluded: frozenset[str] = frozenset(),
) -> Path:
    require(isinstance(value, dict) and set(value) == {"path", "entry_count", "sha256"},
            f"{description} tree identity fields differ")
    path = mounted_path(root, value["path"], description, directory=True)
    expected = physical_directory(expected, description)
    require(path == expected, f"{description} tree identity path differs")
    require(value == {"path": str(Path(SOURCE_MOUNT) / path.relative_to(root)), **receipt_tree_identity(path, excluded=excluded)},
            f"{description} tree identity differs from physical tree")
    return path


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def load_runner(root: Path):
    path = physical_file(root / "compat/resolver-network/run_x86_64.py", "resolver-network runner")
    spec = importlib.util.spec_from_file_location("resolver_network_physical_receipt_runner", path)
    require(spec is not None and spec.loader is not None, "cannot load resolver-network runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def expected_contract() -> dict[str, object]:
    return {
        "network_namespace": "Docker --network none: loopback is the only observed interface and no default route is admitted",
        "conventional_files": "each execution chroot has only runner-written etc/hosts and etc/resolv.conf; the host/container /etc is never written",
        "source_object": "one workload.c object translated with pinned musl 1.2.6 headers and linked unchanged into every reference/candidate artifact",
        "product_arms": ["installed", "extracted"],
        "candidate_modes_per_arm": [
            "static-et-exec", "static-pie", "dynamic-pie ordinary", "dynamic-pie direct-entry",
            "dynamic-non-pie ordinary", "dynamic-non-pie direct-entry",
        ],
        "candidate_execution_count": 12,
        "comparison": "raw exit status, stdout, and stderr equality; no normalization",
        "physical_receipt": "raw execution bytes, physical inputs, link products, manifests and DNS event document are retained below state_root",
    }


def validate_report_document(report: object) -> Mapping[str, object]:
    """Reject summary-only reports before any filesystem-derived claim is made."""

    require(isinstance(report, dict), "resolver-network report is not an object")
    if report.get("schema_version") != 2 or not isinstance(report.get("receipt"), dict):
        raise ReceiptError("resolver-network report has no physical receipt schema")
    fields = {
        "schema_version", "runner", "result", "passed", "state_root", "published_report", "contract",
        "products", "product_identity", "translation", "reference", "candidates", "chroots", "execution", "receipt",
    }
    require(set(report) == fields, "resolver-network report fields differ")
    require(report["runner"] == RUNNER and report["result"] == "pass" and report["passed"] is True,
            "resolver-network report is not a passing native observation")
    require(report["contract"] == expected_contract(), "resolver-network report contract differs")
    receipt = report["receipt"]
    receipt_fields = {
        "schema", "component", "source_mount", "scope", "execution_mode", "image", "sources", "tools", "products",
        "workload", "links", "commands", "headers", "executions", "dns", "execution_root", "family_completion",
        "promotion_ready", "public_support",
    }
    require(set(receipt) == receipt_fields and receipt["schema"] == RECEIPT_SCHEMA and
            receipt["component"] == "resolver-network" and receipt["source_mount"] == SOURCE_MOUNT and
            receipt["scope"] == list(SCOPE) and receipt["execution_mode"] == EXECUTION_MODE,
            "resolver-network physical receipt contract differs")
    require(receipt["family_completion"] is False and receipt["promotion_ready"] is False and
            receipt["public_support"] is False,
            "resolver-network component receipt makes a promotion claim")
    return report


def image_manifest(root: Path, receipt: Mapping[str, object]) -> Mapping[str, object]:
    image = receipt["image"]
    require(isinstance(image, dict) and set(image) == {"id", "manifest"} and image["id"] == PINNED_IMAGE,
            "resolver receipt image identity differs")
    manifest = assert_receipt_file_identity(root, image["manifest"], "pinned core image manifest",
                                            expected=root / IMAGE_MANIFEST)
    value = read_json_bytes(manifest.read_bytes(), "pinned core image manifest")
    require(isinstance(value, dict) and set(value) == {"schema", "image", "path", "files"} and
            value.get("schema") == "crabc.x86_64-owned-utmpx-image-inputs/v1" and
            value.get("image") == PINNED_IMAGE.removeprefix("crabc-core-evidence@") and
            value.get("path") == "/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" and
            isinstance(value.get("files"), dict), "pinned core image manifest differs")
    files = value["files"]
    required = {
        "/usr/local/bin/crabc-x86_64-musl-gcc", "/usr/bin/python3", "/usr/bin/readelf", "/usr/sbin/chroot",
        *(str(path) for path in COMPILER_ORACLE_INPUTS.values()),
    }
    require(required <= set(files), "pinned core image manifest omits a resolver compiler input")
    for invocation, record in files.items():
        require(isinstance(invocation, str) and invocation.startswith("/") and isinstance(record, dict) and
                set(record) == {"path", "sha256", "size", "mode"} and isinstance(record["path"], str) and
                record["path"].startswith("/") and isinstance(record["sha256"], str) and
                re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None and
                type(record["size"]) is int and record["size"] >= 0 and type(record["mode"]) is int and
                0 <= record["mode"] <= 0o777, "pinned core image manifest record differs")
    return value


def source_snapshot(root: Path) -> dict[str, object]:
    return {
        name: receipt_file_identity(root, physical_file(root / relative, f"resolver receipt source {name}"))
        for name, relative in SOURCE_PATHS.items()
    }


def resolved_tool(path: Path, description: str) -> Path:
    try:
        return physical_file(path.resolve(strict=True), description)
    except OSError as error:
        raise ReceiptError(f"cannot resolve {description}: {path}") from error


def command_tool(name: str) -> Path:
    value = shutil.which(name)
    require(value is not None and os.path.isabs(value), f"reader cannot locate {name}")
    return resolved_tool(Path(value), f"{name} tool")


def tool_snapshot(root: Path, products: Mapping[str, Mapping[str, Path]], runner: Any) -> dict[str, object]:
    return {
        "compiler": receipt_file_identity(root, resolved_tool(Path(runner.MUSL_COMPILER), "pinned musl compiler")),
        "python": receipt_file_identity(root, resolved_tool(Path(sys.executable), "DNS fixture Python")),
        "readelf": receipt_file_identity(root, command_tool("readelf")),
        "chroot": receipt_file_identity(root, command_tool("chroot")),
        "compiler_closure": {
            name: receipt_file_identity(root, physical_file(path, f"pinned compiler {name}"))
            for name, path in COMPILER_ORACLE_INPUTS.items()
        },
        "static_drivers": {
            arm: receipt_file_identity(root, physical_file(paths["static"] / "bin/crabc-cc", f"{arm} static driver"))
            for arm, paths in products.items()
        },
        "dynamic_drivers": {
            arm: receipt_file_identity(root, physical_file(paths["dynamic"] / "bin/crabc-cc-dynamic", f"{arm} dynamic driver"))
            for arm, paths in products.items()
        },
    }


def manifest_matches_tool(
    image: Mapping[str, object], record: Mapping[str, object], description: str, *, invocation: str | None = None,
) -> None:
    files = image["files"]
    assert isinstance(files, dict)
    if invocation is None:
        candidates = [item for item in files.values() if isinstance(item, dict) and item.get("path") == record["path"]]
        require(len(candidates) == 1, f"pinned image manifest omits {description}")
        candidate = candidates[0]
    else:
        candidate = files.get(invocation)
        require(isinstance(candidate, dict), f"pinned image manifest omits {description}")
    require(candidate.get("sha256") == record["sha256"] and candidate.get("size") == record["byte_length"] and
            candidate.get("mode") == record["mode"],
            f"pinned image manifest identity differs for {description}")


def product_paths(root: Path, report: Mapping[str, object]) -> dict[str, dict[str, Path]]:
    products = report["products"]
    require(isinstance(products, dict) and set(products) == set(ARMS), "resolver product arm roster differs")
    result: dict[str, dict[str, Path]] = {}
    for arm in ARMS:
        entry = products[arm]
        require(isinstance(entry, dict) and set(entry) == {"static", "dynamic"},
                f"resolver {arm} product kind roster differs")
        result[arm] = {}
        for kind in ("static", "dynamic"):
            item = entry[kind]
            require(isinstance(item, dict) and set(item) == {"source", "path", "manifest"} and
                    item["source"] == f"caller-prepared-{arm}", f"resolver {arm} {kind} product record differs")
            result[arm][kind] = mounted_path(root, item["path"], f"resolver {arm} {kind} product", directory=True)
    physical_roots = {
        (path.stat().st_dev, path.stat().st_ino)
        for arm in ARMS
        for path in result[arm].values()
    }
    require(len(physical_roots) == 4, "resolver product arms reuse a physical product root")
    return result


def validated_product_manifest(runner: Any, kind: str, product: Path, label: str) -> object:
    try:
        return runner.static_manifest(product) if kind == "static" else runner.dynamic_manifest(product)
    except Exception as error:
        raise ReceiptError(f"{label} product validation failed: {error}") from error


def product_snapshot(
    root: Path, report: Mapping[str, object], products: Mapping[str, Mapping[str, Path]], runner: Any,
) -> dict[str, object]:
    result: dict[str, object] = {}
    for arm in ARMS:
        result[arm] = {}
        for kind in ("static", "dynamic"):
            product = products[arm][kind]
            manifest = product / "share/crabc/manifest.json"
            raw_manifest = read_json_bytes(physical_file(manifest, f"resolver {arm} {kind} manifest").read_bytes(),
                                           f"resolver {arm} {kind} manifest")
            validated = validated_product_manifest(runner, kind, product, f"resolver {arm} {kind}")
            require(raw_manifest == validated and report["products"][arm][kind]["manifest"] == raw_manifest,
                    f"resolver {arm} {kind} manifest differs")
            result[arm][kind] = {
                "path": str(Path(SOURCE_MOUNT) / product.relative_to(root)),
                "manifest": receipt_file_identity(root, manifest),
                "tree": receipt_tree_identity(product),
            }
    return result


def expected_product_identity(products: Mapping[str, Mapping[str, Path]], report: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for kind in ("static", "dynamic"):
        installed = tree_identity(products["installed"][kind])
        extracted = tree_identity(products["extracted"][kind])
        identical = (installed == extracted and
                     report["products"]["installed"][kind]["manifest"] == report["products"]["extracted"][kind]["manifest"])
        result[kind] = {"installed": installed, "extracted": extracted, "identical": identical}
    result["passed"] = result["static"]["identical"] is True and result["dynamic"]["identical"] is True
    return result


def command_record(root: Path, state: Path, receipt: Mapping[str, object], label: str) -> dict[str, object]:
    commands = receipt["commands"]
    require(isinstance(commands, dict) and label in commands, f"resolver retained command is absent: {label}")
    record = commands[label]
    require(isinstance(record, dict) and set(record) == {"argv", "status", "stdout", "stderr"},
            f"resolver retained command fields differ: {label}")
    directory = state / "receipt" / "commands"
    argv_path = assert_receipt_file_identity(root, record["argv"], f"{label} argv", expected=directory / f"{label}.argv.json")
    status_path = assert_receipt_file_identity(root, record["status"], f"{label} status", expected=directory / f"{label}.status.json")
    stdout_path = assert_receipt_file_identity(root, record["stdout"], f"{label} stdout", expected=directory / f"{label}.stdout")
    stderr_path = assert_receipt_file_identity(root, record["stderr"], f"{label} stderr", expected=directory / f"{label}.stderr")
    argv = read_json_bytes(argv_path.read_bytes(), f"{label} argv")
    status = read_json_bytes(status_path.read_bytes(), f"{label} status")
    require(isinstance(argv, list) and all(isinstance(item, str) for item in argv) and type(status) in {int, str},
            f"resolver retained command contents differ: {label}")
    return {"argv": argv, "status": status, "stdout": stream_record(stdout_path.read_bytes()),
            "stderr": stream_record(stderr_path.read_bytes())}


def compiler_resource_directory(
    root: Path, state: Path, receipt: Mapping[str, object], tools: Mapping[str, object], headers: Mapping[str, object],
) -> Path:
    resource = headers.get("resource")
    require(isinstance(resource, dict) and set(resource) == {"query", "directory"} and
            isinstance(resource["directory"], str), "resolver compiler resource record differs")
    record = command_record(root, state, receipt, "compiler-resource")
    compiler = tools["compiler"]
    assert isinstance(compiler, Mapping)
    expected_argv = [compiler["path"], "-print-file-name=include"]
    require(record["argv"] == expected_argv and record["status"] == 0 and record["stderr"] == stream_record(b""),
            "resolver compiler resource query differs")
    directory_value = Path(resource["directory"])
    require(directory_value.is_absolute(), "resolver compiler resource directory is not absolute")
    directory = physical_directory(directory_value, "pinned compiler resource headers")
    stdout = (state / "receipt/commands/compiler-resource.stdout").read_bytes()
    require(record["stdout"] == stream_record(stdout) and stdout == (str(directory) + "\n").encode("utf-8"),
            "resolver compiler resource query output differs")
    try:
        replay = subprocess.run(
            [str(compiler["path"]), "-print-file-name=include"], cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReceiptError("resolver compiler resource replay failed") from error
    require(replay.returncode == 0 and replay.stdout == stdout and replay.stderr == b"",
            "resolver compiler does not reproduce its retained resource directory")
    return directory


def header_closure(root: Path, trace: Path, resource: Path) -> dict[str, object]:
    """Rebuild every actual ``-H`` include from pinned physical header bytes."""

    musl_include = physical_directory(MUSL_INCLUDE, "pinned musl include root")
    resource = physical_directory(resource, "pinned compiler resource headers")
    try:
        lines = trace.read_bytes().decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ReceiptError("resolver header trace is not UTF-8") from error
    headers: list[dict[str, object]] = []
    seen: set[Path] = set()
    for line in lines:
        if not line.startswith("."):
            continue
        match = HEADER_TRACE_PATH.fullmatch(line)
        require(match is not None, "resolver header trace has an unparseable include path")
        header = physical_file(Path(match.group(1)), "pinned resolver header")
        try:
            header.relative_to(musl_include)
        except ValueError:
            try:
                header.relative_to(resource)
            except ValueError as error:
                raise ReceiptError("resolver header trace escaped pinned musl/compiler-resource roots") from error
        if header not in seen:
            seen.add(header)
            headers.append(receipt_file_identity(root, header))
    require(headers and musl_include / "netdb.h" in seen, "resolver header trace omits the pinned musl netdb closure")
    return {
        "musl_include": {"path": str(musl_include), "mode": stat.S_IMODE(musl_include.lstat().st_mode)},
        "resource": {"path": str(resource), "mode": stat.S_IMODE(resource.lstat().st_mode)},
        "headers": headers,
    }


def expected_translation_commands(root: Path, state: Path, tools: Mapping[str, object]) -> dict[str, list[str]]:
    compiler = tools["compiler"]["path"]
    source = str(Path(SOURCE_MOUNT) / SOURCE_PATHS["workload"])
    object_path = str(Path(SOURCE_MOUNT) / (state / "workload.o").relative_to(root))
    return {"source": source, "object": object_path, "compiler": str(compiler)}


def pinned_musl_loader(root: Path) -> dict[str, object]:
    loader = MUSL_ROOT / "lib/ld-musl-x86_64.so.1"
    libc = physical_file(MUSL_ROOT / "lib/libc.so", "pinned musl libc")
    require(loader.is_symlink() and os.readlink(loader) == str(MUSL_ROOT / "lib/libc.so") and
            loader.resolve(strict=True) == libc, "pinned musl loader alias differs")
    return {"loader_alias": {"path": str(loader), "target": os.readlink(loader)}, "libc": file_identity(root, libc)}


def validate_translation(
    root: Path, state: Path, report: Mapping[str, object], receipt: Mapping[str, object], tools: Mapping[str, object],
) -> Path:
    translation = report["translation"]
    require(isinstance(translation, dict) and set(translation) == {"compiler", "musl_root", "musl_loader", "source", "headers", "object"},
            "resolver translation fields differ")
    source = physical_file(root / SOURCE_PATHS["workload"], "resolver workload source")
    compiler_summary = {key: tools["compiler"][key] for key in ("path", "sha256", "byte_length")}
    require(translation["musl_root"] == str(MUSL_ROOT) and translation["musl_loader"] == pinned_musl_loader(root) and
            translation["source"] == file_identity(root, source) and translation["compiler"] == compiler_summary,
            "resolver translation source or compiler differs")
    headers = translation["headers"]
    object_record = translation["object"]
    require(isinstance(headers, dict) and set(headers) == {"resource", "record", "trace", "closure"} and
            isinstance(object_record, dict) and set(object_record) == {"compile", "object", "elf_header"},
            "resolver translation record differs")
    resource = compiler_resource_directory(root, state, receipt, tools, headers)
    header = command_record(root, state, receipt, "header-trace")
    compile = command_record(root, state, receipt, "compile")
    require(headers["record"] == header and object_record["compile"] == compile,
            "resolver retained translation command differs")
    paths = expected_translation_commands(root, state, tools)
    header_argv = header["argv"]
    compile_argv = compile["argv"]
    require(header["status"] == 0 and compile["status"] == 0 and header["stdout"] == stream_record(b"") and
            compile["stdout"] == stream_record(b"") and compile["stderr"] == stream_record(b""),
            "resolver translation command failed")
    expected_prefix = [paths["compiler"], "-std=c11", "-D_GNU_SOURCE", "-nostdinc", "-isystem", "/opt/musl-1.2.6/include", "-isystem"]
    require(header_argv[:len(expected_prefix)] == expected_prefix and header_argv[-3:] == ["-E", "-H", paths["source"]] and
            len(header_argv) == len(expected_prefix) + 4, "resolver header trace argv differs")
    require(header_argv[-4] == str(resource), "resolver header trace resource directory differs")
    expected_compile = [*expected_prefix, str(resource), "-c", paths["source"], "-o", paths["object"]]
    require(compile_argv == [paths["compiler"], "-std=c11", "-D_GNU_SOURCE", "-O2", "-fno-builtin", "-fno-stack-protector", "-fPIE", *expected_compile[3:]],
            "resolver compilation argv differs")
    trace = assert_file_identity(root, headers["trace"], "resolver header trace", expected=state / "headers.trace")
    require(trace.read_bytes() == (state / "receipt/commands/header-trace.stderr").read_bytes(),
            "resolver header trace bytes differ")
    receipt_headers = receipt["headers"]
    require(isinstance(receipt_headers, dict) and set(receipt_headers) == {"closure"},
            "resolver retained header closure fields differ")
    closure_path = assert_receipt_file_identity(root, receipt_headers["closure"], "resolver retained header closure",
                                                expected=state / "receipt/header-closure.json")
    closure = header_closure(root, trace, resource)
    require(headers["closure"] == closure and read_json_bytes(closure_path.read_bytes(), "resolver retained header closure") == closure,
            "resolver physical header closure does not reconstruct")
    workload = assert_receipt_file_identity(root, receipt["workload"], "resolver workload object", expected=state / "workload.o")
    require(object_record["object"] == file_identity(root, workload), "resolver workload object report differs")
    data = workload.read_bytes()
    require(len(data) >= 20 and data[:7] == b"\x7fELF\x02\x01\x01" and data[16:20] == b"\x01\x00>\x00",
            "resolver workload is not an x86-64 ET_REL object")
    return workload


def artifact_path(root: Path, record: Mapping[str, object], description: str, expected: Path) -> Path:
    return assert_receipt_file_identity(root, record, description, expected=expected)


def unresolved_symbol_rows(symbol_text: str) -> list[str]:
    return [
        line for line in symbol_text.splitlines()
        if (fields := line.split()) and len(fields) >= 7 and re.fullmatch(r"[1-9][0-9]*:", fields[0]) and fields[6] == "UND"
    ]


def replay_readelf(root: Path, reader: Path, path: Path, arguments: Sequence[str], description: str) -> dict[str, object]:
    """Inspect retained ELF bytes through the receipt-pinned reader only."""

    try:
        completed = subprocess.run(
            [str(reader), *arguments, str(path)], cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReceiptError(f"{description} replay failed") from error
    return {
        "argv": ["readelf", *arguments, str(path)],
        "status": completed.returncode,
        "stdout": stream_record(completed.stdout),
        "stderr": stream_record(completed.stderr),
    }


def replay_elf_audit(root: Path, path: Path, *, mode: str, dynamic: bool, reader: Path) -> dict[str, object]:
    """Replay ``run_x86_64.py:elf_audit`` without entering a chroot or linker."""

    path = physical_file(path, f"{mode} ELF")
    reader = physical_file(reader, "pinned ELF reader")
    header = replay_readelf(root, reader, path, ["-hW"], f"{mode} ELF header")
    programs = replay_readelf(root, reader, path, ["-lW"], f"{mode} ELF program headers")
    dynamic_record = replay_readelf(root, reader, path, ["-dW"], f"{mode} ELF dynamic section")
    symbols = replay_readelf(root, reader, path, ["-sW"], f"{mode} ELF symbols")
    require(header["status"] == 0 and programs["status"] == 0 and symbols["status"] == 0,
            f"{mode} physical ELF inspection failed")
    header_text = str(header["stdout"]["text"])
    program_text = str(programs["stdout"]["text"])
    dynamic_text = str(dynamic_record["stdout"]["text"])
    symbol_text = str(symbols["stdout"]["text"])
    expected_type = "DYN" if mode in {"static-pie", "dynamic-pie"} else "EXEC"
    require("Advanced Micro Devices X86-64" in header_text and re.search(rf"Type:\s+{expected_type}\b", header_text),
            f"{mode} ELF type or machine differs")
    text = "\n".join((header_text, program_text, dynamic_text, symbol_text))
    forbidden = ("ld-musl-", "libc.musl-", "/opt/musl-", "libc.so.6", "ld-linux", "libgcc", "compiler-rt")
    require(not any(marker in text for marker in forbidden), f"{mode} ELF leaks a foreign runtime marker")
    if dynamic:
        require(DYNAMIC_INTERPRETER in program_text and "Shared library: [libc.so]" in dynamic_text and
                "Library runpath: [/usr/lib]" in dynamic_text,
                f"{mode} ELF does not bind the canonical owned dynamic runtime")
    else:
        require("INTERP" not in program_text and "NEEDED" not in dynamic_text,
                f"{mode} static ELF has a dynamic-runtime dependency")
    require(dynamic or not unresolved_symbol_rows(symbol_text), f"{mode} ELF retains an unresolved symbol")
    return {
        "artifact": file_identity(root, path),
        "header": header,
        "program_headers": programs,
        "dynamic": dynamic_record,
        "symbols": symbols,
    }


def validate_reference_link(
    root: Path, state: Path, report: Mapping[str, object], receipt: Mapping[str, object], tools: Mapping[str, object], workload: Path,
) -> Path:
    reference = report["reference"]
    require(isinstance(reference, dict) and set(reference) == {"link", "elf", "path"}, "resolver reference fields differ")
    raw = command_record(root, state, receipt, "reference-link")
    expected = [tools["compiler"]["path"], "-static", "-no-pie", str(Path(SOURCE_MOUNT) / workload.relative_to(root)),
                "-o", str(Path(SOURCE_MOUNT) / (state / "reference").relative_to(root))]
    require(raw == reference["link"] and raw["argv"] == expected and raw["status"] == 0 and
            raw["stdout"] == stream_record(b"") and raw["stderr"] == stream_record(b""),
            "resolver reference link command differs")
    links = receipt["links"]
    require(isinstance(links, dict) and set(links) == {"reference", *ARMS}, "resolver retained link roster differs")
    reference_record = links["reference"]
    require(isinstance(reference_record, dict) and set(reference_record) == {"binary"}, "resolver reference link receipt differs")
    binary = artifact_path(root, reference_record["binary"], "resolver reference binary", state / "reference")
    require(reference["path"] == str(Path(SOURCE_MOUNT) / binary.relative_to(root)) and
            isinstance(reference["elf"], dict) and reference["elf"] == replay_elf_audit(
                root, binary, mode="static-et-exec", dynamic=False, reader=Path(str(tools["readelf"]["path"]))
            ),
            "resolver reference artifact differs")
    return binary


def candidate_link_option(mode: str) -> str:
    return {
        "static-et-exec": "--static-et-exec", "static-pie": "--static-pie",
        "dynamic-pie": "--dynamic-pie", "dynamic-non-pie": "--dynamic-non-pie",
    }[mode]


def validate_linker_from_dynamic_receipt(root: Path, path: Path, image: Mapping[str, object], label: str) -> None:
    value = read_json_bytes(path.read_bytes(), f"{label} dynamic link receipt")
    require(isinstance(value, dict) and isinstance(value.get("resolved_linker"), dict),
            f"{label} dynamic link receipt has no linker identity")
    linker = value["resolved_linker"]
    require(set(linker) == {"path", "sha256"} and isinstance(linker["path"], str) and
            isinstance(linker["sha256"], str), f"{label} dynamic linker record differs")
    actual = physical_file(Path(linker["path"]), f"{label} dynamic linker")
    require(digest(actual) == linker["sha256"], f"{label} dynamic linker bytes differ")
    files = image["files"]
    assert isinstance(files, dict)
    require(any(isinstance(item, dict) and item.get("path") == linker["path"] and
                item.get("sha256") == linker["sha256"] for item in files.values()),
            f"pinned image manifest omits {label} dynamic linker")


def validate_candidate_links(
    root: Path, state: Path, report: Mapping[str, object], receipt: Mapping[str, object],
    tools: Mapping[str, object], products: Mapping[str, Mapping[str, Path]], workload: Path,
    runner: Any, image: Mapping[str, object],
) -> dict[tuple[str, str], Path]:
    candidates = report["candidates"]
    links = receipt["links"]
    require(isinstance(candidates, dict) and set(candidates) == set(ARMS), "resolver candidate arm roster differs")
    require(isinstance(links, dict), "resolver retained links are not an object")
    outputs: dict[tuple[str, str], Path] = {}
    for arm in ARMS:
        arm_candidates = candidates[arm]
        arm_links = links.get(arm)
        require(isinstance(arm_candidates, dict) and set(arm_candidates) == set(ARTIFACT_MODES) and
                isinstance(arm_links, dict) and set(arm_links) == set(ARTIFACT_MODES),
                f"resolver {arm} candidate link roster differs")
        for mode in ARTIFACT_MODES:
            candidate = arm_candidates[mode]
            retained = arm_links[mode]
            require(isinstance(candidate, dict) and set(candidate) == {"link", "receipt_audit", "elf", "path"} and
                    isinstance(retained, dict), f"resolver {arm} {mode} candidate fields differ")
            output = state / "artifacts" / arm / mode / "workload"
            binary = artifact_path(root, retained.get("binary"), f"resolver {arm} {mode} binary", output)
            outputs[(arm, mode)] = binary
            driver = tools["static_drivers"][arm]["path"] if mode.startswith("static") else tools["dynamic_drivers"][arm]["path"]
            argv = [driver, candidate_link_option(mode)]
            if mode.startswith("static"):
                argv.extend(["--link-receipt", "link.receipt.json"])
            argv.extend([str(Path(SOURCE_MOUNT) / workload.relative_to(root)), "-o", str(Path(SOURCE_MOUNT) / output.relative_to(root))])
            raw = command_record(root, state, receipt, f"{arm}-{mode}-link")
            require(candidate["link"] == raw and raw["argv"] == argv and raw["status"] == 0 and
                    raw["stdout"] == stream_record(b"") and raw["stderr"] == stream_record(b""),
                    f"resolver {arm} {mode} link command differs")
            require(candidate["path"] == str(Path(SOURCE_MOUNT) / output.relative_to(root)) and
                    isinstance(candidate["elf"], dict) and candidate["elf"] == replay_elf_audit(
                        root, binary, mode=mode, dynamic=not mode.startswith("static"),
                        reader=Path(str(tools["readelf"]["path"])),
                    ),
                    f"resolver {arm} {mode} output identity differs")
            if mode.startswith("static"):
                require(set(retained) == {"binary", "receipt", "trace", "map"},
                        f"resolver {arm} {mode} retained static link fields differ")
                link = artifact_path(root, retained["receipt"], f"resolver {arm} {mode} static receipt",
                                     output.with_name("link.receipt.json"))
                artifact_path(root, retained["trace"], f"resolver {arm} {mode} static trace",
                              output.with_name("link.receipt.trace"))
                artifact_path(root, retained["map"], f"resolver {arm} {mode} static map",
                              output.with_name("link.receipt.map"))
                read_json_bytes(link.read_bytes(), f"resolver {arm} {mode} static link receipt")
                try:
                    observed = runner.static_receipt_audit(products[arm]["static"], candidate_link_option(mode), workload, output, link)
                except Exception as error:
                    raise ReceiptError(f"resolver {arm} {mode} static link does not reconstruct: {error}") from error
            else:
                require(set(retained) == {"binary", "receipt"},
                        f"resolver {arm} {mode} retained dynamic link fields differ")
                link = artifact_path(root, retained["receipt"], f"resolver {arm} {mode} dynamic receipt",
                                     Path(f"{output}.crabc-link.json"))
                read_json_bytes(link.read_bytes(), f"resolver {arm} {mode} dynamic link receipt")
                try:
                    observed = runner.dynamic_receipt_audit(products[arm]["dynamic"], candidate_link_option(mode), workload, output, link)
                except Exception as error:
                    raise ReceiptError(f"resolver {arm} {mode} dynamic link does not reconstruct: {error}") from error
                validate_linker_from_dynamic_receipt(root, link, image, f"resolver {arm} {mode}")
            require(candidate["receipt_audit"] == observed, f"resolver {arm} {mode} link audit differs")
    return outputs


def candidate_execution_info(label: str) -> tuple[str, str, str, list[str]]:
    for arm in ARMS:
        prefix = arm + "-"
        if not label.startswith(prefix):
            continue
        suffix = label.removeprefix(prefix)
        choices = {
            "static-et-exec": ("static-et-exec", f"{arm}-static-et-exec", ["/workload"]),
            "static-pie": ("static-pie", f"{arm}-static-pie", ["/workload"]),
            "dynamic-pie-ordinary": ("dynamic-pie", f"{arm}-dynamic-pie", ["/workload"]),
            "dynamic-pie-direct-entry": ("dynamic-pie", f"{arm}-dynamic-pie", [DYNAMIC_INTERPRETER, "/workload"]),
            "dynamic-non-pie-ordinary": ("dynamic-non-pie", f"{arm}-dynamic-non-pie", ["/workload"]),
            "dynamic-non-pie-direct-entry": ("dynamic-non-pie", f"{arm}-dynamic-non-pie", [DYNAMIC_INTERPRETER, "/workload"]),
        }
        if suffix in choices:
            mode, root_name, argv = choices[suffix]
            return arm, mode, root_name, argv
    raise ReceiptError(f"resolver candidate label is unknown: {label}")


def expected_candidate_labels() -> tuple[str, ...]:
    return tuple(
        f"{arm}-{suffix}"
        for arm in ARMS
        for suffix in (
            "static-et-exec", "static-pie", "dynamic-pie-ordinary", "dynamic-pie-direct-entry",
            "dynamic-non-pie-ordinary", "dynamic-non-pie-direct-entry",
        )
    )


def expected_command_labels() -> set[str]:
    return {
        "compiler-resource", "header-trace", "compile", "reference-link",
        *(f"{arm}-{mode}-link" for arm in ARMS for mode in ARTIFACT_MODES),
    }


def chroot_layout(root: Path, chroot: Path, *, dynamic: bool) -> dict[str, object]:
    values = {
        "hosts": file_identity(root, chroot / "etc/hosts"),
        "resolv_conf": file_identity(root, chroot / "etc/resolv.conf"),
        "binary": file_identity(root, chroot / "workload"),
    }
    if dynamic:
        values["loader"] = file_identity(root, chroot / "lib/ld-crabc-x86_64.so.1")
    return values


def require_same_file_mode_and_bytes(source: Path, copied: Path, label: str) -> None:
    source = physical_file(source, f"{label} source file")
    copied = physical_file(copied, f"{label} copied file")
    require(
        source.stat().st_size == copied.stat().st_size and digest(source) == digest(copied) and
        stat.S_IMODE(source.lstat().st_mode) == stat.S_IMODE(copied.lstat().st_mode),
        f"{label} copied file bytes or mode differ",
    )


def compare_product_copy(product: Path, execution_root: Path, label: str) -> None:
    """Ensure a dynamic chroot contains the named product bytes without following aliases."""

    product = physical_directory(product, f"{label} source product")
    execution_root = physical_directory(execution_root, f"{label} execution root")
    require(stat.S_IMODE(product.lstat().st_mode) == stat.S_IMODE(execution_root.lstat().st_mode),
            f"{label} dynamic product root mode differs")
    for entry in sorted(product.rglob("*")):
        relative = entry.relative_to(product)
        copied = execution_root / relative
        mode = entry.lstat().st_mode
        copied_mode = copied.lstat().st_mode if copied.exists() or copied.is_symlink() else None
        if stat.S_ISREG(mode):
            require(copied_mode is not None and stat.S_ISREG(copied_mode) and not copied.is_symlink(),
                    f"{label} dynamic product copy differs: {relative}")
            require_same_file_mode_and_bytes(entry, copied, f"{label} dynamic product {relative}")
        elif stat.S_ISLNK(mode):
            require(copied_mode is not None and stat.S_ISLNK(copied_mode) and
                    stat.S_IMODE(mode) == stat.S_IMODE(copied_mode) and os.readlink(entry) == os.readlink(copied),
                    f"{label} dynamic product alias or mode differs: {relative}")
        elif stat.S_ISDIR(mode):
            require(copied_mode is not None and stat.S_ISDIR(copied_mode) and not copied.is_symlink() and
                    stat.S_IMODE(mode) == stat.S_IMODE(copied_mode),
                    f"{label} dynamic product directory or mode differs: {relative}")
        else:
            raise ReceiptError(f"{label} product has unsafe entry: {relative}")


def execution_record(
    root: Path, state: Path, receipt: Mapping[str, object], label: str, expected_argv: Sequence[str], execution_root: Path,
) -> tuple[dict[str, object], tuple[object, bytes, bytes]]:
    executions = receipt["executions"]
    require(isinstance(executions, dict) and label in executions, f"resolver retained execution is absent: {label}")
    record = executions[label]
    require(isinstance(record, dict) and set(record) == {"argv", "status", "stdout", "stderr", "root"},
            f"resolver retained execution fields differ: {label}")
    directory = state / "receipt" / "executions"
    argv_path = assert_receipt_file_identity(root, record["argv"], f"{label} execution argv", expected=directory / f"{label}.argv.json")
    status_path = assert_receipt_file_identity(root, record["status"], f"{label} execution status", expected=directory / f"{label}.status.json")
    stdout_path = assert_receipt_file_identity(root, record["stdout"], f"{label} execution stdout", expected=directory / f"{label}.stdout")
    stderr_path = assert_receipt_file_identity(root, record["stderr"], f"{label} execution stderr", expected=directory / f"{label}.stderr")
    argv = read_json_bytes(argv_path.read_bytes(), f"{label} execution argv")
    status = read_json_bytes(status_path.read_bytes(), f"{label} execution status")
    require(argv == list(expected_argv) and type(status) in {int, str}, f"resolver execution argv or status is invalid: {label}")
    assert_tree_identity(root, record["root"], f"{label} execution root", execution_root)
    stdout = stdout_path.read_bytes()
    stderr = stderr_path.read_bytes()
    return {"exit_status": status, "stdout": stream_record(stdout), "stderr": stream_record(stderr)}, (status, stdout, stderr)


def recompute_event_contract(events: Sequence[Mapping[str, object]], *, executions: int) -> dict[str, object]:
    require(executions >= 1, "DNS event contract has no executions")
    names = {str(event["name"]) for event in events if "name" in event}
    count = lambda predicate: sum(1 for event in events if predicate(event))
    name_counts = {name: count(lambda event, name=name: event.get("name") == name) for name in REQUIRED_SERVER_NAMES}
    malformed = count(lambda event: event.get("name") == "malformed.example.test." and event.get("action") == "malformed-sequence")
    valid_drop = count(lambda event: event.get("role") == "valid" and event.get("name") == "fallback.example.test." and event.get("action") == "drop")
    drop = count(lambda event: event.get("role") == "drop" and event.get("action") == "drop")
    fallback = count(lambda event: event.get("role") == "fallback" and event.get("name") == "fallback.example.test.")
    cname = count(lambda event: event.get("name") == "alias.example.test." and event.get("action") == "cname")
    tc_udp = count(lambda event: event.get("name") == "tc.example.test." and event.get("transport") == "udp" and event.get("action") == "tc-sequence")
    tc_tcp = count(lambda event: event.get("name") == "tc.example.test." and event.get("transport") == "tcp" and event.get("action") == "answer")
    passed = (REQUIRED_SERVER_NAMES <= names and all(value >= executions for value in name_counts.values()) and
              malformed >= executions and valid_drop >= executions and drop >= executions and fallback >= executions and
              cname >= executions and tc_udp >= executions and tc_tcp >= executions)
    return {
        "expected_execution_count": executions,
        "query_counts": name_counts,
        "required_names_seen": sorted(REQUIRED_SERVER_NAMES & names),
        "required_names_missing": sorted(REQUIRED_SERVER_NAMES - names),
        "malformed_sequence_observations": malformed,
        "valid_fallback_drop_observations": valid_drop,
        "drop_endpoint_observations": drop,
        "fallback_query_observations": fallback,
        "cname_query_observations": cname,
        "tc_udp_truncated_observations": tc_udp,
        "tc_tcp_retry_observations": tc_tcp,
        "passed": passed,
    }


def validate_dns(root: Path, state: Path, report: Mapping[str, object], receipt: Mapping[str, object]) -> None:
    dns = receipt["dns"]
    require(isinstance(dns, dict) and set(dns) == {"ready", "events"}, "resolver DNS receipt fields differ")
    ready_path = assert_receipt_file_identity(root, dns["ready"], "resolver DNS ready", expected=state / "receipt/dns-ready.json")
    events_path = assert_receipt_file_identity(root, dns["events"], "resolver DNS events", expected=state / "dns-events.json")
    ready = read_json_bytes(ready_path.read_bytes(), "resolver DNS ready")
    events_document = read_json_bytes(events_path.read_bytes(), "resolver DNS events")
    require(isinstance(ready, dict) and ready == {
        "protocol": "resolver-network-dns-v1", "schema_version": 1,
        "endpoints": {
            "valid": {"ipv4": "127.0.0.1", "port": 53, "udp4_port": 53, "tcp4_port": 53},
            "drop": {"ipv4": "127.0.0.2", "port": 53, "udp4_port": 53, "tcp4_port": 53},
            "fallback": {"ipv4": "127.0.0.3", "port": 53, "udp4_port": 53, "tcp4_port": 53},
        },
    }, "resolver DNS ready document differs")
    require(isinstance(events_document, dict) and set(events_document) == {"schema_version", "events"} and
            events_document["schema_version"] == 1 and isinstance(events_document["events"], list) and
            all(isinstance(item, dict) for item in events_document["events"]), "resolver DNS event document differs")
    execution = report["execution"]
    assert isinstance(execution, Mapping)
    server = execution["dns_server"]
    require(isinstance(server, dict) and set(server) == {"ready", "events", "event_contract"} and
            server["ready"] == ready and server["events"] == events_document["events"],
            "resolver report DNS evidence differs from retained raw documents")
    expected = recompute_event_contract(events_document["events"], executions=13)
    require(server["event_contract"] == expected and expected["passed"] is True,
            "resolver DNS event contract does not reconstruct")


def validate_executions(
    root: Path, state: Path, report: Mapping[str, object], receipt: Mapping[str, object],
    products: Mapping[str, Mapping[str, Path]], outputs: Mapping[tuple[str, str], Path], reference: Path,
) -> None:
    execution = report["execution"]
    require(isinstance(execution, dict) and set(execution) == {
        "reference", "candidates", "comparisons", "reference_expected", "candidate_expected", "expected_stdout", "dns_server",
    }, "resolver execution report fields differ")
    labels = expected_candidate_labels()
    candidates = execution["candidates"]
    receipt_executions = receipt["executions"]
    require(isinstance(candidates, dict) and set(candidates) == set(labels) and
            isinstance(receipt_executions, dict) and set(receipt_executions) == {"reference", *labels},
            "resolver execution matrix is incomplete")
    chroots = report["chroots"]
    expected_chroots = {"reference"}
    for arm in ARMS:
        expected_chroots.update({f"{arm}-static-et-exec", f"{arm}-static-pie", f"{arm}-dynamic-pie", f"{arm}-dynamic-non-pie"})
    require(isinstance(chroots, dict) and set(chroots) == expected_chroots, "resolver chroot roster differs")

    reference_root = state / "chroots/reference"
    reference_outcome, reference_raw = execution_record(root, state, receipt, "reference", ["/workload"], reference_root)
    require(execution["reference"] == reference_outcome, "resolver reference raw outcome differs")
    require(chroots["reference"] == chroot_layout(root, reference_root, dynamic=False), "resolver reference chroot layout differs")
    require(chroots["reference"]["binary"] == file_identity(root, reference_root / "workload") and
            chroots["reference"]["binary"]["sha256"] == file_identity(root, reference)["sha256"],
            "resolver reference chroot binary differs")
    require_same_file_mode_and_bytes(reference, reference_root / "workload", "resolver reference chroot binary")

    raw_candidates: dict[str, tuple[object, bytes, bytes]] = {}
    for label in labels:
        arm, mode, root_name, argv = candidate_execution_info(label)
        execution_root = state / "chroots" / root_name
        outcome, raw = execution_record(root, state, receipt, label, argv, execution_root)
        raw_candidates[label] = raw
        require(candidates[label] == outcome, f"resolver {label} raw outcome differs")
        dynamic = mode.startswith("dynamic")
        require(chroots[root_name] == chroot_layout(root, execution_root, dynamic=dynamic),
                f"resolver {label} chroot layout differs")
        source = outputs[(arm, mode)]
        require(chroots[root_name]["binary"]["sha256"] == file_identity(root, source)["sha256"],
                f"resolver {label} executing binary differs from link product")
        require_same_file_mode_and_bytes(source, execution_root / "workload", f"resolver {label} executing binary")
        require((execution_root / "etc/hosts").read_bytes() == b"127.0.0.1 localhost\n::1 localhost\n" and
                (execution_root / "etc/resolv.conf").read_bytes() ==
                b"# crabc native resolver-network fixture\nnameserver 127.0.0.1\nnameserver 127.0.0.2\nnameserver 127.0.0.3\nsearch search.test\noptions ndots:1 timeout:1 attempts:1\n",
                f"resolver {label} conventional-file fixture differs")
        if dynamic:
            compare_product_copy(products[arm]["dynamic"], execution_root, label)

    expected_reference = reference_raw[0] == 0 and reference_raw[1] == EXPECTED_STDOUT and reference_raw[2] == b""
    expected_candidates = {
        label: raw[0] == 0 and raw[1] == EXPECTED_STDOUT and raw[2] == b""
        for label, raw in raw_candidates.items()
    }
    comparisons = {
        label: {
            "exit_status_match": reference_raw[0] == raw[0],
            "stdout_match": stream_record(reference_raw[1]) == stream_record(raw[1]),
            "stderr_match": stream_record(reference_raw[2]) == stream_record(raw[2]),
        }
        for label, raw in raw_candidates.items()
    }
    require(execution["expected_stdout"] == stream_record(EXPECTED_STDOUT) and
            execution["reference_expected"] is expected_reference and execution["candidate_expected"] == expected_candidates and
            execution["comparisons"] == comparisons and expected_reference and all(expected_candidates.values()) and
            all(all(value.values()) for value in comparisons.values()),
            "resolver raw execution contract does not reconstruct")


def validate_report(root: Path, report_path: Path) -> Mapping[str, object]:
    root = physical_directory(root, "checkout root")
    require(str(root) == SOURCE_MOUNT, "resolver receipt reader requires the pinned /workspace mount")
    report_path = physical_file(report_path, "public resolver-network report")
    public_parent = root / "compat/reports/resolver-network/x86_64"
    require(report_path.is_relative_to(physical_directory(public_parent, "public resolver report directory")),
            "resolver report is not under the public resolver report directory")
    report = validate_report_document(read_json_bytes(report_path.read_bytes(), "public resolver-network report"))
    state = mounted_path(root, report["state_root"], "resolver execution root", directory=True)
    require(state.is_relative_to(root / ".work/x86_64"), "resolver execution root escapes checkout work")
    published = mounted_path(root, report["published_report"], "published resolver report")
    require(published == report_path, "resolver public report path differs from the retained publication target")
    state_report = physical_file(state / "report.json", "retained resolver producer report")
    require(state_report.read_bytes() == report_path.read_bytes(), "public resolver report differs from retained producer report")
    receipt = report["receipt"]
    assert isinstance(receipt, Mapping)
    require(isinstance(receipt["commands"], dict) and set(receipt["commands"]) == expected_command_labels(),
            "resolver retained command roster differs")

    image = image_manifest(root, receipt)
    sources = source_snapshot(root)
    source_seals = receipt["sources"]
    require(isinstance(source_seals, dict) and set(source_seals) == {"before", "after"} and
            source_seals["before"] == sources and source_seals["after"] == sources,
            "resolver source identity changed during or after collection")

    runner = load_runner(root)
    products = product_paths(root, report)
    product_state = product_snapshot(root, report, products, runner)
    product_seals = receipt["products"]
    require(isinstance(product_seals, dict) and set(product_seals) == {"before", "after"} and
            product_seals["before"] == product_state and product_seals["after"] == product_state,
            "resolver product or manifest identity changed during or after collection")
    require(report["product_identity"] == expected_product_identity(products, report) and
            report["product_identity"]["passed"] is True, "resolver installed/extracted product identity differs")

    tools = tool_snapshot(root, products, runner)
    tool_seals = receipt["tools"]
    require(isinstance(tool_seals, dict) and set(tool_seals) == {"before", "after"} and
            tool_seals["before"] == tools and tool_seals["after"] == tools,
            "resolver tool identity changed during or after collection")
    for name in ("compiler", "python", "readelf"):
        assert isinstance(tools[name], Mapping)
        manifest_matches_tool(image, tools[name], name)
    assert isinstance(tools["chroot"], Mapping)
    manifest_matches_tool(image, tools["chroot"], "chroot", invocation="/usr/sbin/chroot")
    compiler_closure = tools["compiler_closure"]
    assert isinstance(compiler_closure, Mapping)
    require(set(compiler_closure) == set(COMPILER_ORACLE_INPUTS), "resolver compiler closure roster differs")
    for name, record in compiler_closure.items():
        assert isinstance(record, Mapping)
        manifest_matches_tool(image, record, f"compiler {name}")

    workload = validate_translation(root, state, report, receipt, tools)
    reference = validate_reference_link(root, state, report, receipt, tools, workload)
    outputs = validate_candidate_links(root, state, report, receipt, tools, products, workload, runner, image)
    validate_executions(root, state, report, receipt, products, outputs, reference)
    validate_dns(root, state, report, receipt)
    assert_tree_identity(root, receipt["execution_root"], "resolver execution root", state,
                         excluded=frozenset({"report.json"}))
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-report")
    validate.add_argument("--root", type=Path, required=True)
    validate.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        validate_report(args.root, args.report)
    except (ReceiptError, OSError, ValueError) as error:
        parser.exit(1, f"resolver-network physical receipt failed: {error}\n")
    print("resolver-network physical receipt: valid; bounded component evidence remains non-promoting")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
