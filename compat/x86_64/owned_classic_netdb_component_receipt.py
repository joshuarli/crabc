#!/usr/bin/env python3
"""Collect and replay the bounded installed classic-netdb component receipt.

This is deliberately a component reader.  It reconstructs the closed
classic host/service lookup matrix, including its controlled DNS transport,
but does not select a resolver-family capability or make any promotion claim.
The reader only inspects retained files and fixed ELF tools; it never builds,
links, runs a consumer, or contacts a network endpoint.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from rust_toolchain import pinned_toolchain

SOURCE_MOUNT = "/workspace"
SCHEMA = "crabc.x86_64-owned-classic-netdb-products/v1"
COMPONENT = "classic-netdb"
SCOPE = ("libc.resolver",)
FULL_MODE = "full-six-mode"
DYNAMIC_MODE = "dynamic-only-four-cell-development"
CASES = (
    "host-numeric", "host-local", "host-buffers", "host-many", "host-dns",
    "dns-record-order", "dns-record-prefix", "dns-batch", "search-precedence",
    "mixed-family", "reverse-local", "reverse-dns", "services", "service-buffers",
    "open-errors", "read-errors", "access-errors", "socket-error", "fcntl-error",
    "empty-reporting", "addrinfo", "threads-fork", "allocation",
)
# These names state the finite behavior claimed by the receipt.  The C probe
# remains the executable oracle for the individual assertions.
BEHAVIOR_ROSTER = {
    "host-numeric": "numeric host forms and h_errno",
    "host-local": "hosts-file lookup and canonical spelling",
    "host-buffers": "host reentrant buffer boundaries",
    "host-many": "large hosts records and address cap",
    "host-dns": "A/AAAA/CNAME, timeout, TCP and source ordering",
    "dns-record-order": "callback order and address cap",
    "dns-record-prefix": "physical late-record boundaries",
    "dns-batch": "batch association, retry, fallback and TCP",
    "search-precedence": "search suffix and DNS failure precedence",
    "mixed-family": "AF_UNSPEC failure precedence",
    "reverse-local": "reverse hosts and services files",
    "reverse-dns": "PTR and numeric fallback",
    "services": "service lookup and pointer identity",
    "service-buffers": "service reentrant buffer boundaries",
    "open-errors": "database open errno propagation",
    "read-errors": "database read errno propagation",
    "access-errors": "database access errno propagation",
    "socket-error": "resolver socket creation errno",
    "fcntl-error": "resolver descriptor-control errno",
    "empty-reporting": "empty legacy providers and herror",
    "addrinfo": "modern getaddrinfo/getnameinfo allocation and errors",
    "threads-fork": "owner lifetime, concurrency and fork isolation",
    "allocation": "non-reentrant owner exhaustion and result lifetime",
}
PROVIDERS = (
    "gethostbyaddr", "gethostbyaddr_r", "gethostbyname", "gethostbyname2",
    "gethostbyname2_r", "gethostbyname_r", "gethostent", "getnetbyaddr",
    "getnetbyname", "getnetent", "getservbyname", "getservbyname_r",
    "getservbyport", "getservbyport_r", "herror",
)
DYNAMIC_CELLS = (
    "dynamic-pie-kernel", "dynamic-pie-direct", "dynamic-non-pie-kernel",
    "dynamic-non-pie-direct",
)
FULL_CELLS = ("static", "static-pie", *DYNAMIC_CELLS)
PINNED_IMAGE = "crabc-core-evidence@sha256:307d75f06680c631437f9faa5f7c726613fcea6f1875dda8cf368ad4b6da1b3d"
IMAGE_MANIFEST = "compat/x86_64/owned_classic_netdb_image_inputs.json"
TOOLCHAIN = pinned_toolchain(ROOT)
TOOLCHAIN_ROOT = Path("/opt/rustup/toolchains") / f"{TOOLCHAIN}-x86_64-unknown-linux-musl"
LINKER_PATH = TOOLCHAIN_ROOT / "lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
SOURCE_PATHS = {
    "producer": "compat/x86_64/owned_classic_netdb.py",
    "runner": "compat/x86_64/run_owned_classic_netdb.sh",
    "probe": "compat/x86_64/owned_classic_netdb_probe.c",
    "namespace": "compat/x86_64/classic_netdb_namespace.py",
    "fixture": "compat/resolver-network/run_x86_64.py",
    "qualification": "compat/x86_64/owned_dynamic_qualification.py",
    "product_evidence": "compat/x86_64/owned_posix_product_evidence.py",
    "payload_evidence": "compat/x86_64/owned_crypt_runtime_evidence.py",
    "reader": "compat/x86_64/owned_classic_netdb_component_receipt.py",
    "image_manifest": IMAGE_MANIFEST,
}
ASSOCIATION_MUSL = "wrong-association=203.0.113.50\nclassic netdb scenario passed\n"
ASSOCIATION_OWNED = "wrong-association=198.51.100.50\nclassic netdb scenario passed\n"


class ReceiptError(RuntimeError):
    """The classic-netdb component receipt is incomplete or unreconstructable."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path, description: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{description} is not valid JSON: {path}") from error


def physical(path: Path, description: str, *, directory: bool = False) -> Path:
    try:
        result = Path(os.path.abspath(path))
        require(result.exists() and not result.is_symlink(), f"{description} is not physical: {path}")
        require(result.is_dir() if directory else stat.S_ISREG(result.lstat().st_mode),
                f"{description} has the wrong type: {path}")
        current = Path(result.anchor)
        for part in result.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return result
    except OSError as error:
        raise ReceiptError(f"{description} is unreadable: {path}") from error


def digest(path: Path) -> str:
    path = physical(path, "hashed artifact")
    value = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def mounted(root: Path, path: Path) -> str:
    try:
        return SOURCE_MOUNT + "/" + path.relative_to(root).as_posix()
    except ValueError as error:
        raise ReceiptError(f"receipt path escapes checkout: {path}") from error


def checkout_file(root: Path, value: object, description: str) -> Path:
    require(isinstance(value, str) and value, f"{description} path is absent")
    relative = Path(value)
    require(not relative.is_absolute() and all(part not in {"", ".", ".."} for part in relative.parts),
            f"{description} path is unsafe")
    return physical(root / relative, description)


def checkout_directory(root: Path, value: object, description: str) -> Path:
    require(isinstance(value, str) and value, f"{description} path is absent")
    relative = Path(value)
    require(not relative.is_absolute() and all(part not in {"", ".", ".."} for part in relative.parts),
            f"{description} path is unsafe")
    return physical(root / relative, description, directory=True)


def mounted_relative(path: Path, description: str) -> str:
    """Translate one argparse ``Path`` from the fixed container mount."""
    value = str(path)
    prefix = SOURCE_MOUNT + "/"
    require(value.startswith(prefix), f"{description} is not below {SOURCE_MOUNT}")
    relative = value.removeprefix(prefix)
    candidate = Path(relative)
    require(candidate.parts and all(part not in {"", ".", ".."} for part in candidate.parts),
            f"{description} mount path is unsafe")
    return relative


def identity(root: Path, path: Path) -> dict[str, object]:
    path = physical(path, "receipt artifact")
    return {"path": path.relative_to(root).as_posix(), "sha256": digest(path), "size": path.stat().st_size}


def assert_identity(root: Path, value: object, description: str, *, expected: Path | None = None) -> Path:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{description} identity fields differ")
    path = checkout_file(root, value["path"], description)
    if expected is not None:
        require(path == physical(expected, description), f"{description} path differs")
    require(value == identity(root, path), f"{description} identity differs")
    return path


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def tree_identity(root: Path) -> dict[str, object]:
    root = physical(root, "product tree", directory=True)
    entries: dict[str, object] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            entries[relative] = {"type": "file", "mode": stat.S_IMODE(mode), "sha256": digest(path)}
        elif stat.S_ISLNK(mode):
            entries[relative] = {"type": "symlink", "mode": stat.S_IMODE(mode), "target": os.readlink(path)}
        elif stat.S_ISDIR(mode):
            entries[relative] = {"type": "directory", "mode": stat.S_IMODE(mode)}
        else:
            raise ReceiptError(f"product tree has unsupported entry: {path}")
    return entries


def tracked_source(root: Path, relative: str) -> dict[str, object]:
    path = checkout_file(root, relative, "classic-netdb source")
    return {**identity(root, path), "mode": stat.S_IMODE(path.stat().st_mode)}


def source_product_seal(root: Path, static: Path | None, dynamic: Path) -> dict[str, object]:
    if str(root) != SOURCE_MOUNT:
        raise ReceiptError("classic-netdb collection requires the pinned /workspace checkout")
    here = str(ROOT)
    require(here == SOURCE_MOUNT, "classic-netdb collector source is not mounted at /workspace")
    if str(dynamic).startswith(SOURCE_MOUNT + "/"):
        dynamic = checkout_directory(root, mounted_relative(dynamic, "dynamic product"), "dynamic product")
    else:
        dynamic = physical(dynamic, "dynamic product", directory=True)
    require(dynamic.is_relative_to(root / ".work"), "dynamic product escapes checkout .work")
    if static is not None:
        if str(static).startswith(SOURCE_MOUNT + "/"):
            static = checkout_directory(root, mounted_relative(static, "static product"), "static product")
        else:
            static = physical(static, "static product", directory=True)
        require(static.is_relative_to(root / ".work"), "static product escapes checkout .work")
    try:
        import owned_posix_product_evidence as products
        dynamic_manifest, _ = products._validate_dynamic_product(dynamic)
        static_manifest = products._validate_static_product(static)[0] if static is not None else None
    except Exception as error:
        raise ReceiptError(f"classic-netdb product validation failed: {error}") from error
    result: dict[str, object] = {
        "sources": {name: tracked_source(root, relative) for name, relative in SOURCE_PATHS.items()},
        "dynamic": {"path": dynamic.relative_to(root).as_posix(), "manifest": identity(root, dynamic_manifest),
                    "tree": tree_identity(dynamic)},
    }
    if static is not None:
        assert static_manifest is not None
        result["static"] = {"path": static.relative_to(root).as_posix(), "manifest": identity(root, static_manifest),
                            "tree": tree_identity(static)}
    return result


def trusted_image_manifest(root: Path) -> dict[str, object]:
    value = read_json(checkout_file(root, IMAGE_MANIFEST, "classic-netdb image manifest"), "classic-netdb image manifest")
    require(isinstance(value, dict) and set(value) == {"schema", "image", "files"} and
            value.get("schema") == "crabc.x86_64-owned-classic-netdb-image-inputs/v1" and
            value.get("image") == PINNED_IMAGE.removeprefix("crabc-core-evidence@") and
            isinstance(value.get("files"), dict),
            "classic-netdb current image manifest differs")
    for path in (str(TOOLCHAIN_ROOT / "bin/rustc"), str(LINKER_PATH),
                 "/usr/bin/readelf", "/usr/bin/nm", "/usr/bin/gcc", "/usr/local/bin/crabc-x86_64-musl-gcc"):
        require(path in value["files"], f"classic-netdb image manifest omits {path}")
    return value


def tool_record(path: Path, description: str) -> dict[str, object]:
    path = physical(path, description)
    return {"path": str(path), "sha256": digest(path), "size": path.stat().st_size,
            "mode": stat.S_IMODE(path.stat().st_mode)}


def tool_roster(root: Path, dynamic: Path, static: Path | None) -> dict[str, object]:
    image = trusted_image_manifest(root)
    tools = {
        "oracle": tool_record(Path("/usr/local/bin/crabc-x86_64-musl-gcc"), "pinned musl compiler"),
        "compiler": tool_record(Path("/usr/bin/gcc"), "pinned header compiler"),
        "linker": tool_record(LINKER_PATH, "pinned LLVM linker"),
        "readelf": tool_record(Path("/usr/bin/readelf"), "pinned ELF reader"),
        "nm": tool_record(Path("/usr/bin/nm"), "pinned symbol reader"),
        "dynamic_driver": tool_record(dynamic / "bin/crabc-cc-dynamic", "dynamic driver"),
    }
    if static is not None:
        tools["static_driver"] = tool_record(static / "bin/crabc-cc", "static driver")
    for name in ("oracle", "compiler", "linker", "readelf", "nm"):
        record = tools[name]
        expected = image["files"].get(str(record["path"]))
        require(expected is not None and all(record[key] == expected[key] for key in ("path", "sha256", "size", "mode")),
                f"{name} is not the pinned core-evidence tool")
    return tools


def cells(mode: str) -> tuple[str, ...]:
    if mode == FULL_MODE:
        return FULL_CELLS
    if mode == DYNAMIC_MODE:
        return DYNAMIC_CELLS
    raise ReceiptError("classic-netdb execution mode differs")


def require_static_mode(mode: str, require_static: bool) -> None:
    if require_static and mode != FULL_MODE:
        raise ReceiptError("classic-netdb acceptance requires static/static-pie evidence")


def validate_component_contract(report: Mapping[str, object]) -> None:
    require(report.get("component") == COMPONENT, "classic-netdb component differs")
    require(report.get("scope") == list(SCOPE), "classic-netdb scope differs")
    require(report.get("cases") == list(CASES), "classic-netdb case roster differs")
    require(report.get("behavior_roster") == BEHAVIOR_ROSTER, "classic-netdb behavior roster differs")
    require(report.get("family_completion") is False and report.get("promotion_ready") is False and
            report.get("public_support") is False, "classic-netdb receipt is promoting")


def replay_readelf(path: Path, *, dynamic: bool) -> bytes:
    """Read current retained ELF bytes with the fixed pinned readelf binary."""
    reader = Path("/usr/bin/readelf")
    require(physical(reader, "pinned ELF reader") == reader, "ELF reader path differs")
    completed = subprocess.run([str(reader), "--wide", "--dyn-syms" if dynamic else "--syms", str(path)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(completed.returncode == 0 and not completed.stderr, "fixed readelf replay failed")
    return completed.stdout


def validate_provider_symbols(path: Path, description: str, names: tuple[str, ...] = PROVIDERS, *, dynamic: bool = True) -> None:
    """Bind exported-provider assertions to current ELF, never retained text."""
    raw = replay_readelf(path, dynamic=dynamic)
    try:
        rows = [line.split() for line in raw.decode("utf-8").splitlines()]
    except UnicodeDecodeError as error:
        raise ReceiptError(f"{description} readelf output is not UTF-8") from error
    for name in names:
        matches = [row for row in rows if len(row) == 8 and row[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and
                   row[6] != "UND" and row[7] == name]
        require(len(matches) == 1, f"{description} lacks one public defined {name}")


def validate_association_difference(value: object) -> None:
    require(isinstance(value, dict) and set(value) == {"case", "entry", "musl_stdout", "owned_stdout", "stderr"},
            "classic-netdb association record fields differ")
    require(value["case"] == "dns-batch" and isinstance(value["entry"], str) and
            value["entry"] in FULL_CELLS and value["musl_stdout"] == ASSOCIATION_MUSL and
            value["owned_stdout"] == ASSOCIATION_OWNED and value["stderr"] == "", "classic-netdb association exception differs")


def validate_events(events: object, arms: int) -> None:
    require(isinstance(events, list) and all(isinstance(item, dict) for item in events), "classic-netdb DNS events differ")
    expected = (
        ("a.example.test.", 1, "udp"), ("tc.example.test.", 1, "tcp"),
        ("42.100.51.198.in-addr.arpa.", 12, "udp"), ("order-after.example.test.", 1, "udp"),
        ("order-before.example.test.", 1, "udp"), ("order-empty.example.test.", 1, "udp"),
        ("order-cap.example.test.", 1, "udp"), ("order-aaaa.example.test.", 28, "udp"),
        ("prefix-a.example.test.", 1, "udp"), ("prefix-aaaa.example.test.", 28, "udp"),
        ("prefix-authority.example.test.", 1, "udp"), ("prefix-rdata.example.test.", 1, "udp"),
        ("prefix-additional.example.test.", 1, "udp"), ("prefix-empty.example.test.", 1, "udp"),
        ("prefix-tcp.example.test.", 1, "tcp"), ("batch.example.test.", 1, "udp"),
        ("batch.example.test.", 28, "udp"), ("batch-mixed.example.test.", 1, "udp"),
        ("batch-mixed.example.test.", 1, "tcp"), ("batch-mixed.example.test.", 28, "udp"),
        ("wrong-association.example.test.", 1, "udp"), ("refused.example.test.", 1, "udp"),
        ("47.100.51.198.in-addr.arpa.", 12, "udp"),
    )
    for name, qtype, transport in expected:
        count = sum(event.get("name") == name and event.get("qtype") == qtype and event.get("transport") == transport
                    for event in events)
        require(count >= arms, f"classic-netdb DNS event evidence is incomplete: {name}/{transport}")
    for role in ("valid", "drop", "fallback"):
        for qtype in (1, 28):
            count = sum(event.get("role") == role and event.get("name") == "batch.example.test." and
                        event.get("qtype") == qtype and event.get("transport") == "udp" for event in events)
            require(count >= arms, f"classic-netdb batch fanout is incomplete: {role}/{qtype}")
            retries = sum(event.get("role") == role and event.get("name") == "batch-retry.example.test." and
                          event.get("qtype") == qtype and event.get("transport") == "udp" for event in events)
            require(retries >= arms * 2, f"classic-netdb batch retry is incomplete: {role}/{qtype}")
    servfail = sum(event.get("name") == "servfail.example.test." and event.get("transport") == "udp" and
                   event.get("action") == "servfail" for event in events)
    require(servfail == arms * 4, "classic-netdb SERVFAIL retry schedule differs")


def dns_events(value: object) -> list[dict[str, object]]:
    """Keep the DNS fixture's versioned document, not only its event array."""
    require(isinstance(value, dict) and set(value) == {"schema_version", "events"} and
            isinstance(value["schema_version"], int) and value["schema_version"] == 1 and
            isinstance(value["events"], list) and all(isinstance(item, dict) for item in value["events"]),
            "classic-netdb DNS events differ")
    return value["events"]


def artifact_bytes(root: Path, record: Mapping[str, object], field: str, work: Path, label: str) -> bytes:
    suffix = "argv.json" if field == "argv" else field
    return assert_identity(root, record[field], f"{label} {field}", expected=work / f"{label}.{suffix}").read_bytes()


def parse_argv(raw: bytes, label: str) -> list[str]:
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{label} argv is invalid JSON") from error
    require(isinstance(value, list) and all(isinstance(item, str) for item in value), f"{label} argv differs")
    return value


def command_plan(root: Path, work: Path, static: Path | None, dynamic: Path,
                 tools: Mapping[str, object], mode: str) -> dict[str, list[str]]:
    """The fixed producer argv roster for one retained component mode."""
    source = root / SOURCE_PATHS["probe"]
    workload = work / "workload.o"
    oracle = work / "oracle"
    header_root = (static or dynamic) / "usr/include"
    tool = lambda name: str(tools[name]["path"])
    mounted_path = lambda path: mounted(root, path)
    plan = {
        "header-trace": [tool("compiler"), "-nostdinc", "-isystem", mounted_path(header_root), "-std=c11", "-fno-builtin",
                         "-E", "-H", mounted_path(source)],
        "compile": ([tool("static_driver"), "-static-pie"] if static is not None else [tool("dynamic_driver"), "--dynamic-pie"])
                   + ["-std=c11", "-fno-builtin", "-c", mounted_path(source), "-o", mounted_path(workload)],
        "oracle-link": [tool("oracle"), "-static", "-fno-pie", "-no-pie", "-pthread", mounted_path(workload), "-o", mounted_path(oracle)],
        "oracle-symbols": [tool("readelf"), "--wide", "--syms", mounted_path(oracle)],
        "dynamic-provider-symbols": [tool("readelf"), "--wide", "--dyn-syms", mounted_path(dynamic / "usr/lib/libc.so")],
    }
    if mode == FULL_MODE:
        assert static is not None
        for name, flag in (("static", "--static-et-exec"), ("static-pie", "--static-pie")):
            plan[f"{name}-link"] = [tool("static_driver"), flag, "--link-receipt", f"{name}.crabc-link.json",
                                      mounted_path(workload), "-o", mounted_path(work / name)]
            plan[f"{name}-symbols"] = [tool("readelf"), "--wide", "--syms", mounted_path(work / name)]
    for name in ("pie", "non-pie"):
        binary = work / f"dynamic-{name}"
        plan[f"dynamic-{name}-link"] = [tool("dynamic_driver"), f"--dynamic-{name}", mounted_path(workload), "-o", mounted_path(binary)]
    return plan


def validate_payload(root: Path, work: Path, value: object, dynamic: Path, mode: str) -> None:
    require(isinstance(value, dict) and set(value) == {"record", "before", "after"}, f"{mode} payload fields differ")
    record = assert_identity(root, value["record"], f"{mode} payload record", expected=work / f"dynamic-{mode}-execution-payload.json")
    before = assert_identity(root, value["before"], f"{mode} payload before", expected=work / f"dynamic-{mode}-execution-payload-before.json")
    after = assert_identity(root, value["after"], f"{mode} payload after", expected=work / f"dynamic-{mode}-execution-payload-after.json")
    expected = payload_record(dynamic, work / f"dynamic-{mode}-root", work / f"dynamic-{mode}",
                              work / f"dynamic-{mode}-root/consumer")
    require(read_json(record, f"{mode} payload record") == expected and read_json(before, f"{mode} payload before") == expected and
            read_json(after, f"{mode} payload after") == expected, f"{mode} copied execution payload differs")


def payload_record(product: Path, execution_root: Path, source_consumer: Path, execution_consumer: Path) -> dict[str, object]:
    """Record just the product payload and the executing consumer.

    The private chroot's mutable ``etc`` fixture is intentionally outside this
    record.  It cannot be mistaken for product bytes, while each runtime file,
    symlink, manifest and consumer must still match its source exactly.
    """
    product = physical(product, "dynamic product", directory=True)
    execution_root = physical(execution_root, "dynamic execution root", directory=True)
    source_consumer = physical(source_consumer, "dynamic source consumer")
    execution_consumer = physical(execution_consumer, "dynamic execution consumer")
    entries: dict[str, object] = {}
    for item in sorted(product.rglob("*")):
        relative = item.relative_to(product).as_posix()
        copied = execution_root / relative
        mode = item.lstat().st_mode
        if stat.S_ISREG(mode):
            require(copied.is_file() and not copied.is_symlink() and digest(item) == digest(copied),
                    f"dynamic payload differs: {relative}")
            entries[relative] = {"type": "file", "source": {"sha256": digest(item), "size": item.stat().st_size},
                                 "execution": {"sha256": digest(copied), "size": copied.stat().st_size}}
        elif stat.S_ISLNK(mode):
            require(copied.is_symlink() and os.readlink(item) == os.readlink(copied), f"dynamic payload alias differs: {relative}")
            entries[relative] = {"type": "symlink", "target": os.readlink(item)}
    require(digest(source_consumer) == digest(execution_consumer), "dynamic execution consumer differs")
    return {"product": product.name, "payload": entries,
            "consumer": {"source": {"sha256": digest(source_consumer), "size": source_consumer.stat().st_size},
                         "execution": {"sha256": digest(execution_consumer), "size": execution_consumer.stat().st_size}}}


def validate_report(root: Path, report_path: Path, *, require_static: bool = False) -> dict[str, object]:
    root = physical(root, "checkout root", directory=True)
    require(str(root) == SOURCE_MOUNT, "classic-netdb reader requires the pinned /workspace mount")
    report_path = physical(report_path, "classic-netdb component report")
    require(report_path.parent.is_relative_to(root / ".work") and report_path.name == "classic-netdb-products.json",
            "classic-netdb report is not a retained checkout .work file")
    report = read_json(report_path, "classic-netdb component report")
    fields = {"schema", "component", "source_mount", "execution_mode", "scope", "cases", "behavior_roster", "sources",
              "products", "seals", "image", "workload", "commands", "links", "payloads", "executions", "network",
              "dns", "audits", "association_differences", "family_completion", "promotion_ready", "public_support"}
    require(isinstance(report, dict) and set(report) == fields and report["schema"] == SCHEMA and
            report["source_mount"] == SOURCE_MOUNT, "classic-netdb report schema differs")
    validate_component_contract(report)
    mode = report["execution_mode"]
    require_static_mode(mode, require_static)
    all_cells = cells(mode)
    products_record = report["products"]
    require(isinstance(products_record, dict) and set(products_record) == ({"static", "dynamic"} if mode == FULL_MODE else {"dynamic"}),
            "classic-netdb product roster differs")
    dynamic = checkout_directory(root, products_record["dynamic"], "dynamic product")
    static_product = checkout_directory(root, products_record["static"], "static product") if mode == FULL_MODE else None
    current_seal = source_product_seal(root, static_product, dynamic)
    require(report["sources"] == current_seal["sources"], "classic-netdb source identity differs")
    seals = report["seals"]
    require(isinstance(seals, dict) and set(seals) == {"source-product-before", "source-product-after", "tools-before", "tools-after"},
            "classic-netdb seal roster differs")
    for name in ("source-product-before", "source-product-after"):
        seal = assert_identity(root, seals[name], name, expected=report_path.parent / f"{name}.json")
        require(read_json(seal, name) == current_seal, f"{name} differs")
    image = report["image"]
    require(isinstance(image, dict) and set(image) == {"id", "manifest"} and image["id"] == PINNED_IMAGE,
            "classic-netdb image record differs")
    manifest = assert_identity(root, image["manifest"], "classic-netdb image manifest",
                               expected=root / IMAGE_MANIFEST)
    require(read_json(manifest, "retained image manifest") == trusted_image_manifest(root), "classic-netdb image manifest differs")
    current_tools = tool_roster(root, dynamic, static_product)
    for name in ("tools-before", "tools-after"):
        seal = assert_identity(root, seals[name], name, expected=report_path.parent / f"{name}.json")
        require(read_json(seal, name) == current_tools, f"{name} differs")
    work = report_path.parent
    workload = assert_identity(root, report["workload"], "classic-netdb installed-header object", expected=work / "workload.o")
    data = workload.read_bytes()
    require(data[:7] == b"\x7fELF\x02\x01\x01" and data[16:20] == b"\x01\x00>\x00", "classic-netdb workload is not x86-64 ET_REL")

    commands = report["commands"]
    expected_commands = command_plan(root, work, static_product, dynamic, current_tools, mode)
    require(isinstance(commands, dict) and set(commands) == set(expected_commands), "classic-netdb command roster differs")
    for label, expected_argv in expected_commands.items():
        record = commands[label]
        require(isinstance(record, dict) and set(record) == {"argv", "stdout", "stderr", "status"}, f"{label} command fields differ")
        argv = parse_argv(artifact_bytes(root, record, "argv", work, label), label)
        require(argv == expected_argv and artifact_bytes(root, record, "status", work, label) == b"0\n", f"{label} command differs")
    trace = artifact_bytes(root, commands["header-trace"], "stderr", work, "header-trace")
    include = mounted(root, (static_product or dynamic) / "usr/include") + "/"
    trace_paths = [line.lstrip(" .") for line in trace.decode("utf-8", "strict").splitlines() if line.lstrip(" .").startswith("/")]
    require(trace_paths and all(path.startswith(include) for path in trace_paths) and mounted(root, (static_product or dynamic) / "usr/include/netdb.h") in trace_paths,
            "classic-netdb header trace is not installed-only")

    # Re-run the sealed reader against the physical ELF bytes.  The retained
    # readelf output is provenance only and cannot be rehashed into a claim.
    validate_provider_symbols(dynamic / "usr/lib/libc.so", "dynamic classic-netdb provider")
    links = report["links"]
    expected_links = {"dynamic-pie", "dynamic-non-pie"} | ({"static", "static-pie"} if mode == FULL_MODE else set())
    require(isinstance(links, dict) and set(links) == expected_links, "classic-netdb link roster differs")
    for name in sorted(expected_links):
        receipt = assert_identity(root, links[name], f"{name} link receipt", expected=work / f"{name}.crabc-link.json")
        linkage = {"static": "static", "static-pie": "static-pie", "dynamic-pie": "pie", "dynamic-non-pie": "non-pie"}[name]
        product = static_product if linkage.startswith("static") else dynamic
        executable = work / name
        assert product is not None
        try:
            import owned_posix_product_evidence as products
            reconstructed = products.validate_retained_link(
                root, SOURCE_MOUNT, product, workload, executable, receipt, linkage,
                {key: current_tools["linker"][key] for key in ("path", "sha256")},
            )
        except Exception as error:
            raise ReceiptError(f"{name} retained link does not reconstruct: {error}") from error
        require(reconstructed["linkage"] == linkage and reconstructed["receipt_sha256"] == digest(receipt),
                f"{name} retained link reconstruction differs")
    for name in ("static", "static-pie"):
        if mode == FULL_MODE:
            validate_provider_symbols(work / name, f"{name} classic-netdb executable", dynamic=False)
    payloads = report["payloads"]
    require(isinstance(payloads, dict) and set(payloads) == {"pie", "non-pie"}, "classic-netdb payload roster differs")
    for link_mode in ("pie", "non-pie"):
        validate_payload(root, work, payloads[link_mode], dynamic, link_mode)

    raw_oracle: dict[str, tuple[bytes, bytes]] = {}
    executions = report["executions"]
    require(isinstance(executions, list) and len(executions) == (1 + len(all_cells)) * len(CASES),
            "classic-netdb execution roster differs")
    expected_entries = ("oracle", *all_cells)
    seen: set[tuple[str, str]] = set()
    for entry in executions:
        require(isinstance(entry, dict) and set(entry) == {"entry", "case", "argv", "stdout", "stderr", "status"},
                "classic-netdb execution fields differ")
        label, case = entry["entry"], entry["case"]
        require(label in expected_entries and case in CASES and (label, case) not in seen, "classic-netdb execution identity differs")
        seen.add((label, case))
        argv = parse_argv(assert_identity(root, entry["argv"], "execution argv").read_bytes(), "execution")
        require(argv and assert_identity(root, entry["status"], "execution status").read_bytes() == b"0\n", "classic-netdb execution failed")
        stdout = assert_identity(root, entry["stdout"], "execution stdout").read_bytes()
        stderr = assert_identity(root, entry["stderr"], "execution stderr").read_bytes()
        if label == "oracle":
            raw_oracle[case] = (stdout, stderr)
    require(seen == {(entry, case) for entry in expected_entries for case in CASES}, "classic-netdb execution matrix is incomplete")
    differences = report["association_differences"]
    require(isinstance(differences, list), "classic-netdb association difference roster differs")
    difference_entries: set[str] = set()
    for item in differences:
        validate_association_difference(item)
        label = item["entry"]
        require(label in all_cells and label not in difference_entries, "classic-netdb association exception roster differs")
        difference_entries.add(label)
    for entry in expected_entries[1:]:
        record = next(item for item in executions if item["entry"] == entry and item["case"] == "dns-batch")
        stdout = assert_identity(root, record["stdout"], "dns-batch stdout").read_bytes()
        stderr = assert_identity(root, record["stderr"], "dns-batch stderr").read_bytes()
        if stdout != raw_oracle["dns-batch"][0] or stderr != raw_oracle["dns-batch"][1]:
            require(entry in difference_entries and stdout.decode() == ASSOCIATION_OWNED and stderr == b"", "classic-netdb raw transcript differs")
        else:
            require(entry not in difference_entries, "classic-netdb association exception is unneeded")
    require(difference_entries == set(all_cells), "classic-netdb association exception does not bind every candidate transcript")
    for entry in expected_entries[1:]:
        for case in CASES:
            if case == "dns-batch":
                continue
            row = next(item for item in executions if item["entry"] == entry and item["case"] == case)
            require((assert_identity(root, row["stdout"], "candidate stdout").read_bytes(),
                     assert_identity(root, row["stderr"], "candidate stderr").read_bytes()) == raw_oracle[case],
                    f"classic-netdb raw transcript differs: {entry}/{case}")
    network = assert_identity(root, report["network"], "classic-netdb network proof")
    proof = read_json(network, "classic-netdb network proof")
    require(proof.get("interfaces") == ["lo"] and proof.get("loopback_up") is True and
            isinstance(proof.get("network_namespace"), str) and isinstance(proof.get("user_namespace"), str),
            "classic-netdb namespace proof differs")
    dns = report["dns"]
    require(isinstance(dns, dict) and set(dns) == {"ready", "events"}, "classic-netdb DNS receipt fields differ")
    assert_identity(root, dns["ready"], "classic-netdb DNS ready")
    events = dns_events(read_json(assert_identity(root, dns["events"], "classic-netdb DNS events"), "classic-netdb DNS events"))
    validate_events(events, 7 if mode == FULL_MODE else 5)
    audits = assert_identity(root, report["audits"], "classic-netdb artifact audits")
    require(isinstance(read_json(audits, "classic-netdb artifact audits"), dict), "classic-netdb artifact audits differ")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--root", type=Path, required=True)
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--require-static", action="store_true")
    parsed = parser.parse_args()
    try:
        if parsed.action == "validate":
            value = validate_report(parsed.root, parsed.report, require_static=parsed.require_static)
            print(json.dumps({"component": value["component"], "execution_mode": value["execution_mode"],
                              "status": "reconstructed"}, sort_keys=True))
    except ReceiptError as error:
        print(f"owned classic-netdb receipt: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
