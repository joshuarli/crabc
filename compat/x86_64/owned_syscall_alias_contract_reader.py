"""Collect and replay the finite x86 syscall alias/linkage component receipt.

The shell runner remains the native judge. This module only gives that judge a
current retained-input boundary. It is deliberately not a generic ELF collector
and cannot select a provider or claim runtime/family completion.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import zlib
from typing import Any, NamedTuple

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import owned_dynamic_receipt
import owned_syscall_alias_authority as authority
import owned_posix_product_evidence as product_evidence
import owned_posix_static_products as static_products
import owned_pthread_alias_contract_reader as pthread_reader

SCHEMA = "crabc.x86_64-owned-syscall-alias-contract/v2"
IMAGE_MANIFEST = MODULE_DIR / "owned-syscall-alias-image-inputs.json"
STATUS = {"component_complete": True, "family_completion": False,
          "runtime_qualification": False, "promotion_ready": False, "public_support": False}
IMAGE = "crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
MUSL_SOURCE_COMMIT = "9fa28ece75d8a2191de7c5bb53bed224c5947417"
# The current runner expands to 47 parametrized ``run`` envelopes. The two
# historical counts remain provenance, never a substitute for this exact
# current roster.
EXPECTED_COMMANDS = 47
HISTORICAL_CORRECTED_COMMANDS = 47
ROOT = Path(__file__).resolve().parents[2]

# The source policy is separate from the final shared-link binding: archives
# keep a strong application override route, while the musl dynamic list closes
# these public names inside libc.so.
PUBLIC_ALIAS_SOURCE_CALLERS = (
    ("__fxstat", "fstat"), ("__fxstatat", "fstatat"), ("ftime", "clock_gettime"),
    ("getloadavg", "sysinfo"), ("sigignore", "sigaction"),
    ("siginterrupt", "sigaction"), ("sigset", "sigaction"),
)
ALIASES = (
    ("clock_gettime", "__clock_gettime"), ("clock_nanosleep", "__clock_nanosleep"),
    ("dup3", "__dup3"), ("fstat", "__fstat"), ("fstatat", "__fstatat"),
    ("fstatfs", "__fstatfs"), ("lseek", "__lseek"), ("madvise", "__madvise"),
    ("mmap", "__mmap"), ("mprotect", "__mprotect"), ("munmap", "__munmap"),
    ("statfs", "__statfs"), ("sysinfo", "__lsysinfo"), ("sigaction", "__sigaction"),
)
ALIAS_GLOBAL_HIDDEN = tuple(body for _alias, body in ALIASES if body not in {"__statfs", "__fstatfs"})
# The raw signal conversion body is not an alias target, but it is still the
# thirteenth global-hidden archive body in this finite component.
GLOBAL_HIDDEN = (*ALIAS_GLOBAL_HIDDEN, "__libc_sigaction")
LOCAL_BODIES = ("__statfs", "__fstatfs")
RUNTIME_SOURCES = (
    "libc/src/c_abi/x86_64/clock_gettime.rs", "libc/src/c_abi/x86_64/clock_nanosleep.rs",
    "libc/src/c_abi/x86_64/descriptor_io.rs", "libc/src/c_abi/x86_64/stat_compat.rs",
    "libc/src/c_abi/x86_64/filesystem_capacity.rs", "libc/src/c_abi/x86_64/memory_mapping.rs",
    "libc/src/c_abi/x86_64/system_observation.rs", "libc/src/c_abi/x86_64/signal_control.rs",
    "libc/src/c_abi/x86_64/owned_dynamic.list",
)
COLLECTOR_SOURCES = (
    "compat/x86_64/run_owned_syscall_alias_contract.sh",
    "compat/x86_64/owned_syscall_alias_contract_reader.py",
    "compat/x86_64/owned_syscall_alias_authority.py",
    "compat/x86_64/owned-syscall-alias-image-inputs.json",
    "compat/x86_64/owned_syscall_alias_contract_probe.c",
    "compat/x86_64/owned_syscall_alias_override_probe.c",
    "compat/x86_64/owned_shared_dynamic_list_probe.c",
    "compat/x86_64/owned-syscall-alias-contract.md",
)
IMAGE_TOOL_PATHS = {
    "oracle_compiler": Path("/usr/local/bin/crabc-x86_64-musl-gcc"),
    "oracle_shared": Path("/opt/musl-1.2.6/lib/libc.so"),
    "oracle_archive": Path("/opt/musl-1.2.6/lib/libc.a"),
}
AMBIENT_TOOL_ROSTER = authority.IMAGE_COMMANDS

def _current_command_stems() -> tuple[str, ...]:
    fixed = (
        "shared-dynamic-list-source", "shared-dynamic-list-product-provenance",
        "shared-dynamic-list-linker-path", "shared-dynamic-list-provider-compile",
        "shared-dynamic-list-caller-compile", "shared-dynamic-list-no-policy-red-link",
        "shared-dynamic-list-selected-link", "contract-compile", "override-compile",
        "probe-object-seal", "oracle-contract-link", "oracle-contract",
        "oracle-override-link", "oracle-override",
    )
    static = tuple(f"{mode}-{probe}{suffix}" for mode in ("static", "static-pie")
                   for probe in ("contract", "override") for suffix in ("-link", ""))
    # Links occur once per probe; execution occurs once per probe and entry.
    dynamic = tuple(
        item for lane in ("oracle-dynamic", "dynamic") for mode in ("pie", "non-pie")
        for item in (f"{lane}-{mode}-contract-link", f"{lane}-{mode}-override-link",
                     f"{lane}-{mode}-contract-kernel", f"{lane}-{mode}-contract-direct",
                     f"{lane}-{mode}-override-kernel", f"{lane}-{mode}-override-direct")
    )
    return (*fixed, *static, *dynamic, "probe-object-link-proof")

CURRENT_COMMAND_STEMS = _current_command_stems()
if len(CURRENT_COMMAND_STEMS) != EXPECTED_COMMANDS or len(set(CURRENT_COMMAND_STEMS)) != EXPECTED_COMMANDS:
    raise RuntimeError("syscall alias command roster is not the fixed 47-envelope contract")

def component_projection() -> dict[str, object]:
    """Return only JSON values; replay compares this serialized contract exactly."""
    return {"aliases": [[alias, body] for alias, body in ALIASES],
            "alias_global_hidden": list(ALIAS_GLOBAL_HIDDEN), "global_hidden": list(GLOBAL_HIDDEN),
            "source_local": list(LOCAL_BODIES), "raw_private_body": "__libc_sigaction",
            "component_complete": True, "family_completion": False, "public_support": False}

class ReceiptError(ValueError):
    pass

class SymbolRow(NamedTuple):
    member: str; value: str; symbol_type: str; binding: str; visibility: str; section: str; name: str

def same_definition(left: SymbolRow, right: SymbolRow) -> bool:
    return (left.member == right.member and left.value == right.value and left.symbol_type == right.symbol_type
            and left.section == right.section)

def require_same_probe_object(probe: str, object_path: str, commands: Mapping[str, Sequence[str]]) -> None:
    if probe not in {"contract", "override"}: raise ValueError("unknown syscall probe")
    expected = {f"{prefix}-{probe}-link" for prefix in ("oracle", "oracle-dynamic-pie", "oracle-dynamic-non-pie", "static", "static-pie", "dynamic-pie", "dynamic-non-pie")}
    if set(commands) != expected: raise ValueError(f"{probe}: incomplete or additional probe links")
    for name, argv in commands.items():
        inputs = [arg for arg in argv if arg.endswith((".o", ".c", ".cc", ".cpp"))]
        if inputs != [object_path]: raise ValueError(f"{name}: link must consume the same compiled probe object")

def require(condition: bool, message: str) -> None:
    if not condition: raise ReceiptError(message)

def same(left: object, right: object) -> bool:
    if type(left) is not type(right): return False
    if isinstance(left, dict): return left.keys() == right.keys() and all(same(value, right[key]) for key, value in left.items())
    if isinstance(left, list): return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right

def physical(path: Path, description: str, directory: bool = False) -> Path:
    require(".." not in Path(path).parts, f"{description} has parent traversal")
    path = Path(os.path.abspath(path)); require(".." not in path.parts, f"{description} has parent traversal")
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part; require(not stat.S_ISLNK(current.lstat().st_mode), f"{description} traverses a symlink")
        mode = path.lstat().st_mode
    except OSError as error: raise ReceiptError(f"{description} is unreadable: {path}") from error
    require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode), f"{description} has wrong node type")
    return path

def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()

def identity(path: Path, root: Path) -> dict[str, object]:
    path = physical(path, "receipt file")
    return {"path": path.relative_to(root).as_posix(), "sha256": digest(path), "size": path.stat().st_size, "mode": stat.S_IMODE(path.stat().st_mode)}

def read_json(path: Path, description: str) -> Any:
    try: return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pthread_reader._unique_object, parse_constant=lambda value: (_ for _ in ()).throw(ReceiptError(f"invalid JSON constant {value}")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error: raise ReceiptError(f"{description} is not JSON: {path}") from error

def copy_file(output: Path, source: Path, retained: str) -> dict[str, object]:
    source = physical(source, retained); target = output / retained; target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, target)
    return {"original": {"path": str(source), "sha256": digest(source), "size": source.stat().st_size, "mode": stat.S_IMODE(source.stat().st_mode)}, "retained": identity(target, output)}

def live_identity(path: Path) -> dict[str, object]:
    """Record a physical execution input before the runner can consume it."""
    path = physical(path, "live execution input")
    return {"path": str(path), "sha256": digest(path), "size": path.stat().st_size,
            "mode": stat.S_IMODE(path.stat().st_mode)}

def _copy_tool(output: Path, name: str) -> dict[str, object]:
    invocation = Path(shutil.which(name, path=authority.IMAGE_PATH) or "")
    require(invocation.is_file(), f"missing collector tool: {name}")
    record = copy_file(output, invocation.resolve(), f"tools/{name}")
    record["invocation"] = str(invocation)
    return record

def source_records(root: Path, output: Path, paths: Sequence[str], category: str, selected_revision: str | None = None) -> dict[str, object]:
    result = {}
    for name in paths:
        source = root / name
        if selected_revision is not None:
            selected = subprocess.check_output(["git", "show", f"{selected_revision}:{name}"], cwd=root)
            require(source.read_bytes() == selected, f"selected runtime source changed: {name}")
        result[name] = copy_file(output, source, f"source/{category}/{name}")
    return result

def admit_inputs(preparation: Path, static_product: Path, dynamic_product: Path, facts_path: Path, inventory_path: Path, image: str) -> dict[str, object]:
    prep, facts, inventory = (read_json(value, name) for value, name in ((preparation, "static preparation"), (facts_path, "full ELF facts"), (inventory_path, "base inventory")))
    require(isinstance(prep, dict) and prep.get("schema") == "crabc.x86_64-owned-posix-static-preparation/v1" and prep.get("status") == "prepared-unqualified", "static preparation schema/status differs")
    source = prep.get("source"); require(isinstance(source, dict) and re.fullmatch("[0-9a-f]{40}", str(source.get("revision"))) and re.fullmatch("[0-9a-f]{64}", str(source.get("content_sha256"))), "static preparation source differs")
    require(static_product == preparation.parent / "products" / "primary", "static product is not preparation primary")
    require((static_product / "usr/lib/libc.a").is_file() and (dynamic_product / "usr/lib/libc.so").is_file(), "product payload is missing")
    require(isinstance(facts, dict) and isinstance(inventory, dict) and facts.get("schema") == "crabc.x86_64-native-abi-elf-facts/v1" and inventory.get("schema") == "crabc.x86_64-native-abi-inventory/v1", "full ELF/base inventory schema differs")
    require(facts.get("image") == image and inventory.get("image") == image, "ELF inputs use another image")
    binding = facts.get("base_inventory", {}).get("report", {}).get("original", {})
    require(binding.get("sha256") == digest(inventory_path), "full ELF facts bind another base inventory")
    for key, product, relative in (("candidate-static", static_product, "usr/lib/libc.a"), ("candidate-shared", dynamic_product, "usr/lib/libc.so")):
        record = facts.get("artifacts", {}).get(key, {}).get("identity", {})
        artifact = product / relative
        require(record.get("sha256") == digest(artifact) and record.get("size") == artifact.stat().st_size, f"full ELF facts do not bind {key}")
    return source

def _copy_tree(output: Path, source: Path, name: str) -> dict[str, object]:
    target = output / "products" / name
    shutil.copytree(source, target, symlinks=True, copy_function=shutil.copy2)
    return {"original": str(source), "retained": target.relative_to(output).as_posix()}

def _validate_retained_cohort(output: Path, inputs: Mapping[str, object], products: Mapping[str, object]) -> None:
    """Reconstruct the selected product/provenance cohort from retained bytes."""
    require(set(products) == {"static", "dynamic"}, "retained product roster differs")
    require(all(products[name].get("retained") == "products/" + name for name in products), "retained product placement differs")
    static_root = physical(output / products["static"]["retained"], "retained static product", True)
    dynamic_root = physical(output / products["dynamic"]["retained"], "retained dynamic product", True)
    try:
        static_manifest, _static_files = product_evidence._validate_static_product(static_root)
        dynamic_manifest, dynamic_files = product_evidence._validate_dynamic_product(dynamic_root)
    except product_evidence.ProductEvidenceError as error:
        raise ReceiptError(f"retained product contract differs: {error}") from error
    prep = read_json(output / inputs["static_preparation"]["retained"]["path"], "retained static preparation")
    facts = read_json(output / inputs["elf_facts"]["retained"]["path"], "retained full ELF facts")
    inventory = read_json(output / inputs["base_inventory"]["retained"]["path"], "retained base inventory")
    require(isinstance(prep, dict) and isinstance(facts, dict) and isinstance(inventory, dict), "retained cohort input differs")
    require(prep.get("schema") == "crabc.x86_64-owned-posix-static-preparation/v1" and prep.get("status") == "prepared-unqualified", "retained preparation differs")
    source = prep.get("source"); require(isinstance(source, dict), "retained preparation source differs")
    require(same(prep.get("products", {}).get("primary", {}).get("tree"), static_products.tree_identity(static_root)), "retained static tree differs from preparation")
    state = read_json(dynamic_root / "share/crabc/dynamic-product-state.json", "retained dynamic state")
    try:
        pthread_reader._validate_dynamic_materialization_state(state, source.get("content_sha256"), dynamic_files, "retained syscall dynamic state")
    except pthread_reader.ReceiptError as error:
        raise ReceiptError(str(error)) from error
    require(facts.get("schema") == "crabc.x86_64-native-abi-elf-facts/v1" and inventory.get("schema") == "crabc.x86_64-native-abi-inventory/v1", "retained facts/inventory schema differs")
    require(facts.get("image") == IMAGE and inventory.get("image") == IMAGE, "retained cohort image differs")
    require(facts.get("base_inventory", {}).get("report", {}).get("original", {}).get("sha256") == digest(output / inputs["base_inventory"]["retained"]["path"]), "retained facts inventory binding differs")
    for key, root, relative in (("candidate-static", static_root, "usr/lib/libc.a"), ("candidate-shared", dynamic_root, "usr/lib/libc.so")):
        fact = facts.get("artifacts", {}).get(key, {}).get("identity", {})
        artifact = root / relative
        require(fact.get("sha256") == digest(artifact) and fact.get("size") == artifact.stat().st_size, f"retained facts {key} binding differs")
    candidate = facts.get("base_inventory", {}).get("candidate_build", {})
    require(candidate.get("revision") == source.get("revision") and candidate.get("source_content_sha256") == source.get("content_sha256"), "retained facts/preparation source cohort differs")
    shared = read_json(dynamic_root / "share/crabc/libc-shared.provenance.json", "retained shared provenance")
    selected_list = shared.get("shared_dynamic_list", {}).get("source", {}) if isinstance(shared, dict) else {}
    require(selected_list.get("path") == "libc/src/c_abi/x86_64/owned_dynamic.list", "retained shared dynamic-list path differs")
    require(selected_list.get("sha256") == digest(output / inputs["selected_dynamic_list"]["retained"]["path"]), "retained shared dynamic-list differs")
    product_files = {
        "static_libc": (static_root, "usr/lib/libc.a"),
        "static_driver": (static_root, "bin/crabc-cc"),
        "static_manifest": (static_root, "share/crabc/manifest.json"),
        "dynamic_libc": (dynamic_root, "usr/lib/libc.so"),
        "dynamic_driver": (dynamic_root, "bin/crabc-cc-dynamic"),
        "dynamic_loader": (dynamic_root, "lib/ld-crabc-x86_64.so.1"),
        "dynamic_manifest": (dynamic_root, "share/crabc/manifest.json"),
        "dynamic_producer_tools": (dynamic_root, "share/crabc/producer-tools.json"),
        "dynamic_shared_provenance": (dynamic_root, "share/crabc/libc-shared.provenance.json"),
    }
    for name, (product_root, relative) in product_files.items():
        binding = inputs.get(name, {}); retained = output / binding.get("retained", {}).get("path", "")
        require(retained.is_file() and retained.read_bytes() == (product_root / relative).read_bytes(), f"retained product input differs: {name}")
    producer_tools = read_json(output / inputs["dynamic_producer_tools"]["retained"]["path"], "retained dynamic producer tools")
    try:
        linker = Path(producer_tools["rustc"]["sysroot"]) / "lib/rustlib" / producer_tools["target"] / "bin/gcc-ld/ld.lld"
    except (KeyError, TypeError) as error:
        raise ReceiptError("retained dynamic producer tools lack selected LLD") from error
    require(inputs["dynamic_linker"]["original"].get("path") == str(linker), "retained selected LLD path differs")
    require(static_manifest == static_root / "share/crabc/manifest.json" and dynamic_manifest == dynamic_root / "share/crabc/manifest.json", "retained manifest paths differ")

def execution_environment(root: Path, temporary: Path) -> dict[str, str]:
    # The runner and every timeout child inherit this exact environment.
    # Product drivers independently apply their existing scrubbed tool policy.
    return {"PATH": authority.IMAGE_PATH, "LC_ALL": "C", "TZ": "UTC",
            "SOURCE_DATE_EPOCH": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "TMPDIR": str(temporary), "HOME": str(temporary),
            "RUSTUP_HOME": "/opt/rustup", "CARGO_HOME": str(root / ".work/x86_64/cargo")}


def expected_commands(work: Path, inputs: Mapping[str, object], root: Path) -> dict[str, list[str]]:
    """Every argument is derived from the finite runner and selected placements."""
    def path(name): return str(work / name)
    def original(name): return inputs[name]["original"]["path"]
    def source(name): return str(root / "compat/x86_64" / name)
    dynamic = original("dynamic_driver")
    oracle = original("oracle_compiler")
    shared = str(root / "libc/src/c_abi/x86_64/owned_dynamic.list")
    commands = {
        "shared-dynamic-list-source": ["python3", "-B", "-", shared, path("shared-dynamic-list-source.json")],
        "shared-dynamic-list-product-provenance": ["python3", "-B", "-", original("dynamic_shared_provenance"), path("shared-dynamic-list-source.json"), path("shared-dynamic-list-product-provenance.json")],
        "shared-dynamic-list-linker-path": ["python3", "-B", "-", original("dynamic_producer_tools"), path("shared-dynamic-list-linker.txt")],
        "probe-object-seal": ["python3", "-B", "-", str(work), source("owned_syscall_alias_contract_probe.c"), source("owned_syscall_alias_override_probe.c")],
        "probe-object-link-proof": ["python3", "-B", "-", str(work), str(root / "compat/x86_64")],
    }
    for part in ("provider", "caller"):
        stem = "shared-dynamic-list-" + part
        commands[stem + "-compile"] = [dynamic, "--dynamic-shared-object", "-std=c11", "-fno-builtin", "-fno-stack-protector", *(["-DCRABC_SHARED_DYNAMIC_LIST_PROVIDER"] if part == "provider" else []), "-c", source("owned_shared_dynamic_list_probe.c"), "-o", path(stem + ".o")]
    for selected in (False, True):
        name = "shared-dynamic-list-" + ("selected" if selected else "no-policy")
        commands[name + ("-link" if selected else "-red-link")] = [original("dynamic_linker"), "-shared", "--hash-style=sysv", *(["--dynamic-list=" + shared] if selected else []), path("shared-dynamic-list-provider.o"), path("shared-dynamic-list-caller.o"), "-o", path(name + ".so")]
    for probe in ("contract", "override"):
        obj = path(probe + ".o")
        commands[probe + "-compile"] = [dynamic, "--dynamic-pie", "-std=c11", "-fno-builtin", "-fno-stack-protector", "-c", source("owned_syscall_alias_" + probe + "_probe.c"), "-o", obj]
        stem = "oracle-" + probe
        commands[stem + "-link"] = [oracle, "-static", "-no-pie", obj, "-o", path(stem)]
        commands[stem] = [path(stem), path("regular")]
        for mode in ("static", "static-pie"):
            stem = mode + "-" + probe
            commands[stem + "-link"] = [original("static_driver"), "-" + mode, obj, "-o", path(stem)]
            commands[stem] = [path(stem), path("regular")]
        for lane in ("oracle-dynamic", "dynamic"):
            for mode in ("pie", "non-pie"):
                stem = lane + "-" + mode + "-" + probe
                if lane == "oracle-dynamic":
                    flags = ["-pie" if mode == "pie" else "-no-pie", obj, *(["-Wl,--export-dynamic"] if probe == "override" else []), "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1"]
                    commands[stem + "-link"] = [oracle, *flags, "-o", path(stem)]
                else:
                    commands[stem + "-link"] = [dynamic, "--dynamic-" + mode, *(["-rdynamic"] if probe == "override" else []), obj, "-o", path(stem)]
                for entry in ("kernel", "direct"):
                    loader = "/lib/ld-musl-x86_64.so.1" if lane == "oracle-dynamic" else "/lib/ld-crabc-x86_64.so.1"
                    commands[stem + "-" + entry] = ["chroot", path(lane + "-" + mode + "-root"), *([loader] if entry == "direct" else []), "/" + probe, "/scratch/regular", *(["shared"] if probe == "override" else [])]
    require(set(commands) == set(CURRENT_COMMAND_STEMS), "expected command contract differs")
    return commands


def _validate_command_argv(stem, argv, command_runner, inputs, root=None):
    if root is None:
        root = Path(inputs["selected_dynamic_list"]["original"]["path"]).parents[4]
    require(same(argv, expected_commands(command_runner, inputs, root).get(stem)),
            f"exact command argv differs: {stem}")


def _require_symbol_observations(runner: Path) -> None:
    """Replay the runner's finite same-definition and visibility predicates."""
    def rows(path: Path, wanted: set[str]) -> dict[str, list[SymbolRow]]:
        result: dict[str, list[SymbolRow]] = {}
        member = ""; table = ""
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("File: "):
                member = line[6:]; table = ""; continue
            if line.startswith("Symbol table '"):
                table = line.split("'", 2)[1]; continue
            fields = line.split()
            if table in wanted and len(fields) >= 8 and fields[0].endswith(":") and fields[6] != "UND":
                row = SymbolRow(member, fields[1], fields[3], fields[4], fields[5], fields[6], fields[7].split("@", 1)[0])
                result.setdefault(row.name, []).append(row)
        return result
    def one(table: Mapping[str, list[SymbolRow]], name: str, label: str) -> SymbolRow:
        values = table.get(name, []); require(len(values) == 1 and values[0].section.isdecimal() and 0 < int(values[0].section) < 0xff00, f"{label}: expected one defined {name}"); return values[0]
    def shape(row: SymbolRow) -> tuple[str, str, str]: return row.symbol_type, row.binding, row.visibility
    def dynamic(path: Path) -> dict[str, list[SymbolRow]]:
        table = rows(path, {".dynsym"})
        for public, _body in ALIASES: require(shape(one(table, public, path.name)) == ("FUNC", "WEAK", "DEFAULT"), f"{path.name}: public alias shape differs")
        for body in GLOBAL_HIDDEN + LOCAL_BODIES: require(not table.get(body), f"{path.name}: private body leaked dynamically")
        return table
    def shared(path: Path) -> dict[str, list[SymbolRow]]:
        table = rows(path, {".symtab"})
        for public, body in ALIASES:
            alias, target = one(table, public, path.name), one(table, body, path.name)
            require(shape(alias) == ("FUNC", "WEAK", "DEFAULT") and target.symbol_type == "FUNC" and target.binding == "LOCAL" and target.visibility in {"DEFAULT", "HIDDEN"} and same_definition(alias, target), f"{path.name}: shared alias/body differs: {public}")
        raw = one(table, "__libc_sigaction", path.name)
        require(raw.symbol_type == "FUNC" and raw.binding == "LOCAL" and raw.visibility in {"DEFAULT", "HIDDEN"}, f"{path.name}: raw signal body differs")
        return table
    def archive(path: Path) -> dict[str, list[SymbolRow]]:
        table = rows(path, {".symtab"})
        for public, body in ALIASES:
            alias, target = one(table, public, path.name), one(table, body, path.name)
            expected = ("FUNC", "LOCAL", "DEFAULT") if body in LOCAL_BODIES else ("FUNC", "GLOBAL", "HIDDEN")
            require(shape(alias) == ("FUNC", "WEAK", "DEFAULT") and shape(target) == expected and same_definition(alias, target), f"{path.name}: archive alias/body differs: {public}")
        require(shape(one(table, "__libc_sigaction", path.name)) == ("FUNC", "GLOBAL", "HIDDEN"), f"{path.name}: raw signal archive body differs")
        return table
    musl_dynamic = dynamic(runner / "musl-dynamic-symbols.txt")
    candidate_dynamic = dynamic(runner / "candidate-dynamic-symbols.txt")
    musl_shared = shared(runner / "musl-shared-symbols.txt")
    candidate_shared = shared(runner / "candidate-shared-symbols.txt")
    musl_static = archive(runner / "musl-static-symbols.txt")
    candidate_static = archive(runner / "candidate-static-symbols.txt")
    for public, _body in ALIASES:
        require(shape(one(musl_dynamic, public, "musl dynamic")) == shape(one(candidate_dynamic, public, "candidate dynamic")) and shape(one(musl_shared, public, "musl shared")) == shape(one(candidate_shared, public, "candidate shared")) and shape(one(musl_static, public, "musl static")) == shape(one(candidate_static, public, "candidate static")), f"musl/candidate alias metadata differs: {public}")
    for mode in ("pie", "non-pie"):
        path = runner / f"dynamic-{mode}-override.symbols.txt"
        table = rows(path, {".dynsym"})
        for public, _body in ALIASES:
            require(shape(one(table, public, path.name)) == ("FUNC", "GLOBAL", "DEFAULT"),
                    f"{path.name}: application override shape differs")
    relocations = (runner / "candidate-shared-relocations.txt").read_text(encoding="utf-8")
    for _caller, public in PUBLIC_ALIAS_SOURCE_CALLERS:
        require(re.search(r"\b" + re.escape(public) + r"(?:@[^\s]+)?\b", relocations) is None, f"candidate shared retains public relocation {public}")

def validate_dynamic_link_receipts(output, runner, inputs, command_runner):
    """Replay the installed driver's actual four final-link input receipts."""
    product = Path(inputs["dynamic_driver"]["original"]["path"]).parents[1]
    retained_product = output / "products/dynamic"
    linker = inputs["dynamic_linker"]["original"]
    for mode in ("pie", "non-pie"):
        crt = "Scrt1.o" if mode == "pie" else "crt1.o"
        for probe in ("contract", "override"):
            stem = f"dynamic-{mode}-{probe}"
            record = read_json(runner / (stem + ".crabc-link.json"), "dynamic link receipt")
            owned_dynamic_receipt.validate(record, format="crabc-x86-64-owned-dynamic-sysroot-v1",
                                           label=stem, fail=lambda message: require(False, message))
            names = ["crti.o", "libc.so", "crtn.o", crt, "crabc-dynamic-attach.o"]
            def original(name): return str(product / "usr/lib" / name)
            obj = str(command_runner / (probe + ".o"))
            runtime = sorted("usr/lib/" + name for name in [*names, "libcrabc-builtins.a"])
            input_rows = [{"path": original(name), "sha256": digest(retained_product / "usr/lib" / name)} for name in names]
            input_rows += [{"path": obj, "sha256": digest(runner / (probe + ".o"))},
                           {"path": original("libcrabc-builtins.a"), "sha256": digest(retained_product / "usr/lib/libcrabc-builtins.a")}]
            command = [linker["path"], *(["-pie"] if mode == "pie" else []), "--hash-style=sysv",
                       "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
                       "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib",
                       *(["--export-dynamic"] if probe == "override" else []), "--dynamic-linker", "/lib/ld-crabc-x86_64.so.1",
                       original(crt), original("crabc-dynamic-attach.o"), original("crti.o"), obj,
                       original("libc.so"), original("libcrabc-builtins.a"), original("crtn.o"), "-o", str(command_runner / stem)]
            require(same(record["input_receipts"], input_rows) and record["owned_runtime_inputs"] == runtime
                    and same(record["resolved_linker"], {key: linker[key] for key in ("path", "sha256")})
                    and record["manifest_sha256"] == inputs["dynamic_manifest"]["original"]["sha256"]
                    and record["output_sha256"] == digest(runner / stem)
                    and record["output_path"] == str(command_runner / stem) and record["link_command"] == command,
                    f"dynamic final link input/output differs: {stem}")
            direct = [original(crt), original("crabc-dynamic-attach.o"), original("crti.o"), obj, original("libc.so"), original("crtn.o")]
            trace = record["link_trace"]
            require(type(trace) is list and [line for line in trace if line in direct] == direct
                    and all(line in direct or line.startswith(original("libcrabc-builtins.a") + "(") and line.endswith(")") for line in trace),
                    f"dynamic final link trace differs: {stem}")
            expected = {"schema": 2, "mode": "pie" if mode == "pie" else "exec", "binding": "now",
                        "runtime_imports": [], "application_dsos": {}, "application_runpath": "/usr/lib",
                        "application_rpath": None, "application_search_kind": "runpath", "application_hash_style": "sysv", "campaign_complete": False}
            require(all(same(record[key], value) for key, value in expected.items()), f"dynamic final link policy differs: {stem}")


def validate_artifact_observations(output, runner, inputs, command_runner):
    """The report cannot substitute an oracle stream for a candidate artifact."""
    def retained(name): return output / inputs[name]["retained"]["path"]
    validate_dynamic_link_receipts(output, runner, inputs, command_runner)
    for stem, name, tables in (
        ("musl-static", "oracle_archive", {".symtab"}),
        ("candidate-static", "static_libc", {".symtab"}),
        ("musl-shared", "oracle_shared", {".symtab", ".dynsym"}),
        ("candidate-shared", "dynamic_libc", {".symtab", ".dynsym"}),
        ("musl-dynamic", "oracle_shared", {".dynsym"}),
        ("candidate-dynamic", "dynamic_libc", {".dynsym"}),
    ):
        authority.require_symbol_stream(runner / (stem + "-symbols.txt"), retained(name),
                                        inputs[name]["original"]["path"], tables)
    authority.require_relocation_stream(runner / "candidate-shared-relocations.txt", retained("dynamic_libc"))
    for part in ("selected", "no-policy"):
        stem = "shared-dynamic-list-" + part
        authority.require_relocation_stream(runner / (stem + ".relocations.txt"), runner / (stem + ".so"))
    authority.require_symbol_stream(runner / "shared-dynamic-list-selected.dynsym.txt",
                                    runner / "shared-dynamic-list-selected.so", "", {".dynsym"})
    for mode in ("pie", "non-pie"):
        binary = "dynamic-" + mode + "-override"
        authority.require_symbol_stream(runner / (binary + ".symbols.txt"), runner / binary, "", {".dynsym"})
    for stem in CURRENT_COMMAND_STEMS:
        if stem.endswith("-compile"):
            name, elf_type = stem.removesuffix("-compile") + ".o", 1
        elif stem.endswith("-link") and not stem.startswith("shared-dynamic-list-"):
            name = stem.removesuffix("-link")
            elf_type = 2 if name.startswith(("oracle-contract", "oracle-override", "static-contract", "static-override")) or "non-pie" in name else 3
        else:
            continue
        require(authority.Elf(physical(runner / name, "runner ELF")).elf_type == elf_type,
                f"runner ELF type differs: {name}")
    require((runner / "regular").read_bytes() == b"syscall alias regular file\n"
            and stat.S_IMODE((runner / "regular").stat().st_mode) == 0o644, "regular input bytes/mode differ")
    # The executed chroot receives exactly the selected runtime plus its linked
    # applications and the regular input; inspect all nodes through product owners.
    dynamic_root = output / "products/dynamic"
    for lane in ("oracle-dynamic", "dynamic"):
        for mode in ("pie", "non-pie"):
            root = physical(runner / f"{lane}-{mode}-root", "runtime root", True)
            # tree_identity contains a sorted entry list; compare using the same
            # owner after accounting for the three explicitly staged inputs.
            additions = {"contract": runner / f"{lane}-{mode}-contract",
                         "override": runner / f"{lane}-{mode}-override", "scratch/regular": runner / "regular"}
            for relative, source in additions.items():
                require(live_identity(root / relative) == {**live_identity(source), "path": str(root / relative)},
                        f"runtime staged input differs: {lane}/{mode}/{relative}")
            if lane == "oracle-dynamic":
                for relative in ("lib/ld-musl-x86_64.so.1", "usr/lib/libc.so"):
                    require(digest(root / relative) == digest(retained("oracle_shared"))
                            and stat.S_IMODE((root / relative).stat().st_mode) == inputs["oracle_shared"]["original"]["mode"], "oracle runtime differs")
                require({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} == set(additions) | {"lib/ld-musl-x86_64.so.1", "usr/lib/libc.so"}, "oracle runtime roster differs")
            else:
                # Existing product validation enforces exact manifest placement,
                # modes and declared loader alias; compare payload nodes directly.
                for entry in dynamic_root.rglob('*'):
                    relative = entry.relative_to(dynamic_root)
                    destination = root / relative
                    if entry.is_symlink():
                        require(destination.is_symlink() and os.readlink(destination) == os.readlink(entry), "runtime alias differs")
                    elif entry.is_file():
                        require(live_identity(destination) == {**live_identity(entry), "path": str(destination)}, "runtime product payload differs")
                require({p.relative_to(root).as_posix() for p in root.rglob('*')} ==
                        {p.relative_to(dynamic_root).as_posix() for p in dynamic_root.rglob('*')} | set(additions) | {"scratch"}, "candidate runtime roster differs")


def validate_runner_placements(runner):
    """Apply the runner's fixed umask and output roster independently of seals."""
    programs = {stem.removesuffix("-link") for stem in CURRENT_COMMAND_STEMS
                if stem.endswith("-link") and not stem.startswith("shared-dynamic-list-")}
    programs |= {"shared-dynamic-list-no-policy.so", "shared-dynamic-list-selected.so"}
    raw = {stem + "." + suffix for stem in CURRENT_COMMAND_STEMS
           for suffix in ("argv.json", "stdin", "stdout", "stderr", "status")}
    raw |= {
        "regular", "contract.o", "override.o", "probe-object-seal.json", "probe-object-link-proof.json",
        "shared-dynamic-list-provider.o", "shared-dynamic-list-caller.o",
        "shared-dynamic-list-source.json", "shared-dynamic-list-product-provenance.json", "shared-dynamic-list-linker.txt",
        "shared-dynamic-list-no-policy.relocations.txt", "shared-dynamic-list-selected.relocations.txt", "shared-dynamic-list-selected.dynsym.txt",
        "musl-dynamic-symbols.txt", "musl-shared-symbols.txt", "musl-static-symbols.txt",
        "candidate-dynamic-symbols.txt", "candidate-shared-symbols.txt", "candidate-static-symbols.txt",
        "candidate-shared-relocations.txt", "source-public-callers.json",
        *(f"dynamic-{mode}-override.symbols.txt" for mode in ("pie", "non-pie")),
        *(f"dynamic-{mode}-{probe}.crabc-link.json" for mode in ("pie", "non-pie") for probe in ("contract", "override")),
    }
    roots = {f"{lane}-{mode}-root" for lane in ("oracle-dynamic", "dynamic") for mode in ("pie", "non-pie")}
    require({node.name for node in runner.iterdir()} == programs | raw | roots, "runner retained node roster differs")
    for name in programs | raw:
        path = physical(runner / name, "runner output")
        require(stat.S_IMODE(path.stat().st_mode) == (0o755 if name in programs else 0o644),
                f"runner output mode differs: {name}")
    # An enclosing workspace may contribute its setgid directory bit. The
    # runtime roots still have the runner's 0755 access permissions.
    for name in roots | {"."}:
        path = physical(runner / name, "runner root", True)
        require(stat.S_IMODE(path.stat().st_mode) & ~0o2000 == 0o755, "runner root mode differs")


def validate_runner_work(
    output: Path,
    runner: Path,
    inputs: Mapping[str, object],
    source: Mapping[str, object],
    command_runner: Path | None = None,
) -> dict[str, object]:
    runner = physical(runner, "runner evidence", directory=True)
    validate_runner_placements(runner)
    for node in runner.rglob('*'):
        if node.is_symlink():
            relative = node.relative_to(runner).as_posix()
            require(relative in {f"dynamic-{mode}-root/lib/ld-musl-x86_64.so.1" for mode in ("pie", "non-pie")}
                    and os.readlink(node) == "ld-crabc-x86_64.so.1", "runner contains undeclared symlink")
        else:
            require(stat.S_ISREG(node.lstat().st_mode) or stat.S_ISDIR(node.lstat().st_mode), "runner contains special node")
    command_runner = runner if command_runner is None else Path(command_runner)
    require(command_runner.is_absolute(), "runner command root is not absolute")
    collector = source["collector"]
    original_root = Path(collector["compat/x86_64/run_owned_syscall_alias_contract.sh"]["original"]["path"]).parents[2]
    script = (output / collector["compat/x86_64/run_owned_syscall_alias_contract.sh"]["retained"]["path"]).read_text()
    environment = execution_environment(original_root, command_runner.parent)
    files = sorted(runner.glob("*.argv.json")); require(len(files) == EXPECTED_COMMANDS, "runner command-envelope roster differs")
    commands: dict[str, list[str]] = {}
    for path in files:
        value = read_json(path, "runner command"); require(isinstance(value, dict) and set(value) == {"argv", "timeout_seconds", "execution_argv", "environment", "cwd"} and same(value.get("timeout_seconds"), 45) and isinstance(value.get("argv"), list), f"command envelope differs: {path.name}")
        stem = path.name.removesuffix(".argv.json"); commands[stem] = value["argv"]
        for suffix in ("stdout", "stderr", "status"): require((runner / f"{stem}.{suffix}").is_file(), f"missing command transcript: {stem}.{suffix}")
        require((runner / f"{stem}.status").read_bytes() == b"0\n", f"command failed: {stem}")
        _validate_command_argv(stem, commands[stem], command_runner, inputs, original_root)
        require(value["execution_argv"] == ["timeout", "45", *commands[stem]]
                and value["environment"] == environment and value["cwd"] == str(original_root),
                f"command execution environment differs: {stem}")
        stdin = (runner / f"{stem}.stdin").read_bytes()
        if commands[stem][:3] == ["python3", "-B", "-"]:
            match = re.search(r"^run " + re.escape(stem) + r" .*?<<'PY'\n(.*?)\nPY$", script, re.MULTILINE | re.DOTALL)
            require(match is not None and stdin == (match.group(1) + "\n").encode(), f"Python command stdin differs: {stem}")
        else:
            require(stdin == b"", f"command stdin differs: {stem}")
    require(set(commands) == set(CURRENT_COMMAND_STEMS), "runner command stems differ")
    for stem in commands:
        if stem.endswith("-link") or stem.endswith("-compile") or stem in {"probe-object-seal", "probe-object-link-proof", "shared-dynamic-list-source", "shared-dynamic-list-product-provenance", "shared-dynamic-list-linker-path", "shared-dynamic-list-no-policy-red-link", "shared-dynamic-list-selected-link"}:
            require((runner / f"{stem}.stdout").read_bytes() == b"" and (runner / f"{stem}.stderr").read_bytes() == b"", f"command diagnostics differ: {stem}")
            continue
        expected = b"owned-syscall-alias-contract-ok\n" if "contract" in stem else b"owned-syscall-alias-override-ok\n"
        require((runner / f"{stem}.stdout").read_bytes() == expected and (runner / f"{stem}.stderr").read_bytes() == b"", f"runtime transcript differs: {stem}")
    for probe in ("contract", "override"):
        require_same_probe_object(probe, str(command_runner / f"{probe}.o"), {name: argv for name, argv in commands.items() if name.endswith(f"-{probe}-link")})
    require((runner / "probe-object-link-proof.json").read_bytes() == (runner / "probe-object-seal.json").read_bytes(), "probe object link proof differs")
    seal = read_json(runner / "probe-object-seal.json", "probe object seal"); require(isinstance(seal, dict) and set(seal) == {"contract", "override"}, "probe seal roster differs")
    collector = source["collector"]
    for probe, source_name in (("contract", "compat/x86_64/owned_syscall_alias_contract_probe.c"), ("override", "compat/x86_64/owned_syscall_alias_override_probe.c")):
        row = seal[probe]; obj = runner / f"{probe}.o"; require(isinstance(row, dict) and row.get("object_path") == str(command_runner / f"{probe}.o") and row.get("source_path") == collector[source_name]["original"]["path"] and row.get("object_sha256") == digest(obj) and row.get("source_sha256") == collector[source_name]["retained"]["sha256"], f"{probe} object/source seal differs")
    require((runner / "probe-object-link-proof.stdout").read_bytes() == b"" and (runner / "probe-object-link-proof.stderr").read_bytes() == b"", "probe object proof diagnostics differ")
    callers = read_json(runner / "source-public-callers.json", "source caller roster")
    require(callers == [{"caller": caller, "public_alias": alias} for caller, alias in PUBLIC_ALIAS_SOURCE_CALLERS], "source caller roster differs")
    for name in ("musl-static-symbols.txt", "candidate-static-symbols.txt", "musl-shared-symbols.txt", "candidate-shared-symbols.txt", "candidate-shared-relocations.txt"):
        require((runner / name).is_file(), f"missing retained ELF stream: {name}")
    validate_artifact_observations(output, runner, inputs, command_runner)
    _require_symbol_observations(runner)
    list_source = read_json(runner / "shared-dynamic-list-source.json", "dynamic-list source observation")
    list_product = read_json(runner / "shared-dynamic-list-product-provenance.json", "dynamic-list product observation")
    shared_provenance = read_json(output / inputs["dynamic_shared_provenance"]["retained"]["path"], "shared provenance")
    require(list_product == {"dynamic_list": shared_provenance["shared_dynamic_list"], "libc_shared_link_command": shared_provenance["libc_shared_link_command"]}, "dynamic-list observation is not selected provenance")
    list_bytes = (output / inputs["selected_dynamic_list"]["retained"]["path"]).read_text()
    members = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*;", list_bytes)
    allocation = ["malloc", "calloc", "realloc", "free", "memalign", "posix_memalign", "aligned_alloc", "malloc_usable_size"]
    require(list_source.get("allocation_entrypoints") == allocation
            and list_source.get("data_symbols") == [name for name in members if name not in allocation],
            "dynamic-list scope is not derived from the pinned source")
    require(list_source.get("sha256") == digest(output / inputs["selected_dynamic_list"]["retained"]["path"])
            == "264ae3bf630a7f6d894a51f91f9acae45b89a5f639537353d03af1a04e9da0f9"
            and list_source.get("source") == str(original_root / "libc/src/c_abi/x86_64/owned_dynamic.list"), "dynamic-list source observation differs")
    require(isinstance(list_source, dict) and isinstance(list_product, dict) and list_product.get("dynamic_list") == {"source": {"path": "libc/src/c_abi/x86_64/owned_dynamic.list", "sha256": list_source.get("sha256"), "mode": 0o644}, "data_symbols": list_source.get("data_symbols"), "allocation_entrypoints": list_source.get("allocation_entrypoints")}, "dynamic-list provenance observation differs")
    command = list_product.get("libc_shared_link_command")
    expected_flag = "--dynamic-list=$SOURCE/libc/src/c_abi/x86_64/owned_dynamic.list"
    require(isinstance(command, list) and all(isinstance(value, str) for value in command) and command.count(expected_flag) == 1 and not any(value in {"-Bsymbolic", "-Bsymbolic-functions"} for value in command), "dynamic-list final link command differs")
    require((runner / "shared-dynamic-list-linker.txt").read_text(encoding="utf-8") == inputs["dynamic_linker"]["original"]["path"] + "\n", "dynamic-list selected LLD differs")
    no_policy = (runner / "shared-dynamic-list-no-policy.relocations.txt").read_text(encoding="utf-8")
    selected = (runner / "shared-dynamic-list-selected.relocations.txt").read_text(encoding="utf-8")
    dynsym = (runner / "shared-dynamic-list-selected.dynsym.txt").read_text(encoding="utf-8")
    require(re.search(r"R_X86_64_JUMP_SLOT.*ordinary_local_call", no_policy) is not None and "ordinary_local_call" not in selected and re.search(r"R_X86_64_GLOB_DAT.*optind", selected) is not None and re.search(r"R_X86_64_JUMP_SLOT.*malloc", selected) is not None and re.search(r"\boptind\b", dynsym) is not None and re.search(r"\bmalloc\b", dynsym) is not None, "dynamic-list relocation predicate differs")
    return {"path": runner.relative_to(output).as_posix(), "original": str(command_runner), "command_count": len(commands), "commands": sorted(commands), "probe_object_seal": identity(runner / "probe-object-seal.json", output)}

def collect_report(*, root: Path, output: Path, static_preparation: Path, static_product: Path, dynamic_product: Path, elf_facts: Path, base_inventory: Path, image: str) -> dict[str, object]:
    root = physical(root, "checkout", directory=True); require(image == IMAGE and os.environ.get("CRABC_X86_SYSCALL_ALIAS_IMAGE_ID") == image, "collector is not bound to the pinned core evidence image")
    output = Path(os.path.abspath(output)); require(output.parent.is_relative_to(root / ".work") and not output.exists(), "output must be a fresh checkout .work child"); output.mkdir(parents=True, mode=0o700)
    static_preparation, elf_facts, base_inventory = (physical(value, label) for value, label in ((static_preparation, "static preparation"), (elf_facts, "full ELF facts"), (base_inventory, "base inventory")))
    static_product, dynamic_product = (physical(value, label, True) for value, label in ((static_product, "static product"), (dynamic_product, "dynamic product")))
    for value in (static_preparation, static_product, dynamic_product, elf_facts, base_inventory): require(value.is_relative_to(root / ".work"), "receipt input is outside checkout .work")
    source_before = static_products.source_identity(root); selected_source = admit_inputs(static_preparation, static_product, dynamic_product, elf_facts, base_inventory, image)
    product_inputs = {
        "static_libc": static_product / "usr/lib/libc.a",
        "static_driver": static_product / "bin/crabc-cc",
        "static_manifest": static_product / "share/crabc/manifest.json",
        "dynamic_libc": dynamic_product / "usr/lib/libc.so",
        "dynamic_driver": dynamic_product / "bin/crabc-cc-dynamic",
        "dynamic_loader": dynamic_product / "lib/ld-crabc-x86_64.so.1",
        "dynamic_manifest": dynamic_product / "share/crabc/manifest.json",
        "dynamic_producer_tools": dynamic_product / "share/crabc/producer-tools.json",
        "dynamic_shared_provenance": dynamic_product / "share/crabc/libc-shared.provenance.json",
    }
    producer_tools = read_json(product_inputs["dynamic_producer_tools"], "dynamic producer tools")
    try:
        linker = Path(producer_tools["rustc"]["sysroot"]) / "lib/rustlib" / producer_tools["target"] / "bin/gcc-ld/ld.lld"
    except (KeyError, TypeError) as error:
        raise ReceiptError("dynamic producer tools lack selected LLD") from error
    inputs = {"static_preparation": copy_file(output, static_preparation, "inputs/static-preparation.json"), "elf_facts": copy_file(output, elf_facts, "inputs/full-elf-facts.json"), "base_inventory": copy_file(output, base_inventory, "inputs/base-inventory.json"), "selected_dynamic_list": copy_file(output, root / "libc/src/c_abi/x86_64/owned_dynamic.list", "inputs/selected-dynamic-list"), **{name: copy_file(output, path, f"inputs/products/{name}") for name, path in product_inputs.items()}, "dynamic_linker": copy_file(output, linker, "inputs/tools/dynamic-linker"), **{name: copy_file(output, path, f"inputs/oracle/{name}") for name, path in IMAGE_TOOL_PATHS.items()}}
    image_manifest = read_json(IMAGE_MANIFEST, "trusted image input manifest")
    require(same(authority.image_input_manifest(), image_manifest), "live tools are not the pinned image inputs")
    image_inputs = {path: copy_file(output, Path(record["path"]), "inputs/image/" + hashlib.sha256(path.encode()).hexdigest())
                    for path, record in image_manifest["files"].items()}
    inputs_before = {name: dict(binding["original"]) for name, binding in inputs.items()}
    products = {"static": _copy_tree(output, static_product, "static"), "dynamic": _copy_tree(output, dynamic_product, "dynamic")}
    _validate_retained_cohort(output, inputs, products)
    tools = {name: _copy_tool(output, name) for name in AMBIENT_TOOL_ROSTER}
    tools_before = {name: dict(binding["original"]) for name, binding in tools.items()}
    runner_tmp = output / "runner-tmp"; runner_tmp.mkdir(mode=0o700)
    command = [str(root / "compat/x86_64/run_owned_syscall_alias_contract.sh"), str(static_product), str(dynamic_product)]
    result = subprocess.run(command, cwd=root, env=execution_environment(root, runner_tmp), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    (output / "collector-command.json").write_text(json.dumps({"argv": command, "environment": execution_environment(root, runner_tmp), "cwd": str(root), "status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, sort_keys=True) + "\n")
    require(result.returncode == 0, "native syscall runner failed")
    for name, before in inputs_before.items():
        require(live_identity(Path(str(before["path"]))) == before, f"execution input changed during native run: {name}")
    try:
        product_evidence._validate_static_product(static_product)
        product_evidence._validate_dynamic_product(dynamic_product)
    except product_evidence.ProductEvidenceError as error:
        raise ReceiptError(f"supplied product changed during native run: {error}") from error
    match = re.search(r"evidence: (?P<path>.+)$", result.stdout, re.MULTILINE); require(match is not None, "runner did not identify evidence path")
    runner = physical(Path(match.group("path")), "runner evidence", True); require(runner.is_relative_to(runner_tmp), "runner evidence escaped receipt root")
    source = {"collector": source_records(root, output, COLLECTOR_SOURCES, "collector"), "selected_runtime": source_records(root, output, RUNTIME_SOURCES, "selected-runtime", str(selected_source["revision"]))}
    for name, before in tools_before.items():
        require(live_identity(Path(str(before["path"]))) == before, f"collector tool changed during native execution: {name}")
    require(same(authority.image_input_manifest(), image_manifest), "pinned image inputs changed during execution")
    source_after = static_products.source_identity(root); require(same(source_before, source_after), "collector source changed during native execution")
    authority.capture_git_objects(root, output, {source_before["revision"], selected_source["revision"]})
    report = {"schema": SCHEMA, "status": STATUS, "image": image, "musl_source_commit": MUSL_SOURCE_COMMIT, "collector_source": {"before": source_before, "after": source_after}, "selected_product_source": selected_source, "image_inputs": image_inputs, "inputs": inputs, "products": products, "source": source, "tools": tools, "runner": validate_runner_work(output, runner, inputs, source, runner), "historical_epochs": {"source_recompiling_harness": {"revision": "1494e97c", "command_count": 45}, "corrected_harness": {"revision": "3bf0a0cb", "command_count": HISTORICAL_CORRECTED_COMMANDS}}, "selection_projection": component_projection()}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return validate_report(output / "report.json")

def _validate_report(report_path: Path) -> dict[str, object]:
    """Replay retained bytes only; never invoke compiler, linker, or ELF tools."""
    report_path = physical(report_path, "receipt report"); output = physical(report_path.parent, "receipt root", True); report = read_json(report_path, "receipt report")
    require(isinstance(report, dict) and report.get("schema") == SCHEMA and same(report.get("status"), STATUS) and report.get("image") == IMAGE and report.get("musl_source_commit") == MUSL_SOURCE_COMMIT, "schema/status/image differs")
    require(set(report) == {"schema", "status", "image", "musl_source_commit", "collector_source", "selected_product_source", "inputs", "image_inputs", "products", "source", "tools", "runner", "historical_epochs", "selection_projection"}, "report fields differ")
    require(set(report.get("source", {})) == {"collector", "selected_runtime"}, "source category roster differs")
    require(same(report.get("selection_projection"), component_projection()), "selection projection differs")
    collector_seal = report.get("collector_source", {})
    require(isinstance(collector_seal, dict) and set(collector_seal) == {"before", "after"} and same(collector_seal["before"], collector_seal["after"])
            and isinstance(collector_seal["before"], dict) and re.fullmatch("[0-9a-f]{40}", str(collector_seal["before"].get("revision")))
            and re.fullmatch("[0-9a-f]{64}", str(collector_seal["before"].get("content_sha256"))), "collector source seal differs")
    selected_product_source = report.get("selected_product_source", {})
    require(isinstance(selected_product_source, dict) and re.fullmatch("[0-9a-f]{40}", str(selected_product_source.get("revision"))) and re.fullmatch("[0-9a-f]{64}", str(selected_product_source.get("content_sha256"))), "selected product source seal differs")
    original_root = Path(report["source"]["collector"]["compat/x86_64/run_owned_syscall_alias_contract.sh"]["original"]["path"]).parents[2]
    require(original_root.is_absolute() and ".." not in original_root.parts, "collector logical root differs")
    source_trees = {}
    for category, seal in (("collector", collector_seal["before"]), ("selected_runtime", selected_product_source)):
        derived, files = authority.source_tree(output, seal["revision"])
        require(same(seal, derived), f"{category} source content does not match retained Git tree")
        source_trees[category] = files
    for category, roster in (("collector", COLLECTOR_SOURCES), ("selected_runtime", RUNTIME_SOURCES)):
        records = report.get("source", {}).get(category, {}); require(isinstance(records, dict) and set(records) == set(roster), f"{category} source roster differs")
        revision = report["collector_source"]["before"]["revision"] if category == "collector" else report["selected_product_source"]["revision"]
        for name, binding in records.items():
            retained = binding.get("retained", {}); original = binding.get("original", {}); require(same(identity(output / retained["path"], output), retained) and original.get("sha256") == retained.get("sha256") and same(original.get("size"), retained.get("size")) and same(original.get("mode"), retained.get("mode")) and Path(str(original.get("path", ""))).is_absolute(), f"retained {category} source changed: {name}")
            require(original["path"] == str(original_root / name), f"source logical placement differs: {name}")
            mode, data, symlink = source_trees[category][name]
            require(not symlink and same(original["mode"], mode) and (output / retained["path"]).read_bytes() == data, f"retained {category} source bytes/mode do not match Git tree: {name}")
            if category == "collector":
                trusted = physical(ROOT / name, "validator collector source")
                require(trusted.read_bytes() == data and stat.S_IMODE(trusted.stat().st_mode) == mode,
                        f"collector source does not match validator authority: {name}")
    manifest_name = "compat/x86_64/owned-syscall-alias-image-inputs.json"
    require(source_trees["collector"][manifest_name][1] == IMAGE_MANIFEST.read_bytes(), "retained image manifest does not match validator's image authority")
    image_manifest = read_json(IMAGE_MANIFEST, "trusted image input manifest")
    image_inputs = report.get("image_inputs", {})
    require(set(image_inputs) == set(image_manifest["files"]), "image input roster differs")
    for invocation, binding in image_inputs.items():
        expected = image_manifest["files"][invocation]
        retained = binding["retained"]
        require(same(binding["original"], expected)
                and same(identity(output / retained["path"], output), retained)
                and all(same(retained[key], expected[key]) for key in ("sha256", "mode", "size")),
                f"retained immutable image input differs: {invocation}")
    tools = report.get("tools", {}); require(set(tools) == set(AMBIENT_TOOL_ROSTER), "tool roster differs")
    for name, binding in tools.items():
        retained = binding.get("retained", {}); original = binding.get("original", {})
        require(set(binding) == {"original", "retained", "invocation"} and isinstance(binding.get("invocation"), str) and Path(binding["invocation"]).is_absolute() and same(identity(output / retained["path"], output), retained) and original.get("sha256") == retained.get("sha256") and same(original.get("size"), retained.get("size")) and same(original.get("mode"), retained.get("mode")) and Path(str(original.get("path", ""))).is_absolute(), f"retained tool changed: {name}")
        require(same(original, image_manifest["files"].get(binding["invocation"])), f"tool identity is not in pinned image: {name}")
    inputs = report.get("inputs", {}); require(set(inputs) == {"static_preparation", "elf_facts", "base_inventory", "selected_dynamic_list", "static_libc", "static_driver", "static_manifest", "dynamic_libc", "dynamic_driver", "dynamic_loader", "dynamic_manifest", "dynamic_producer_tools", "dynamic_shared_provenance", "dynamic_linker", "oracle_compiler", "oracle_shared", "oracle_archive"}, "input roster differs")
    for name, binding in inputs.items():
        retained = binding.get("retained", {}); original = binding.get("original", {})
        require(same(identity(output / retained["path"], output), retained) and original.get("sha256") == retained.get("sha256") and same(original.get("size"), retained.get("size")) and same(original.get("mode"), retained.get("mode")) and Path(str(original.get("path", ""))).is_absolute(), f"retained input changed: {name}")
    for name, path in IMAGE_TOOL_PATHS.items():
        require(same(inputs[name]["original"], image_manifest["files"][str(path)]), f"pinned image input path differs: {name}")
    require(same(inputs["dynamic_linker"]["original"], image_manifest["files"].get(inputs["dynamic_linker"]["original"]["path"])), "selected LLD is not the pinned image input")
    products = report.get("products", {})
    static_original = Path(products["static"]["original"])
    dynamic_original = Path(products["dynamic"]["original"])
    require(static_original == Path(inputs["static_preparation"]["original"]["path"]).parent / "products/primary", "static primary logical placement differs")
    for path in (static_original, dynamic_original):
        require(path.is_relative_to(original_root / ".work") and ".." not in path.parts, "product logical root differs")
    for name, product, relative in (
        ("static_libc", static_original, "usr/lib/libc.a"), ("static_driver", static_original, "bin/crabc-cc"),
        ("static_manifest", static_original, "share/crabc/manifest.json"),
        ("dynamic_libc", dynamic_original, "usr/lib/libc.so"), ("dynamic_driver", dynamic_original, "bin/crabc-cc-dynamic"),
        ("dynamic_loader", dynamic_original, "lib/ld-crabc-x86_64.so.1"),
        ("dynamic_manifest", dynamic_original, "share/crabc/manifest.json"),
        ("dynamic_producer_tools", dynamic_original, "share/crabc/producer-tools.json"),
        ("dynamic_shared_provenance", dynamic_original, "share/crabc/libc-shared.provenance.json"),
        ("selected_dynamic_list", original_root, "libc/src/c_abi/x86_64/owned_dynamic.list"),
    ):
        require(inputs[name]["original"]["path"] == str(product / relative), f"input logical placement differs: {name}")
    _validate_retained_cohort(output, inputs, products)
    retained_preparation = read_json(output / inputs["static_preparation"]["retained"]["path"], "retained static preparation")
    require(retained_preparation.get("source") == selected_product_source, "retained preparation/selected source differs")
    require(same(report.get("historical_epochs"), {"source_recompiling_harness": {"revision": "1494e97c", "command_count": 45}, "corrected_harness": {"revision": "3bf0a0cb", "command_count": HISTORICAL_CORRECTED_COMMANDS}}), "historical epochs differ")
    runner = report.get("runner", {}); require(runner.get("command_count") == EXPECTED_COMMANDS and runner.get("commands") == sorted(runner.get("commands", [])) and isinstance(runner.get("original"), str), "runner roster differs")
    derived_runner = validate_runner_work(output, output / runner["path"], inputs, report["source"], Path(runner["original"]))
    require(same(runner, derived_runner), "runner projection differs from retained observations")
    command = read_json(output / "collector-command.json", "collector command")
    expected_command = [
        report["source"]["collector"]["compat/x86_64/run_owned_syscall_alias_contract.sh"]["original"]["path"],
        report["products"]["static"]["original"],
        report["products"]["dynamic"]["original"],
    ]
    original_root = Path(expected_command[0]).parents[2]
    require(command.get("environment") == execution_environment(original_root, Path(runner["original"]).parent)
            and command.get("cwd") == str(original_root), "collector environment differs")
    require(same(command.get("status"), 0) and command.get("argv") == expected_command
            and isinstance(command.get("stdout"), str) and isinstance(command.get("stderr"), str)
            and command["stderr"] == ""
            and command["stdout"] == "owned syscall alias contract evidence: " + runner["original"] + "\n"
            + "owned syscall alias contract: PASS (pinned musl archive/shared aliases, static/static-PIE and shared PIE/non-PIE public overrides, source-shaped internal call paths); evidence: " + runner["original"] + "\n", "collector command differs")
    return report

def validate_report(report_path: Path) -> dict[str, object]:
    try:
        return _validate_report(report_path)
    except (ValueError, OSError, KeyError, TypeError, IndexError, zlib.error) as error:
        raise ReceiptError(str(error)) from error

def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("mode", choices=("collect", "validate-report")); parser.add_argument("--root", type=Path, default=ROOT); parser.add_argument("--output", type=Path); parser.add_argument("--static-preparation", type=Path); parser.add_argument("--static-product", type=Path); parser.add_argument("--dynamic-product", type=Path); parser.add_argument("--elf-facts", type=Path); parser.add_argument("--base-inventory", type=Path); parser.add_argument("--image-id"); parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "collect":
            require(all(value is not None for value in (args.output, args.static_preparation, args.static_product, args.dynamic_product, args.elf_facts, args.base_inventory, args.image_id)) and args.report is None, "collect requires output, products, preparation, ELF facts/base inventory, and image id")
            report = collect_report(root=args.root, output=args.output, static_preparation=args.static_preparation, static_product=args.static_product, dynamic_product=args.dynamic_product, elf_facts=args.elf_facts, base_inventory=args.base_inventory, image=args.image_id)
        else:
            require(args.report is not None and all(value is None for value in (args.output, args.static_preparation, args.static_product, args.dynamic_product, args.elf_facts, args.base_inventory, args.image_id)), "validate-report takes only --report")
            report = validate_report(args.report)
        print(f"owned syscall alias receipt validated: {report['runner']['command_count']} retained commands; component only")
        return 0
    except (ReceiptError, OSError, subprocess.CalledProcessError, ValueError, KeyError, TypeError, IndexError) as error:
        print(f"ERROR: owned syscall alias receipt: {error}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
