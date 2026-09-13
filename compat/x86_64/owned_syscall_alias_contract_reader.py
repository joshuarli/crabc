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
from typing import Any, NamedTuple

SCHEMA = "crabc.x86_64-owned-syscall-alias-contract/v1"
STATUS = {"component_complete": True, "family_completion": False,
          "runtime_qualification": False, "promotion_ready": False, "public_support": False}
IMAGE = "crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
MUSL_SOURCE_COMMIT = "9fa28ece75d8a2191de7c5bb53bed224c5947417"
# The current runner retains 45 parametrized ``run`` envelopes.  Its two
# additional corrected-epoch source checks are retained as raw observations;
# the historical 47-command count must not be fabricated as 47 argv files.
EXPECTED_COMMANDS = 45
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
    "compat/x86_64/owned_syscall_alias_contract_probe.c",
    "compat/x86_64/owned_syscall_alias_override_probe.c",
    "compat/x86_64/owned_shared_dynamic_list_probe.c",
    "compat/x86_64/owned-syscall-alias-contract.md",
)

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
    try: return json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ReceiptError(f"invalid JSON constant {value}")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error: raise ReceiptError(f"{description} is not JSON: {path}") from error

def copy_file(output: Path, source: Path, retained: str) -> dict[str, object]:
    source = physical(source, retained); target = output / retained; target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, target)
    return {"original": {"path": str(source), "sha256": digest(source), "size": source.stat().st_size}, "retained": identity(target, output)}

def source_seal(root: Path) -> dict[str, object]:
    try:
        require(not subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True), "collector checkout is not clean")
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError as error: raise ReceiptError("cannot inspect collector source") from error
    require(re.fullmatch("[0-9a-f]{40}", revision) is not None, "collector revision is invalid")
    return {"revision": revision, "clean": True}

def source_records(root: Path, output: Path, paths: Sequence[str], category: str, selected_revision: str | None = None) -> dict[str, object]:
    result = {}
    for name in paths:
        source = root / name
        if selected_revision is not None:
            selected = subprocess.check_output(["git", "show", f"{selected_revision}:{name}"], cwd=root)
            require(source.read_bytes() == selected, f"selected runtime source changed: {name}")
        target = output / "source" / category / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, target)
        result[name] = identity(target, output)
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

def validate_runner_work(output: Path, runner: Path) -> dict[str, object]:
    runner = physical(runner, "runner evidence", directory=True)
    files = sorted(runner.glob("*.argv.json")); require(len(files) == EXPECTED_COMMANDS, "runner command-envelope roster differs")
    commands: dict[str, list[str]] = {}
    for path in files:
        value = read_json(path, "runner command"); require(isinstance(value, list) and all(isinstance(arg, str) for arg in value), f"command argv differs: {path.name}")
        stem = path.name.removesuffix(".argv.json"); commands[stem] = value
        for suffix in ("stdout", "stderr", "status"): require((runner / f"{stem}.{suffix}").is_file(), f"missing command transcript: {stem}.{suffix}")
        require((runner / f"{stem}.status").read_bytes() == b"0\n", f"command failed: {stem}")
    for probe in ("contract", "override"):
        require_same_probe_object(probe, str(runner / f"{probe}.o"), {name: argv for name, argv in commands.items() if name.endswith(f"-{probe}-link")})
    seal = read_json(runner / "probe-object-seal.json", "probe object seal"); require(isinstance(seal, dict) and set(seal) == {"contract", "override"}, "probe seal roster differs")
    callers = read_json(runner / "source-public-callers.json", "source caller roster")
    require(callers == [{"caller": caller, "public_alias": alias} for caller, alias in PUBLIC_ALIAS_SOURCE_CALLERS], "source caller roster differs")
    for name in ("musl-static-symbols.txt", "candidate-static-symbols.txt", "musl-shared-symbols.txt", "candidate-shared-symbols.txt", "candidate-shared-relocations.txt"):
        require((runner / name).is_file(), f"missing retained ELF stream: {name}")
    return {"path": runner.relative_to(output).as_posix(), "command_count": len(commands), "commands": sorted(commands), "probe_object_seal": identity(runner / "probe-object-seal.json", output)}

def collect_report(*, root: Path, output: Path, static_preparation: Path, static_product: Path, dynamic_product: Path, elf_facts: Path, base_inventory: Path, image: str) -> dict[str, object]:
    root = physical(root, "checkout", directory=True); require(image == IMAGE, "collector must use the pinned core evidence image")
    output = Path(os.path.abspath(output)); require(output.parent.is_relative_to(root / ".work") and not output.exists(), "output must be a fresh checkout .work child"); output.mkdir(parents=True, mode=0o700)
    static_preparation, elf_facts, base_inventory = (physical(value, label) for value, label in ((static_preparation, "static preparation"), (elf_facts, "full ELF facts"), (base_inventory, "base inventory")))
    static_product, dynamic_product = (physical(value, label, True) for value, label in ((static_product, "static product"), (dynamic_product, "dynamic product")))
    for value in (static_preparation, static_product, dynamic_product, elf_facts, base_inventory): require(value.is_relative_to(root / ".work"), "receipt input is outside checkout .work")
    collector_source = source_seal(root); selected_source = admit_inputs(static_preparation, static_product, dynamic_product, elf_facts, base_inventory, image)
    product_inputs = {
        "static_libc": static_product / "usr/lib/libc.a",
        "static_driver": static_product / "bin/crabc-cc",
        "static_manifest": static_product / "share/crabc/manifest.json",
        "dynamic_libc": dynamic_product / "usr/lib/libc.so",
        "dynamic_driver": dynamic_product / "bin/crabc-cc-dynamic",
        "dynamic_loader": dynamic_product / "lib/ld-crabc-x86_64.so.1",
        "dynamic_manifest": dynamic_product / "share/crabc/manifest.json",
    }
    inputs = {"static_preparation": copy_file(output, static_preparation, "inputs/static-preparation.json"), "elf_facts": copy_file(output, elf_facts, "inputs/full-elf-facts.json"), "base_inventory": copy_file(output, base_inventory, "inputs/base-inventory.json"), **{name: copy_file(output, path, f"inputs/products/{name}") for name, path in product_inputs.items()}}
    runner_tmp = output / "runner-tmp"; runner_tmp.mkdir(mode=0o700)
    command = [str(root / "compat/x86_64/run_owned_syscall_alias_contract.sh"), str(static_product), str(dynamic_product)]
    result = subprocess.run(command, cwd=root, env={**os.environ, "TMPDIR": str(runner_tmp)}, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    (output / "collector-command.json").write_text(json.dumps({"argv": command, "status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, sort_keys=True) + "\n")
    require(result.returncode == 0, "native syscall runner failed")
    match = re.search(r"evidence: (?P<path>.+)$", result.stdout, re.MULTILINE); require(match is not None, "runner did not identify evidence path")
    runner = physical(Path(match.group("path")), "runner evidence", True); require(runner.is_relative_to(runner_tmp), "runner evidence escaped receipt root")
    source = {"collector": source_records(root, output, COLLECTOR_SOURCES, "collector"), "selected_runtime": source_records(root, output, RUNTIME_SOURCES, "selected-runtime", str(selected_source["revision"]))}
    tools = {}
    for name in ("python3", "readelf", "timeout"):
        source_tool = Path(shutil.which(name) or "").resolve(); require(source_tool.is_file(), f"missing collector tool: {name}")
        tools[name] = copy_file(output, source_tool, f"tools/{name}")
    report = {"schema": SCHEMA, "status": STATUS, "image": image, "musl_source_commit": MUSL_SOURCE_COMMIT, "collector_source": collector_source, "selected_product_source": selected_source, "inputs": inputs, "source": source, "tools": tools, "runner": validate_runner_work(output, runner), "historical_epochs": {"source_recompiling_harness": {"revision": "1494e97c", "command_count": 45}, "corrected_harness": {"revision": "3bf0a0cb", "command_count": HISTORICAL_CORRECTED_COMMANDS}}, "selection_projection": {"aliases": list(ALIASES), "alias_global_hidden": list(ALIAS_GLOBAL_HIDDEN), "global_hidden": list(GLOBAL_HIDDEN), "source_local": list(LOCAL_BODIES), "raw_private_body": "__libc_sigaction", "component_complete": True, "family_completion": False, "public_support": False}}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report

def validate_report(report_path: Path) -> dict[str, object]:
    """Replay retained bytes only; never invoke compiler, linker, or ELF tools."""
    report_path = physical(report_path, "receipt report"); output = physical(report_path.parent, "receipt root", True); report = read_json(report_path, "receipt report")
    require(isinstance(report, dict) and report.get("schema") == SCHEMA and same(report.get("status"), STATUS) and report.get("image") == IMAGE and report.get("musl_source_commit") == MUSL_SOURCE_COMMIT, "schema/status/image differs")
    projection = {"aliases": list(ALIASES), "alias_global_hidden": list(ALIAS_GLOBAL_HIDDEN), "global_hidden": list(GLOBAL_HIDDEN), "source_local": list(LOCAL_BODIES), "raw_private_body": "__libc_sigaction", "component_complete": True, "family_completion": False, "public_support": False}
    require(same(report.get("selection_projection"), projection), "selection projection differs")
    for category, roster in (("collector", COLLECTOR_SOURCES), ("selected_runtime", RUNTIME_SOURCES)):
        records = report.get("source", {}).get(category, {}); require(isinstance(records, dict) and set(records) == set(roster), f"{category} source roster differs")
        for name, record in records.items(): require(identity(output / record["path"], output) == record, f"retained {category} source changed: {name}")
    tools = report.get("tools", {}); require(set(tools) == {"python3", "readelf", "timeout"}, "tool roster differs")
    for name, binding in tools.items():
        retained = binding.get("retained", {}); require(identity(output / retained["path"], output) == retained and binding.get("original", {}).get("sha256") == retained.get("sha256"), f"retained tool changed: {name}")
    inputs = report.get("inputs", {}); require(set(inputs) == {"static_preparation", "elf_facts", "base_inventory", "static_libc", "static_driver", "static_manifest", "dynamic_libc", "dynamic_driver", "dynamic_loader", "dynamic_manifest"}, "input roster differs")
    for binding in inputs.values():
        retained = binding.get("retained", {}); require(identity(output / retained["path"], output) == retained and binding.get("original", {}).get("sha256") == retained.get("sha256"), "retained input changed")
    require(same(report.get("historical_epochs"), {"source_recompiling_harness": {"revision": "1494e97c", "command_count": 45}, "corrected_harness": {"revision": "3bf0a0cb", "command_count": HISTORICAL_CORRECTED_COMMANDS}}), "historical epochs differ")
    runner = report.get("runner", {}); require(runner.get("command_count") == EXPECTED_COMMANDS and runner.get("commands") == sorted(runner.get("commands", [])), "runner roster differs")
    validate_runner_work(output, output / runner["path"])
    command = read_json(output / "collector-command.json", "collector command"); require(command.get("status") == 0 and isinstance(command.get("argv"), list), "collector command differs")
    return report

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
    except (ReceiptError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"ERROR: owned syscall alias receipt: {error}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
