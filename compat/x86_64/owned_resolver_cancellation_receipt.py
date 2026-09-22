#!/usr/bin/env python3
"""Replay one retained owned-resolver cancellation receipt.

``owned_resolver_cancellation.py`` deliberately keeps the cancellation
observations as raw stdout/stderr pairs because descriptor retirement and the
last syscall errno are part of the behavior.  This reader turns that producer
directory into a public, read-only receipt boundary.  It never compiles, links,
or executes a resolver consumer.  It authenticates the exact application
object, installed static and dynamic products, driver receipts, ELF facts and
every retained oracle/candidate observation before returning a report.

The receipt is a component proof only.  It neither selects a resolver family
nor makes a promotion or public-support claim.
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
import subprocess
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-resolver-cancellation-products/v1"
SOURCE = "compat/x86_64/owned_resolver_cancellation_probe.c"
ARTIFACT_AUDIT = "artifact-audits.json"
STATUS = "execution-status.json"
ORDINARY_DIFFERENCES = "ordinary-errno-differences.json"
SOURCE_LATER_DIFFERENCES = "masked-later-errno-differences.json"
NETWORK_ISOLATION = "network-isolation.json"
STATIC_ARTIFACTS = (
    ("static-et-exec", "--static-et-exec", "static"),
    ("static-pie", "--static-pie", "static-pie"),
)
DYNAMIC_ARTIFACTS = (
    ("dynamic-pie", "--dynamic-pie", "dynamic-pie"),
    ("dynamic-non-pie", "--dynamic-non-pie", "dynamic-non-pie"),
)
ENTRY_MODES = (
    "static-et-exec",
    "static-pie",
    "dynamic-pie-kernel",
    "dynamic-pie-direct",
    "dynamic-non-pie-kernel",
    "dynamic-non-pie-direct",
)
ENTRY_LABELS = ("oracle", *ENTRY_MODES)
PROVIDER_FILES = (
    ("oracle-symbols.txt", "oracle", False),
    ("static-et-exec-symbols.txt", "static-et-exec", False),
    ("static-pie-symbols.txt", "static-pie", False),
    ("dynamic-provider-symbols.txt", "dynamic-product", True),
)
NETWORK_NAMESPACE = re.compile(r"^net:\[[0-9]+\]$")
USER_NAMESPACE = re.compile(r"^user:\[[0-9]+\]$")
TRANSITION_OBSERVATION = {
    "canceled": 1,
    "returned": 0,
    "cleanup": 1,
    "cleanup_fds": 0,
    "leaked": 0,
    "state": 0,
    "transmitted": 0,
    "success": 0,
    "errno": 0,
}


class ReceiptError(RuntimeError):
    """The retained cancellation evidence is incomplete or has drifted."""


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
        return json.loads(
            physical_file(path, description).read_text(encoding="utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{description} is not valid JSON: {path}") from error


def physical_file(path: Path, description: str) -> Path:
    """Return a regular file only when no path component is a symlink."""

    try:
        result = Path(os.path.abspath(path))
        metadata = result.lstat()
        require(stat.S_ISREG(metadata.st_mode) and not result.is_symlink(),
                f"{description} is not a physical regular file: {path}")
        current = Path(result.anchor)
        for part in result.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return result
    except OSError as error:
        raise ReceiptError(f"{description} is unreadable: {path}") from error


def physical_directory(path: Path, description: str) -> Path:
    """Return a directory only when no path component is a symlink."""

    try:
        result = Path(os.path.abspath(path))
        metadata = result.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and not result.is_symlink(),
                f"{description} is not a physical directory: {path}")
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


def artifact_record(path: Path) -> dict[str, object]:
    path = physical_file(path, "receipt artifact")
    return {"path": str(path), "sha256": digest(path), "byte_length": path.stat().st_size}


def _below(root: Path, path: Path, description: str, *, directory: bool) -> Path:
    value = physical_directory(path, description) if directory else physical_file(path, description)
    require(value.is_relative_to(root / ".work"), f"{description} escapes checkout .work")
    return value


def _source_digest(root: Path) -> str:
    """Match the producer's live nonignored source digest byte-for-byte."""

    try:
        output = subprocess.check_output(
            ["git", "-c", f"safe.directory={root}", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReceiptError("cannot enumerate the source bound to cancellation evidence") from error
    names = sorted(set(output.split(b"\0")) - {b""})
    value = sha256()
    for name in names:
        path = root / os.fsdecode(name)
        try:
            mode = path.lstat().st_mode
            contents = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        except OSError as error:
            raise ReceiptError(f"cannot read source-bound path: {path}") from error
        value.update(name + b"\0" + str(stat.S_IMODE(mode)).encode() + b"\0")
        value.update(sha256(contents).digest())
    return value.hexdigest()


def _fixture(root: Path) -> Any:
    """Load the producer's installed-product audit helpers from this checkout."""

    source = physical_file(root / "compat/resolver-network/run_x86_64.py", "resolver fixture helper")
    name = f"owned_resolver_cancellation_fixture_{sha256(str(root).encode()).hexdigest()[:16]}"
    spec = importlib.util.spec_from_file_location(name, source)
    require(spec is not None and spec.loader is not None, "cannot load resolver fixture helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        raise ReceiptError(f"cannot load resolver fixture helper: {error}") from error
    return module


def _cancellation() -> Any:
    try:
        import owned_resolver_cancellation as cancellation
    except ImportError as error:
        raise ReceiptError("cannot load resolver cancellation behavior contract") from error
    return cancellation


def _raw(work: Path, name: str, description: str) -> Path:
    return physical_file(work / name, description)


def _strict_observation(cancellation: Any, output: bytes, description: str) -> dict[str, int]:
    try:
        fields = output.decode("ascii").split()
        pairs = [field.split("=", 1) for field in fields]
    except UnicodeDecodeError as error:
        raise ReceiptError(f"{description} is not ASCII") from error
    require(all(len(pair) == 2 and pair[0] and pair[1] for pair in pairs),
            f"{description} has a malformed observation field")
    require(len(pairs) == len({pair[0] for pair in pairs}), f"{description} repeats an observation field")
    try:
        result = cancellation.observation(output)
    except (RuntimeError, UnicodeDecodeError, ValueError) as error:
        raise ReceiptError(f"{description} is not a complete cancellation observation") from error
    require(all(isinstance(value, int) for value in result.values()),
            f"{description} has a non-integer observation")
    return result


def _expected_status(cancellation: Any) -> list[dict[str, object]]:
    return [
        {"entry": entry, "api": api, "scenario": scenario, "exit_status": 0}
        for entry in ENTRY_LABELS
        for api, scenario in cancellation.CASES
    ]


def _verify_transition(work: Path, cancellation: Any, *, fallback: bool) -> None:
    label = "oracle-connect-transition" if fallback else "oracle-fastopen-transition"
    observation = _strict_observation(cancellation, _raw(work, label + ".stdout", label + " stdout").read_bytes(),
                                      label + " stdout")
    require(observation == TRANSITION_OBSERVATION, f"{label} observation differs")
    try:
        lines = _raw(work, label + ".stderr", label + " stderr").read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ReceiptError(f"{label} stderr is not UTF-8") from error
    expected = (["tcp-fastopen-option state=1", "tcp-connect state=1", "tcp-sendmsg fastopen=0 state=0"]
                if fallback else ["tcp-fastopen-option state=1", "tcp-sendmsg fastopen=1 state=1"])
    require(lines[:len(expected)] == expected and
            all(line == "tcp-sendmsg fastopen=0 state=0" for line in lines[len(expected):]),
            f"{label} source transition differs")


def _verify_namespace(work: Path) -> dict[str, object]:
    value = read_json(work / NETWORK_ISOLATION, "cancellation network isolation")
    require(isinstance(value, dict) and set(value) == {
        "interfaces", "network_namespace", "user_namespace", "loopback_up", "isolation", "parent_network_namespace",
    }, "cancellation network isolation fields differ")
    require(value["interfaces"] == ["lo"], "cancellation receipt was not isolated to loopback")
    require(value["loopback_up"] is True, "cancellation receipt loopback is down")
    require(value["isolation"] in {"docker-network-none", "user-net-namespace"},
            "cancellation receipt isolation mode differs")
    require(isinstance(value["network_namespace"], str) and NETWORK_NAMESPACE.fullmatch(value["network_namespace"]),
            "cancellation receipt network namespace is invalid")
    require(isinstance(value["user_namespace"], str) and USER_NAMESPACE.fullmatch(value["user_namespace"]),
            "cancellation receipt user namespace is invalid")
    parent = value["parent_network_namespace"]
    require(parent is None or (isinstance(parent, str) and NETWORK_NAMESPACE.fullmatch(parent) and
                               parent != value["network_namespace"]),
            "cancellation receipt parent network namespace is invalid")
    return value


def _provider_rows(raw: bytes, providers: frozenset[str]) -> dict[str, list[str]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ReceiptError("provider symbol audit is not UTF-8") from error
    found: dict[str, list[str]] = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 8 and fields[7] in providers:
            require(fields[7] not in found, f"provider symbol audit duplicates {fields[7]}")
            found[fields[7]] = fields
    require(set(found) == providers, f"provider symbol audit misses {sorted(providers-set(found))}")
    for name, fields in found.items():
        require(fields[3] == "FUNC" and fields[4] in {"GLOBAL", "WEAK"} and
                fields[5] == "DEFAULT" and fields[6] != "UND",
                f"provider symbol audit has incorrect binding: {name}: {fields}")
    return found


def _replay_provider_symbols(work: Path, dynamic: Path, cancellation: Any) -> None:
    binaries = {
        "oracle": work / "oracle",
        "static-et-exec": work / "static-et-exec",
        "static-pie": work / "static-pie",
        "dynamic-product": dynamic / "usr/lib/libc.so",
    }
    for raw_name, binary_name, is_dynamic in PROVIDER_FILES:
        binary = physical_file(binaries[binary_name], f"provider binary {binary_name}")
        recorded = _raw(work, raw_name, f"provider raw audit {binary_name}").read_bytes()
        try:
            replay = subprocess.run(
                ["readelf", "--wide", "--dyn-syms" if is_dynamic else "--syms", str(binary)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        except OSError as error:
            raise ReceiptError("cannot replay pinned provider symbol audit") from error
        require(replay.returncode == 0 and replay.stdout + replay.stderr == recorded,
                f"provider symbol audit bytes differ: {binary_name}")
        _provider_rows(recorded, cancellation.PROVIDERS)


def _replay_artifact_audits(root: Path, work: Path, static: Path, dynamic: Path,
                            audit: Mapping[str, object], fixture: Any) -> None:
    require(set(audit) == {"source_sha256", "source", "object", "products", "artifacts"},
            "cancellation artifact audit fields differ")
    require(audit["source"] == artifact_record(root / SOURCE), "cancellation source artifact differs")
    require(audit["object"] == artifact_record(work / "workload.o"), "cancellation workload object differs")
    products = audit["products"]
    require(isinstance(products, dict) and products == {
        "static": fixture.tree_identity(static), "dynamic": fixture.tree_identity(dynamic),
    }, "cancellation installed product tree differs")
    recorded = audit["artifacts"]
    require(isinstance(recorded, dict) and set(recorded) == {
        "static-et-exec", "static-pie", "dynamic-pie", "dynamic-non-pie",
    }, "cancellation artifact mode roster differs")
    object_file = physical_file(work / "workload.o", "cancellation workload object")
    expected: dict[str, object] = {}
    for label, option, elf_mode in STATIC_ARTIFACTS:
        output = physical_file(work / label, f"cancellation {label} binary")
        receipt = physical_file(work / (label + ".receipt.json"), f"cancellation {label} link receipt")
        expected[label] = {
            "receipt": fixture.static_receipt_audit(static, option, object_file, output, receipt),
            "elf": fixture.elf_audit(output, mode=elf_mode, dynamic=False),
        }
    for label, option, elf_mode in DYNAMIC_ARTIFACTS:
        output = physical_file(work / label, f"cancellation {label} binary")
        receipt = physical_file(work / (label + ".crabc-link.json"), f"cancellation {label} link receipt")
        expected[label] = {
            "receipt": fixture.dynamic_receipt_audit(dynamic, option, object_file, output, receipt),
            "elf": fixture.elf_audit(output, mode=elf_mode, dynamic=True),
        }
    require(recorded == expected, "cancellation artifact audit no longer replays")


def _replay_observations(work: Path, cancellation: Any) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    status = read_json(work / STATUS, "cancellation execution status")
    expected_status = _expected_status(cancellation)
    require(status == expected_status, "cancellation execution status matrix differs")
    oracle: dict[tuple[str, str], tuple[dict[str, int], bytes]] = {}
    ordinary: list[dict[str, object]] = []
    source_later: list[dict[str, object]] = []
    for entry in ENTRY_LABELS:
        for api, scenario in cancellation.CASES:
            label = f"{entry}-{api}-{scenario}"
            current = _strict_observation(cancellation, _raw(work, label + ".stdout", label + " stdout").read_bytes(),
                                          label + " stdout")
            stderr = _raw(work, label + ".stderr", label + " stderr").read_bytes()
            if entry == "oracle":
                oracle[(api, scenario)] = (current, stderr)
                continue
            expected, oracle_stderr = oracle[(api, scenario)]
            try:
                difference = cancellation.compare_observation(api, scenario, expected, oracle_stderr, current, stderr)
            except RuntimeError as error:
                raise ReceiptError(f"cancellation observation differs for {label}: {error}") from error
            if difference == "ordinary":
                ordinary.append({"entry": entry, "api": api, "scenario": scenario,
                                 "oracle_errno": expected["errno"], "owned_errno": current["errno"]})
            elif difference == "source-later-syscall":
                source_later.append({"entry": entry, "api": api, "scenario": scenario,
                                     "oracle_errno": expected["errno"], "owned_errno": current["errno"]})
            else:
                require(difference is None, f"unknown cancellation difference kind: {difference}")
    require(read_json(work / ORDINARY_DIFFERENCES, "ordinary cancellation errno differences") == ordinary,
            "ordinary cancellation errno receipt differs")
    require(read_json(work / SOURCE_LATER_DIFFERENCES, "source-later cancellation errno differences") == source_later,
            "source-later cancellation errno receipt differs")
    return ordinary, source_later


def validate_report(root: Path, work: Path, *, static_product: Path, dynamic_product: Path,
                    require_static: bool = True) -> dict[str, object]:
    """Authenticate a complete, same-source six-entry cancellation receipt."""

    require(require_static, "cancellation family receipt requires the static entry modes")
    root = physical_directory(root, "checkout root")
    require((root / ".work").is_dir(), "checkout root has no .work directory")
    work = _below(root, work, "cancellation evidence directory", directory=True)
    static = _below(root, static_product, "static cancellation product", directory=True)
    dynamic = _below(root, dynamic_product, "dynamic cancellation product", directory=True)
    require(len({work, static, dynamic}) == 3, "cancellation evidence and products must be distinct")
    source_before = _source_digest(root)
    prior_bytecode_policy = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        cancellation = _cancellation()
        fixture = _fixture(root)
    finally:
        sys.dont_write_bytecode = prior_bytecode_policy
    static_before = fixture.tree_identity(static)
    dynamic_before = fixture.tree_identity(dynamic)
    audit = read_json(work / ARTIFACT_AUDIT, "cancellation artifact audit")
    require(isinstance(audit, dict) and audit.get("source_sha256") == source_before,
            "cancellation receipt source identity differs")
    _replay_artifact_audits(root, work, static, dynamic, audit, fixture)
    _replay_provider_symbols(work, dynamic, cancellation)
    namespace = _verify_namespace(work)
    _verify_transition(work, cancellation, fallback=False)
    _verify_transition(work, cancellation, fallback=True)
    ordinary, source_later = _replay_observations(work, cancellation)
    require(_source_digest(root) == source_before, "source changed during cancellation receipt replay")
    require(fixture.tree_identity(static) == static_before and fixture.tree_identity(dynamic) == dynamic_before,
            "product changed during cancellation receipt replay")
    return {
        "schema": SCHEMA,
        "source_sha256": source_before,
        "work": str(work),
        "products": {"static": static_before, "dynamic": dynamic_before},
        "entry_modes": list(ENTRY_MODES),
        "case_count": len(cancellation.CASES),
        "execution_count": len(_expected_status(cancellation)),
        "network_isolation": namespace,
        "ordinary_errno_differences": ordinary,
        "source_later_errno_differences": source_later,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate",))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--static-product", type=Path, required=True)
    parser.add_argument("--dynamic-product", type=Path, required=True)
    values = parser.parse_args()
    try:
        report = validate_report(values.root, values.work, static_product=values.static_product,
                                 dynamic_product=values.dynamic_product)
        print(json.dumps(report, sort_keys=True))
    except ReceiptError as error:
        parser.exit(1, f"owned resolver cancellation receipt: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
