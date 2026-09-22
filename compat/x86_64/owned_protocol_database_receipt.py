#!/usr/bin/env python3
"""Read one retained fixed-musl-proto.c product receipt without executing it.

The reader accepts only the raw evidence made by
``owned_protocol_database.py``: the pinned musl ``proto.lo`` oracle, the one
project-header object, three separate but byte-identical product pairs, link
receipts, current provider ELF projections, isolated chroot roots, and every
oracle/candidate stdout, stderr, status, and argv sidecar.  It never builds,
links, or runs a consumer.  Its readelf/nm replays only authenticate retained
provider and oracle bytes against their named current artifacts.

The C ABI proven here remains musl's fixed table.  A Rust facade snapshot of
``/etc/protocols`` is a separate API and is deliberately absent from this
receipt.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_protocol_database as producer  # noqa: E402


SCHEMA = producer.SCHEMA
COMPONENT = producer.COMPONENT
ARMS = producer.ARMS
ENTRY_MODES = producer.ENTRY_MODES
PROVIDERS = producer.PROVIDERS
REPORT_NAME = "owned-protocol-database-products.json"


class ReceiptError(RuntimeError):
    """The protocol-database receipt is missing, mutable, or malformed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def physical(path: Path, description: str, *, directory: bool = False) -> Path:
    try:
        value = Path(os.path.abspath(path))
        metadata = value.lstat()
        require(not value.is_symlink(), f"{description} is a symlink: {path}")
        require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
                f"{description} has the wrong type: {path}")
        current = Path(value.anchor)
        for part in value.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return value
    except OSError as error:
        raise ReceiptError(f"cannot read {description}: {path}") from error


def below_work(root: Path, path: Path, description: str, *, directory: bool) -> Path:
    value = physical(path, description, directory=directory)
    require(value.is_relative_to(root / ".work"), f"{description} escapes checkout .work")
    return value


def _relative(root: Path, value: object, description: str, *, directory: bool = False) -> Path:
    require(isinstance(value, str) and value, f"{description} path is absent")
    path = Path(value)
    require(not path.is_absolute() and path.parts and all(part not in {"", ".", ".."} for part in path.parts),
            f"{description} path escapes checkout")
    return below_work(root, root / path, description, directory=directory)


def identity(root: Path, path: Path, description: str) -> dict[str, object]:
    value = physical(path, description)
    require(value.is_relative_to(root), f"{description} escapes checkout")
    return {
        "path": value.relative_to(root).as_posix(),
        "sha256": sha256(value.read_bytes()).hexdigest(),
        "byte_length": value.stat().st_size,
        "mode": stat.S_IMODE(value.stat().st_mode),
    }


def resolve_identity(root: Path, record: object, description: str) -> Path:
    require(isinstance(record, dict) and set(record) == {"path", "sha256", "byte_length", "mode"},
            f"{description} identity differs")
    path = _relative(root, record["path"], description)
    require(identity(root, path, description) == record, f"{description} identity differs")
    return path


def read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        result = json.loads(physical(path, description).read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"cannot read {description}: {error}") from error
    require(isinstance(result, dict), f"{description} is not a JSON object")
    return result


def fixture(root: Path) -> Any:
    try:
        return producer.fixture_module()
    except producer.ProtocolDatabaseError as error:
        raise ReceiptError(str(error)) from error


def _source(root: Path, value: object) -> None:
    require(isinstance(value, dict) and set(value) == {"before", "after"}, "protocol receipt source seal differs")
    expected = producer.source_records(root)
    require(value["before"] == expected and value["after"] == expected,
            "protocol receipt source has changed")


def _reported_products(root: Path, value: object, helper: Any) -> dict[str, dict[str, object]]:
    require(isinstance(value, dict) and set(value) == {"before", "after"}, "protocol receipt product seal differs")
    before, after = value["before"], value["after"]
    require(isinstance(before, dict) and before == after and set(before) == set(ARMS),
            "protocol receipt product arms differ")
    paths: dict[str, Path] = {}
    for arm in ARMS:
        arm_value = before[arm]
        require(isinstance(arm_value, dict) and set(arm_value) == {"static", "dynamic"},
                f"protocol receipt {arm} product shape differs")
        for kind in ("static", "dynamic"):
            item = arm_value[kind]
            require(isinstance(item, dict) and set(item) == {"path", "manifest", "payload_tree", "physical_tree"},
                    f"protocol receipt {arm} {kind} product shape differs")
            paths[f"{arm}-{kind}"] = _relative(root, item["path"], f"{arm} {kind} product", directory=True)
    try:
        observed = producer._products(helper, paths)
    except (producer.ProtocolDatabaseError, OSError, ValueError, RuntimeError) as error:
        raise ReceiptError(f"protocol receipt product validation failed: {error}") from error
    require(observed == before, "protocol receipt product identity differs")
    return observed


def _oracle(root: Path, work: Path, value: object) -> None:
    require(isinstance(value, dict) and set(value) == {"archive", "object", "symbols", "undefined"},
            "protocol receipt musl oracle shape differs")
    archive_record = value["archive"]
    require(isinstance(archive_record, dict) and set(archive_record) == {"path", "sha256", "byte_length", "mode"},
            "protocol receipt musl archive identity differs")
    try:
        output = subprocess.run((producer.MUSL_CC, "-print-file-name=libc.a"), cwd=root, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReceiptError("cannot query pinned musl archive") from error
    require(output.returncode == 0 and not output.stderr, "cannot query pinned musl archive")
    archive = physical(Path(output.stdout.decode("utf-8").strip()), "pinned musl archive")
    observed_archive = {"path": str(archive), "sha256": sha256(archive.read_bytes()).hexdigest(),
                        "byte_length": archive.stat().st_size, "mode": stat.S_IMODE(archive.stat().st_mode)}
    require(archive_record == observed_archive, "protocol receipt musl archive differs")
    object_file = resolve_identity(root, value["object"], "protocol receipt musl proto object")
    symbols = resolve_identity(root, value["symbols"], "protocol receipt musl proto symbols")
    undefined = resolve_identity(root, value["undefined"], "protocol receipt musl proto imports")
    require(object_file.is_relative_to(work) and symbols.is_relative_to(work) and undefined.is_relative_to(work),
            "protocol receipt musl oracle escapes report work root")
    try:
        extracted = subprocess.run(("ar", "p", archive, "proto.lo"), cwd=root, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=False, timeout=10)
        replay_symbols = subprocess.run(("readelf", "--wide", "--syms", object_file), cwd=root,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
        replay_imports = subprocess.run(("nm", "--undefined-only", "--format=posix", object_file), cwd=root,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReceiptError("cannot replay pinned musl proto oracle") from error
    require(extracted.returncode == 0 and extracted.stdout == object_file.read_bytes() and not extracted.stderr,
            "protocol receipt musl proto object differs")
    require(replay_symbols.returncode == 0 and not replay_symbols.stderr and replay_symbols.stdout == symbols.read_bytes(),
            "protocol receipt musl proto symbols differ")
    require(replay_imports.returncode == 0 and not replay_imports.stderr and replay_imports.stdout == undefined.read_bytes(),
            "protocol receipt musl proto imports differ")
    try:
        producer.provider_rows(replay_symbols.stdout, "retained musl proto symbols")
    except producer.ProtocolDatabaseError as error:
        raise ReceiptError(str(error)) from error
    imports = sorted(line.split()[0] for line in replay_imports.stdout.decode("utf-8").splitlines() if line.split())
    require(imports == ["strcmp", "strlen"], "protocol receipt musl proto imports differ")


def _candidate_paths(root: Path, value: object, workload: Path, products: Mapping[str, Mapping[str, object]],
                     helper: Any) -> dict[str, Path]:
    require(isinstance(value, dict) and set(value) == set(ARMS), "protocol receipt candidate arm roster differs")
    result: dict[str, Path] = {}
    for arm in ARMS:
        item = value[arm]
        require(isinstance(item, dict) and set(item) == {"static-et-exec", "static-pie", "dynamic-pie", "dynamic-non-pie"},
                f"protocol receipt {arm} candidate mode roster differs")
        static_root = _relative(root, products[arm]["static"]["path"], f"{arm} static product", directory=True)
        dynamic_root = _relative(root, products[arm]["dynamic"]["path"], f"{arm} dynamic product", directory=True)
        for mode, option, elf_mode, dynamic in (
            ("static-et-exec", "--static-et-exec", "static", False),
            ("static-pie", "--static-pie", "static-pie", False),
            ("dynamic-pie", "--dynamic-pie", "dynamic-pie", True),
            ("dynamic-non-pie", "--dynamic-non-pie", "dynamic-non-pie", True),
        ):
            row = item[mode]
            require(isinstance(row, dict) and set(row) == {"binary", "receipt", "elf"},
                    f"protocol receipt {arm} {mode} candidate shape differs")
            binary = resolve_identity(root, row["binary"], f"{arm} {mode} candidate")
            try:
                audit = (helper.dynamic_receipt_audit(dynamic_root, option, workload, binary,
                                                      Path(str(binary) + ".crabc-link.json")) if dynamic else
                         helper.static_receipt_audit(static_root, option, workload, binary,
                                                     binary.parent / "link.receipt.json"))
                elf = helper.elf_audit(binary, mode=elf_mode, dynamic=dynamic)
            except (OSError, RuntimeError, ValueError) as error:
                raise ReceiptError(f"cannot replay {arm} {mode} link evidence: {error}") from error
            require(row["receipt"] == audit and row["elf"] == elf,
                    f"protocol receipt {arm} {mode} link evidence differs")
            result[f"{arm}-{mode}"] = binary
    return result


def _providers(root: Path, value: object, oracle: Path, candidates: Mapping[str, Path],
               products: Mapping[str, Mapping[str, object]]) -> None:
    expected = {"oracle", *(f"{arm}-{mode}" for arm in ARMS for mode in ("static-et-exec", "static-pie")),
                *(f"{arm}-dynamic-provider" for arm in ARMS)}
    require(isinstance(value, dict) and set(value) == expected, "protocol receipt provider roster differs")
    for label in sorted(expected):
        row = value[label]
        require(isinstance(row, dict) and set(row) == {"binary", "dynamic", "symbols"},
                f"protocol receipt provider shape differs: {label}")
        dynamic = label.endswith("dynamic-provider")
        require(row["dynamic"] is dynamic, f"protocol receipt provider dynamic form differs: {label}")
        expected_binary = (oracle if label == "oracle" else
                           _relative(root, products[label.split("-", 1)[0]]["dynamic"]["path"],
                                     f"{label} product", directory=True) / "usr/lib/libc.so"
                           if dynamic else candidates[label])
        binary = resolve_identity(root, row["binary"], f"{label} provider binary")
        require(binary == expected_binary, f"protocol receipt provider binary differs: {label}")
        symbols = resolve_identity(root, row["symbols"], f"{label} provider symbols")
        try:
            replay = subprocess.run(("readelf", "--wide", "--dyn-syms" if dynamic else "--syms", binary), cwd=root,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReceiptError(f"cannot replay {label} provider symbols") from error
        require(replay.returncode == 0 and not replay.stderr and replay.stdout == symbols.read_bytes(),
                f"protocol receipt provider symbols differ: {label}")
        try:
            producer.provider_rows(replay.stdout, label)
        except producer.ProtocolDatabaseError as error:
            raise ReceiptError(str(error)) from error


def _isolation(root: Path, value: object) -> dict[str, Path]:
    labels = {"oracle", *(f"{arm}-{mode}" for arm in ARMS for mode in ("static-et-exec", "static-pie", "dynamic-pie", "dynamic-non-pie"))}
    require(isinstance(value, dict) and set(value) == labels, "protocol receipt isolation roster differs")
    result: dict[str, Path] = {}
    for label in labels:
        row = value[label]
        require(isinstance(row, dict) and set(row) == {"root", "protocols", "tree"},
                f"protocol receipt {label} isolation shape differs")
        work_root = _relative(root, row["root"], f"{label} execution root", directory=True)
        protocols = resolve_identity(root, row["protocols"], f"{label} isolated protocols fixture")
        require(protocols == work_root / "etc/protocols" and protocols.read_bytes() == producer.POISON_PROTOCOLS,
                f"protocol receipt {label} has no fixed-table isolation fixture")
        helper = fixture(root)
        require(row["tree"] == helper.receipt_tree_identity(work_root),
                f"protocol receipt {label} isolated root differs")
        result[label] = work_root
    return result


def _executions(root: Path, value: object, isolation: Mapping[str, Path]) -> None:
    expected = producer.expected_executions()
    require(isinstance(value, dict) and set(value) == set(expected), "protocol receipt execution roster differs")
    oracle_streams: tuple[bytes, bytes, bytes] | None = None
    for label, (root_label, argv) in expected.items():
        row = value[label]
        require(isinstance(row, dict) and set(row) == {"root", "argv", "status", "stdout", "stderr"},
                f"protocol receipt {label} execution shape differs")
        require(row["root"] == root_label and root_label in isolation, f"protocol receipt {label} root differs")
        argv_path = resolve_identity(root, row["argv"], f"{label} argv")
        status_path = resolve_identity(root, row["status"], f"{label} status")
        stdout_path = resolve_identity(root, row["stdout"], f"{label} stdout")
        stderr_path = resolve_identity(root, row["stderr"], f"{label} stderr")
        try:
            recorded_argv = json.loads(argv_path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise ReceiptError(f"protocol receipt {label} argv differs") from error
        streams = (status_path.read_bytes(), stdout_path.read_bytes(), stderr_path.read_bytes())
        require(recorded_argv == argv and streams == (b"0\n", b"", b""),
                f"protocol receipt {label} raw outcome differs")
        if oracle_streams is None:
            oracle_streams = streams
        else:
            require(streams == oracle_streams, f"protocol receipt {label} raw musl replay differs")


def validate_report(root: Path, report_path: Path) -> dict[str, object]:
    """Authenticate every retained protocol-table input without native execution."""

    root = physical(root, "checkout root", directory=True)
    require((root / ".work").is_dir(), "checkout root has no .work directory")
    report_file = below_work(root, report_path if report_path.is_absolute() else root / report_path,
                             "protocol receipt report", directory=False)
    require(report_file.name == REPORT_NAME, "protocol receipt report name differs")
    work = report_file.parent
    report = read_json(report_file, "protocol receipt report")
    require(set(report) == {
        "schema", "component", "oracle", "source", "products", "workload", "oracle_binary", "candidates",
        "providers", "isolation", "executions", "entry_modes", "family_completion", "promotion_ready", "public_support",
    }, "protocol receipt report shape differs")
    require((report["schema"], report["component"], report["entry_modes"], report["family_completion"],
             report["promotion_ready"], report["public_support"]) ==
            (SCHEMA, COMPONENT, list(ENTRY_MODES), False, False, False), "protocol receipt identity differs")
    source_before = producer.source_records(root)
    _source(root, report["source"])
    helper = fixture(root)
    products_before = _reported_products(root, report["products"], helper)
    _oracle(root, work, report["oracle"])
    workload = resolve_identity(root, report["workload"], "protocol receipt workload")
    oracle_binary = resolve_identity(root, report["oracle_binary"], "protocol receipt oracle binary")
    candidates = _candidate_paths(root, report["candidates"], workload, products_before, helper)
    _providers(root, report["providers"], oracle_binary, candidates, products_before)
    isolation = _isolation(root, report["isolation"])
    _executions(root, report["executions"], isolation)
    require(producer.source_records(root) == source_before, "protocol receipt source changed during replay")
    require(_reported_products(root, report["products"], helper) == products_before,
            "protocol receipt product changed during replay")
    return {
        "schema": SCHEMA,
        "component": COMPONENT,
        "arms": list(ARMS),
        "entry_modes": list(ENTRY_MODES),
        "execution_count": len(producer.expected_executions()),
        "providers": list(PROVIDERS),
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate_report(ROOT, args.report), sort_keys=True))
    except ReceiptError as error:
        print(f"owned protocol database receipt: ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
