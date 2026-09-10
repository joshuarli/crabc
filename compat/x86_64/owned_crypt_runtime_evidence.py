#!/usr/bin/env python3
"""Seal the dynamic-root payload consumed by the bounded crypt receipt."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from owned_posix_product_evidence import ProductEvidenceError, _validate_dynamic_product


EXECUTION_PAYLOAD_SCHEMA = "crabc.x86_64-owned-crypt-runtime-execution-payload/v1"


class CryptRuntimeEvidenceError(RuntimeError):
    """The product copy or application that executed does not match its receipt."""


def fail(message: str) -> None:
    raise CryptRuntimeEvidenceError(message)


def absolute(path: Path, description: str) -> Path:
    """Make an existing path absolute after rejecting lexical and symlink hops."""

    if ".." in path.parts:
        fail(f"{description} has lexical parent traversal: {path}")
    result = Path(os.path.abspath(path))
    current = Path(result.anchor)
    try:
        for component in result.parts[1:-1]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{description} traverses a symlink: {path}")
        result.lstat()
    except OSError as error:
        raise CryptRuntimeEvidenceError(f"{description} is unreadable: {path}") from error
    return result


def directory(path: Path, description: str) -> Path:
    path = absolute(path, description)
    try:
        if not stat.S_ISDIR(path.lstat().st_mode):
            fail(f"{description} is not a physical directory: {path}")
    except OSError as error:
        raise CryptRuntimeEvidenceError(f"{description} is unreadable: {path}") from error
    return path


def regular(path: Path, description: str) -> Path:
    path = absolute(path, description)
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            fail(f"{description} is not a physical regular file: {path}")
    except OSError as error:
        raise CryptRuntimeEvidenceError(f"{description} is unreadable: {path}") from error
    return path


def digest(path: Path) -> str:
    path = regular(path, "hashed artifact")
    value = sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                value.update(block)
    except OSError as error:
        raise CryptRuntimeEvidenceError(f"cannot hash artifact: {path}") from error
    return value.hexdigest()


def file_record(path: Path, description: str) -> dict[str, str]:
    path = regular(path, description)
    return {"path": str(path), "sha256": digest(path)}


def alias_record(path: Path, description: str) -> dict[str, str]:
    path = absolute(path, description)
    try:
        if not stat.S_ISLNK(path.lstat().st_mode):
            fail(f"{description} is not a symbolic link: {path}")
        return {"path": str(path), "target": os.readlink(path)}
    except OSError as error:
        raise CryptRuntimeEvidenceError(f"{description} is unreadable: {path}") from error


def no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def json_object(path: Path, description: str) -> dict[str, Any]:
    path = regular(path, description)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_pairs)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise CryptRuntimeEvidenceError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        fail(f"{description} is not an object")
    return value


def relative(value: object, description: str) -> str:
    if not isinstance(value, str):
        fail(f"{description} has a non-string path")
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{description} has an unsafe path: {value}")
    return value


def manifest_aliases(manifest: Path) -> dict[str, str]:
    value = json_object(manifest, "dynamic product manifest")
    aliases = value.get("symlinks")
    if not isinstance(aliases, dict):
        fail("dynamic product manifest has no symbolic-link roster")
    result: dict[str, str] = {}
    for path, target in aliases.items():
        result[relative(path, "dynamic product manifest alias")] = target if isinstance(target, str) else fail(
            "dynamic product manifest has a non-string alias target"
        )
    return dict(sorted(result.items()))


def dynamic_product(product: Path) -> tuple[Path, Path, dict[str, str], dict[str, str]]:
    product = directory(product, "dynamic product")
    try:
        manifest, files = _validate_dynamic_product(product)
    except ProductEvidenceError as error:
        raise CryptRuntimeEvidenceError(f"dynamic product validation failed: {error}") from error
    manifest = regular(manifest, "dynamic product manifest")
    return product, manifest, dict(sorted(files.items())), manifest_aliases(manifest)


def copied_file(source: Path, execution: Path, description: str) -> dict[str, dict[str, str]]:
    source_record = file_record(source, f"{description} source")
    execution_record = file_record(execution, f"{description} copy")
    if source_record["sha256"] != execution_record["sha256"]:
        fail(f"{description} copy differs from source")
    return {"source": source_record, "execution": execution_record}


def copied_alias(source: Path, execution: Path, expected_target: str, description: str) -> dict[str, dict[str, str]]:
    source_record = alias_record(source, f"{description} source")
    execution_record = alias_record(execution, f"{description} copy")
    if source_record["target"] != expected_target:
        fail(f"{description} source target differs from manifest")
    if execution_record["target"] != source_record["target"]:
        fail(f"{description} copy target differs from source")
    return {"source": source_record, "execution": execution_record}


def exact_record(value: object, fields: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{description} fields drifted")
    return value


def assert_file_record(value: object, path: Path, description: str) -> None:
    record = exact_record(value, {"path", "sha256"}, description)
    if record != file_record(path, description):
        fail(f"{description} identity drifted")


def assert_alias_record(value: object, path: Path, description: str) -> None:
    record = exact_record(value, {"path", "target"}, description)
    current = alias_record(path, description)
    if record.get("path") != current["path"]:
        fail(f"{description} path drifted")
    if record.get("target") != current["target"]:
        fail(f"{description} target drifted")


def assert_execution_tree(
    execution_root: Path, files: dict[str, str], aliases: dict[str, str], consumer: Path | tuple[Path, ...]
) -> None:
    """Reject additions as well as changed runtime files in the private root."""

    execution_root = directory(execution_root, "execution root")
    consumers = (consumer,) if isinstance(consumer, Path) else consumer
    if not isinstance(consumers, tuple) or not consumers:
        fail("execution consumer roster differs")
    consumer_relatives: set[str] = set()
    for entry in consumers:
        entry = regular(entry, "execution consumer")
        try:
            relative = entry.relative_to(execution_root).as_posix()
        except ValueError as error:
            raise CryptRuntimeEvidenceError("execution consumer escapes the execution root") from error
        consumer_relatives.add(relative)
    if len(consumer_relatives) != len(consumers):
        fail("execution consumer roster duplicates a path")
    expected_files = {"share/crabc/manifest.json", *files, *consumer_relatives}
    expected_aliases = set(aliases)
    observed_files: set[str] = set()
    observed_aliases: set[str] = set()
    try:
        entries = sorted(execution_root.rglob("*"))
    except OSError as error:
        raise CryptRuntimeEvidenceError("cannot enumerate execution root") from error
    for entry in entries:
        name = entry.relative_to(execution_root).as_posix()
        try:
            mode = entry.lstat().st_mode
        except OSError as error:
            raise CryptRuntimeEvidenceError(f"cannot inspect execution payload: {entry}") from error
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISREG(mode):
            observed_files.add(name)
        elif stat.S_ISLNK(mode):
            observed_aliases.add(name)
        else:
            fail(f"execution payload has a non-file entry: {name}")
    if observed_files != expected_files:
        fail("execution payload file roster drifted")
    if observed_aliases != expected_aliases:
        fail("execution alias roster drifted")


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    parent = directory(path.parent, "execution evidence parent")
    path = Path(os.path.abspath(path))
    if path.parent != parent or path.exists() or path.is_symlink():
        fail("execution payload record already exists or is unsafe")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise CryptRuntimeEvidenceError(f"cannot write execution payload record: {path}") from error


def record_execution_payload(
    product: Path, execution_root: Path, source_consumer: Path, execution_consumer: Path, record_path: Path
) -> dict[str, Any]:
    """Record a complete copied product and its consumer before candidate launch."""

    product, manifest, files, aliases = dynamic_product(product)
    execution_root = directory(execution_root, "execution root")
    source_consumer = regular(source_consumer, "source consumer")
    execution_consumer = regular(execution_consumer, "execution consumer")
    assert_execution_tree(execution_root, files, aliases, execution_consumer)
    record = {
        "schema": EXECUTION_PAYLOAD_SCHEMA,
        "product": {"root": str(product), "manifest": copied_file(
            manifest, execution_root / "share/crabc/manifest.json", "execution manifest",
        )},
        "execution_root": str(execution_root),
        "payload": {
            name: copied_file(product / name, execution_root / name, f"execution payload {name}")
            for name in files
        },
        "aliases": {
            name: copied_alias(product / name, execution_root / name, target, f"execution alias {name}")
            for name, target in aliases.items()
        },
        "consumer": copied_file(source_consumer, execution_consumer, "execution consumer"),
    }
    write_new_json(record_path, record)
    return record


def audit_execution_payload(
    product: Path, execution_root: Path, source_consumer: Path, execution_consumer: Path, record_path: Path
) -> dict[str, Any]:
    """Recheck the source, copied product, aliases, and consumer against one record."""

    product, manifest, files, aliases = dynamic_product(product)
    execution_root = directory(execution_root, "execution root")
    source_consumer = regular(source_consumer, "source consumer")
    execution_consumer = regular(execution_consumer, "execution consumer")
    record_path = regular(record_path, "execution payload record")
    record = json_object(record_path, "execution payload record")
    record = exact_record(record, {"schema", "product", "execution_root", "payload", "aliases", "consumer"},
                          "execution payload record")
    if record["schema"] != EXECUTION_PAYLOAD_SCHEMA:
        fail("execution payload record schema drifted")
    if record["execution_root"] != str(execution_root):
        fail("execution root path drifted")
    product_record = exact_record(record["product"], {"root", "manifest"}, "execution product")
    if product_record["root"] != str(product):
        fail("execution product root drifted")
    manifest_record = exact_record(product_record["manifest"], {"source", "execution"}, "execution manifest")
    assert_file_record(manifest_record["source"], manifest, "execution manifest source")
    assert_file_record(manifest_record["execution"], execution_root / "share/crabc/manifest.json",
                       "execution manifest copy")
    if manifest_record["source"]["sha256"] != manifest_record["execution"]["sha256"]:
        fail("execution manifest copy differs from source")

    payload = record["payload"]
    if not isinstance(payload, dict) or set(payload) != set(files):
        fail("execution payload roster drifted")
    for name in files:
        item = exact_record(payload[name], {"source", "execution"}, f"execution payload {name}")
        assert_file_record(item["source"], product / name, f"execution payload {name} source")
        assert_file_record(item["execution"], execution_root / name, f"execution payload {name} copy")
        if item["source"]["sha256"] != item["execution"]["sha256"]:
            fail(f"execution payload {name} copy differs from source")

    aliases_record = record["aliases"]
    if not isinstance(aliases_record, dict) or set(aliases_record) != set(aliases):
        fail("execution alias roster drifted")
    for name, target in aliases.items():
        item = exact_record(aliases_record[name], {"source", "execution"}, f"execution alias {name}")
        assert_alias_record(item["source"], product / name, f"execution alias {name} source")
        assert_alias_record(item["execution"], execution_root / name, f"execution alias {name} copy")
        if item["source"]["target"] != target:
            fail(f"execution alias {name} source target differs from manifest")
        if item["execution"]["target"] != item["source"]["target"]:
            fail(f"execution alias {name} copy target differs from source")

    consumer_record = exact_record(record["consumer"], {"source", "execution"}, "execution consumer")
    assert_file_record(consumer_record["source"], source_consumer, "execution consumer source")
    assert_file_record(consumer_record["execution"], execution_consumer, "execution consumer copy")
    if consumer_record["source"]["sha256"] != consumer_record["execution"]["sha256"]:
        fail("execution consumer copy differs from source")
    assert_execution_tree(execution_root, files, aliases, execution_consumer)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("record", "audit"):
        command = commands.add_parser(action)
        command.add_argument("--product", type=Path, required=True)
        command.add_argument("--execution-root", type=Path, required=True)
        command.add_argument("--source-consumer", type=Path, required=True)
        command.add_argument("--execution-consumer", type=Path, required=True)
        command.add_argument("--record", type=Path, required=True)
    parsed = parser.parse_args()
    try:
        if parsed.action == "record":
            record_execution_payload(
                parsed.product, parsed.execution_root, parsed.source_consumer, parsed.execution_consumer, parsed.record,
            )
        else:
            json.dump(
                audit_execution_payload(
                    parsed.product, parsed.execution_root, parsed.source_consumer, parsed.execution_consumer, parsed.record,
                ), sys.stdout, sort_keys=True, separators=(",", ":"),
            )
            sys.stdout.write("\n")
    except CryptRuntimeEvidenceError as error:
        print(f"owned crypt runtime execution evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
