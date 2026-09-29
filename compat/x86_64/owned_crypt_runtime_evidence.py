#!/usr/bin/env python3
"""Seal the dynamic-root payload consumed by the bounded crypt receipt."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from owned_posix_product_evidence import ProductEvidenceError, _validate_dynamic_product


EXECUTION_PAYLOAD_SCHEMA = "crabc.x86_64-owned-crypt-runtime-execution-payload/v1"
EDGE_SCHEMA = "crabc.x86_64-owned-crypt-runtime-edge/v1"
EDGE_SOURCE = HERE / "owned_crypt_runtime_probe.c"
EDGE_ROWS = (
    "sha256-default", "sha256-min-clamp", "sha256-min", "sha256-leading-zero",
    "sha512-default", "sha512-min-clamp", "sha512-min", "empty-salt",
    "noncanonical-salt", "extra-field", "overlong-salt", "missing-rounds",
    "signed-rounds", "overflow-rounds", "above-max-rounds", "legacy-md5", "legacy-bcrypt",
)
EDGE_SUPPORTED = frozenset(EDGE_ROWS[:7])
EDGE_ORACLE_ROWS = tuple(name for name in EDGE_ROWS if name not in {"overflow-rounds", "above-max-rounds"})
EDGE_ORACLE_SHA256 = "a4ac792956a8e9f4f4df8447123057f6e3f12ec14e2e78addaa876dc6577d370"
EDGE_CANDIDATE_SHA256 = "57ef0ae0fc42bf6fca8125da5fd05ea09ec75954b751089d7d257238f834e3d3"
EDGE_FLAGS = ["-std=c11", "-D_GNU_SOURCE", "-fno-builtin", "-fno-stack-protector"]
EDGE_COMMANDS = ("oracle-compile", "candidate-compile", "oracle", "link-pie", "link-non-pie",
                 "dynamic-pie-kernel", "dynamic-pie-direct", "dynamic-non-pie-kernel", "dynamic-non-pie-direct")


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


def edge_observations(raw: bytes, rows: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """Decode the complete bounded observer stream without trusting its roster."""

    try:
        lines = raw.decode("ascii").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise CryptRuntimeEvidenceError("edge observation is not ASCII") from error
    if len(lines) != 2 * len(rows):
        fail("edge observation row count drifted")
    observations: dict[str, dict[str, str]] = {}
    for index, name in enumerate(rows):
        observations[name] = {}
        for offset, entry in enumerate(("crypt", "crypt_r")):
            line = lines[2 * index + offset]
            prefix = f"{name} {entry} "
            if not line.startswith(prefix) or not line.endswith("\n"):
                fail(f"edge observation order drifted at {name} {entry}")
            value = line[len(prefix):-1]
            if value != "null" and (len(value) % 2 or any(c not in "0123456789abcdef" for c in value)):
                fail(f"edge observation has invalid bytes at {name} {entry}")
            observations[name][entry] = value
    return observations


def edge_semantics(oracle: bytes, candidate: bytes) -> dict[str, dict[str, dict[str, str]]]:
    if sha256(oracle).hexdigest() != EDGE_ORACLE_SHA256:
        fail("edge pinned-musl observation bytes differ")
    if sha256(candidate).hexdigest() != EDGE_CANDIDATE_SHA256:
        fail("edge installed-product observation bytes differ")
    reference = edge_observations(oracle, EDGE_ORACLE_ROWS)
    product = edge_observations(candidate, EDGE_ROWS)
    for name in EDGE_ROWS:
        for side, rows in (("oracle", reference), ("candidate", product)):
            if name not in rows:
                continue
            if rows[name]["crypt"] != rows[name]["crypt_r"]:
                fail(f"edge {side} public and reentrant results differ at {name}")
        observed = product[name]["crypt"]
        if name in EDGE_SUPPORTED:
            if observed in ("null", "2a") or reference[name]["crypt"] in ("null", "2a"):
                fail(f"edge supported SHA returned null or unsupported at {name}")
            value = bytes.fromhex(observed)
            if not value.startswith((b"$5$rounds=", b"$6$rounds=")):
                fail(f"edge supported SHA result has wrong format at {name}")
            expected = bytes.fromhex(reference[name]["crypt"])
            if name.endswith("default"):
                expected = expected[:3] + b"rounds=5000$" + expected[3:]
            if value != expected:
                fail(f"edge supported SHA differs from pinned musl at {name}")
        elif observed != "2a":
            fail(f"edge excluded format was accepted at {name}")
    for left, right in (("sha256-min-clamp", "sha256-min"),
                        ("sha256-min", "sha256-leading-zero"),
                        ("sha512-min-clamp", "sha512-min")):
        if product[left]["crypt"] != product[right]["crypt"]:
            fail(f"edge rounds normalization differs for {left} and {right}")
    return {"oracle": reference, "candidate": product}


def edge_run_command(work: Path, label: str, command: list[str], environment: dict[str, str]) -> None:
    prefix = work / label
    if any(Path(str(prefix) + suffix).exists() for suffix in (".stdout", ".stderr", ".status", ".command.json")):
        fail(f"edge command evidence already exists: {label}")
    with Path(str(prefix) + ".stdout").open("xb") as output, Path(str(prefix) + ".stderr").open("xb") as error:
        status = subprocess.run(command, cwd=HERE.parents[1], env=environment, stdin=subprocess.DEVNULL,
                                stdout=output, stderr=error, check=False).returncode
    write_new_json(Path(str(prefix) + ".command.json"),
                   {"command": command, "environment": environment, "cwd": str(HERE.parents[1]), "status": status})
    Path(str(prefix) + ".status").write_text(f"{status}\n", encoding="ascii")
    if status != 0:
        fail(f"edge {label} exited with {status}")


def edge_expected_commands(edge: Path, product: Path) -> dict[str, list[str]]:
    import owned_crypt_profile as profile

    source = EDGE_SOURCE
    commands = {
        "oracle-compile": [profile.ORACLE_CC, "-static", "-fno-pie", "-no-pie", *EDGE_FLAGS,
                           str(source), "-o", str(edge / "oracle")],
        "candidate-compile": [str(product / "bin/crabc-cc-dynamic"), "--dynamic-pie", *EDGE_FLAGS,
                              "-DCRABC_X86_CRYPT_CANDIDATE", "-c", str(source),
                              "-o", str(edge / "workload.o")],
        "oracle": profile.runtime_command(edge, "oracle"),
    }
    for mode in ("pie", "non-pie"):
        commands[f"link-{mode}"] = [str(product / "bin/crabc-cc-dynamic"), f"--dynamic-{mode}",
                                    str(edge / "workload.o"), "-o", str(edge / f"dynamic-{mode}-consumer")]
        for entry in ("kernel", "direct"):
            label = f"dynamic-{mode}-{entry}"
            commands[label] = profile.runtime_command(edge, label)
    return commands


def edge_run(work: Path, product: Path) -> Path:
    """Translate one physical source through pinned musl and the installed driver."""

    import owned_crypt_profile as profile
    from owned_posix_product_evidence import validate_link

    work = directory(work, "edge parent")
    product, _, _, _ = dynamic_product(product)
    edge = work / "edge"
    edge.mkdir()
    source = regular(EDGE_SOURCE, "edge source")
    oracle_cc = regular(Path(profile.ORACLE_CC), "pinned musl compiler")
    environment = profile.ENVIRONMENT
    commands = edge_expected_commands(edge, product)
    for label in ("oracle-compile", "candidate-compile", "oracle"):
        edge_run_command(edge, label, commands[label], environment)
    for mode in ("pie", "non-pie"):
        binary = edge / f"dynamic-{mode}-consumer"
        edge_run_command(edge, f"link-{mode}", commands[f"link-{mode}"], environment)
        validate_link(product, edge / "workload.o", binary, Path(str(binary) + ".crabc-link.json"), mode)
        execution = edge / f"dynamic-{mode}-root"
        subprocess.run(["cp", "-a", str(product), str(execution)], check=True)
        subprocess.run(["cp", str(binary), str(execution / "consumer")], check=True)
        payload = edge / f"dynamic-{mode}-execution-payload.json"
        record_execution_payload(product, execution, binary, execution / "consumer", payload)
        audit_execution_payload(product, execution, binary, execution / "consumer", payload)
        for entry in ("kernel", "direct"):
            label = f"dynamic-{mode}-{entry}"
            edge_run_command(edge, label, commands[label], profile.ENVIRONMENT)
            edge_semantics((edge / "oracle.stdout").read_bytes(), (edge / f"{label}.stdout").read_bytes())
            audit_execution_payload(product, execution, binary, execution / "consumer", payload)
    outputs = {label: file_record(edge / f"{label}.stdout", f"edge {label} stdout")
               for label in ("oracle", "dynamic-pie-kernel", "dynamic-pie-direct",
                             "dynamic-non-pie-kernel", "dynamic-non-pie-direct")}
    receipt = {"schema": EDGE_SCHEMA, "source": file_record(source, "edge source"),
               "oracle_compiler": file_record(oracle_cc, "pinned musl compiler"),
               "installed_driver": file_record(product / "bin/crabc-cc-dynamic", "installed driver"),
               "installed_manifest": file_record(product / "share/crabc/manifest.json", "installed manifest"),
               "oracle": file_record(edge / "oracle", "edge oracle"),
               "workload": file_record(edge / "workload.o", "edge workload"),
               "consumers": {mode: file_record(edge / f"dynamic-{mode}-consumer", "edge consumer")
                             for mode in ("pie", "non-pie")}, "outputs": outputs,
               "links": {mode: file_record(edge / f"dynamic-{mode}-consumer.crabc-link.json", "edge link receipt")
                         for mode in ("pie", "non-pie")},
               "commands": {label: {suffix: file_record(edge / f"{label}.{suffix}", f"edge {label} {suffix}")
                                    for suffix in ("command.json", "stdout", "stderr", "status")}
                            for label in EDGE_COMMANDS},
               "observations": edge_semantics((edge / "oracle.stdout").read_bytes(),
                                               (edge / "dynamic-pie-kernel.stdout").read_bytes())}
    receipt_path = edge / "receipt.json"
    write_new_json(receipt_path, receipt)
    edge_audit(receipt_path, product)
    return receipt_path


def edge_audit(receipt_path: Path, product: Path) -> dict[str, Any]:
    receipt_path = regular(receipt_path, "edge receipt")
    edge = directory(receipt_path.parent, "edge evidence")
    product, _, _, _ = dynamic_product(product)
    record = json_object(receipt_path, "edge receipt")
    exact_record(record, {"schema", "source", "oracle_compiler", "installed_driver", "installed_manifest",
                          "oracle", "workload", "consumers", "outputs", "links", "commands", "observations"}, "edge receipt")
    if record["schema"] != EDGE_SCHEMA:
        fail("edge receipt schema drifted")
    import owned_crypt_profile as profile
    for key, path in (("source", EDGE_SOURCE), ("oracle_compiler", Path(profile.ORACLE_CC)),
                      ("installed_driver", product / "bin/crabc-cc-dynamic"),
                      ("installed_manifest", product / "share/crabc/manifest.json"),
                      ("oracle", edge / "oracle"), ("workload", edge / "workload.o")):
        assert_file_record(record[key], path, f"edge {key}")
    for mode in ("pie", "non-pie"):
        assert_file_record(record["consumers"][mode], edge / f"dynamic-{mode}-consumer", f"edge {mode} consumer")
        link_path = edge / f"dynamic-{mode}-consumer.crabc-link.json"
        assert_file_record(record["links"][mode], link_path, f"edge {mode} link receipt")
        from owned_posix_product_evidence import validate_link
        validate_link(product, edge / "workload.o", edge / f"dynamic-{mode}-consumer", link_path, mode)
        audit_execution_payload(product, edge / f"dynamic-{mode}-root", edge / f"dynamic-{mode}-consumer",
                                edge / f"dynamic-{mode}-root/consumer", edge / f"dynamic-{mode}-execution-payload.json")
    if set(record["links"]) != {"pie", "non-pie"} or set(record["consumers"]) != {"pie", "non-pie"}:
        fail("edge installed linkage roster drifted")
    if set(record["commands"]) != set(EDGE_COMMANDS):
        fail("edge command roster drifted")
    expected_commands = edge_expected_commands(edge, product)
    for label in EDGE_COMMANDS:
        item = exact_record(record["commands"][label], {"command.json", "stdout", "stderr", "status"},
                            f"edge {label} command artifacts")
        for suffix in item:
            assert_file_record(item[suffix], edge / f"{label}.{suffix}", f"edge {label} {suffix}")
        expected_command = {"command": expected_commands[label], "environment": profile.ENVIRONMENT,
                            "cwd": str(HERE.parents[1]), "status": 0}
        if json_object(edge / f"{label}.command.json", f"edge {label} command") != expected_command:
            fail(f"edge {label} invocation drifted")
        if (edge / f"{label}.status").read_bytes() != b"0\n" or (edge / f"{label}.stderr").read_bytes() != b"":
            fail(f"edge {label} status or stderr drifted")
        if label not in ("oracle", "dynamic-pie-kernel", "dynamic-pie-direct",
                         "dynamic-non-pie-kernel", "dynamic-non-pie-direct") and (edge / f"{label}.stdout").read_bytes() != b"":
            fail(f"edge {label} unexpected build output")
    oracle = (edge / "oracle.stdout").read_bytes()
    for label, value in record["outputs"].items():
        if label not in ("oracle", "dynamic-pie-kernel", "dynamic-pie-direct",
                         "dynamic-non-pie-kernel", "dynamic-non-pie-direct"):
            fail("edge output roster drifted")
        assert_file_record(value, edge / f"{label}.stdout", f"edge {label} stdout")
        if label != "oracle" and edge_semantics(oracle, (edge / f"{label}.stdout").read_bytes()) != record["observations"]:
            fail("edge candidate observations differ across installed entry forms")
    if len(record["outputs"]) != 5:
        fail("edge output roster is incomplete")
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
    edge_command = commands.add_parser("edge-run")
    edge_command.add_argument("--work", type=Path, required=True)
    edge_command.add_argument("--product", type=Path, required=True)
    edge_command = commands.add_parser("edge-audit")
    edge_command.add_argument("--record", type=Path, required=True)
    edge_command.add_argument("--product", type=Path, required=True)
    parsed = parser.parse_args()
    try:
        if parsed.action == "record":
            record_execution_payload(
                parsed.product, parsed.execution_root, parsed.source_consumer, parsed.execution_consumer, parsed.record,
            )
        elif parsed.action == "audit":
            json.dump(
                audit_execution_payload(
                    parsed.product, parsed.execution_root, parsed.source_consumer, parsed.execution_consumer, parsed.record,
                ), sys.stdout, sort_keys=True, separators=(",", ":"),
            )
            sys.stdout.write("\n")
        elif parsed.action == "edge-run":
            print(edge_run(parsed.work, parsed.product))
        else:
            edge_audit(parsed.record, parsed.product)
            print("owned crypt runtime edge: PASS")
    except CryptRuntimeEvidenceError as error:
        print(f"owned crypt runtime execution evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
