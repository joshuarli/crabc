#!/usr/bin/env python3
"""Reread the executed copied-loader libc identity layouts and their bytes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct
import sys
from typing import Mapping

from native_shadow_receipt import Receipt, ReceiptError, read_receipt


RUNNER = "owned-loader-libc-identity"
ROOT = Path(__file__).resolve().parents[2]
MODES = ("pie", "non-pie")
LAYOUTS = (
    "copied-prefix-root-libc",
    "prefix-only-libc",
    "hardlink-one-identity",
    "two-distinct-libc-identities",
    "override-without-canonical-identity",
)
PARAMETERS = {
    "ALLOCATOR_BACKEND": "native-shadow",
    "ENTRY": "direct-copied-interpreter",
    "IDENTITY_FAILURE_STATUS": "127",
    "MODES": "pie,non-pie",
}
ROOT_LIBC = "usr/lib/libc.so"
ROOT_ALIAS = "lib/libc.musl-x86_64.so.1"
PREFIX_LIBC = "prefix/usr/lib/libc.so"
PREFIX_ALIAS = "prefix/lib/libc.musl-x86_64.so.1"
BASE_FILES = {"prefix/lib/loader", ROOT_LIBC, ROOT_ALIAS, "consumer", "plugins/libcli.so"}
IDENTITY_LINE = re.compile(r"(?P<path>\S+) dev=(?P<dev>[0-9]+) inode=(?P<inode>[0-9]+) size=(?P<size>[0-9]+)\Z")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ReceiptError(f"{RUNNER}: {reason}")


def _json_product(directory: Path, name: str) -> dict:
    try:
        value = json.loads((directory / "products" / name).read_text())
    except (OSError, ValueError) as error:
        raise ReceiptError(f"{RUNNER}: product {name} is not readable JSON: {error}") from error
    _require(isinstance(value, dict), f"product {name} is not a JSON object")
    return value


def _required_files(layout: str) -> set[str]:
    files = set(BASE_FILES)
    if layout in {"prefix-only-libc", "hardlink-one-identity", "two-distinct-libc-identities"}:
        files.update((PREFIX_LIBC, PREFIX_ALIAS))
    if layout == "two-distinct-libc-identities":
        files.update(("p/libc.so", "consumer-mutated"))
    if layout == "override-without-canonical-identity":
        files.add("override/libc.so")
    return files


def _identity_facts(directory: Path, work: str, case_id: str, files: set[str]) -> dict[str, tuple[int, int]]:
    log = directory / "logs" / f"{case_id}.identity"
    prefix = f"/workspace/{work}/{case_id}/"
    facts: dict[str, tuple[int, int]] = {}
    for line in log.read_text().splitlines():
        match = IDENTITY_LINE.fullmatch(line)
        _require(match is not None and match["path"].startswith(prefix), f"invalid alias identity fact in {case_id}")
        relative = match["path"][len(prefix):]
        _require(relative in files and relative not in facts, f"unexpected alias identity fact in {case_id}")
        name = f"{case_id}-{relative.replace('/', '-')}"
        size = int(match["size"])
        _require(size == (directory / "products" / name).stat().st_size,
                 f"alias identity size differs from retained {name}")
        facts[relative] = (int(match["dev"]), int(match["inode"]))
        _require(facts[relative][1] != 0, f"zero alias identity in {case_id}")
    _require(set(facts) == files, f"missing alias identity facts in {case_id}")
    return facts


def _check_aliases(case_id: str, layout: str, facts: Mapping[str, tuple[int, int]]) -> None:
    root = facts[ROOT_LIBC]
    _require(facts[ROOT_ALIAS] == root, f"alias identity mismatch in {case_id}")
    if layout == "hardlink-one-identity":
        _require(facts[PREFIX_LIBC] == root and facts[PREFIX_ALIAS] == root,
                 f"alias identity mismatch in {case_id}")
    elif layout in {"prefix-only-libc", "two-distinct-libc-identities"}:
        prefix = facts[PREFIX_LIBC]
        _require(prefix == facts[PREFIX_ALIAS] and prefix != root,
                 f"alias identity mismatch in {case_id}")
        if layout == "two-distinct-libc-identities":
            _require(facts["p/libc.so"] == prefix, f"alias identity mismatch in {case_id}")
    elif layout == "override-without-canonical-identity":
        _require(facts["override/libc.so"] != root, f"alias identity mismatch in {case_id}")


def _check_product_identity(retained: Receipt, directory: Path) -> None:
    required = {
        "dynamic-loader": "lib/ld-crabc-x86_64.so.1",
        "dynamic-libc": "usr/lib/libc.so",
        "dynamic-driver": "bin/crabc-cc-dynamic",
        "dynamic-loader-provenance": "share/crabc/loader.provenance.json",
        "dynamic-libc-provenance": "share/crabc/libc-shared.provenance.json",
    }
    _require(set(required) | {"dynamic-manifest", "dynamic-product-state", "identity-source"}
             <= set(retained.products), "missing executed product or provenance")
    manifest = _json_product(directory, "dynamic-manifest")
    state = _json_product(directory, "dynamic-product-state")
    provenance = _json_product(directory, "dynamic-libc-provenance")
    _require(state.get("allocator_backend") == provenance.get("allocator_backend") == "native-shadow",
             "product provenance does not select native-shadow")
    manifest_files = manifest.get("files")
    payload_files = state.get("payload_files")
    _require(isinstance(manifest_files, dict) and isinstance(payload_files, dict),
             "product identity maps are missing")
    for name, path in required.items():
        digest = retained.products[name]["sha256"]
        _require(manifest_files.get(path) == digest and payload_files.get(path) == digest,
                 f"product provenance does not identify {name}")

    producer = (ROOT / "compat/x86_64/run_owned_loader_libc_identity.sh").read_bytes()
    start_marker = b'cat >"$source" <<\'C\'\n'
    end_marker = b"\nC\n"
    _require(producer.count(start_marker) == 1, "identity fixture source has no unique producer")
    start = producer.index(start_marker) + len(start_marker)
    _require(end_marker in producer[start:], "identity fixture source has no terminator")
    end = producer.index(end_marker, start)
    expected_source = producer[start:end + 1]
    _require((directory / "products/identity-source").read_bytes() == expected_source,
             "fixture source differs from current producer")


def _check_consumer_entry(directory: Path, case_id: str, mode: str, program: str) -> None:
    image = (directory / "products" / f"{case_id}-{program}").read_bytes()
    _require(len(image) >= 64 and image[:6] == b"\x7fELF\x02\x01",
             f"consumer ELF entry mode is invalid in {case_id}")
    kind, machine = struct.unpack_from("<HH", image, 16)
    expected_kind = 3 if mode == "pie" else 2
    _require(kind == expected_kind and machine == 62,
             f"consumer ELF entry mode differs in {case_id}")
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    _require(phentsize == 56 and phnum > 0 and phoff + phentsize * phnum <= len(image),
             f"consumer ELF program headers are invalid in {case_id}")
    interpreters = []
    for index in range(phnum):
        kind, _, offset, _, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", image, phoff + index * phentsize)
        if kind == 3:
            _require(offset + size <= len(image), f"consumer ELF interpreter is invalid in {case_id}")
            interpreters.append(image[offset:offset + size])
    _require(interpreters == [b"/lib/ld-crabc-x86_64.so.1\0"],
             f"consumer ELF interpreter differs in {case_id}")


def _check_link_facts(directory: Path, logs: Mapping[str, object], case_id: str, layout: str) -> None:
    library_path = {
        "prefix-only-libc": "/prefix/usr/lib:/usr/lib",
        "override-without-canonical-identity": "/override",
    }.get(layout, "/usr/lib")
    consumer_path = {
        "prefix-only-libc": "$ORIGIN/plugins:/prefix/usr/lib:/usr/lib",
        "override-without-canonical-identity": "$ORIGIN/plugins:/override:/usr/lib",
    }.get(layout, "$ORIGIN/plugins:/usr/lib")
    required = {
        f"{case_id}-library.dynamic": "Shared library: [libc.so]",
        f"{case_id}-consumer.dynamic": "Shared library: [libcli.so]",
        f"{case_id}-library.runpath.dynamic": f"Library runpath: [{library_path}]",
        f"{case_id}-consumer.runpath.dynamic": f"Library runpath: [{consumer_path}]",
    }
    if layout == "two-distinct-libc-identities":
        required[f"{case_id}-mutated.dynamic"] = "Shared library: [p/libc.so]"
    _require(set(required) <= set(logs), f"missing fixture link facts in {case_id}")
    for name, text in required.items():
        contents = (directory / "logs" / name).read_text()
        _require(contents.count(text) == 1, f"wrong fixture link facts in {case_id}")
    consumer = (directory / "logs" / f"{case_id}-consumer.dynamic").read_text()
    _require(consumer.count("Shared library: [libc.so]") == 1,
             f"consumer lost its libc dependency in {case_id}")


def read_identity_receipt(root: Path, *, seal: Mapping[str, str] | None = None) -> Receipt:
    """Validate every retained layout after the runner's temporary tree is gone."""
    retained = read_receipt(root, RUNNER, seal=seal)
    directory = retained.path.parent
    _require(dict(retained.parameters) == PARAMETERS, "unexpected identity-run parameters")
    expected = [f"{mode}-{layout}" for mode in MODES for layout in LAYOUTS]
    cases = {case["id"]: case for case in retained.cases}
    _require(set(cases) == set(expected) | {"runner"}, "missing identity cases")
    _require([case["id"] for case in retained.cases] == expected + ["runner"],
             "identity cases are out of execution order")
    _require((directory / "logs/runner.status").read_bytes() == b"0\n", "runner status is not zero")
    document = json.loads(retained.path.read_text())
    work = document.get("work")
    _require(isinstance(work, str) and re.fullmatch(
        r"\.work/x86_64/tmp/owned-loader-libc-identity\.[A-Za-z0-9]+", work) is not None,
        "unexpected identity work directory")
    _check_product_identity(retained, directory)
    for mode in MODES:
        for layout in LAYOUTS:
            case_id = f"{mode}-{layout}"
            files = _required_files(layout)
            names = {f"{case_id}-{relative.replace('/', '-')}" for relative in files}
            _require(names | {f"{case_id}-executed-program"} <= set(retained.products),
                     f"missing executed binaries in {case_id}")
            logs = cases[case_id]["logs"]
            required_logs = {f"{case_id}.{suffix}" for suffix in ("stdout", "stderr", "status", "identity")}
            failure = layout in {"two-distinct-libc-identities", "override-without-canonical-identity"}
            expected_log = "expected-libcidentity.stderr" if failure else f"{case_id}.expected.stdout"
            _require(required_logs | {expected_log} <= set(logs), f"missing transcript in {case_id}")
            _check_link_facts(directory, logs, case_id, layout)
            facts = _identity_facts(directory, work, case_id, files)
            _check_aliases(case_id, layout, facts)
            loader = retained.products["dynamic-loader"]["sha256"]
            libc = retained.products["dynamic-libc"]["sha256"]
            _require(retained.products[f"{case_id}-prefix-lib-loader"]["sha256"] == loader,
                     f"executed loader differs from product in {case_id}")
            for relative in files:
                if relative.endswith("libc.so") or relative.endswith("libc.musl-x86_64.so.1"):
                    name = f"{case_id}-{relative.replace('/', '-')}"
                    _require(retained.products[name]["sha256"] == libc,
                             f"executed libc differs from product in {case_id}")
            program = "consumer-mutated" if layout == "two-distinct-libc-identities" else "consumer"
            _check_consumer_entry(directory, case_id, mode, "consumer")
            if program != "consumer":
                _check_consumer_entry(directory, case_id, mode, program)
            _require(retained.products[f"{case_id}-executed-program"] == retained.products[f"{case_id}-{program}"],
                     f"executed fixture differs from retained program in {case_id}")
            if layout == "two-distinct-libc-identities":
                _require(retained.products[f"{case_id}-consumer-mutated"]["sha256"] !=
                         retained.products[f"{case_id}-consumer"]["sha256"],
                         f"second-libc fixture was not mutated in {case_id}")
            stdout = (directory / "logs" / f"{case_id}.stdout").read_bytes()
            stderr = (directory / "logs" / f"{case_id}.stderr").read_bytes()
            status = (directory / "logs" / f"{case_id}.status").read_bytes()
            if failure:
                _require(status == b"127\n" and stdout == b"" and stderr == b"libcidentity\n"
                         and (directory / "logs/expected-libcidentity.stderr").read_bytes() == stderr,
                         f"wrong status-127 transcript in {case_id}")
            else:
                libc_path = "/prefix/usr/lib/libc.so" if layout == "prefix-only-libc" else "/usr/lib/libc.so"
                expected_stdout = ("identity dependency constructor\n"
                                   "identity application constructor\n"
                                   f"identity libc {libc_path}\n"
                                   "identity application main 17\n").encode()
                _require(status == b"0\n" and stderr == b"" and stdout == expected_stdout
                         and (directory / "logs" / expected_log).read_bytes() == expected_stdout,
                         f"wrong successful transcript in {case_id}")
    return retained


def main() -> int:
    parser = argparse.ArgumentParser(description="reread the native-shadow loader libc identity receipt")
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    try:
        retained = read_identity_receipt(arguments.root)
    except (ReceiptError, OSError, ValueError, UnicodeError) as error:
        print(f"loader libc identity receipt: {error}", file=sys.stderr)
        return 1
    print(f"loader libc identity receipt: PASS ({len(retained.cases)} retained cases; {retained.path})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
