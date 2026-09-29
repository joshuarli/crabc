#!/usr/bin/env python3
"""Reread the executed startup and successful-call errno matrix.

The shared native-shadow receipt validates the current source seal and every
retained byte. This reader also requires the complete static/dynamic execution
matrix and compares each retained successful-call transcript with the pinned
musl program run in the same link kind.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import native_shadow_receipt


RUNNER = "owned-mimalloc-startup-errno"
ROOT = Path(__file__).resolve().parents[2]
MODES = (
    "oracle-static", "oracle-dynamic", "static-static", "static-static-pie",
    "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
INPUT_PRODUCTS = {
    "input-startup-source", "input-success-source", "input-startup-object",
    "input-startup-dynamic-object",
    "input-success-object", "input-success-cases", "input-passwd", "input-group",
    "input-hosts", "input-data", "input-static-manifest",
    "input-dynamic-manifest", "input-static-libc-provenance",
    "input-dynamic-libc-provenance", "input-dynamic-loader-provenance",
    "input-static-libc", "input-dynamic-libc", "input-dynamic-loader",
    "link-static-static", "link-static-static-pie",
    "link-success-static-static", "link-success-static-static-pie",
}
PRODUCTS = INPUT_PRODUCTS | {
    *(f"program-startup-{mode}" for mode in MODES),
    *(f"program-success-{mode}" for mode in MODES),
}
CASES = {*(f"startup-{mode}" for mode in MODES), *(f"success-{mode}" for mode in MODES)}
PARAMETERS = {
    "STATIC_BACKEND": "native-shadow", "DYNAMIC_BACKEND": "native-shadow",
    "STATIC_SUPPLIED": "yes", "DYNAMIC_SUPPLIED": "yes",
}
HEADER = re.compile(r"([^\s]+) (first|later) status=([0-9]+)\Z")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise native_shadow_receipt.ReceiptError(f"{RUNNER}: {message}")


def _transcript(path: Path, roster: list[str], mode: str) -> bytes:
    data = path.read_bytes()
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise native_shadow_receipt.ReceiptError(f"{RUNNER}: invalid transcript {path.name}") from error
    static = mode == "oracle-static" or mode.startswith("static-")
    expected = [
        (name, position, "100" if static and name == "dlopen-libc" else "0")
        for name in roster for position in ("first", "later")
    ]
    observed = []
    body_lines = 0
    for line in lines:
        match = HEADER.fullmatch(line)
        if match:
            if observed and observed[-1][2] == "0":
                _require(body_lines > 0, f"transcript {path.name} has no output for {observed[-1]}")
            observed.append((match.group(1), match.group(2), match.group(3)))
            body_lines = 0
        else:
            _require(bool(observed), f"transcript {path.name} starts without a case header")
            body_lines += 1
    _require(bool(observed), f"transcript {path.name} has no cases")
    if observed[-1][2] == "0":
        _require(body_lines > 0, f"transcript {path.name} lacks measured output")
    _require(observed == expected, f"transcript {path.name} lacks the exact case roster")
    return data


def read_startup_errno_receipt(root: Path) -> native_shadow_receipt.Receipt:
    read = native_shadow_receipt.read_receipt(root, RUNNER)
    _require(dict(read.parameters) == PARAMETERS, "receipt has non-canonical product parameters")
    _require(set(read.products) == PRODUCTS, "receipt is missing executed products or input identities")
    _require(read.products["input-startup-object"]["sha256"]
             != read.products["input-startup-dynamic-object"]["sha256"],
             "static and dynamic startup modes share one application object")
    by_id = {case["id"]: case for case in read.cases}
    _require(set(by_id) == CASES, "receipt is missing startup or successful-call cases")
    retained = read.path.parent
    metadata = {}
    for product in ("input-static-manifest", "input-dynamic-manifest", "input-dynamic-libc-provenance"):
        try:
            metadata[product] = json.loads((retained / "products" / product).read_text())
        except (OSError, ValueError) as error:
            raise native_shadow_receipt.ReceiptError(f"{RUNNER}: unreadable {product}: {error}") from error
    static_manifest = metadata["input-static-manifest"]
    dynamic_manifest = metadata["input-dynamic-manifest"]
    _require(isinstance(static_manifest, dict) and static_manifest.get("allocator_backend") == "native-shadow",
             "input-static-manifest does not identify a native-shadow product")
    _require(isinstance(metadata["input-dynamic-libc-provenance"], dict)
             and metadata["input-dynamic-libc-provenance"].get("allocator_backend") == "native-shadow",
             "input-dynamic-libc-provenance does not identify a native-shadow product")
    installed = static_manifest.get("installed", {})
    static_files = installed.get("files", {}) if isinstance(installed, dict) else {}
    dynamic_files = dynamic_manifest.get("files", {}) if isinstance(dynamic_manifest, dict) else {}
    _require(isinstance(static_files, dict) and isinstance(dynamic_files, dict),
             "product manifests have malformed file inventories")
    for source, installed in (
        ("input-static-libc", "usr/lib/libc.a"),
        ("input-static-libc-provenance", "share/crabc/libc-static.provenance.json"),
    ):
        _require(static_files.get(installed) == read.products[source]["sha256"],
                 f"static manifest does not identify {source}")
    for source, installed in (
        ("input-dynamic-libc", "usr/lib/libc.so"),
        ("input-dynamic-loader", "lib/ld-crabc-x86_64.so.1"),
        ("input-dynamic-libc-provenance", "share/crabc/libc-shared.provenance.json"),
        ("input-dynamic-loader-provenance", "share/crabc/loader.provenance.json"),
    ):
        _require(dynamic_files.get(installed) == read.products[source]["sha256"],
                 f"dynamic manifest does not identify {source}")
    for mode in ("static", "static-pie"):
        for kind in ("startup", "success"):
            name = f"link-{kind}-static-{mode}" if kind == "success" else f"link-static-{mode}"
            program = f"program-{kind}-static-{mode}"
            source = f"input-{kind}-object"
            try:
                link = json.loads((retained / "products" / name).read_text())
            except (OSError, ValueError) as error:
                raise native_shadow_receipt.ReceiptError(f"{RUNNER}: unreadable {name}: {error}") from error
            _require(isinstance(link, dict), f"{name} is not a link receipt")
            inputs = link.get("input_receipts", [])
            _require(isinstance(inputs, list), f"{name} has malformed input receipts")
            by_role = {item.get("role"): item.get("sha256") for item in inputs if isinstance(item, dict)}
            output = link.get("output", {})
            _require(isinstance(output, dict) and output.get("sha256") == read.products[program]["sha256"]
                     and by_role.get("application") == read.products[source]["sha256"]
                     and by_role.get("libc") == read.products["input-static-libc"]["sha256"],
                     f"{name} does not identify the executed program and its inputs")
    for mode in ("pie", "non-pie"):
        for kind in ("startup", "success"):
            kernel = read.products[f"program-{kind}-dynamic-{mode}-kernel"]["sha256"]
            direct = read.products[f"program-{kind}-dynamic-{mode}-direct"]["sha256"]
            _require(kernel == direct, f"dynamic-{mode} {kind} entries used different programs")
    for mode in MODES:
        startup = by_id[f"startup-{mode}"]
        logs = {f"{mode}.stdout", f"{mode}.stderr", f"{mode}.status"}
        _require(set(startup["logs"]) == logs, f"startup-{mode} lacks exact status/stdout/stderr")
        _require((retained / "logs" / f"{mode}.status").read_bytes() == b"0\n",
                 f"startup-{mode} did not exit successfully")
        for stream in ("stdout", "stderr"):
            _require((retained / "logs" / f"{mode}.{stream}").read_bytes() == b"",
                     f"startup-{mode} wrote {stream}")
        _require(set(by_id[f"success-{mode}"]["logs"]) == {f"success-{mode}.transcript"},
                 f"success-{mode} lacks its complete transcript")
    roster_bytes = (retained / "products/input-success-cases").read_bytes()
    try:
        roster = roster_bytes.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise native_shadow_receipt.ReceiptError(f"{RUNNER}: invalid successful-call roster") from error
    _require(bool(roster) and all(roster) and len(set(roster)) == len(roster),
             "successful-call roster is empty or repeated")
    transcripts = {
        mode: _transcript(retained / "logs" / f"success-{mode}.transcript", roster, mode)
        for mode in MODES
    }
    for mode in MODES[2:]:
        oracle = "oracle-static" if mode.startswith("static-") else "oracle-dynamic"
        _require(transcripts[mode] == transcripts[oracle],
                 f"success-{mode} transcript differs from pinned musl {oracle}")
    return read


def main() -> int:
    parser = argparse.ArgumentParser(description="reread the native-shadow startup errno receipt")
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    try:
        read = read_startup_errno_receipt(arguments.root)
    except (native_shadow_receipt.ReceiptError, OSError, UnicodeError) as error:
        print(f"startup errno receipt: {error}", file=sys.stderr)
        return 1
    print(f"startup errno receipt: PASS ({len(read.cases)} retained cases; {read.path})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
