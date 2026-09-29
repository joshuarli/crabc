#!/usr/bin/env python3
"""Validate physical loader iteration/close race products and raw outcomes."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_dynamic_qualification as qualification

EXPECTED = (
    "oracle-static", "oracle-dynamic-kernel", "oracle-dynamic-direct",
    "accepted-static", "accepted-static-pie", "accepted-pie-kernel",
    "accepted-pie-direct", "accepted-non-pie-kernel", "accepted-non-pie-direct",
    "native-static", "native-static-pie", "native-pie-kernel",
    "native-pie-direct", "native-non-pie-kernel", "native-non-pie-direct",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def physical(path: Path) -> Path:
    require(path.is_absolute() and path.is_dir() and not path.is_symlink()
            and path.resolve(strict=True) == path and path.is_relative_to(ROOT / ".work"),
            f"unsafe evidence path: {path}")
    return path


def products(paths: list[Path], source: str) -> dict[str, dict[str, str]]:
    result = {}
    for label, path in zip(("accepted-static", "accepted-dynamic", "native-static", "native-dynamic"), paths, strict=True):
        path = physical(path)
        manifest = path / "share/crabc/manifest.json"
        value = json.loads(manifest.read_text())
        if "static" in label:
            require(value.get("source_sha256") == source, f"{label} source seal differs")
            for name, expected in value["installed"]["files"].items():
                require(sha(path / name) == expected, f"{label} payload differs: {name}")
            allocator = value.get("allocator_backend")
        else:
            state = json.loads((path / "share/crabc/dynamic-product-state.json").read_text())
            require(state.get("source_sha256") == source, f"{label} source seal differs")
            qualification.product_identity(path)
            allocator = state.get("allocator_backend")
        require(allocator == ("accepted-c" if label.startswith("accepted") else "native-shadow"),
                f"{label} allocator differs")
        result[label] = {"path": str(path), "manifest_sha256": sha(manifest)}
    return result


def cases(work: Path) -> list[dict[str, str]]:
    with (work / "results.tsv").open(newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    require(tuple(row["case"] for row in rows) == EXPECTED, "case roster differs")
    for row in rows:
        label = row["case"]
        mode = "static" if "static" in label else "dynamic"
        require(row["mode"] == mode and row["status"] == "0", f"{label} failed")
        require((work / f"{label}.status").read_bytes() == b"0\n", f"{label} status differs")
        stdout = work / f"{label}.stdout"
        stderr = work / f"{label}.stderr"
        require(sha(stdout) == row["stdout_sha256"] and sha(stderr) == row["stderr_sha256"]
                and stderr.read_bytes() == b"", f"{label} raw output differs")
        output = stdout.read_text()
        if mode == "static":
            require(re.fullmatch(r"static images=[1-9][0-9]*\n", output) is not None,
                    f"{label} static snapshot differs")
        else:
            require(re.fullmatch(r"dynamic callbacks=1 reopen=same constructors=1 destructors=0 "
                                 r"main_tls=23,29 worker_tls=41,43 module=[1-9][0-9]*\n", output) is not None,
                    f"{label} lifecycle differs")
    return rows


def validate(work: Path, paths: list[Path], receipt: Path) -> None:
    work = physical(work)
    source = qualification.source_digest()
    report = json.loads(receipt.read_text())
    require(report.get("schema") == "crabc.x86_64-loader-iterate-close-race/v1"
            and report.get("source_sha256") == source, "receipt source differs")
    require(report.get("products") == products(paths, source), "product receipt differs")
    require(report.get("objects") == {name: sha(work / name) for name in ("probe.o", "plugin.o")},
            "same-object receipt differs")
    require(report.get("cases") == cases(work), "case receipt differs")


def main() -> int:
    if len(sys.argv) != 7 or sys.argv[1] not in ("collect", "validate"):
        raise SystemExit("usage: reader {collect|validate} WORK ACCEPTED_STATIC ACCEPTED_DYNAMIC NATIVE_STATIC NATIVE_DYNAMIC")
    action, work = sys.argv[1], physical(Path(sys.argv[2]))
    paths = [Path(value) for value in sys.argv[3:]]
    source = qualification.source_digest()
    receipt = work / "receipt.json"
    if action == "collect":
        report = {"schema": "crabc.x86_64-loader-iterate-close-race/v1",
                  "source_sha256": source, "products": products(paths, source),
                  "objects": {name: sha(work / name) for name in ("probe.o", "plugin.o")},
                  "cases": cases(work)}
        receipt.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    validate(work, paths, receipt)
    print(f"loader iterate/close race: {len(EXPECTED)}/{len(EXPECTED)} pass; receipt: {receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
