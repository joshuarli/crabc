#!/usr/bin/env python3
"""Compile the MQ workload once through its selected installed product."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "compat/x86_64/owned_message_queues_probe.c"
WITNESS_HEADER = ROOT / "compat/x86_64/owned_cancellation_proc_witness.h"


def physical_directory(argument: str, label: str) -> Path:
    path = Path(argument).resolve(strict=True)
    if not path.is_dir() or not path.is_relative_to(ROOT / ".work"):
        raise ValueError(f"message queues {label} must be a physical checkout .work directory")
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_workload(product: Path, work: Path) -> dict[str, object]:
    product = physical_directory(str(product), "product")
    work = physical_directory(str(work), "work")
    if work.is_relative_to(product):
        raise ValueError("message queues compilation must not write into its installed product")
    driver = product / "bin/crabc-cc-dynamic"
    manifest = product / "share/crabc/manifest.json"
    output = work / "probe.o"
    receipt = work / "compile.json"
    inputs = {str(path): digest(path) for path in (driver, manifest, SOURCE, WITNESS_HEADER)}
    if any(path.exists() or path.is_symlink() for path in (output, receipt, work / "compile.stdout", work / "compile.stderr")):
        raise ValueError("message queues compilation outputs already exist")
    command = [str(driver), "--dynamic-pie", "-std=c11", "-fno-builtin", "-c", str(SOURCE), "-o", str(output)]
    with (work / "compile.stdout").open("x") as stdout, (work / "compile.stderr").open("x") as stderr:
        subprocess.run(command, check=True, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
    if any(digest(Path(path)) != before for path, before in inputs.items()):
        raise ValueError("message queues compilation inputs changed during translation")
    header = output.read_bytes()[:20]
    if header[:7] != b"\x7fELF\x02\x01\x01" or int.from_bytes(header[16:18], "little") != 1 or int.from_bytes(header[18:20], "little") != 62:
        raise ValueError("message queues compiler did not produce a native x86-64 relocatable object")
    record = {"schema": "crabc.x86_64-owned-message-queues-compile/v1", "product": str(product),
              "argv": command, "input_sha256": inputs, "output": str(output), "output_sha256": digest(output)}
    with receipt.open("x") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return record


def main() -> int:
    if len(sys.argv) != 3:
        raise ValueError("usage: compile_owned_message_queues.py PRODUCT WORK")
    compile_workload(Path(sys.argv[1]), Path(sys.argv[2]))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"message queues compilation: {error}") from error
