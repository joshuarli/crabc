#!/usr/bin/env python3
"""Read the installed worker-transfer C/selected-C/native-shadow receipt."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt
import owned_dynamic_qualification as qualification

RUNNER = "owned-native-allocator-worker-transfer"
FIXTURE = ROOT / "compat/allocator/x86_64_m8_worker_transfer.c"
EXPECTED = ("worker exit cleanup and TSD: 1 1\n"
            "joined reallocarray growth and overflow preservation: ok\n")
MODES = ("musl", "accepted-c", "native-shadow")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_receipt(output: str) -> dict[str, Any]:
    marker = "native-allocator-worker-transfer evidence: "
    directories = [line.removeprefix(marker) for line in output.splitlines() if line.startswith(marker)]
    if len(directories) != 1:
        raise ValueError("worker transfer emitted no unique evidence directory")
    receipt = native_shadow_receipt.read_receipt(ROOT, RUNNER)
    raw = json.loads(receipt.path.read_text(encoding="utf-8"))
    work = ROOT / Path(directories[0]).relative_to("/workspace")
    if (work != ROOT / raw["work"] or not work.is_dir() or work.is_symlink()
            or work.parent != ROOT / ".work/x86_64/tmp"):
        raise ValueError("worker transfer receipt names another build root")
    if receipt.parameters != {"MODES": "musl,accepted-c,native-shadow", "ENTRY": "static-pie", "TIMEOUT": "60"}:
        raise ValueError("worker transfer parameters changed")
    if receipt.case_ids() != [*MODES, "runner"]:
        raise ValueError("worker transfer omitted an executable or completion case")
    product_root = receipt.path.parent / "products"
    required = {"fixture", *(f"binary-{mode}" for mode in MODES)}
    for mode in MODES[1:]:
        required.update((f"{mode}-manifest", f"{mode}-provenance", f"{mode}-build"))
    if set(receipt.products) != required:
        raise ValueError("worker transfer product set changed")
    if digest(product_root / "fixture") != digest(FIXTURE):
        raise ValueError("worker transfer fixture differs from source")
    for mode in MODES:
        binary = work / mode
        if digest(binary) != digest(product_root / f"binary-{mode}"):
            raise ValueError(f"worker transfer executed another {mode} binary")
    source = qualification.source_digest()
    for mode in MODES[1:]:
        root = work / f"{mode}-sysroot/share/crabc"
        for name, original in (("manifest", root / "manifest.json"),
                               ("provenance", root / "libc-static.provenance.json"),
                               ("build", work / f"{mode}-build.json")):
            if digest(original) != digest(product_root / f"{mode}-{name}"):
                raise ValueError(f"worker transfer {mode} {name} changed")
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("allocator_backend") != mode or manifest.get("source_sha256") != source:
            raise ValueError(f"worker transfer {mode} is not current source-built product")
        if json.loads((work / f"{mode}-build.json").read_text(encoding="utf-8")) != manifest:
            raise ValueError(f"worker transfer {mode} build record disagrees with installed product")
    logs = receipt.path.parent / "logs"
    for case in receipt.cases:
        if case["id"] == "runner":
            if (logs / "runner.status").read_text(encoding="utf-8") != "0\n":
                raise ValueError("worker transfer completion failed")
            continue
        mode = case["id"]
        if set(case["logs"]) != {f"{mode}.stdout", f"{mode}.stderr"}:
            raise ValueError(f"worker transfer {mode} lacks raw output")
        if (logs / f"{mode}.stdout").read_text(encoding="utf-8") != EXPECTED:
            raise ValueError(f"worker transfer {mode} differs from musl transcript")
        if (logs / f"{mode}.stderr").read_bytes():
            raise ValueError(f"worker transfer {mode} wrote stderr")
    return {"path": str(receipt.path), "sha256": digest(receipt.path),
            "source": dict(receipt.source), "source_sha256": source,
            "case_count": len(receipt.cases),
            "fixture_sha256": digest(FIXTURE)}
