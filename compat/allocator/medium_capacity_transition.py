#!/usr/bin/env python3
"""Locate the first medium-page capacity difference in paired static PIE clients."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix(".c")
BRIDGE = Path(__file__).with_name("pinned_c_page_map_soak_bridge.c")
TRACE = re.compile(
    r"^trace index=(\d+) request=(\d+) usable=(\d+) entries=(\d+)"
    r" medium_used=(\d+) medium_abandoned=(\d+)$"
)
ALIGNMENT = re.compile(
    r"^alignment size=(\d+) aligned16=(\d+) usable_min=(\d+) usable_max=(\d+)$"
)
DONE = "done blocks=10 request=65536"
BLOCKS = 10
REQUEST = 65536
ALIGNMENT_SIZES = (1, 8, 9, 15, 16, 17, 24, 32, 10248, 65536)
ALIGNMENT_SAMPLES = 16
PINNED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"


class DiagnosticError(RuntimeError):
    """A product or trace cannot support the paired observation."""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def static_pie_identity(binary: Path) -> dict[str, str]:
    header = subprocess.check_output(["readelf", "-h", str(binary)], text=True)
    program_headers = subprocess.check_output(["readelf", "-l", str(binary)], text=True)
    if ("DYN (Position-Independent Executable file)" not in header or
        "Advanced Micro Devices X86-64" not in header or
        re.search(r"^\s*INTERP\s", program_headers, re.MULTILINE)):
        raise DiagnosticError(f"product is not x86-64 static PIE: {binary}")
    return {"sha256": digest(binary), "elf_type": "DYN", "link_mode": "static-pie"}


def parse_trace(output: str) -> list[dict[str, int]]:
    lines = output.splitlines()
    if len(lines) != BLOCKS + 1 or lines[-1] != DONE:
        raise DiagnosticError("trace has an incomplete allocation sequence")
    samples = []
    for index, line in enumerate(lines[:-1]):
        match = TRACE.fullmatch(line)
        if match is None:
            raise DiagnosticError(f"malformed trace line {index}")
        values = dict(zip(
            ("index", "request", "usable", "entries", "medium_used", "medium_abandoned"),
            (int(value) for value in match.groups()),
        ))
        if (values["index"] != index or values["request"] != REQUEST or
            values["usable"] < REQUEST or values["entries"] < values["medium_used"] or
            values["medium_used"] < 8 or values["medium_used"] % 8 != 0 or
            values["medium_abandoned"] > values["medium_used"]):
            raise DiagnosticError(f"invalid medium trace state at allocation {index}")
        samples.append(values)
    return samples


def parse_alignment(output: str) -> list[dict[str, int]]:
    lines = output.splitlines()
    if (len(lines) != len(ALIGNMENT_SIZES) + 1 or
        lines[-1] != "done sizes=10 samples_per_size=16"):
        raise DiagnosticError("alignment trace has an incomplete size sequence")
    samples = []
    for index, line in enumerate(lines[:-1]):
        match = ALIGNMENT.fullmatch(line)
        if match is None:
            raise DiagnosticError(f"malformed alignment line {index}")
        size, aligned16, minimum, maximum = (int(value) for value in match.groups())
        if (size != ALIGNMENT_SIZES[index] or aligned16 > ALIGNMENT_SAMPLES or
            minimum < size or maximum < minimum):
            raise DiagnosticError(f"invalid alignment state at size {size}")
        samples.append({"size": size, "aligned16": aligned16,
                        "usable_min": minimum, "usable_max": maximum})
    return samples


def first_change(samples: list[dict[str, int]], field: str) -> int | None:
    baseline = samples[0][field]
    return next((point["index"] for point in samples[1:] if point[field] > baseline), None)


def compare(c: list[dict[str, int]], native: list[dict[str, int]]) -> dict[str, Any]:
    if len(c) != BLOCKS or len(native) != BLOCKS:
        raise DiagnosticError("paired trace omits an allocation")
    result = {
        "first_usable_divergence": next(
            (index for index, (left, right) in enumerate(zip(c, native))
             if left["usable"] != right["usable"]), None),
        "first_medium_slice_divergence": next(
            (index for index, (left, right) in enumerate(zip(c, native))
             if left["medium_used"] != right["medium_used"]), None),
        "c_first_new_medium_page": first_change(c, "medium_used"),
        "native_first_new_medium_page": first_change(native, "medium_used"),
        "c_first_abandoned_page": first_change(c, "medium_abandoned"),
        "native_first_abandoned_page": first_change(native, "medium_abandoned"),
    }
    result["source_parity"] = (
        result["first_usable_divergence"] is None and
        result["first_medium_slice_divergence"] is None and
        result["c_first_abandoned_page"] == result["native_first_abandoned_page"]
    )
    return result


def alignment_parity(c: list[dict[str, int]], native: list[dict[str, int]]) -> bool:
    if len(c) != len(ALIGNMENT_SIZES) or len(native) != len(ALIGNMENT_SIZES):
        raise DiagnosticError("paired alignment trace omits a request size")
    return all(
        left["size"] == right["size"] and
        right["aligned16"] == ALIGNMENT_SAMPLES and
        (right["size"] <= 8 or
         (right["usable_min"] == left["usable_min"] and
          right["usable_max"] == left["usable_max"]))
        for left, right in zip(c, native)
    )


def run_product(binary: Path, mode: str, output: Path) -> dict[str, Any]:
    argv = [str(binary.resolve())] + ([mode] if mode in ("worker", "alignment") else [])
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    output.mkdir(parents=True, exist_ok=False)
    (output / "stdout.txt").write_text(result.stdout)
    (output / "stderr.txt").write_text(result.stderr)
    if result.returncode != 0 or result.stderr:
        raise DiagnosticError(f"{binary.name} {mode} failed with exit {result.returncode}")
    return {
        "argv": argv, "exit_status": result.returncode,
        "stdout_sha256": digest(output / "stdout.txt"),
        "stderr_sha256": digest(output / "stderr.txt"),
        "samples": parse_alignment(result.stdout) if mode == "alignment"
                   else parse_trace(result.stdout),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-binary", type=Path, required=True)
    parser.add_argument("--c-product-json", type=Path, required=True)
    parser.add_argument("--native-binary", type=Path, required=True)
    parser.add_argument("--native-sysroot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-parity", action="store_true")
    arguments = parser.parse_args()
    product = json.loads(arguments.c_product_json.read_text())
    if (product.get("fixture_sha256") != digest(FIXTURE) or
        product.get("bridge_sha256") != digest(BRIDGE) or
        product.get("binary_sha256") != digest(arguments.c_binary) or
        product.get("pinned_archive_sha256") != PINNED_ARCHIVE_SHA256 or
        product.get("link_mode") != "musl-static-pie"):
        raise DiagnosticError("pinned C product differs from the diagnostic inputs")
    manifest_path = arguments.native_sysroot / "share/crabc/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("allocator_backend") != "native-shadow":
        raise DiagnosticError("native product does not select the Rust allocator")
    output = arguments.output.resolve()
    if not output.is_relative_to((ROOT / ".work").resolve()):
        raise DiagnosticError("diagnostic output must stay in the owning worktree .work")
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "source_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "fixture_sha256": digest(FIXTURE), "bridge_sha256": digest(BRIDGE),
        "c_product": product, "native_manifest_sha256": digest(manifest_path),
        "c_elf": static_pie_identity(arguments.c_binary),
        "native_elf": static_pie_identity(arguments.native_binary),
        "modes": {},
    }
    for mode in ("initial", "worker"):
        c = run_product(arguments.c_binary, mode, output / f"c-{mode}")
        native = run_product(arguments.native_binary, mode, output / f"native-{mode}")
        comparison = compare(c["samples"], native["samples"])
        report["modes"][mode] = {"c": c, "native": native, "comparison": comparison}
        print(mode, comparison)
    c = run_product(arguments.c_binary, "alignment", output / "c-alignment")
    native = run_product(arguments.native_binary, "alignment", output / "native-alignment")
    native_max_align = all(point["aligned16"] == ALIGNMENT_SAMPLES
                           for point in native["samples"])
    size_parity = alignment_parity(c["samples"], native["samples"])
    report["alignment"] = {"c": c, "native": native,
                           "native_all_pointers_aligned_16": native_max_align,
                           "source_parity_where_abi_allows": size_parity}
    print("alignment", [(left["size"], left["aligned16"], right["aligned16"],
                         left["usable_min"], right["usable_min"])
                        for left, right in zip(c["samples"], native["samples"])])
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    parity = (size_parity and
              all(mode["comparison"]["source_parity"] for mode in report["modes"].values()))
    return 0 if native_max_align and (not arguments.require_parity or parity) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DiagnosticError as error:
        print(f"medium capacity diagnostic: {error}", file=sys.stderr)
        raise SystemExit(2) from error
