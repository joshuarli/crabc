#!/usr/bin/env python3
"""Compare joined medium-page release in pinned C and owned Rust products.

Both static PIE products run the same C client. The driver parks all allocator
owners at each audit and waits for this reader to capture its current mapping
before allowing the next transition. This is a diagnostic, not a gate reader.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = Path(__file__).with_name("medium-collection-churn-v3.5.0.json")
FIXTURE = Path(__file__).with_name("medium_collection_churn.c")
BRIDGE = Path(__file__).with_name("pinned_c_page_map_soak_bridge.c")
NUMBER = re.compile(r"([a-z_]+)=([0-9]+)")
PHASE = re.compile(r"\bphase=([a-z0-9_]+)\b")
VMA_HEADER = re.compile(r"^[0-9a-f]+-[0-9a-f]+\s", re.MULTILINE)
REQUIRED = {
    "epoch", "rss_kib", "hwm_kib", "rollup_rss_kib", "anonymous_kib",
    "anon_huge_kib", "referenced_kib", "page_map_entries", "page_map_submaps",
    "arena_registry_count",
    "small_empty", "small_used", "medium_empty", "medium_used",
    "large_empty", "large_used", "singleton_empty", "singleton_used",
    "medium_abandoned", "medium_detached", "medium_attached",
    "medium_remote_pending", "medium_reusable", "medium_retired",
}
MEDIUM_FIELDS = (
    "medium_empty", "medium_used", "medium_abandoned", "medium_detached",
    "medium_attached", "medium_remote_pending", "medium_reusable", "medium_retired",
)


class DiagnosticError(RuntimeError):
    """A product, protocol, or paired source observation is incomplete."""


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


def parse_snapshot(line: str) -> dict[str, int | str]:
    if not line.startswith("snapshot "):
        raise DiagnosticError("expected one quiescent snapshot")
    phase = PHASE.search(line)
    numbers = {key: int(value) for key, value in NUMBER.findall(line)}
    if phase is None or REQUIRED - numbers.keys() or len(numbers) != len(REQUIRED):
        raise DiagnosticError("snapshot has missing or extra scalar fields")
    if numbers["rss_kib"] < 0 or numbers["rollup_rss_kib"] < 0:
        raise DiagnosticError("snapshot lacks current RSS")
    if numbers["medium_abandoned"] + numbers["medium_detached"] + numbers["medium_attached"] != (
        numbers["medium_empty"] + numbers["medium_used"]
    ):
        raise DiagnosticError("medium owner buckets do not partition registered slices")
    numbers["phase"] = phase.group(1)
    return numbers


def arena_mapping(smaps: str) -> dict[str, Any]:
    blocks = re.split(r"(?=^[0-9a-f]+-[0-9a-f]+ )", smaps, flags=re.MULTILINE)
    arenas = []
    for block in blocks:
        if not VMA_HEADER.match(block):
            continue
        size = re.search(r"^Size:\s+(\d+)", block, re.MULTILINE)
        if size is None or int(size.group(1)) != 1_048_576:
            continue
        def value(name: str) -> int:
            match = re.search(rf"^{name}:\s+(\d+)", block, re.MULTILINE)
            if match is None:
                raise DiagnosticError(f"arena mapping lacks {name}")
            return int(match.group(1))
        flags = re.search(r"^VmFlags:\s+(.+)", block, re.MULTILINE)
        arenas.append({
            "size_kib": 1_048_576, "rss_kib": value("Rss"),
            "anonymous_kib": value("Anonymous"),
            "anon_huge_kib": value("AnonHugePages"),
            "referenced_kib": value("Referenced"),
            "vm_flags": flags.group(1).split() if flags else [],
        })
    if not arenas:
        raise DiagnosticError("no regular 1 GiB arena mapping")
    return {
        "count": len(arenas), "mappings": arenas,
        **{field: sum(arena[field] for arena in arenas)
           for field in ("size_kib", "rss_kib", "anonymous_kib",
                         "anon_huge_kib", "referenced_kib")},
    }


def profile_workload(contract: dict[str, Any], profile: str) -> dict[str, int]:
    if profile not in contract["profile_options"]:
        raise DiagnosticError(f"unknown purge profile: {profile}")
    return contract["pressure_workload" if profile.startswith("pressure-") else "workload"]


def expected_phases(contract: dict[str, Any], profile: str = "source-default") -> list[tuple[int, str]]:
    workload = profile_workload(contract, profile)
    return [(0, "baseline")] + [
        (epoch, phase)
        for epoch in range(1, workload["epochs"] + 1)
        for phase in contract["phase_order"][1:]
    ]


def run_product(binary: Path, profile: str, output: Path, contract: dict[str, Any]) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment.pop("MIMALLOC_PURGE_DELAY", None)
    environment.pop("mimalloc_purge_delay", None)
    environment.pop("MIMALLOC_PAGE_FULL_RETAIN", None)
    environment.pop("mimalloc_page_full_retain", None)
    environment.pop("CRABC_MEDIUM_CHURN_PRESSURE", None)
    workload = profile_workload(contract, profile)
    environment.update(contract["profile_options"][profile])
    process = subprocess.Popen(
        [str(binary.resolve())], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1, env=environment,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    lines: list[str] = []
    samples: list[dict[str, Any]] = []
    with (output / "stdout.txt").open("w") as raw:
        try:
            for epoch, phase in expected_phases(contract, profile):
                ready, _, _ = select.select([process.stdout], [], [], 30)
                if not ready:
                    raise DiagnosticError(f"{binary.name} stalled before {epoch}:{phase}")
                line = process.stdout.readline()
                lines.append(line)
                raw.write(line)
                raw.flush()
                fields = parse_snapshot(line)
                if fields["epoch"] != epoch or fields["phase"] != phase:
                    raise DiagnosticError(f"out-of-order snapshot: {fields['epoch']}:{fields['phase']}")
                smaps = Path(f"/proc/{process.pid}/smaps").read_text()
                mapping = arena_mapping(smaps)
                smaps_name = f"epoch-{epoch:02d}-{phase}.smaps"
                (output / smaps_name).write_text(smaps)
                samples.append({"fields": fields, "arena": mapping,
                                "smaps_path": smaps_name, "smaps_sha256": digest(output / smaps_name)})
                process.stdin.write("x")
                process.stdin.flush()
            for line in process.stdout:
                lines.append(line)
                raw.write(line)
            status = process.wait(timeout=30)
            stderr = process.stderr.read()
        except Exception as error:
            process.kill()
            process.wait()
            (output / "stderr.txt").write_text(process.stderr.read())
            (output / "error.txt").write_text(f"{type(error).__name__}: {error}\n")
            raise
    (output / "stderr.txt").write_text(stderr)
    done = (f"done epochs={workload['epochs']} "
            f"blocks_per_epoch={workload['blocks_per_epoch']} "
            f"request={workload['request_bytes']}\n")
    if status != 0 or stderr or not lines or lines[-1] != done:
        raise DiagnosticError(f"incomplete workload: {binary.name}, exit {status}, stderr {stderr!r}")
    return {
        "binary_sha256": digest(binary), "profile": profile,
        "exit_status": status, "stdout_sha256": digest(output / "stdout.txt"),
        "stderr_sha256": digest(output / "stderr.txt"), "samples": samples,
    }


def release_phase(samples: list[dict[str, Any]], epoch: int, significant_kib: int) -> str:
    points = {s["fields"]["phase"]: s for s in samples if s["fields"]["epoch"] == epoch}
    allocated = points["allocated"]["arena"]["rss_kib"]
    for phase in ("remote_joined", "owner_cleared", "owner_joined", "settled_20ms"):
        if allocated - points[phase]["arena"]["rss_kib"] >= significant_kib:
            return phase
    return "retained_after_20ms"


def compare_pressure(c: dict[str, Any], native: dict[str, Any], contract: dict[str, Any],
                     profile: str) -> dict[str, Any]:
    expected = expected_phases(contract, profile)
    if len(c["samples"]) != len(expected) or len(native["samples"]) != len(expected):
        raise DiagnosticError("pressure product omitted a transition")
    mismatches = []
    checkpoints = []
    for c_sample, n_sample in zip(c["samples"], native["samples"]):
        c_fields, n_fields = c_sample["fields"], n_sample["fields"]
        point = (c_fields["epoch"], c_fields["phase"])
        if point != (n_fields["epoch"], n_fields["phase"]):
            raise DiagnosticError("pressure product reordered transitions")
        for field in MEDIUM_FIELDS:
            if c_fields[field] != n_fields[field]:
                mismatches.append(f"{point[0]}:{point[1]}:{field}")
        if c_fields["page_map_entries"] != n_fields["page_map_entries"]:
            mismatches.append(f"{point[0]}:{point[1]}:page_map_entries")
        checkpoints.append({
            "epoch": point[0], "phase": point[1],
            "c": {"page_map_entries": c_fields["page_map_entries"],
                  "arena_registry_count": c_fields["arena_registry_count"],
                  "medium_used": c_fields["medium_used"],
                  "rss_kib": c_fields["rss_kib"],
                  "anonymous_kib": c_fields["anonymous_kib"],
                  "anon_huge_kib": c_fields["anon_huge_kib"],
                  "arena": c_sample["arena"]},
            "native": {"page_map_entries": n_fields["page_map_entries"],
                       "arena_registry_count": n_fields["arena_registry_count"],
                       "medium_used": n_fields["medium_used"],
                       "rss_kib": n_fields["rss_kib"],
                       "anonymous_kib": n_fields["anonymous_kib"],
                       "anon_huge_kib": n_fields["anon_huge_kib"],
                       "arena": n_sample["arena"]},
        })
    for name, product in (("c", c), ("native", native)):
        for epoch in range(1, profile_workload(contract, profile)["epochs"] + 1):
            points = {sample["fields"]["phase"]: sample
                      for sample in product["samples"] if sample["fields"]["epoch"] == epoch}
            allocated, drained = points["allocated"], points["settled_20ms"]
            if allocated["arena"]["count"] < 2:
                mismatches.append(f"{epoch}:{name}:multi-arena pressure absent")
            if name == "native" and allocated["fields"]["arena_registry_count"] < 2:
                mismatches.append(f"{epoch}:{name}:second arena absent from registry")
            if allocated["fields"]["medium_used"] == 0:
                mismatches.append(f"{epoch}:{name}:medium image absent")
            if (drained["fields"]["medium_used"] != 0 or
                allocated["fields"]["page_map_entries"] -
                    drained["fields"]["page_map_entries"] < 128):
                mismatches.append(f"{epoch}:{name}:registered medium image retained after drain")
    return {"status": "match" if not mismatches else "diverge",
            "mismatches": mismatches, "checkpoints": checkpoints,
            "arena_release_phases": [
                {"epoch": epoch,
                 "c": release_phase(c["samples"], epoch, contract["significant_arena_release_kib"]),
                 "native": release_phase(native["samples"], epoch,
                                         contract["significant_arena_release_kib"])}
                for epoch in range(1, profile_workload(contract, profile)["epochs"] + 1)
            ]}


def compare(c: dict[str, Any], native: dict[str, Any], contract: dict[str, Any],
            profile: str) -> dict[str, Any]:
    if profile.startswith("pressure-"):
        return compare_pressure(c, native, contract, profile)
    significant = contract["significant_arena_release_kib"]
    nonabandoning = contract["profile_options"][profile].get("MIMALLOC_PAGE_FULL_RETAIN") == "-1"
    if len(c["samples"]) != len(native["samples"]) or len(c["samples"]) != len(expected_phases(contract, profile)):
        raise DiagnosticError("paired product omitted a transition")
    mismatches = []
    for c_sample, native_sample in zip(c["samples"], native["samples"]):
        c_fields, n_fields = c_sample["fields"], native_sample["fields"]
        if (c_fields["epoch"], c_fields["phase"]) != (n_fields["epoch"], n_fields["phase"]):
            raise DiagnosticError("paired product reordered transitions")
        for field in MEDIUM_FIELDS:
            if c_fields[field] != n_fields[field]:
                mismatches.append(f"{c_fields['epoch']}:{c_fields['phase']}:{field}")
    releases = []
    for epoch in range(1, contract["workload"]["epochs"] + 1):
        c_points = {s["fields"]["phase"]: s["fields"] for s in c["samples"] if s["fields"]["epoch"] == epoch}
        n_points = {s["fields"]["phase"]: s["fields"] for s in native["samples"] if s["fields"]["epoch"] == epoch}
        for name, points in (("c", c_points), ("native", n_points)):
            if points["allocated"]["medium_used"] < contract["workload"]["medium_pages_per_epoch"] * 8:
                mismatches.append(f"{epoch}:{name}:medium image absent")
            if points["allocated"]["page_map_entries"] != points["remote_joined"]["page_map_entries"]:
                mismatches.append(f"{epoch}:{name}:registration changed before survivor free")
            if nonabandoning:
                if points["allocated"]["medium_abandoned"] != 0:
                    mismatches.append(f"{epoch}:{name}:nonabandoning medium was abandoned")
                if points["remote_joined"]["medium_remote_pending"] < 128:
                    mismatches.append(f"{epoch}:{name}:joined remote heads were absent")
                if (points["owner_cleared"]["page_map_entries"] != points["allocated"]["page_map_entries"] or
                    points["owner_cleared"]["medium_used"] != points["allocated"]["medium_used"]):
                    mismatches.append(f"{epoch}:{name}:pending pages released before owner exit")
                release = points["owner_joined"]
            else:
                if points["allocated"]["medium_abandoned"] < 128:
                    mismatches.append(f"{epoch}:{name}:full medium pages were not abandoned")
                release = points["owner_cleared"]
            if points["allocated"]["page_map_entries"] - release["page_map_entries"] < 128:
                mismatches.append(f"{epoch}:{name}:medium registration did not release")
            if release["medium_used"] != 0:
                mismatches.append(f"{epoch}:{name}:medium page remained after collection")
        c_release = release_phase(c["samples"], epoch, significant)
        native_release = release_phase(native["samples"], epoch, significant)
        if c_release != native_release:
            mismatches.append(f"{epoch}:arena release {c_release} vs {native_release}")
        releases.append({"epoch": epoch, "c": c_release, "native": native_release})
    return {"status": "match" if not mismatches else "diverge",
            "mismatches": mismatches, "arena_release_phases": releases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-binary", type=Path, required=True)
    parser.add_argument("--c-product-json", type=Path, required=True)
    parser.add_argument("--native-binary", type=Path, required=True)
    parser.add_argument("--native-sysroot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    contract = json.loads(CONTRACT.read_text())
    product = json.loads(arguments.c_product_json.read_text())
    if (product.get("pinned_archive_sha256") != contract["upstream"]["archive_sha256"] or
        product.get("fixture_sha256") != digest(FIXTURE) or
        product.get("bridge_sha256") != digest(BRIDGE) or
        product.get("binary_sha256") != digest(arguments.c_binary) or
        product.get("link_mode") != "musl-static-pie"):
        raise DiagnosticError("pinned C build identity differs from the diagnostic inputs")
    manifest_path = arguments.native_sysroot / "share/crabc/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("allocator_backend") != "native-shadow":
        raise DiagnosticError("native product sysroot does not select the Rust allocator")
    c_identity = static_pie_identity(arguments.c_binary)
    native_identity = static_pie_identity(arguments.native_binary)
    output = arguments.output.resolve()
    if not output.is_relative_to((ROOT / ".work").resolve()):
        raise DiagnosticError("diagnostic output must stay in the owning worktree .work")
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "schema": contract["schema"], "contract_sha256": digest(CONTRACT),
        "fixture_sha256": digest(FIXTURE), "bridge_sha256": digest(BRIDGE),
        "c_product": product, "native_manifest_sha256": digest(manifest_path),
        "c_elf": c_identity, "native_elf": native_identity,
        "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "profiles": {},
    }
    for profile in contract["profiles"]:
        c = run_product(arguments.c_binary, profile, output / f"c-{profile}", contract)
        native = run_product(arguments.native_binary, profile, output / f"native-{profile}", contract)
        comparison = compare(c, native, contract, profile)
        report["profiles"][profile] = {"c": c, "native": native, "comparison": comparison}
        print(profile, comparison["status"], comparison["arena_release_phases"])
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if all(p["comparison"]["status"] == "match" for p in report["profiles"].values()) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DiagnosticError as error:
        print(f"medium churn diagnostic: {error}", file=sys.stderr)
        raise SystemExit(2) from error
