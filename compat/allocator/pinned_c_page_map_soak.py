#!/usr/bin/env python3
"""Observe pinned C registered PageMap slices during the unchanged native soak.

Builds the exact pinned source in one static musl image with its allocator
override. The existing soak fixture supplies joined, drained checkpoints;
the companion C bridge reads the process PageMap only at those checkpoints.
The static-PIE mode selects musl's relocation-capable startup object through
a private copy of the installed compiler specs; it does not change the pinned
allocator or soak source. Static non-PIE remains available for comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import run as harness


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/x86_64/owned_native_allocator_soak_probe.c"
BRIDGE = Path(__file__).with_name("pinned_c_page_map_soak_bridge.c")
ARTIFACTS = ROOT / ".work/allocator-x86_64/target/compat/allocator/x86_64/pinned-c-page-map-soak"
SEED = "0x5eed0002"
ROUNDS = 1200
WORKERS = 8
INTERVAL = 60
WATCHDOG = 900
FIELD = re.compile(r"([a-z_]+)=([0-9]+)")
MUSL_SPECS = Path("/opt/musl-1.2.6/lib/musl-gcc.specs")
PIE_STARTFILE = "/opt/musl-1.2.6/lib/rcrt1.o"
SHARED_STARTFILE = "/opt/musl-1.2.6/lib/Scrt1.o"


def artifact_dir(link_mode: str) -> Path:
    if link_mode == "static":
        return ARTIFACTS
    if link_mode == "static-pie":
        return ARTIFACTS / "static-pie"
    raise ValueError(f"unsupported diagnostic link mode: {link_mode}")


def static_pie_specs(installed: str) -> str:
    """Select self-relocating CRT startup without changing installed musl files.

    The installed wrapper selects ``Scrt1.o`` even with ``-static-pie``. That
    startup reaches libc before applying the image's relative relocations and
    faults before main. Musl's ``rcrt1.o`` relocates the image first.
    """

    if installed.count(SHARED_STARTFILE) != 1 or PIE_STARTFILE in installed:
        raise ValueError("installed musl specs do not have the expected startup selection")
    return installed.replace(SHARED_STARTFILE, PIE_STARTFILE)


def fields(line: str) -> dict[str, int]:
    return {key: int(value) for key, value in FIELD.findall(line)}


def parse_soak(output: str) -> dict[str, object]:
    lines = output.splitlines()
    if not lines or lines[0] != (
        f"soak seed=0x000000005eed0002 rounds={ROUNDS} workers={WORKERS} "
        f"checkpoint_interval={INTERVAL}"
    ):
        raise ValueError("the pinned C soak header differs from the requested workload")
    checkpoints = [fields(line) for line in lines if line.startswith("checkpoint ")]
    rounds = list(range(INTERVAL, ROUNDS + 1, INTERVAL))
    if [point.get("round") for point in checkpoints] != rounds:
        raise ValueError("the pinned C soak omitted or reordered a checkpoint")
    for point in checkpoints:
        if point.get("allocations") != point.get("frees"):
            raise ValueError("the pinned C soak checkpoint did not drain")
        if point.get("page_map_entries", 0) <= 0 or point.get("page_map_submaps", 0) <= 0:
            raise ValueError("the pinned C PageMap observation is absent")
    summaries = [fields(line) for line in lines if line.startswith("summary ")]
    if len(summaries) != 1 or summaries[0].get("allocations") != summaries[0].get("frees"):
        raise ValueError("the pinned C soak summary is missing or not drained")
    if summaries[0].get("cleanup_runs") != ROUNDS * WORKERS:
        raise ValueError("the pinned C soak did not complete all owner exits")
    first = max(point["page_map_entries"] for point in checkpoints if point["round"] <= ROUNDS // 2)
    second = max(point["page_map_entries"] for point in checkpoints if point["round"] > ROUNDS // 2)
    return {
        "first_half_max": first,
        "second_half_max": second,
        "second_half_allowed_at_ten_percent": first + first // 10,
        "exceeds_ten_percent": second > first + first // 10,
        "checkpoints": [
            {"round": point["round"], "page_map_entries": point["page_map_entries"],
             "page_map_submaps": point["page_map_submaps"]}
            for point in checkpoints
        ],
        "summary": summaries[0],
    }


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command: list[str], *, cwd: Path, stdout: Path, stderr: Path,
            timeout: int, env: dict[str, str] | None = None) -> int:
    with stdout.open("wb") as out, stderr.open("wb") as err:
        return subprocess.run(command, cwd=cwd, stdout=out, stderr=err,
                              timeout=timeout, env=env, check=False).returncode


def build_product(artifacts: Path, link_mode: str) -> tuple[Path, dict[str, object]]:
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline=True)
    startup: dict[str, str] = {}
    if link_mode == "static":
        compiler = shutil.which("musl-gcc")
        link_flags = ["-fno-pie", "-no-pie", "-static"]
    elif link_mode == "static-pie":
        compiler = shutil.which("gcc")
        installed = MUSL_SPECS.read_text()
        corrected = artifacts / "musl-static-pie.specs"
        corrected.write_text(static_pie_specs(installed))
        startfile = Path(PIE_STARTFILE)
        if not startfile.is_file():
            raise ValueError(f"musl static-PIE startup object is absent: {startfile}")
        link_flags = [f"-specs={corrected}", "-fPIE", "-static-pie"]
        startup = {
            "installed_specs_sha256": digest(MUSL_SPECS),
            "corrected_specs_sha256": digest(corrected),
            "selected_startfile": str(startfile),
            "selected_startfile_sha256": digest(startfile),
        }
    else:
        raise ValueError(f"unsupported diagnostic link mode: {link_mode}")
    if compiler is None:
        raise ValueError("a compiler for the selected musl link mode is absent")
    binary = artifacts / ("soak-pinned-c-static-pie" if link_mode == "static-pie" else "soak-pinned-c-static")
    with tempfile.TemporaryDirectory(prefix="pinned-c-page-map-source-", dir=artifacts) as temp:
        source = harness.safe_extract(archive, Path(temp), pin["archive_root"])
        command = [
            compiler, *link_flags, "-std=c11", "-O2", "-g",
            "-DNDEBUG", "-DMI_BUILD_RELEASE=1", "-DMI_DEBUG=0", "-DMI_STAT=0",
            "-DMI_SECURE=0", "-DMI_GUARDED=0", "-DMI_LIBC_MUSL=1",
            "-DMI_MALLOC_OVERRIDE=1", "-DCRABC_NATIVE_ALLOCATOR_AUDIT",
            "-I", str(source / "include"), "-I", str(source / "src"),
            str(FIXTURE), str(BRIDGE), str(source / "src/static.c"),
            "-pthread", "-o", str(binary),
        ]
        status = execute(command, cwd=source, stdout=artifacts / "build.stdout",
                         stderr=artifacts / "build.stderr", timeout=300)
        if status != 0:
            raise ValueError(f"pinned C diagnostic build failed with status {status}")
    symbols = subprocess.run(["nm", "-an", str(binary)], check=True,
                             capture_output=True, text=True).stdout
    symbol_lines = [line.split() for line in symbols.splitlines()]
    addresses = {parts[-1]: parts[0] for parts in symbol_lines if len(parts) >= 3}
    if (addresses.get("malloc") != addresses.get("mi_malloc")
            or addresses.get("free") != addresses.get("mi_free")
            or "__mi_page_map" not in addresses):
        raise ValueError("pinned C allocator override or PageMap image is absent")
    elf_header = subprocess.run(["readelf", "-h", str(binary)], check=True,
                                capture_output=True, text=True).stdout
    elf_match = re.search(r"^\s*Type:\s+(DYN|EXEC)\b", elf_header, re.MULTILINE)
    if elf_match is None:
        raise ValueError("the pinned C product has no recognized ELF type")
    elf_type = elf_match.group(1)
    if elf_type != ("DYN" if link_mode == "static-pie" else "EXEC"):
        raise ValueError("the pinned C product has the wrong ELF link mode")
    return binary, {
        "pinned_version": pin["version"],
        "pinned_archive_sha256": digest(archive),
        "fixture_sha256": digest(FIXTURE),
        "bridge_sha256": digest(BRIDGE),
        "binary_sha256": digest(binary),
        "page_map_symbol": addresses["__mi_page_map"],
        "malloc_mi_malloc_address": addresses["malloc"],
        "free_mi_free_address": addresses["free"],
        "link_mode": f"musl-{link_mode}",
        "elf_type": elf_type,
        "startup": startup,
        "compile_flags": command[1:command.index("-I")],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replays", type=int, default=1)
    parser.add_argument("--link-mode", choices=("static", "static-pie"), default="static")
    args = parser.parse_args()
    if not 1 <= args.replays <= 32:
        parser.error("--replays must be between 1 and 32")
    artifacts = artifact_dir(args.link_mode)
    artifacts.mkdir(parents=True, exist_ok=True)
    binary, product = build_product(artifacts, args.link_mode)
    environment = os.environ.copy()
    environment.pop("CRABC_NATIVE_ALLOCATOR_CLASS_SNAPSHOT", None)
    report: dict[str, object] = {
        "diagnostic": "pinned-c-page-map-soak",
        "workload": {"seed": SEED, "rounds": ROUNDS, "workers": WORKERS,
                     "checkpoint_interval": INTERVAL, "watchdog_seconds": WATCHDOG},
        "product": product,
        "replays": [],
    }
    command = [str(binary), SEED, str(ROUNDS), str(WORKERS), str(INTERVAL), str(WATCHDOG)]
    for replay in range(1, args.replays + 1):
        name = f"replay-{replay:02}"
        stdout = artifacts / f"{name}.stdout"
        stderr = artifacts / f"{name}.stderr"
        status = execute(command, cwd=artifacts, stdout=stdout, stderr=stderr,
                         timeout=WATCHDOG + 30, env=environment)
        (artifacts / f"{name}.status").write_text(f"{status}\n")
        if status != 0:
            raise ValueError(f"{name} exited {status}; raw output retained at {stdout}")
        observation = parse_soak(stdout.read_text())
        report["replays"].append({"name": name, **observation})
        (artifacts / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{name}: first={observation['first_half_max']} "
              f"second={observation['second_half_max']} "
              f"exceeds_ten_percent={observation['exceeds_ten_percent']}", flush=True)
    print(f"raw diagnostic: {artifacts}")


if __name__ == "__main__":
    main()
