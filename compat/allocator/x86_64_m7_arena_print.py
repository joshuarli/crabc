#!/usr/bin/env python3
"""Compare the pinned arena renderer and native public entries byte for byte."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

import run as harness
import perf_engine_x86_64 as engine
import x86_64_m4_gate as operations

FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_arena_print.c"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m7-arena-print"
BEGIN = "CRABC_MI_ARENA_PRINT_BEGIN\n"
END = "CRABC_MI_ARENA_PRINT_END\n"
STATES = ("empty", "reserved", "managed", "allocated", "freed", "purged",
          "usage-40", "usage-60", "usage-90", "full", "singleton", "medium")
INPUTS = ("crabc-mimalloc/src/arena_print.rs", "crabc-mimalloc/src/arena.rs",
          "crabc-mimalloc/src/types.rs", "crabc-mimalloc/src/source_heap_api.rs",
          "crabc-mimalloc/src/subproc_registry.rs", "crabc-mimalloc/src/lib.rs",
          "compat/allocator/native-mi-adapter/src/lib.rs", "compat/allocator/x86_64_m4_gate.py",
          "compat/allocator/run.py", "Cargo.lock")


def output_image(stdout: str, stderr: str, route: str) -> tuple[str, tuple[int, ...]]:
    """Project only an arena pointer whose identity the fixture independently reports."""
    identity = re.match(r"ARENA_ID=([0-9A-F]+)\n", stdout)
    if identity is None or stdout.count(BEGIN) != 1 or stdout.count(END) != 1:
        raise harness.HarnessError("arena-print execution lost its identity or output frame")
    before, framed = stdout.split(BEGIN)
    body, after = framed.split(END)
    lengths = re.fullmatch(r"CALLBACK_LENGTHS=([0-9,]*)\n", after)
    if before != identity.group(0) or lengths is None:
        raise harness.HarnessError("arena-print execution emitted output outside its frame")
    fragments = tuple(int(value) for value in lengths.group(1).split(",") if value)
    if route == "stderr":
        if body or fragments:
            raise harness.HarnessError("default arena output bypassed stderr")
        body = stderr
    elif stderr:
        raise harness.HarnessError("registered arena output bypassed its callback")
    address = int(identity.group(1), 16)
    headers = list(re.finditer(r"(?m)^arena ([0-9]+) at (0x[0-9A-F]+):", body))
    if address == 0:
        if headers or body != "total pages in arenas: 0\n":
            raise harness.HarnessError("empty arena group lost its exact source output")
        return body, fragments
    if len(headers) != 1 or headers[0].group(1) != "0" or int(headers[0].group(2), 16) != address:
        raise harness.HarnessError("arena header does not name the fixture's exact reserved arena")
    start, end = headers[0].span(2)
    return body[:start] + "<arena-id>" + body[end:], fragments


def compare_executions(executions: dict[str, dict], paths: Path) -> list[str]:
    different = []
    for name, pair in executions.items():
        images = {}
        route = name.split(".")[3]
        for side, record in pair.items():
            stdout = (paths / record["stdout"]).read_bytes().decode("ascii")
            stderr = (paths / record["stderr"]).read_bytes().decode("ascii")
            images[side] = output_image(stdout, stderr, route)
        if images["c"] != images["rust"]:
            different.append(name)
    return sorted(different)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--replay", action="store_true")
    arguments = parser.parse_args()
    report_path = ARTIFACTS / "report.json"
    if arguments.replay:
        report = json.loads(report_path.read_text())
        current_git = engine.git_provenance()
        if report["git"] != current_git or not current_git.get("clean"):
            raise harness.HarnessError("arena-print replay requires its exact clean source")
        source = ARTIFACTS / "source" / harness.load_pin()["archive_root"]
        if engine.tree_digest((source / "src", source / "include")) != report["source_tree"]:
            raise harness.HarnessError("retained pinned arena source differs from its physical inputs")
        expected = {f"{profile}.{state}.{entry}.{route}.{verbose}"
                    for profile in ("release", "debug-1") for state in STATES
                    for entry in ("show", "print") for route in ("callback", "stderr")
                    for verbose in ("0", "-1", "1")}
        if set(report["executions"]) != expected:
            raise harness.HarnessError("retained arena-print receipt lacks the declared execution matrix")
        for name, record in report["inputs"].items():
            if engine.file_record(harness.ROOT / name) != record:
                raise harness.HarnessError(f"retained arena-print source differs: {name}")
        for name, record in report["files"].items():
            if engine.file_record(ARTIFACTS / name) != record:
                raise harness.HarnessError(f"retained arena-print input differs: {name}")
        different = compare_executions(report["executions"], ARTIFACTS)
        for name, pair in report["executions"].items():
            profile, state, entry, route, verbose = name.split(".")
            for side, record in pair.items():
                binary = ARTIFACTS / profile / f"operations-{side}"
                replay = subprocess.run([str(binary), state, entry, route, verbose], cwd=binary.parent,
                                        env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                if replay.returncode:
                    raise harness.HarnessError(f"retained arena-print executable failed: {name}/{side}")
                retained = output_image((ARTIFACTS / record["stdout"]).read_bytes().decode("ascii"),
                                        (ARTIFACTS / record["stderr"]).read_bytes().decode("ascii"), route)
                if retained != output_image(replay.stdout.decode("ascii"), replay.stderr.decode("ascii"), route):
                    raise harness.HarnessError(f"retained arena-print execution changed: {name}/{side}")
        if report["mismatch"] != different or report["status"] != ("red" if different else "passed"):
            raise harness.HarnessError("retained arena-print verdict differs from its raw executions")
        if different:
            print(f"arena-print physical replay reproduced RED: {different}")
            return 1
        print("arena-print retained physical output matched")
        return 0
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    inputs = {path: engine.file_record(harness.ROOT / path) for path in INPUTS}
    inputs[harness.relative(FIXTURE)] = engine.file_record(FIXTURE)
    inputs[harness.relative(Path(__file__))] = engine.file_record(Path(__file__))
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, arguments.offline)
    source = harness.safe_extract(archive, ARTIFACTS / "source", pin["archive_root"])
    executions = {}
    files = {}
    for profile in ("release", "debug-1"):
        directory = ARTIFACTS / profile
        directory.mkdir(exist_ok=True)
        binaries = {"c": operations.build_c_driver(source, directory, FIXTURE, profile)}
        binaries["rust"] = operations.build_rust_driver(source, directory, FIXTURE, profile)
        for side, binary in binaries.items():
            files[f"{profile}/{binary.name}"] = engine.file_record(binary)
        for state in STATES:
            for entry in ("show", "print"):
                for route in ("callback", "stderr"):
                    for verbose in ("0", "-1", "1"):
                        name = f"{profile}.{state}.{entry}.{route}.{verbose}"
                        executions[name] = {}
                        for side, binary in binaries.items():
                            command = [str(binary), state, entry, route, verbose]
                            execution = subprocess.run(command, cwd=binary.parent, env={},
                                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                            stdout, stderr = f"{name}.{side}.stdout", f"{name}.{side}.stderr"
                            (ARTIFACTS / stdout).write_bytes(execution.stdout)
                            (ARTIFACTS / stderr).write_bytes(execution.stderr)
                            if execution.returncode:
                                raise harness.HarnessError(f"arena print {name}/{side} exited {execution.returncode}")
                            executions[name][side] = {"command": command, "stdout": stdout, "stderr": stderr}
                            for output in (stdout, stderr):
                                files[output] = engine.file_record(ARTIFACTS / output)
    different = compare_executions(executions, ARTIFACTS)
    if any(engine.file_record(harness.ROOT / path) != record for path, record in inputs.items()):
        raise harness.HarnessError("arena-print source changed while its evidence was executing")
    report = {
        "status": "red" if different else "passed", "git": engine.git_provenance(),
        "pin": {key: pin[key] for key in ("tag", "sha256", "revision")},
        "source_files": harness.source_file_records(source, ("src/arena.c", "src/static.c", "include/mimalloc/internal.h")),
        "source_tree": engine.tree_digest((source / "src", source / "include")),
        "fixture": engine.file_record(FIXTURE), "inputs": inputs, "files": files,
        "executions": executions, "mismatch": different,
    }
    harness.write_json(report_path, report)
    print(f"arena-print {'RED' if different else 'passed'}: {different}")
    return int(bool(different))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
