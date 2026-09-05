#!/usr/bin/env python3
"""Replay a pinned native pthread stress source profile through supplied products."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

import crabc_cc_static as compiler_contract
import owned_posix_product_evidence as product_evidence
import owned_pthread_stress_source as source_profile

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "compat/x86_64"
SOURCE = ROOT / "tests/fixtures/pthread_stress_test.c"
IO_CANCELLATION_SOURCE = HERE / "owned_io_cancellation_probe.c"
ORACLE = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
FLAGS = ["-std=c11", "-O2", "-D_POSIX_C_SOURCE=200809L", "-fno-builtin"]
USAGE = "usage: run_owned_pthread_stress.sh [--static-sysroot STATIC_SYSROOT] [--iterations N] [--timeout SECONDS] [--source-profile native-v1|frozen] DYNAMIC_SYSROOT"


class ArgumentError(ValueError):
    """Malformed CLI; rejected before evidence creation."""


class EvidenceError(ValueError):
    """A consumed identity or observable contract differs."""


@dataclass(frozen=True)
class Options:
    static: Path | None
    dynamic: Path
    iterations: int = 10
    timeout: float = 10.0
    source_profile: str = "native-v1"


@dataclass(frozen=True)
class Observation:
    status: int | str
    stdout: bytes
    stderr: bytes

    def __post_init__(self):
        # JSON false compares equal to zero in Python; it is never an exit code.
        if type(self.status) is not int and not (type(self.status) is str and self.status == "TIMEOUT"):
            raise EvidenceError("observation status type must be an integer or exact TIMEOUT")


def parse_arguments(arguments):
    remaining, values = list(arguments), {}
    while remaining and remaining[0].startswith("--"):
        option = remaining.pop(0)
        if option not in ("--static-sysroot", "--iterations", "--timeout", "--source-profile") or option in values or not remaining or not remaining[0] or remaining[0].startswith("-"):
            raise ArgumentError(USAGE)
        values[option] = remaining.pop(0)
    if len(remaining) != 1 or not remaining[0] or remaining[0].startswith("-"):
        raise ArgumentError(USAGE)
    try:
        iterations = int(values.get("--iterations", "10"))
        timeout = float(values.get("--timeout", "10"))
    except ValueError as error:
        raise ArgumentError(USAGE) from error
    if not 1 <= iterations <= 100 or not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise ArgumentError(USAGE)
    profile = values.get("--source-profile", "native-v1")
    if profile not in source_profile.PROFILES:
        raise ArgumentError(USAGE)
    return Options(Path(values["--static-sysroot"]) if "--static-sysroot" in values else None,
                   Path(remaining[0]), iterations, timeout, profile)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def physical_directory(path):
    lexical = Path(path).absolute()
    physical = lexical.resolve(strict=True)
    if ".." in Path(path).parts or lexical != physical or not physical.is_dir() or not physical.is_relative_to(ROOT / ".work"):
        raise EvidenceError(f"expected physical checkout .work directory: {path}")
    return physical


def identities(paths):
    return {str(path): {"sha256": digest(path), "mode": path.stat().st_mode,
                        "resolved_path": str(path.resolve(strict=True))} for path in sorted(set(map(Path, paths)))}


def audit_identities(records):
    for name, expected in records.items():
        try:
            actual = identities([Path(name)])[name]
        except OSError as error:
            raise EvidenceError(f"identity changed: {name}") from error
        if actual != expected:
            raise EvidenceError(f"identity changed: {name}")


def stream_snapshot(data):
    return {"hex": data.hex(), "byte_length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def snapshot(observation):
    return {"status": observation.status, "stdout": stream_snapshot(observation.stdout), "stderr": stream_snapshot(observation.stderr)}


def compare(reference, candidate):
    clean = Observation(0, b"pthread stress ok\n", b"")
    return {"passed": reference == candidate == clean, "equal": reference == candidate,
            "oracle_clean": reference == clean, "candidate_clean": candidate == clean}


def cells(include_static):
    return ("oracle", *(("static", "static-pie") if include_static else ()),
            "pie-kernel", "pie-direct", "non-pie-kernel", "non-pie-direct")


def summarize(records, iterations, include_static):
    if len(records) != iterations:
        raise EvidenceError("iteration roster differs")
    expected = cells(include_static)
    result = []
    for index, record in enumerate(records, 1):
        if set(record) != set(expected):
            raise EvidenceError("cell roster differs")
        result.append({"iteration": index, "observations": {cell: snapshot(record[cell]) for cell in expected},
                       "comparisons": {cell: compare(record["oracle"], record[cell]) for cell in expected}})
    return {"passed": all(item["passed"] for iteration in result for item in iteration["comparisons"].values()),
            "observation_count": iterations * len(expected), "cell_roster": list(expected), "iterations": result}


def signal_group(child, signum):
    try:
        os.killpg(child.pid, signum)
    except ProcessLookupError:
        pass


def observe(argv, cwd, prefix, timeout):
    """Retain actual child termination before propagating a supervisor interruption."""
    command = list(map(str, argv))
    child = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    stdout, stderr, status = b"", b"", None
    try:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
            status = child.returncode
        except subprocess.TimeoutExpired:
            signal_group(child, signal.SIGKILL)
            stdout, stderr = child.communicate()
            status = "TIMEOUT"
    except BaseException:
        # Keep the original interruption, but first retire the private group and
        # reap the direct child. communicate retains bytes read before SIGINT.
        signal_group(child, signal.SIGTERM)
        try:
            stdout, stderr = child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            signal_group(child, signal.SIGKILL)
            stdout, stderr = child.communicate()
        else:
            # A descendant may have closed the streams but stayed in the group.
            signal_group(child, signal.SIGKILL)
        status = child.returncode
        raise
    finally:
        Path(str(prefix) + ".stdout").write_bytes(stdout)
        Path(str(prefix) + ".stderr").write_bytes(stderr)
        write_json(str(prefix) + ".status.json", {"command": command, "cwd": str(cwd), "timeout_seconds": timeout,
                   "pid": child.pid, "process_group": child.pid, "status": status, "returncode": child.returncode})
    return Observation(status, stdout, stderr)


def command(argv, prefix, cwd=ROOT):
    with Path(str(prefix) + ".stdout").open("wb") as stdout, Path(str(prefix) + ".stderr").open("wb") as stderr:
        subprocess.run(list(map(str, argv)), cwd=cwd, stdout=stdout, stderr=stderr, check=True)


def audit_link(product, workload, executable, receipt, linkage):
    return product_evidence.validate_link(product, workload, executable, receipt, linkage)


def header_audit(product, work, source=None):
    source = SOURCE if source is None else source
    compiler = compiler_contract.compiler()
    base = [compiler, "-nostdinc", "-isystem", str(product / "usr/include"), "-ffreestanding",
            "-fno-builtin", "-fstack-protector-strong", *FLAGS, "-fPIE"]
    commands = {"dependencies": [*base, "-M", str(source)], "preprocessor": [*base, "-E", str(source)]}
    environment = compiler_contract.clean_environment()
    outputs = {name: subprocess.check_output(argv, cwd=ROOT, env=environment) for name, argv in commands.items()}
    headers = {}
    for name in outputs["dependencies"].decode().replace("\\\n", " ").split(":", 1)[1].split():
        path = Path(name).resolve(strict=True)
        if path == source:
            continue
        if not path.is_relative_to(product / "usr/include"):
            raise EvidenceError(f"unowned header: {path}")
        headers[str(path.relative_to(product))] = digest(path)
    for name in ("pthread.h", "stdio.h", "signal.h", "unistd.h"):
        if "usr/include/" + name not in headers:
            raise EvidenceError(f"missing installed header: {name}")
    return {"commands": commands, "environment": environment,
            "compiler": {"path": compiler, **identities([Path(compiler)])[compiler]}, "headers": headers,
            "outputs": {name: hashlib.sha256(value).hexdigest() for name, value in outputs.items()}}, outputs


def audit_raw_observation(prefix, expected):
    status = json.loads(Path(str(prefix) + ".status.json").read_text())
    actual = Observation(status["status"], Path(str(prefix) + ".stdout").read_bytes(),
                         Path(str(prefix) + ".stderr").read_bytes())
    if actual != expected:
        raise EvidenceError(f"retained raw observation changed: {prefix}")


def profile_result(profile, passed):
    """A passing remainder cannot satisfy the separate I/O cancellation owner."""
    return {"passed_scope": "remaining-native-pthread-stress-workload" if profile == "native-v1" else "frozen-pthread-stress-workload",
            "remaining_stress_workload_passed": passed if profile == "native-v1" else None,
            "native_aggregate_complete": False,
            "replacement_io_cancellation_required": ["READ_FILE", "ASYNC_LOOP"],
            "replacement_io_cancellation_source": {"path": str(IO_CANCELLATION_SOURCE.relative_to(ROOT)),
                                                   "sha256": digest(IO_CANCELLATION_SOURCE)},
            "replacement_io_cancellation_receipt": None,
            "replacement_io_cancellation_binding": "composite owner must bind the same-product I/O-cancellation family receipt"}


def run(arguments):
    options = parse_arguments(arguments)
    product = physical_directory(options.dynamic)
    static = physical_directory(options.static) if options.static else None
    product_evidence._validate_dynamic_product(product)
    if static:
        product_evidence._validate_static_product(static)
    temporary = physical_directory(os.environ.get("TMPDIR", ""))
    work = Path(tempfile.mkdtemp(prefix="owned-pthread-stress.", dir=temporary))
    print(f"pthread-stress evidence: {work}", flush=True)
    workload = work / "workload.o"
    prepared_source = work / "pthread_stress_test.c"
    source_map = source_profile.materialize(SOURCE, prepared_source, options.source_profile)
    write_json(work / "source-map.json", source_map)
    compile_argv = [product / "bin/crabc-cc-dynamic", "--dynamic-pie", *FLAGS, "-c", prepared_source, "-o", workload]
    provenance = [SOURCE, prepared_source, work / "source-map.json", Path(source_profile.__file__), IO_CANCELLATION_SOURCE,
                  Path(__file__), HERE / "run_owned_pthread_stress.sh",
                  Path(product_evidence.__file__), Path(compiler_contract.__file__), ROOT / "compat/pthread-stress/run.py",
                  ROOT / "compat/pthread-stress/README.md", product / "bin/crabc-cc-dynamic",
                  product / "share/crabc/crabc_cc_static.py", product / "share/crabc/manifest.json",
                  Path(compiler_contract.compiler()), ORACLE, Path("/opt/musl-1.2.6/lib/libc.a"),
                  Path("/opt/musl-1.2.6/.crabc-oracle")]
    # Freeze source, tool, and oracle inputs before the installed driver consumes them.
    inputs = identities(provenance)
    header_record, header_outputs = header_audit(product, work, prepared_source)
    command(compile_argv, work / "compile")
    compiled_object = identities([workload])
    for name, data in header_outputs.items():
        (work / (name + (".d" if name == "dependencies" else ".i"))).write_bytes(data)
    write_json(work / "compile.json", {"command": list(map(str, compile_argv)), "inputs": inputs,
               "compiler_environment": header_record["environment"], "compiler": header_record["compiler"],
               "header_audit": header_record, "source_map": source_map, "object_sha256": digest(workload)})
    oracle_argv = [ORACLE, "-static", "-fno-pie", "-no-pie", "-pthread", workload, "-o", work / "oracle"]
    command(oracle_argv, work / "oracle-link")
    links, bindings = [], []
    if static:
        for mode in ("static", "static-pie"):
            binary = work / mode
            receipt = Path(str(binary) + ".crabc-link.json")
            command([static / "bin/crabc-cc", "-" + mode, "--link-receipt", receipt.name, workload, "-o", binary], work / ("link-" + mode), cwd=work)
            bindings.append((static, workload, binary, receipt, mode))
    for mode in ("pie", "non-pie"):
        binary = work / ("dynamic-" + mode)
        command([product / "bin/crabc-cc-dynamic", "--dynamic-" + mode, workload, "-o", binary], work / ("link-" + mode))
        bindings.append((product, workload, binary, Path(str(binary) + ".crabc-link.json"), mode))
    for binding in bindings:
        links.append(audit_link(*binding))
    execution = work / "execution-root"
    shutil.copytree(product, execution, symlinks=True)
    binaries = [work / "oracle", *(binding[2] for binding in bindings)]
    for binary in binaries:
        shutil.copy2(binary, execution / binary.name)
        if digest(binary) != digest(execution / binary.name):
            raise EvidenceError("execution copy differs")
    commands = {"oracle": ["/oracle"]}
    if static:
        commands.update({mode: ["/" + mode] for mode in ("static", "static-pie")})
    for mode in ("pie", "non-pie"):
        commands[mode + "-kernel"] = ["/dynamic-" + mode]
        commands[mode + "-direct"] = ["/lib/ld-crabc-x86_64.so.1", "/dynamic-" + mode]
    audit_identities(compiled_object)
    consumed = identities([*provenance, workload, work / "compile.json", *binaries,
                           work / "dependencies.d", work / "preprocessor.i",
                           *(binding[3] for binding in bindings),
                           *(path for path in execution.rglob("*") if path.is_file())])
    write_json(work / "consumed.json", consumed)
    consumed_receipt = digest(work / "consumed.json")
    records, raw_files = [], []
    for iteration in range(1, options.iterations + 1):
        record = {}
        for cell in cells(static is not None):
            prefix = work / f"iteration-{iteration:03d}-{cell}"
            observation = observe(["chroot", execution, *commands[cell]], ROOT, prefix, options.timeout)
            record[cell] = observation
            raw_files.extend(Path(str(prefix) + suffix) for suffix in (".stdout", ".stderr", ".status.json"))
            if not compare(observation, observation)["passed"]:
                print(f"iteration {iteration} {cell}: {observation.status}; stdout={observation.stdout!r}; stderr={observation.stderr!r}", flush=True)
        records.append(record)
        print(f"iteration {iteration}/{options.iterations} retained", flush=True)
    report = summarize(records, options.iterations, static is not None)
    audit_identities(inputs)
    audit_identities(compiled_object)
    for iteration, record in enumerate(records, 1):
        for cell, observation in record.items():
            audit_raw_observation(work / f"iteration-{iteration:03d}-{cell}", observation)
    audit_identities(consumed)
    if digest(work / "consumed.json") != consumed_receipt:
        raise EvidenceError("consumed receipt changed")
    if header_audit(product, work, prepared_source)[0] != header_record:
        raise EvidenceError("installed header/preprocessor closure changed")
    final_links = [audit_link(*binding) for binding in bindings]
    if final_links != links:
        raise EvidenceError("link identity changed")
    report.update(profile_result(options.source_profile, report["passed"]))
    report.update({"schema": "crabc.x86_64-owned-pthread-stress/v2", "campaign_complete": False,
                   "source_profile": options.source_profile, "source_map": source_map,
                   "source_map_receipt_sha256": digest(work / "source-map.json"),
                   "prepared_source_sha256": digest(prepared_source),
                   "source_sha256": digest(SOURCE), "workload_object_sha256": digest(workload),
                   "compile_receipt_sha256": digest(work / "compile.json"), "consumed_receipt_sha256": consumed_receipt,
                   "oracle_link_command": list(map(str, oracle_argv)), "links": links,
                   "raw_artifacts": identities(raw_files), "timeout_seconds": options.timeout})
    write_json(work / "pthread-stress.json", report)
    print(f"owned pthread stress {report['passed_scope']}: {'PASS' if report['passed'] else 'FAIL'} "
          f"({report['observation_count']} raw observations; native aggregate incomplete)", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(run(sys.argv[1:]))
    except ArgumentError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
    except (ValueError, OSError, subprocess.SubprocessError, product_evidence.ProductEvidenceError) as error:
        print(f"owned pthread stress: {error}", file=sys.stderr)
        raise SystemExit(1)
