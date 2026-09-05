#!/usr/bin/env python3
"""Retain installed-driver objects and raw residual signal differentials."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "compat/x86_64"
CONTRACT = HERE / "owned-posix-signals.toml"
ORACLE = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
REQUIRED_SCENARIOS = ("sets", "actions-masks", "queue-delivery", "suspend-delivery",
                      "sigpause-cancellation", "sigsuspend-cancellation", "interrupt-bookkeeping",
                      "alternate-stack", "alternate-minimum", "signalfd")
import crabc_cc_static as compiler_contract
import owned_dynamic_qualification as qualification
import owned_posix_product_evidence as product_evidence



def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def contained_directory(path, label):
    lexical = Path(path).absolute()
    physical = lexical.resolve(strict=True)
    if not str(path) or ".." in Path(path).parts or lexical != physical or not physical.is_dir() or not physical.is_relative_to(ROOT / ".work"):
        raise ValueError(f"signal-full {label} must be a physical checkout .work directory")
    return physical


def command(arguments, output, *, cwd=ROOT):
    with Path(str(output) + ".stdout").open("wb") as stdout, Path(str(output) + ".stderr").open("wb") as stderr:
        subprocess.run([str(argument) for argument in arguments], check=True, cwd=cwd, stdout=stdout, stderr=stderr)


def observe(root, executable, scenario, output):
    invocation = [sys.executable, "-B", str(HERE / "run_pthread_wait_witness.py"), str(root), *executable, scenario]
    with Path(str(output) + ".stdout").open("wb") as stdout, Path(str(output) + ".stderr").open("wb") as stderr:
        child = subprocess.Popen(invocation, cwd=ROOT, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            status = {"returncode": child.wait(timeout=20), "timed_out": False}
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            status = {"returncode": None, "timed_out": True}
    Path(str(output) + ".status.json").write_text(json.dumps(status, sort_keys=True) + "\n")
    return status


def same_observation(reference, candidate):
    return all(Path(str(reference) + suffix).read_bytes() == Path(str(candidate) + suffix).read_bytes()
               for suffix in (".status.json", ".stdout", ".stderr"))


def compile_workload(product, work):
    source = HERE / "owned_posix_signals_probe.c"
    output = work / "workload.o"
    dependencies = work / "workload.d"
    arguments = [product / "bin/crabc-cc-dynamic", "--dynamic-pie", "-std=c11", "-fno-builtin",
                 "-c", source, "-o", output]
    command(arguments, work / "compile")
    dependency_command = [compiler_contract.compiler(), "-nostdinc", "-isystem", str(product / "usr/include"),
                          "-std=c11", "-ffreestanding", "-fno-builtin", "-fstack-protector-strong", "-fPIE", "-M", str(source)]
    with dependencies.open("wb") as stream:
        subprocess.run(dependency_command, check=True, stdout=stream, cwd=ROOT, env=compiler_contract.clean_environment())
    # The driver supplies -nostdinc and its installed include directory. Reject
    # dependencies outside that product and the two exact local workload files.
    paths = dependencies.read_text().replace("\\\n", " ").split(":", 1)[1].split()
    local = {source.resolve(), (HERE / "owned_cancellation_proc_witness.h").resolve()}
    headers = {}
    for name in paths:
        path = Path(name).resolve(strict=True)
        if path not in local:
            if not path.is_relative_to(product / "usr/include"):
                raise ValueError(f"unowned signal header dependency: {path}")
            headers[str(path.relative_to(product))] = digest(path)
    for required in ("signal.h", "pthread.h", "sys/signalfd.h", "errno.h"):
        if "usr/include/" + required not in headers:
            raise ValueError(f"missing installed signal header dependency: {required}")
    receipt = {"command": list(map(str, arguments)), "dependency_audit_command": dependency_command,
               "compiler_sha256": digest(compiler_contract.compiler()), "object_sha256": digest(output),
               "product_manifest_sha256": digest(product / "share/crabc/manifest.json"),
               "sources": {str(path.relative_to(ROOT)): digest(path) for path in sorted(local)}, "headers": headers}
    (work / "compile.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return output


def audit_link(executable, receipt_path, workload, product, linkage):
    identity = product_evidence.validate_link(product, workload, executable, receipt_path, linkage)
    command(["readelf", "-hldW", executable], Path(str(executable) + ".elf"))
    return identity


def validate_contract(contract):
    if set(contract) != {"schema", "capability", "scenarios", "reused_cases", "primary_spelling_owner"}:
        raise ValueError("signal-full contract fields differ")
    if contract["schema"] != "crabc.x86_64-owned-posix-signals/v1" or contract["capability"] != "process.signal":
        raise ValueError("signal-full contract identity differs")
    scenarios, reused = contract["scenarios"], contract["reused_cases"]
    if not isinstance(scenarios, list) or tuple(scenarios) != REQUIRED_SCENARIOS:
        raise ValueError("signal-full scenario roster differs")
    if reused != ["signal-helpers", "io-cancellation", "pthread-signal", "posix-timers"]:
        raise ValueError("signal-full reused case roster differs")
    if any(name not in qualification.CASES for name in reused):
        raise ValueError("signal-full reused case is unregistered")
    owners = contract["primary_spelling_owner"]
    if not isinstance(owners, dict) or any(name not in scenarios + reused for name in owners):
        raise ValueError("signal-full spelling owner is unregistered")
    expected = next(row["symbols"] for row in tomllib.loads((HERE / "owned-posix-runtime-catalog.toml").read_text())["capability"] if row["id"] == "process.signal")
    symbols = [name for names in owners.values() for name in names]
    if len(set(symbols)) != len(symbols) or set(symbols) != set(expected):
        raise ValueError("signal-full frozen spelling partition differs")
    return contract


def parse_arguments(arguments):
    """Select optional installed products before any mutable evidence exists."""
    usage = "usage: run_owned_posix_signals.sh [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]"
    remaining = list(arguments)
    static = None
    if remaining and remaining[0] == "--static-sysroot":
        if len(remaining) < 2 or not remaining[1] or remaining[1].startswith("-"):
            raise ValueError(usage)
        static = remaining[1]
        remaining = remaining[2:]
    if len(remaining) > 1 or any(not argument or argument.startswith("-") for argument in remaining):
        raise ValueError(usage)
    return static, remaining[0] if remaining else None


def run(arguments):
    static_argument, dynamic_argument = parse_arguments(arguments)
    temporary = contained_directory(os.environ.get("TMPDIR", ""), "TMPDIR")
    product = contained_directory(dynamic_argument, "dynamic product") if dynamic_argument else None
    static = contained_directory(static_argument, "static product") if static_argument else None
    # Supplied inputs are validated before output creation or any producer runs.
    if product is not None:
        product_evidence._validate_dynamic_product(product)
    if static is not None:
        product_evidence._validate_static_product(static)
    include_static = static is not None or dynamic_argument is None
    contract = validate_contract(tomllib.loads(CONTRACT.read_text()))
    source_identity = qualification.source_digest()
    revision = qualification.git("rev-parse", "HEAD").decode().strip()
    scenarios = contract["scenarios"]
    work = Path(tempfile.mkdtemp(prefix="owned-posix-signals.", dir=temporary))
    print(f"signal-full evidence: {work}", flush=True)
    try:
        if product is None:
            product = work / "dynamic-sysroot"
            command([sys.executable, "-B", ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py", "--output", product], work / "dynamic-build")
        workload = compile_workload(product, work)
        command([ORACLE, "-static", "-fno-pie", "-no-pie", "-pthread", workload, "-o", work / "oracle"], work / "oracle-link")
        execution_root = work / "execution-root"
        shutil.copytree(product, execution_root, symlinks=True)
        shutil.copy2(work / "oracle", execution_root / "oracle")
        comparisons = []
        failures = []
        for scenario in scenarios:
            status = observe(execution_root, ["/oracle"], scenario, work / f"oracle-{scenario}")
            if status != {"returncode": 0, "timed_out": False}:
                failures.append(f"oracle:{scenario}")
        candidates = []
        links = []
        if include_static:
            if static is None:
                static = work / "static-sysroot"
                command([sys.executable, "-B", ROOT / "scripts/build_x86_64_owned_sysroot.py", "--output", static], work / "static-build")
            for mode in ("static", "static-pie"):
                executable = work / mode
                receipt = Path(str(executable) + ".crabc-link.json")
                command([static / "bin/crabc-cc", "-" + mode, "--link-receipt", receipt.name, workload, "-o", executable], work / f"link-{mode}", cwd=work)
                links.append(audit_link(executable, receipt, workload, static, mode))
                shutil.copy2(executable, execution_root / mode)
                candidates.append((mode, ["/" + mode]))
        for mode in ("pie", "non-pie"):
            executable = work / f"dynamic-{mode}"
            command([product / "bin/crabc-cc-dynamic", "--dynamic-" + mode, workload, "-o", executable], work / f"link-{mode}")
            links.append(audit_link(executable, Path(str(executable) + ".crabc-link.json"), workload, product, mode))
            shutil.copy2(executable, execution_root / executable.name)
            candidates.append((f"{mode}-kernel", ["/" + executable.name]))
            candidates.append((f"{mode}-direct", ["/lib/ld-crabc-x86_64.so.1", "/" + executable.name]))
        for mode, invocation in candidates:
            for scenario in scenarios:
                output = work / f"{mode}-{scenario}"
                observe(execution_root, invocation, scenario, output)
                equal = same_observation(work / f"oracle-{scenario}", output)
                comparisons.append({"mode": mode, "scenario": scenario, "equal": equal})
                if not equal:
                    failures.append(f"{mode}:{scenario}")
        if qualification.source_digest() != source_identity:
            raise ValueError("signal-full source changed during execution")
        receipt = {"source_sha256": source_identity, "revision": revision, "schema": "crabc.x86_64-owned-posix-signals/v1", "workload_object_sha256": digest(workload),
                   "contract_sha256": digest(CONTRACT), "product_manifest_sha256": digest(product / "share/crabc/manifest.json"),
                   "oracle_files": {str(path): digest(path) for path in (ORACLE, Path("/opt/musl-1.2.6/lib/libc.a"), Path("/opt/musl-1.2.6/.crabc-oracle"))}, "comparisons": comparisons,
                   "static_product_manifest_sha256": digest(static / "share/crabc/manifest.json") if static is not None else None,
                   "links": links, "reused_cases": contract["reused_cases"], "failures": failures}
        (work / "signal-full.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        if failures:
            raise ValueError("signal-full differential failed: " + ", ".join(failures))
        print("owned POSIX signals: PASS (residual spelling workload; retained raw status/stdout/stderr)")
    finally:
        for path in (work, *work.rglob("*")):
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o444 | (0o111 if path.is_dir() else 0))
        print(f"evidence: {work}", flush=True)


if __name__ == "__main__":
    try:
        run(sys.argv[1:])
    except (ValueError, OSError, subprocess.CalledProcessError, product_evidence.ProductEvidenceError) as error:
        print(f"owned POSIX signals: {error}", file=sys.stderr)
        raise SystemExit(1)
