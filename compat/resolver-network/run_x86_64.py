#!/usr/bin/env python3
"""Qualify the bounded resolver/network workload through owned x86 products.

The sole C object is translated with the pinned musl 1.2.6 headers.  It is
linked into a pinned-musl reference plus the installed owned static and
dynamic products, then every candidate runs in a disposable chroot with only
fixture ``/etc/hosts`` and ``/etc/resolv.conf``.  The outer container must have
only its loopback network namespace; the local UDP/TCP DNS fixture remains
outside each chroot but within that same private namespace.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MUSL_ROOT = Path("/opt/musl-1.2.6")
MUSL_COMPILER = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
SOURCE = ROOT / "compat/resolver-network/workload.c"
DNS_SERVER = ROOT / "compat/resolver-network/dns_server.py"
DEFAULT_WORK_ROOT = ROOT / ".work/x86_64/resolver-network"
DEFAULT_REPORT = ROOT / "compat/reports/resolver-network/x86_64/latest.json"
STATIC_FORMAT = "crabc-x86-64-sealed-static-driver-v1"
DYNAMIC_FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
DYNAMIC_INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
DNS_PORT = 53
ROLE_ADDRESSES = {"valid": "127.0.0.1", "drop": "127.0.0.2", "fallback": "127.0.0.3"}
RESOLVER_CONFIG = """# crabc native resolver-network fixture
nameserver 127.0.0.1
nameserver 127.0.0.2
nameserver 127.0.0.3
search search.test
options ndots:1 timeout:1 attempts:1
"""
HOSTS_CONFIG = "127.0.0.1 localhost\n::1 localhost\n"
EXPECTED_STDOUT = (
    "resolver.a=198.51.100.42\n"
    "resolver.aaaa=2001:db8::42\n"
    "resolver.nxdomain=HOST_NOT_FOUND\n"
    "resolver.nodata=NO_DATA\n"
    "resolver.malformed-wrong-id=accepted-valid\n"
    "resolver.cname=target.example.test\n"
    "resolver.tc-tcp=accepted-over-tcp\n"
    "resolver.search=searchhost.search.test\n"
    "resolver.fallback=second-server\n"
    "network.tcp4=loopback\n"
    "network.tcp6=loopback\n"
    "network.udp4=loopback\n"
    "network.udp6=loopback\n"
    "network.socketpair-sendmsg-recvmsg=ok\n"
    "network.ancillary-scm-rights=ok\n"
    "network.epoll=readiness\n"
    "network.shutdown-half-close=eof\n"
    "network.partial-send=short-write\n"
    "network.socket-timeout=EAGAIN\n"
    "network.eintr=EINTR\n"
    "network.nonblocking-recv=EAGAIN\n"
    "network.poll-select=readiness\n"
)
REQUIRED_SERVER_NAMES = {
    "a.example.test.", "aaaa.example.test.", "nxdomain.example.test.",
    "nodata.example.test.", "malformed.example.test.", "alias.example.test.",
    "tc.example.test.", "searchhost.search.test.", "fallback.example.test.",
}


class RunnerError(RuntimeError):
    """The native resolver-network gate cannot safely produce evidence."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_record(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise RunnerError(f"required regular artifact is absent or unsafe: {path}")
    return {"path": str(path), "sha256": sha256_file(path), "byte_length": path.stat().st_size}


def stream_record(value: bytes) -> dict[str, object]:
    return {
        "byte_length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "text": value.decode("utf-8", errors="replace"),
    }


def require_native_loopback_container() -> None:
    """Reject a host or a container that has any network interface but lo."""

    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise RunnerError("native resolver-network gate requires Linux/x86-64 without emulation")
    if os.geteuid() != 0:
        raise RunnerError("native resolver-network gate requires root only for private chroot execution")
    try:
        lines = Path("/proc/net/dev").read_text(encoding="ascii").splitlines()[2:]
    except OSError as error:
        raise RunnerError("cannot inspect the container network namespace") from error
    interfaces = {line.split(":", 1)[0].strip() for line in lines if ":" in line}
    if interfaces != {"lo"}:
        raise RunnerError(
            "native resolver-network gate requires Docker --network none; "
            f"observed interfaces: {', '.join(sorted(interfaces)) or 'none'}"
        )
    try:
        routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    except OSError as error:
        raise RunnerError("cannot inspect the container route table") from error
    if any(len(line.split()) >= 3 and line.split()[1:3] == ["00000000", "00000000"] for line in routes):
        raise RunnerError("native resolver-network gate refuses a default route")


def physical_directory(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise RunnerError(f"{description} is absent or unsafe: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise RunnerError(f"cannot resolve {description}: {path}") from error


def physical_regular(path: Path, description: str, *, executable: bool = False) -> Path:
    if path.is_symlink() or not path.is_file() or (executable and not os.access(path, os.X_OK)):
        raise RunnerError(f"{description} is absent or unsafe: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise RunnerError(f"cannot resolve {description}: {path}") from error


def pinned_musl_loader() -> dict[str, object]:
    """Record the fixed musl loader/libc identity without treating its alias as unsafe."""

    loader = MUSL_ROOT / "lib/ld-musl-x86_64.so.1"
    libc = physical_regular(MUSL_ROOT / "lib/libc.so", "pinned musl libc", executable=True)
    if not loader.is_symlink() or os.readlink(loader) != str(MUSL_ROOT / "lib/libc.so"):
        raise RunnerError("pinned musl loader alias drifted")
    if loader.resolve(strict=True) != libc:
        raise RunnerError("pinned musl loader alias does not resolve to pinned libc")
    return {"loader_alias": {"path": str(loader), "target": os.readlink(loader)}, "libc": artifact_record(libc)}


def private_work_root(path: Path) -> Path:
    checkout = ROOT.resolve(strict=True)
    boundary = checkout / ".work"
    absolute = path if path.is_absolute() else checkout / path
    try:
        resolved = absolute.resolve(strict=False)
        resolved.relative_to(boundary)
    except (OSError, ValueError) as error:
        raise RunnerError(f"native resolver-network work root must stay below {boundary}") from error
    resolved.mkdir(parents=True, exist_ok=True)
    return physical_directory(resolved, "native resolver-network work root")


def command_record(
    arguments: Sequence[str], *, cwd: Path, timeout: float, environment: Mapping[str, str] | None = None
) -> dict[str, object]:
    env = dict(environment) if environment is not None else None
    try:
        result = subprocess.run(
            list(arguments), cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout,
        )
        return {"argv": list(arguments), "status": result.returncode,
                "stdout": stream_record(result.stdout), "stderr": stream_record(result.stderr)}
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, bytes) else b""
        stderr = error.stderr if isinstance(error.stderr, bytes) else b""
        return {"argv": list(arguments), "status": "TIMEOUT",
                "stdout": stream_record(stdout), "stderr": stream_record(stderr)}
    except OSError as error:
        return {"argv": list(arguments), "status": f"EXEC_ERROR:{error.errno or 'unknown'}",
                "stdout": stream_record(b""), "stderr": stream_record(str(error).encode("utf-8"))}


def require_success(record: Mapping[str, object], description: str) -> None:
    if record.get("status") != 0:
        raise RunnerError(f"{description} failed: {record.get('status')}")


def run_checked(arguments: Sequence[str], *, cwd: Path, timeout: float, description: str) -> dict[str, object]:
    record = command_record(arguments, cwd=cwd, timeout=timeout)
    require_success(record, description)
    return record


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-sysroot", type=Path, required=True)
    parser.add_argument("--dynamic-sysroot", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 120:
        parser.error("--timeout must be > 0 and <= 120")
    return args


def static_manifest(sysroot: Path) -> dict[str, object]:
    """Validate the static tree as an exact installed owned product."""

    manifest_path = physical_regular(sysroot / "share/crabc/manifest.json", "static sysroot manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RunnerError("static sysroot manifest is unreadable") from error
    if not isinstance(manifest, dict) or manifest.get("format") != "crabc-x86-64-owned-static-sysroot-v1":
        raise RunnerError("static sysroot has the wrong installed product format")
    installed = manifest.get("installed")
    if not isinstance(installed, dict) or not isinstance(installed.get("files"), dict):
        raise RunnerError("static sysroot manifest lacks its installed file hashes")
    expected = installed["files"]
    observed: set[str] = set()
    for entry in sorted(sysroot.rglob("*")):
        relative = entry.relative_to(sysroot).as_posix()
        if entry.is_symlink():
            raise RunnerError(f"static sysroot contains a symlink: {relative}")
        if entry.is_dir():
            continue
        if not entry.is_file():
            raise RunnerError(f"static sysroot contains a nonregular entry: {relative}")
        if relative != "share/crabc/manifest.json":
            observed.add(relative)
    if observed != set(expected):
        raise RunnerError("static sysroot manifest payload roster drifted")
    for relative, digest in expected.items():
        if not isinstance(relative, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RunnerError("static sysroot manifest has an invalid payload hash")
        artifact = physical_regular(sysroot / relative, f"static sysroot payload {relative}")
        if sha256_file(artifact) != digest:
            raise RunnerError(f"static sysroot payload hash drifted: {relative}")
    for required in ("bin/crabc-cc", "usr/lib/libc.a", "usr/lib/libcrabc-builtins.a", "usr/lib/crt1.o", "usr/lib/rcrt1.o", "usr/lib/crti.o", "usr/lib/crtn.o"):
        physical_regular(sysroot / required, f"static sysroot required payload {required}", executable=required.startswith("bin/"))
    return manifest


def dynamic_manifest(sysroot: Path) -> dict[str, object]:
    """Validate the dynamic tree and its sole compatibility interpreter alias."""

    manifest_path = physical_regular(sysroot / "share/crabc/manifest.json", "dynamic sysroot manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RunnerError("dynamic sysroot manifest is unreadable") from error
    aliases = {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}
    if not isinstance(manifest, dict) or (
        manifest.get("schema"), manifest.get("format"), manifest.get("target"), manifest.get("symlinks")
    ) != (1, DYNAMIC_FORMAT, "x86_64-unknown-linux-musl", aliases):
        raise RunnerError("dynamic sysroot has the wrong installed product format")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RunnerError("dynamic sysroot manifest lacks payload hashes")
    observed: set[str] = set()
    seen_aliases: dict[str, str] = {}
    for entry in sorted(sysroot.rglob("*")):
        relative = entry.relative_to(sysroot).as_posix()
        if entry.is_symlink():
            seen_aliases[relative] = os.readlink(entry)
        elif entry.is_dir():
            continue
        elif entry.is_file():
            if relative != "share/crabc/manifest.json":
                observed.add(relative)
        else:
            raise RunnerError(f"dynamic sysroot contains a nonregular entry: {relative}")
    if observed != set(files) or seen_aliases != aliases:
        raise RunnerError("dynamic sysroot manifest payload roster drifted")
    for relative, digest in files.items():
        if not isinstance(relative, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RunnerError("dynamic sysroot manifest has an invalid payload hash")
        artifact = physical_regular(sysroot / relative, f"dynamic sysroot payload {relative}")
        if sha256_file(artifact) != digest:
            raise RunnerError(f"dynamic sysroot payload hash drifted: {relative}")
    for required in ("bin/crabc-cc-dynamic", "lib/ld-crabc-x86_64.so.1", "usr/lib/libc.so", "usr/lib/libcrabc-builtins.a", "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/crti.o", "usr/lib/crtn.o", "usr/lib/crabc-dynamic-attach.o"):
        physical_regular(sysroot / required, f"dynamic sysroot required payload {required}", executable=required.startswith(("bin/", "lib/")))
    return manifest


def compiler_resource_directory(compiler: Path, timeout: float) -> Path:
    record = run_checked([str(compiler), "-print-file-name=include"], cwd=ROOT, timeout=timeout, description="pinned musl compiler resource query")
    stdout = record["stdout"]
    assert isinstance(stdout, Mapping)
    value = str(stdout["text"]).strip()
    return physical_directory(Path(value), "pinned musl compiler resource headers")


def header_trace(compiler: Path, resource: Path, output: Path, timeout: float) -> dict[str, object]:
    """Require the shared object to see pinned musl, never installed crabc headers."""

    try:
        process = subprocess.run(
            [str(compiler), "-std=c11", "-D_GNU_SOURCE", "-nostdinc", "-isystem", str(MUSL_ROOT / "include"),
             "-isystem", str(resource), "-E", "-H", str(SOURCE)],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerError("pinned-musl resolver workload header trace did not complete") from error
    record = {"argv": [str(compiler), "-std=c11", "-D_GNU_SOURCE", "-nostdinc", "-isystem", str(MUSL_ROOT / "include"),
                       "-isystem", str(resource), "-E", "-H", str(SOURCE)], "status": process.returncode,
              "stderr": stream_record(process.stderr)}
    require_success(record, "pinned-musl resolver workload header trace")
    trace = process.stderr.decode("utf-8", errors="replace")
    output.write_text(trace, encoding="utf-8")
    if str(MUSL_ROOT / "include") not in trace:
        raise RunnerError("resolver workload did not include pinned musl headers")
    forbidden = (str(ROOT / "include"), "/usr/include")
    if any(marker in trace for marker in forbidden):
        raise RunnerError("resolver workload header trace escaped pinned musl/resource headers")
    return {"record": record, "trace": artifact_record(output)}


def compile_object(compiler: Path, resource: Path, output: Path, timeout: float) -> dict[str, object]:
    record = run_checked(
        [str(compiler), "-std=c11", "-D_GNU_SOURCE", "-O2", "-fno-builtin", "-fno-stack-protector", "-fPIE",
         "-nostdinc", "-isystem", str(MUSL_ROOT / "include"), "-isystem", str(resource), "-c", str(SOURCE), "-o", str(output)],
        cwd=ROOT, timeout=timeout, description="single pinned-musl-header resolver workload compilation",
    )
    object_record = artifact_record(output)
    header = run_checked(["readelf", "-hW", str(output)], cwd=ROOT, timeout=timeout, description="resolver object ELF inspection")
    text = header["stdout"]
    assert isinstance(text, Mapping)
    if "REL (Relocatable file)" not in str(text["text"]) or "Advanced Micro Devices X86-64" not in str(text["text"]):
        raise RunnerError("shared resolver workload object is not x86-64 ET_REL")
    return {"compile": record, "object": object_record, "elf_header": header}


def static_receipt_audit(sysroot: Path, mode: str, object_file: Path, output: Path, receipt: Path) -> dict[str, object]:
    try:
        data = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RunnerError(f"static {mode} receipt is unreadable") from error
    selected = {"--static-et-exec": ("static-et-exec", "crt1.o", "ET_EXEC"), "--static-pie": ("static-pie", "rcrt1.o", "ET_DYN")}[mode]
    if not isinstance(data, dict) or data.get("schema") != 1 or data.get("format") != STATIC_FORMAT:
        raise RunnerError(f"static {mode} receipt format drifted")
    mode_data = data.get("mode")
    if not isinstance(mode_data, dict) or (
        mode_data.get("id"), mode_data.get("crt_object"), mode_data.get("elf_type"), mode_data.get("interpreter")
    ) != (*selected, "absent"):
        raise RunnerError(f"static {mode} receipt mode drifted")
    runtime = [("crt-entry", sysroot / "usr/lib" / selected[1]), ("crt-prologue", sysroot / "usr/lib/crti.o"),
               ("libc", sysroot / "usr/lib/libc.a"), ("builtins", sysroot / "usr/lib/libcrabc-builtins.a"),
               ("crt-epilogue", sysroot / "usr/lib/crtn.o")]
    expected = [{"role": role, "path": str(path.relative_to(sysroot)), "sha256": sha256_file(path)} for role, path in runtime]
    expected.append({"role": "application", "path": str(object_file.resolve()), "sha256": sha256_file(object_file)})
    if data.get("input_receipts") != expected:
        raise RunnerError(f"static {mode} receipt does not bind the exact owned runtime and shared object")
    output_record = {"path": str(output), "sha256": sha256_file(output)}
    if data.get("output") != output_record:
        raise RunnerError(f"static {mode} receipt output identity drifted")
    for field, path in (("map", receipt.with_suffix(".map")), ("trace", receipt.with_suffix(".trace"))):
        if data.get(field) != {"path": path.name, "sha256": sha256_file(path)}:
            raise RunnerError(f"static {mode} receipt {field} identity drifted")
    trace = receipt.with_suffix(".trace").read_text(encoding="utf-8", errors="strict")
    direct = {str(object_file.resolve()), *(str(path) for role, path in runtime if role not in {"libc", "builtins"})}
    archives = {str(path) for role, path in runtime if role in {"libc", "builtins"}}
    seen_direct: set[str] = set()
    seen_archives: set[str] = set()
    for line in (line.strip() for line in trace.splitlines() if line.strip()):
        if line in direct:
            seen_direct.add(line)
        elif line in archives or any(line.startswith(archive + "(") and line.endswith(")") for archive in archives):
            seen_archives.add(next(archive for archive in archives if line == archive or (line.startswith(archive + "(") and line.endswith(")"))))
        else:
            raise RunnerError(f"static {mode} link trace consumed an unowned input: {line}")
    if seen_direct != direct or seen_archives != archives or any(marker in trace for marker in ("/opt/musl", "libgcc", "compiler-rt", "ld-linux", "libc.so.6")):
        raise RunnerError(f"static {mode} link trace escaped the exact owned input boundary")
    return {"receipt": artifact_record(receipt), "trace": artifact_record(receipt.with_suffix(".trace")), "map": artifact_record(receipt.with_suffix(".map"))}


def dynamic_receipt_audit(sysroot: Path, mode: str, object_file: Path, output: Path, receipt: Path) -> dict[str, object]:
    try:
        data = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RunnerError(f"dynamic {mode} receipt is unreadable") from error
    selected = {"--dynamic-pie": ("pie", "Scrt1.o"), "--dynamic-non-pie": ("exec", "crt1.o")}[mode]
    if not isinstance(data, dict) or (
        data.get("schema"), data.get("format"), data.get("mode"), data.get("binding"), data.get("runtime_imports"), data.get("application_runpath"),
        data.get("output_path"), data.get("output_sha256"), data.get("manifest_sha256"), data.get("application_dsos")
    ) != (1, DYNAMIC_FORMAT, selected[0], "now", [], "/usr/lib", str(output.resolve()), sha256_file(output), sha256_file(sysroot / "share/crabc/manifest.json"), {}):
        raise RunnerError(f"dynamic {mode} receipt contract drifted")
    library = sysroot / "usr/lib"
    runtime = [library / "crti.o", library / "libc.so", library / "crtn.o", library / selected[1], library / "crabc-dynamic-attach.o"]
    archive = library / "libcrabc-builtins.a"
    expected_inputs = [{"path": str(path), "sha256": sha256_file(path)} for path in [*runtime, object_file.resolve(), archive]]
    if data.get("input_receipts") != expected_inputs:
        raise RunnerError(f"dynamic {mode} receipt does not bind the exact owned runtime and shared object")
    if data.get("owned_runtime_inputs") != sorted(path.relative_to(sysroot).as_posix() for path in [*runtime, archive]):
        raise RunnerError(f"dynamic {mode} runtime receipt roster drifted")
    trace = data.get("link_trace")
    if not isinstance(trace, list) or any(not isinstance(line, str) for line in trace):
        raise RunnerError(f"dynamic {mode} link trace is invalid")
    allowed = {*(str(path) for path in runtime), str(object_file.resolve())}
    seen: set[str] = set()
    for line in trace:
        if line in allowed:
            seen.add(line)
        elif line == str(archive) or (line.startswith(str(archive) + "(") and line.endswith(")")):
            continue
        else:
            raise RunnerError(f"dynamic {mode} link trace consumed an unowned input: {line}")
    if seen != allowed:
        raise RunnerError(f"dynamic {mode} link trace omitted an exact direct input")
    return {"receipt": artifact_record(receipt), "link_trace": trace, "input_count": len(expected_inputs)}


def unresolved_symbol_rows(symbol_text: str) -> list[str]:
    """Return non-null ELF symbol-table rows whose section index is ``UND``.

    Every ELF table has index zero, a mandated undefined *null* symbol.  It is
    not a link dependency, including in a fully static PIE, so scanning for the
    word ``UND`` alone would reject every valid candidate.
    """

    unresolved: list[str] = []
    for line in symbol_text.splitlines():
        fields = line.split()
        if len(fields) >= 7 and re.fullmatch(r"[1-9][0-9]*:", fields[0]) and fields[6] == "UND":
            unresolved.append(line)
    return unresolved


def elf_audit(path: Path, *, mode: str, dynamic: bool) -> dict[str, object]:
    header = run_checked(["readelf", "-hW", str(path)], cwd=ROOT, timeout=10, description=f"{mode} ELF header inspection")
    programs = run_checked(["readelf", "-lW", str(path)], cwd=ROOT, timeout=10, description=f"{mode} ELF program inspection")
    dynamic_record = command_record(["readelf", "-dW", str(path)], cwd=ROOT, timeout=10)
    symbols = run_checked(["readelf", "-sW", str(path)], cwd=ROOT, timeout=10, description=f"{mode} ELF symbol inspection")
    header_text = str(header["stdout"]["text"])
    program_text = str(programs["stdout"]["text"])
    dynamic_text = str(dynamic_record["stdout"]["text"])
    symbol_text = str(symbols["stdout"]["text"])
    expected_type = "DYN" if mode in {"static-pie", "dynamic-pie"} else "EXEC"
    if "Advanced Micro Devices X86-64" not in header_text or not re.search(rf"Type:\s+{expected_type}\b", header_text):
        raise RunnerError(f"{mode} ELF type or machine drifted")
    text = "\n".join((header_text, program_text, dynamic_text, symbol_text))
    forbidden = ("ld-musl-", "libc.musl-", "/opt/musl-", "libc.so.6", "ld-linux", "libgcc", "compiler-rt")
    if any(marker in text for marker in forbidden):
        raise RunnerError(f"{mode} ELF leaks a foreign runtime marker")
    if dynamic:
        if DYNAMIC_INTERPRETER not in program_text or "Shared library: [libc.so]" not in dynamic_text or "Library runpath: [/usr/lib]" not in dynamic_text:
            raise RunnerError(f"{mode} ELF does not bind the canonical owned dynamic runtime")
    elif "INTERP" in program_text or "NEEDED" in dynamic_text:
        raise RunnerError(f"{mode} static ELF has a dynamic-runtime dependency")
    # A static executable has no provider for a non-null ``UND`` row.  The
    # dynamic driver, however, records an exact owned ``libc.so`` input,
    # emits the sole DT_NEEDED entry below, and uses --no-undefined. Its
    # ordinary imports are therefore the intended dynamic ABI boundary rather
    # than unresolved static-link residue.
    if not dynamic and unresolved_symbol_rows(symbol_text):
        raise RunnerError(f"{mode} ELF retains an unresolved symbol")
    return {"artifact": artifact_record(path), "header": header, "program_headers": programs, "dynamic": dynamic_record, "symbols": symbols}


def link_artifacts(static_root: Path, dynamic_root: Path, object_file: Path, work: Path, timeout: float) -> dict[str, dict[str, object]]:
    artifacts: dict[str, dict[str, object]] = {}
    work.mkdir()
    static_driver = physical_regular(static_root / "bin/crabc-cc", "sealed static driver", executable=True)
    for option, label in (("--static-et-exec", "static-et-exec"), ("--static-pie", "static-pie")):
        directory = work / label
        directory.mkdir()
        output = directory / "workload"
        receipt = directory / "link.receipt.json"
        # The sealed driver deliberately binds receipt sidecars to its caller
        # directory and rejects an absolute sidecar path.
        command = command_record([str(static_driver), option, "--link-receipt", receipt.name, str(object_file), "-o", str(output)], cwd=directory, timeout=timeout)
        if command["status"] != 0:
            stderr = command["stderr"]
            assert isinstance(stderr, Mapping)
            raise RunnerError(f"owned {label} link failed: {command['status']}: {stderr['text']}")
        artifacts[label] = {"link": command, "receipt_audit": static_receipt_audit(static_root, option, object_file, output, receipt), "elf": elf_audit(output, mode=label, dynamic=False), "path": str(output)}
    dynamic_driver = physical_regular(dynamic_root / "bin/crabc-cc-dynamic", "sealed dynamic driver", executable=True)
    for option, label in (("--dynamic-pie", "dynamic-pie"), ("--dynamic-non-pie", "dynamic-non-pie")):
        directory = work / label
        directory.mkdir()
        output = directory / "workload"
        command = command_record([str(dynamic_driver), option, str(object_file), "-o", str(output)], cwd=directory, timeout=timeout)
        if command["status"] != 0:
            stderr = command["stderr"]
            assert isinstance(stderr, Mapping)
            raise RunnerError(f"owned {label} link failed: {command['status']}: {stderr['text']}")
        receipt = Path(f"{output}.crabc-link.json")
        artifacts[label] = {"link": command, "receipt_audit": dynamic_receipt_audit(dynamic_root, option, object_file, output, receipt), "elf": elf_audit(output, mode=label, dynamic=True), "path": str(output)}
    return artifacts


def link_reference(compiler: Path, object_file: Path, output: Path, timeout: float) -> dict[str, object]:
    # The pinned musl compiler's default PIE form is ET_DYN without an
    # interpreter and faults before _start on this image.  The reference is a
    # static oracle, so force its conventional runnable ET_EXEC form instead
    # of comparing candidates to a malformed reference process.
    command = run_checked([str(compiler), "-static", "-no-pie", str(object_file), "-o", str(output)], cwd=ROOT, timeout=timeout, description="pinned-musl static resolver reference link")
    return {"link": command, "elf": elf_audit(output, mode="static-et-exec", dynamic=False), "path": str(output)}


def write_fixture_files(root: Path) -> dict[str, object]:
    etc = root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    hosts = etc / "hosts"
    resolv = etc / "resolv.conf"
    for path, contents in ((hosts, HOSTS_CONFIG), (resolv, RESOLVER_CONFIG)):
        if path.exists() or path.is_symlink():
            raise RunnerError(f"chroot fixture path is already occupied: {path}")
        path.write_text(contents, encoding="ascii")
        path.chmod(0o644)
    return {"hosts": artifact_record(hosts), "resolv_conf": artifact_record(resolv)}


def static_chroot(binary: Path, root: Path) -> dict[str, object]:
    root.mkdir()
    fixture = write_fixture_files(root)
    candidate = root / "workload"
    shutil.copy2(binary, candidate)
    candidate.chmod(0o755)
    fixture["binary"] = artifact_record(candidate)
    return fixture


def dynamic_chroot(binary: Path, sysroot: Path, root: Path) -> dict[str, object]:
    shutil.copytree(sysroot, root, symlinks=True)
    fixture = write_fixture_files(root)
    candidate = root / "workload"
    shutil.copy2(binary, candidate)
    candidate.chmod(0o755)
    fixture["binary"] = artifact_record(candidate)
    fixture["loader"] = artifact_record(root / DYNAMIC_INTERPRETER.lstrip("/"))
    return fixture



def run_chroot_raw(root: Path, argv: Sequence[str], timeout: float) -> tuple[int | str, bytes, bytes]:
    chroot = shutil.which("chroot")
    if chroot is None or not os.path.isabs(chroot):
        raise RunnerError("requires an absolute chroot command")
    try:
        process = subprocess.run([chroot, str(root), *argv], cwd=ROOT, env={"LC_ALL": "C", "PATH": "/bin"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)
        return process.returncode, process.stdout, process.stderr
    except subprocess.TimeoutExpired as error:
        return "TIMEOUT", error.stdout if isinstance(error.stdout, bytes) else b"", error.stderr if isinstance(error.stderr, bytes) else b""
    except OSError as error:
        return f"EXEC_ERROR:{error.errno or 'unknown'}", b"", str(error).encode("utf-8")


def start_server(events_path: Path) -> tuple[subprocess.Popen[bytes], dict[str, object]]:
    process = subprocess.Popen([sys.executable, "-B", str(DNS_SERVER), "--events", str(events_path)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(timeout=5.0):
            raise RunnerError("loopback DNS server did not publish readiness")
        line = process.stdout.readline()
        try:
            ready = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RunnerError("loopback DNS server readiness is invalid") from error
        if not isinstance(ready, dict) or ready.get("protocol") != "resolver-network-dns-v1":
            raise RunnerError("loopback DNS server protocol drifted")
        endpoints = ready.get("endpoints")
        if not isinstance(endpoints, dict):
            raise RunnerError("loopback DNS server has no endpoint manifest")
        for role, address in ROLE_ADDRESSES.items():
            endpoint = endpoints.get(role)
            if not isinstance(endpoint, dict) or (endpoint.get("ipv4"), endpoint.get("port"), endpoint.get("udp4_port"), endpoint.get("tcp4_port")) != (address, DNS_PORT, DNS_PORT, DNS_PORT):
                raise RunnerError(f"loopback DNS server endpoint drifted for {role}")
        return process, ready
    except Exception:
        stop_server(process)
        raise
    finally:
        selector.close()


def stop_server(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3.0)


def load_events(path: Path) -> tuple[list[dict[str, object]], str | None]:
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
        events = decoded.get("events")
        if not isinstance(events, list):
            return [], "DNS event record has no events list"
        return [event for event in events if isinstance(event, dict)], None
    except (OSError, json.JSONDecodeError) as error:
        return [], str(error)


def event_contract(events: Iterable[Mapping[str, object]]) -> dict[str, object]:
    events = list(events)
    names = {str(event["name"]) for event in events if "name" in event}
    count = lambda predicate: sum(1 for event in events if predicate(event))
    malformed = any(event.get("name") == "malformed.example.test." and event.get("action") == "malformed-sequence" for event in events)
    valid_drop = count(lambda event: event.get("role") == "valid" and event.get("name") == "fallback.example.test." and event.get("action") == "drop")
    drop = count(lambda event: event.get("role") == "drop" and event.get("action") == "drop")
    fallback = count(lambda event: event.get("role") == "fallback" and event.get("name") == "fallback.example.test.")
    cname = any(event.get("name") == "alias.example.test." and event.get("action") == "cname" for event in events)
    tc_udp = any(event.get("name") == "tc.example.test." and event.get("transport") == "udp" and event.get("action") == "tc-sequence" for event in events)
    tc_tcp = any(event.get("name") == "tc.example.test." and event.get("transport") == "tcp" and event.get("action") == "answer" for event in events)
    passed = REQUIRED_SERVER_NAMES <= names and malformed and valid_drop >= 2 and drop >= 2 and fallback >= 2 and cname and tc_udp and tc_tcp
    return {"required_names_seen": sorted(REQUIRED_SERVER_NAMES & names), "required_names_missing": sorted(REQUIRED_SERVER_NAMES - names), "malformed_sequence_seen": malformed, "valid_fallback_drop_observations": valid_drop, "drop_endpoint_observations": drop, "fallback_query_observations": fallback, "cname_query_seen": cname, "tc_udp_truncated_seen": tc_udp, "tc_tcp_retry_seen": tc_tcp, "passed": passed}


def outcome(status: int | str, stdout: bytes, stderr: bytes) -> dict[str, object]:
    return {"exit_status": status, "stdout": stream_record(stdout), "stderr": stream_record(stderr)}


def compare(reference: Mapping[str, object], candidate: Mapping[str, object]) -> dict[str, bool]:
    return {"exit_status_match": reference["exit_status"] == candidate["exit_status"], "stdout_match": reference["stdout"] == candidate["stdout"], "stderr_match": reference["stderr"] == candidate["stderr"]}


def publish_report(source: Path, destination: Path) -> Path:
    destination = destination if destination.is_absolute() else ROOT / destination
    try:
        destination.resolve(strict=False).relative_to(ROOT.resolve(strict=True) / "compat/reports")
    except (OSError, ValueError) as error:
        raise RunnerError("published resolver report must stay below compat/reports") from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise RunnerError("published resolver report path is a symlink")
    with tempfile.NamedTemporaryFile(prefix=".resolver-network-", dir=destination.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(source.read_bytes())
        stream.flush()
        os.fsync(stream.fileno())
    try:
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return physical_regular(destination, "published native resolver-network report")


def write_report(path: Path, report: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    with temporary.open("rb") as stream:
        os.fsync(stream.fileno())
    temporary.replace(path)


def run(args: argparse.Namespace) -> tuple[dict[str, object], Path, Path | None]:
    require_native_loopback_container()
    work_parent = private_work_root(args.work_root)
    state = Path(tempfile.mkdtemp(prefix="run-", dir=work_parent))
    report_path = state / "report.json"
    report: dict[str, object] = {"schema_version": 1, "runner": "crabc-resolver-network-native-x86", "result": "fail", "passed": False, "state_root": str(state), "published_report": str(args.report), "contract": {"network_namespace": "Docker --network none: loopback is the only observed interface and no default route is admitted", "conventional_files": "each execution chroot has only runner-written etc/hosts and etc/resolv.conf; the host/container /etc is never written", "source_object": "one workload.c object translated with pinned musl 1.2.6 headers and linked unchanged into every reference/candidate artifact", "candidate_modes": ["static-et-exec", "static-pie", "dynamic-pie ordinary", "dynamic-pie direct-entry", "dynamic-non-pie ordinary", "dynamic-non-pie direct-entry"], "comparison": "raw exit status, stdout, and stderr equality; no normalization"}}
    try:
        compiler = physical_regular(MUSL_COMPILER, "pinned musl compiler", executable=True)
        physical_directory(MUSL_ROOT, "pinned musl root")
        physical_directory(MUSL_ROOT / "include", "pinned musl headers")
        musl_loader = pinned_musl_loader()
        physical_regular(SOURCE, "resolver workload source")
        physical_regular(DNS_SERVER, "loopback DNS fixture")
        static_state: dict[str, object] = {"source": "caller-prepared"}
        dynamic_state: dict[str, object] = {"source": "caller-prepared"}
        static_root = physical_directory(args.static_sysroot, "prepared static sysroot")
        dynamic_root = physical_directory(args.dynamic_sysroot, "prepared dynamic sysroot")
        static_state["path"] = str(static_root)
        dynamic_state["path"] = str(dynamic_root)
        static_state["manifest"] = static_manifest(static_root)
        dynamic_state["manifest"] = dynamic_manifest(dynamic_root)
        report["products"] = {"static": static_state, "dynamic": dynamic_state}
        resource = compiler_resource_directory(compiler, args.timeout)
        object_file = state / "workload.o"
        report["translation"] = {"compiler": artifact_record(compiler), "musl_root": str(MUSL_ROOT), "musl_loader": musl_loader, "source": artifact_record(SOURCE), "headers": header_trace(compiler, resource, state / "headers.trace", args.timeout), "object": compile_object(compiler, resource, object_file, args.timeout)}
        reference_file = state / "reference"
        report["reference"] = link_reference(compiler, object_file, reference_file, args.timeout)
        artifacts = link_artifacts(static_root, dynamic_root, object_file, state / "artifacts", args.timeout)
        report["candidates"] = artifacts
        chroots = state / "chroots"
        chroots.mkdir()
        layouts = {
            "reference": static_chroot(reference_file, chroots / "reference"),
            "static-et-exec": static_chroot(Path(str(artifacts["static-et-exec"]["path"])), chroots / "static-et-exec"),
            "static-pie": static_chroot(Path(str(artifacts["static-pie"]["path"])), chroots / "static-pie"),
            "dynamic-pie": dynamic_chroot(Path(str(artifacts["dynamic-pie"]["path"])), dynamic_root, chroots / "dynamic-pie"),
            "dynamic-non-pie": dynamic_chroot(Path(str(artifacts["dynamic-non-pie"]["path"])), dynamic_root, chroots / "dynamic-non-pie"),
        }
        report["chroots"] = layouts
        events_path = state / "dns-events.json"
        server, ready = start_server(events_path)
        try:
            reference_outcome = outcome(*run_chroot_raw(chroots / "reference", ["/workload"], args.timeout))
            runs: dict[str, dict[str, object]] = {
                "static-et-exec": outcome(*run_chroot_raw(chroots / "static-et-exec", ["/workload"], args.timeout)),
                "static-pie": outcome(*run_chroot_raw(chroots / "static-pie", ["/workload"], args.timeout)),
                "dynamic-pie-ordinary": outcome(*run_chroot_raw(chroots / "dynamic-pie", ["/workload"], args.timeout)),
                "dynamic-pie-direct-entry": outcome(*run_chroot_raw(chroots / "dynamic-pie", [DYNAMIC_INTERPRETER, "/workload"], args.timeout)),
                "dynamic-non-pie-ordinary": outcome(*run_chroot_raw(chroots / "dynamic-non-pie", ["/workload"], args.timeout)),
                "dynamic-non-pie-direct-entry": outcome(*run_chroot_raw(chroots / "dynamic-non-pie", [DYNAMIC_INTERPRETER, "/workload"], args.timeout)),
            }
        finally:
            stop_server(server)
        events, event_error = load_events(events_path)
        comparisons = {name: compare(reference_outcome, item) for name, item in runs.items()}
        reference_expected = reference_outcome["exit_status"] == 0 and reference_outcome["stdout"] == stream_record(EXPECTED_STDOUT.encode("utf-8")) and reference_outcome["stderr"] == stream_record(b"")
        candidate_expected = {name: item["exit_status"] == 0 and item["stdout"] == stream_record(EXPECTED_STDOUT.encode("utf-8")) and item["stderr"] == stream_record(b"") for name, item in runs.items()}
        dns = event_contract(events)
        if event_error is not None:
            dns["passed"] = False
            dns["error"] = event_error
        passed = reference_expected and all(candidate_expected.values()) and all(all(item.values()) for item in comparisons.values()) and dns["passed"] is True
        report["execution"] = {"reference": reference_outcome, "candidates": runs, "comparisons": comparisons, "reference_expected": reference_expected, "candidate_expected": candidate_expected, "expected_stdout": stream_record(EXPECTED_STDOUT.encode("utf-8")), "dns_server": {"ready": ready, "events": events, "event_contract": dns}}
        report["passed"] = passed
        report["result"] = "pass" if passed else "fail"
    except RunnerError as error:
        report["error"] = str(error)
    write_report(report_path, report)
    published = publish_report(report_path, args.report) if report["passed"] is True else None
    return report, report_path, published


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report, report_path, published = run(args)
    except RunnerError as error:
        print(f"native resolver-network: ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"state_root": str(report_path.parent), "report": str(report_path), "latest_report": str(published) if published is not None else None, "passed": report.get("passed") is True}, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
