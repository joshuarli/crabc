#!/usr/bin/env python3
"""Reduced pinned-native correctness smoke for legacy memory observers.

This is not a benchmark or release qualification run. It compiles the
observer-only ELF identities with pinned musl, exercises representative frozen
workload routes at reduced counts, and checks every R/C lifetime ordering that
has a distinct source-local boundary.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import pty
import select
import shutil
import subprocess
import sys
import termios
import tty
from pathlib import Path
from typing import Callable, Sequence


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORK = ROOT / ".work/x86_64/native-performance-observers-smoke"
EXPECTED_STDOUT = b"ok\n"
READY_ENV = "CRABC_PERF_OBSERVER_READY_FD"
CONTINUE_ENV = "CRABC_PERF_OBSERVER_CONTINUE_FD"
DIAGNOSTIC_MARKER_ENV = "CRABC_PERF_MARKER_FD"
READY_FD = 97
CONTINUE_FD = 98
SPAN_BYTES = 128 * 1024 * 1024
SPAN_NEEDLE = b"needle"


class SmokeError(RuntimeError):
    """The observer did not preserve its frozen source contract."""


def work_directory(path: Path) -> Path:
    boundary = (ROOT / ".work/x86_64").resolve()
    candidate = path.resolve()
    try:
        candidate.relative_to(boundary)
    except ValueError as error:
        raise SmokeError(f"work directory must remain below {boundary}: {candidate}") from error
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def clean_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop(READY_ENV, None)
    environment.pop(CONTINUE_ENV, None)
    environment.pop(DIAGNOSTIC_MARKER_ENV, None)
    return environment


def compile_checked(compiler: str, arguments: Sequence[str]) -> None:
    result = subprocess.run(
        [compiler, "-std=c11", "-O2", "-fno-builtin", "-fno-stack-protector",
         "-Wall", "-Wextra", "-Werror", *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise SmokeError(
            f"compile failed: argv={result.args!r} stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def run_plain(binary: Path, arguments: Sequence[str]) -> None:
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=ROOT,
        env=clean_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    if result.returncode != 0 or result.stdout != EXPECTED_STDOUT or result.stderr:
        raise SmokeError(
            f"ordinary fixture changed: argv={result.args!r} status={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def assert_separate_artifacts(original: Path, observer: Path) -> None:
    if original.samefile(observer):
        raise SmokeError(f"observer reuses the timed artifact: {observer}")
    original_digest = hashlib.sha256(original.read_bytes()).digest()
    observer_digest = hashlib.sha256(observer.read_bytes()).digest()
    if original_digest == observer_digest:
        raise SmokeError(f"observer lacks a distinct ELF identity: {observer}")


def close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def observer_descriptor(descriptor: int, target: int) -> int:
    """Move a child endpoint away from normal Python descriptors."""

    if descriptor == target:
        return descriptor
    temporary = fcntl.fcntl(descriptor, fcntl.F_DUPFD, 100)
    try:
        os.dup2(temporary, target)
    finally:
        close_descriptor(temporary)
    close_descriptor(descriptor)
    return target


def terminate_and_reap(process: subprocess.Popen[bytes] | None) -> str | None:
    """Reap only a child owned by this smoke runner within finite deadlines."""

    if process is None or process.poll() is not None:
        return None
    try:
        process.terminate()
    except ProcessLookupError:
        pass
    except OSError as error:
        return f"could not terminate observer child: {error}"
    try:
        process.communicate(timeout=2)
        return None
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as error:
            return f"observer child could not be killed: {error}"
        try:
            process.communicate(timeout=2)
            return None
        except subprocess.TimeoutExpired:
            return "observer child could not be reaped after terminate/kill deadlines"
        except OSError as error:
            return f"observer child could not be reaped after kill: {error}"
    except OSError as error:
        return f"observer child could not be reaped: {error}"


def wait_for_ready(descriptor: int, context: str) -> None:
    readable, _, _ = select.select([descriptor], [], [], 5)
    if not readable:
        raise SmokeError(f"observer did not reach checkpoint deadline: {context}")
    if os.read(descriptor, 1) != b"R":
        raise SmokeError(f"observer checkpoint did not emit R: {context}")


def read_pty_stdout(descriptor: int) -> bytes:
    readable, _, _ = select.select([descriptor], [], [], 5)
    if not readable:
        raise SmokeError("original source output was not present at main-final")
    received = os.read(descriptor, 16)
    if received != EXPECTED_STDOUT:
        raise SmokeError(f"original source output changed before main-final: {received!r}")
    return received


Checkpoint = Callable[[str, subprocess.Popen[bytes]], None]


def run_observed(binary: Path, arguments: Sequence[str], phases: Sequence[str],
                 checkpoint: Checkpoint | None = None,
                 require_direct_stdout_before_final: bool = False) -> None:
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    output_master: int | None = None
    output_slave: int | None = None
    process: subprocess.Popen[bytes] | None = None
    failed = False
    try:
        ready_write = observer_descriptor(ready_write, READY_FD)
        continue_read = observer_descriptor(continue_read, CONTINUE_FD)
        if require_direct_stdout_before_final:
            output_master, output_slave = pty.openpty()
            tty.setraw(output_slave, when=termios.TCSANOW)
        environment = clean_environment()
        environment[READY_ENV] = str(ready_write)
        environment[CONTINUE_ENV] = str(continue_read)
        process = subprocess.Popen(
            [str(binary), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=output_slave if output_slave is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(ready_write, continue_read),
        )
        close_descriptor(ready_write)
        ready_write = None
        close_descriptor(continue_read)
        continue_read = None
        if output_slave is not None:
            close_descriptor(output_slave)
            output_slave = None
        for phase in phases:
            wait_for_ready(ready_read, f"{binary.name} {arguments!r} phase={phase}")
            if checkpoint is not None:
                checkpoint(phase, process)
            if phase == "main-final" and require_direct_stdout_before_final:
                assert output_master is not None
                read_pty_stdout(output_master)
            if os.write(continue_write, b"C") != 1:
                raise SmokeError("observer continue descriptor did not accept C")
        _stdout, stderr = process.communicate(timeout=15)
        if process.returncode != 0 or stderr:
            raise SmokeError(
                f"observer failed: argv={[str(binary), *arguments]!r} status={process.returncode} "
                f"stderr={stderr!r}"
            )
        if not require_direct_stdout_before_final and _stdout != EXPECTED_STDOUT:
            raise SmokeError(
                f"observer changed source stdout: argv={[str(binary), *arguments]!r} "
                f"stdout={_stdout!r}"
            )
        readable, _, _ = select.select([ready_read], [], [], 0)
        if readable and os.read(ready_read, 1):
            raise SmokeError("observer emitted an undeclared extra checkpoint")
    except BaseException:
        failed = True
        raise
    finally:
        close_descriptor(ready_read)
        close_descriptor(ready_write)
        close_descriptor(continue_read)
        close_descriptor(continue_write)
        close_descriptor(output_master)
        close_descriptor(output_slave)
        cleanup_error = terminate_and_reap(process)
        if cleanup_error and not failed:
            raise SmokeError(cleanup_error)


def run_bad_acknowledgement(binary: Path, arguments: Sequence[str]) -> None:
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    failed = False
    try:
        ready_write = observer_descriptor(ready_write, READY_FD)
        continue_read = observer_descriptor(continue_read, CONTINUE_FD)
        environment = clean_environment()
        environment[READY_ENV] = str(ready_write)
        environment[CONTINUE_ENV] = str(continue_read)
        process = subprocess.Popen(
            [str(binary), *arguments], cwd=ROOT, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(ready_write, continue_read),
        )
        close_descriptor(ready_write)
        ready_write = None
        close_descriptor(continue_read)
        continue_read = None
        wait_for_ready(ready_read, f"{binary.name} {arguments!r} phase=main-initial")
        if os.write(continue_write, b"C") != 1:
            raise SmokeError("observer initial continue descriptor did not accept C")
        wait_for_ready(ready_read, f"{binary.name} {arguments!r} phase=bad-ack target")
        if os.write(continue_write, b"X") != 1:
            raise SmokeError("observer bad acknowledgement descriptor did not accept X")
        stdout, stderr = process.communicate(timeout=10)
        if process.returncode == 0 or stdout != EXPECTED_STDOUT or stderr:
            raise SmokeError(
                f"bad acknowledgement did not preserve cleanup failure: status={process.returncode} "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
    except BaseException:
        failed = True
        raise
    finally:
        close_descriptor(ready_read)
        close_descriptor(ready_write)
        close_descriptor(continue_read)
        close_descriptor(continue_write)
        cleanup_error = terminate_and_reap(process)
        if cleanup_error and not failed:
            raise SmokeError(cleanup_error)


def run_missing_acknowledgement(binary: Path, arguments: Sequence[str]) -> None:
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    failed = False
    try:
        ready_write = observer_descriptor(ready_write, READY_FD)
        continue_read = observer_descriptor(continue_read, CONTINUE_FD)
        environment = clean_environment()
        environment[READY_ENV] = str(ready_write)
        environment[CONTINUE_ENV] = str(continue_read)
        process = subprocess.Popen(
            [str(binary), *arguments], cwd=ROOT, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(ready_write, continue_read),
        )
        close_descriptor(ready_write)
        ready_write = None
        close_descriptor(continue_read)
        continue_read = None
        wait_for_ready(ready_read, f"{binary.name} {arguments!r} phase=main-initial")
        if os.write(continue_write, b"C") != 1:
            raise SmokeError("observer initial continue descriptor did not accept C")
        wait_for_ready(ready_read, f"{binary.name} {arguments!r} phase=missing-ack target")
        close_descriptor(continue_write)
        continue_write = None
        stdout, stderr = process.communicate(timeout=10)
        if process.returncode == 0 or stdout != EXPECTED_STDOUT or stderr:
            raise SmokeError(
                f"missing acknowledgement did not preserve cleanup failure: status={process.returncode} "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
    except BaseException:
        failed = True
        raise
    finally:
        close_descriptor(ready_read)
        close_descriptor(ready_write)
        close_descriptor(continue_read)
        close_descriptor(continue_write)
        cleanup_error = terminate_and_reap(process)
        if cleanup_error and not failed:
            raise SmokeError(cleanup_error)


def run_bad_environment(binary: Path, arguments: Sequence[str]) -> None:
    malformed = clean_environment()
    malformed[READY_ENV] = "02"
    malformed[CONTINUE_ENV] = "98"
    result = subprocess.run(
        [str(binary), *arguments], cwd=ROOT, env=malformed,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5,
    )
    if result.returncode != 2 or result.stdout or result.stderr:
        raise SmokeError("malformed observer descriptor text did not fail before source work")
    partial = clean_environment()
    partial[READY_ENV] = "97"
    result = subprocess.run(
        [str(binary), *arguments], cwd=ROOT, env=partial,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5,
    )
    if result.returncode != 2 or result.stdout or result.stderr:
        raise SmokeError("partial observer descriptor environment did not fail before source work")


def fd_points_to(process: subprocess.Popen[bytes], path: Path) -> None:
    descriptor_root = Path(f"/proc/{process.pid}/fd")
    targets = {Path(os.readlink(descriptor)).resolve() for descriptor in descriptor_root.iterdir()}
    if path.resolve() not in targets:
        raise SmokeError(f"real fixture descriptor is not live at checkpoint: {path}")


def assert_thread_is_live(process: subprocess.Popen[bytes]) -> None:
    tasks = list((Path(f"/proc/{process.pid}/task")).iterdir())
    if len(tasks) < 2:
        raise SmokeError("original worker had exited before its declared checkpoint")


def maps_contain(process: subprocess.Popen[bytes], *paths: Path) -> None:
    mappings = Path(f"/proc/{process.pid}/maps").read_text(encoding="utf-8")
    for path in paths:
        if str(path.resolve()) not in mappings:
            raise SmokeError(f"live mapping is absent at checkpoint: {path}")


def maps_exclude(process: subprocess.Popen[bytes], token: str) -> None:
    mappings = Path(f"/proc/{process.pid}/maps").read_text(encoding="utf-8")
    if token in mappings:
        raise SmokeError(f"released mapping remains live after source cleanup: {token}")


def stage_sources(work: Path) -> dict[str, Path]:
    io_file = work / "io-fixture.bin"
    io_file.write_bytes(bytes(range(256)) * 16)
    format_file = work / "format-fixture.bin"
    format_file.write_bytes(b"lane-private format fixture\n")
    span_source = work / "span-source.bin"
    span_destination = work / "span-destination.bin"
    span_mapping_bytes = SPAN_BYTES + 16
    with span_source.open("wb") as stream:
        stream.truncate(span_mapping_bytes)
        stream.seek(SPAN_BYTES - len(SPAN_NEEDLE))
        stream.write(SPAN_NEEDLE)
        stream.seek(SPAN_BYTES)
        stream.write(b"\0")
    with span_destination.open("wb") as stream:
        stream.truncate(span_mapping_bytes)
    return {
        "io": io_file,
        "format": format_file,
        "span_source": span_source,
        "span_destination": span_destination,
    }


def build_artifacts(compiler: str, work: Path) -> dict[str, Path]:
    binaries = work / "binaries"
    if binaries.exists():
        shutil.rmtree(binaries)
    binaries.mkdir(parents=True)
    common = ["-pthread"]
    compile_checked(
        compiler,
        [*common, "compat/perf/fixtures/workload.c", "-o", str(binaries / "original-workload")],
    )
    compile_checked(
        compiler,
        [*common, "compat/perf/x86_64_memory_observer_workload.c", "-o", str(binaries / "observer-workload")],
    )
    compile_checked(
        compiler,
        ["compat/perf/fixtures/startup_constructor.c", "-o", str(binaries / "original-constructor")],
    )
    compile_checked(
        compiler,
        ["compat/perf/x86_64_memory_observer_constructor.c", "-o", str(binaries / "observer-constructor")],
    )

    symbols_source = work / "symbols.c"
    symbols_source.write_text(
        "__attribute__((visibility(\"default\"))) int bench_symbol_0(void) { return 0; }\n",
        encoding="ascii",
    )
    symbols = binaries / "libsymbols_1.so"
    compile_checked(compiler, ["-fPIC", "-shared", str(symbols_source), "-o", str(symbols)])

    tls_directory = binaries / "tls"
    tls_directory.mkdir()
    for index in range(8):
        compile_checked(
            compiler,
            ["-fPIC", "-shared", f"-DTLS_GROWTH_INDEX={index}",
             "compat/perf/fixtures/tls_growth_dso.c", "-o",
             str(tls_directory / f"libbench_tls_growth_{index}.so")],
        )

    graph_sources = {
        "libbench_graph_leaf_left.so": "int bench_graph_leaf_left(void) { return 7; }\n",
        "libbench_graph_leaf_right.so": "int bench_graph_leaf_right(void) { return 11; }\n",
        "libbench_graph_mid_left.so": (
            "extern int bench_graph_leaf_left(void); "
            "int bench_graph_mid_left(void) { return bench_graph_leaf_left() + 3; }\n"
        ),
        "libbench_graph_mid_right.so": (
            "extern int bench_graph_leaf_right(void); "
            "int bench_graph_mid_right(void) { return bench_graph_leaf_right() + 4; }\n"
        ),
        "libbench_graph_root.so": (
            "extern int bench_graph_mid_left(void); extern int bench_graph_mid_right(void); "
            "int bench_graph_root_value(void) { return bench_graph_mid_left() + bench_graph_mid_right() + 6; }\n"
        ),
    }
    for name, contents in graph_sources.items():
        source = work / f"{name}.c"
        source.write_text(contents, encoding="ascii")
        command = ["-fPIC", "-shared", str(source), f"-Wl,-soname,{name}",
                   "-Wl,-rpath,$ORIGIN", "-o", str(binaries / name)]
        if name == "libbench_graph_mid_left.so":
            command.extend(("-L", str(binaries), "-lbench_graph_leaf_left"))
        elif name == "libbench_graph_mid_right.so":
            command.extend(("-L", str(binaries), "-lbench_graph_leaf_right"))
        elif name == "libbench_graph_root.so":
            command.extend(("-L", str(binaries), "-lbench_graph_mid_left", "-lbench_graph_mid_right"))
        compile_checked(compiler, command)
    compile_checked(
        compiler,
        ["compat/perf/fixtures/startup_graph.c", "-L", str(binaries), "-lbench_graph_root",
         "-Wl,-rpath,$ORIGIN", "-o", str(binaries / "original-graph")],
    )
    compile_checked(
        compiler,
        ["compat/perf/x86_64_memory_observer_graph.c", "-L", str(binaries),
         "-lbench_graph_root", "-Wl,-rpath,$ORIGIN", "-o", str(binaries / "observer-graph")],
    )
    staged = stage_sources(work)
    return {
        "binaries": binaries,
        "original_workload": binaries / "original-workload",
        "observer_workload": binaries / "observer-workload",
        "original_constructor": binaries / "original-constructor",
        "observer_constructor": binaries / "observer-constructor",
        "original_graph": binaries / "original-graph",
        "observer_graph": binaries / "observer-graph",
        "symbols": symbols,
        "tls_directory": tls_directory,
        **staged,
    }


def phases(*items: str) -> tuple[str, ...]:
    return ("main-initial", *items, "main-final")


def run_smoke(compiler: str, work: Path) -> None:
    artifacts = build_artifacts(compiler, work)
    original = artifacts["original_workload"]
    observer = artifacts["observer_workload"]
    io_file = artifacts["io"]

    assert_separate_artifacts(artifacts["original_workload"], artifacts["observer_workload"])
    assert_separate_artifacts(artifacts["original_constructor"], artifacts["observer_constructor"])
    assert_separate_artifacts(artifacts["original_graph"], artifacts["observer_graph"])

    run_plain(original, ("clock_gettime", "2"))
    run_plain(observer, ("clock_gettime", "2"))
    run_plain(artifacts["original_constructor"], ("startup_constructor_destructor", "1"))
    run_plain(artifacts["observer_constructor"], ("startup_constructor_destructor", "1"))
    run_plain(artifacts["original_graph"], ("startup_dependency_graph", "1"))
    run_plain(artifacts["observer_graph"], ("startup_dependency_graph", "1"))

    run_observed(observer, ("startup", "1"), phases())
    run_observed(
        artifacts["observer_constructor"], ("startup_constructor_destructor", "1"), phases(),
        require_direct_stdout_before_final=True,
    )
    run_observed(artifacts["observer_graph"], ("startup_dependency_graph", "1"), phases())
    for mode in ("clock_gettime", "gettimeofday", "getpid"):
        run_observed(observer, (mode, "2"), phases("clock-final-call"))
    run_observed(observer, ("open_close", "2"), phases("open-before-close"))
    run_observed(
        observer, ("fd_file_4k", "1", str(io_file)), phases("fd-before-close"),
        lambda phase, process: fd_points_to(process, io_file) if phase == "fd-before-close" else None,
    )
    for mode, path in (("stdio_file_4k", io_file), ("stdio_format_parse", artifacts["format"])):
        run_observed(
            observer, (mode, "1", str(path)), phases("stdio-before-fclose"),
            lambda phase, process, path=path: fd_points_to(process, path)
            if phase == "stdio-before-fclose" else None,
        )

    run_observed(
        observer, ("pthread_create_join_tls", "2"), phases("pthread-callback-ready"),
        lambda phase, process: assert_thread_is_live(process) if phase == "pthread-callback-ready" else None,
    )
    run_observed(observer, ("pthread_mutex_uncontended", "2"), phases("mutex-before-destroy"))
    run_observed(
        observer, ("pthread_mutex_cond_ping_pong", "1"), phases("pingpong-before-worker-exit"),
        lambda phase, process: assert_thread_is_live(process) if phase == "pingpong-before-worker-exit" else None,
    )

    def tls_checkpoint(phase: str, process: subprocess.Popen[bytes]) -> None:
        if phase.startswith("tls-parent-load-"):
            maps_contain(process, artifacts["tls_directory"] / "libbench_tls_growth_0.so")
        elif phase == "tls-worker-complete":
            assert_thread_is_live(process)
            maps_contain(process, artifacts["tls_directory"] / "libbench_tls_growth_7.so")

    run_observed(
        observer, ("loader_dynamic_tls_growth", "8", str(artifacts["tls_directory"])),
        phases(*(f"tls-parent-load-{index}" for index in range(8)), "tls-worker-complete"),
        tls_checkpoint,
    )

    for mode, args in (
        ("memcpy_16k", ("2",)), ("memset_16k", ("2",)),
        ("strlen_16k", ("2",)), ("memchr_16k", ("2",)),
        ("strstr_4k", ("2",)), ("memmem_4k", ("2",)),
        ("memcpy_matrix", ("1", "64", "0", "0")),
        ("memset_matrix", ("1", "64", "0")),
        ("strlen_matrix", ("1", "64", "0")),
        ("memchr_matrix", ("1", "64", "0")),
        ("strstr_matrix", ("1", "64", "0")),
        ("memmem_matrix", ("1", "64", "0")),
    ):
        run_observed(observer, (mode, *args), phases("scalar-arrays-live"))

    def span_checkpoint(phase: str, process: subprocess.Popen[bytes]) -> None:
        if phase == "span-before-first-munmap":
            maps_contain(process, artifacts["span_source"], artifacts["span_destination"])
        elif phase == "main-final":
            maps_exclude(process, "span-source.bin")
            maps_exclude(process, "span-destination.bin")

    run_observed(
        observer,
        ("span_matrix", "1", "memcpy", str(SPAN_BYTES), "0",
         str(artifacts["span_source"]), str(artifacts["span_destination"])),
        phases("span-before-first-munmap"), span_checkpoint,
    )
    for mode in ("allocator_64", "allocator_4k"):
        run_observed(observer, (mode, "1"), phases("allocator-before-final-free"))
    run_observed(
        observer, ("dlsym_1", "1", str(artifacts["symbols"]), "bench_symbol_0"),
        phases("dlsym-before-dlclose"),
        lambda phase, process: maps_contain(process, artifacts["symbols"])
        if phase == "dlsym-before-dlclose" else None,
    )
    run_observed(
        observer, ("dlopen_graph", "1", str(artifacts["binaries"] / "libbench_graph_root.so")),
        phases("graph-before-dlclose"),
        lambda phase, process: maps_contain(
            process, artifacts["binaries"] / "libbench_graph_root.so"
        ) if phase == "graph-before-dlclose" else None,
    )

    run_bad_environment(observer, ("clock_gettime", "1"))
    run_bad_acknowledgement(observer, ("open_close", "1"))
    run_missing_acknowledgement(observer, ("fd_file_4k", "1", str(io_file)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compiler",
        default="/usr/local/bin/crabc-x86_64-musl-gcc",
        help="pinned native C compiler inside the x86 evidence container",
    )
    parser.add_argument(
        "--work",
        type=Path,
        default=DEFAULT_WORK,
        help="state directory below this checkout's .work/x86_64",
    )
    arguments = parser.parse_args()
    try:
        run_smoke(arguments.compiler, work_directory(arguments.work))
    except (OSError, SmokeError, subprocess.TimeoutExpired) as error:
        print(f"x86_64 legacy memory observer smoke: {error}", file=sys.stderr)
        return 1
    print("x86_64 legacy memory observer smoke: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
