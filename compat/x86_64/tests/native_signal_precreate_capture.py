#!/usr/bin/env python3
"""Capture bounded process and thread state for a slow signal/fork receiver."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time


ROOT = Path(__file__).resolve().parents[3]
WORK = ROOT / ".work"
STATUS_KEYS = frozenset({
    "Name", "State", "Tgid", "Pid", "PPid", "Threads", "SigPnd", "ShdPnd",
    "SigBlk", "SigIgn", "SigCgt", "voluntary_ctxt_switches",
    "nonvoluntary_ctxt_switches",
})


def regular(path: Path) -> Path:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"not a physical regular file: {path}")
    return path


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with regular(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except (OSError, ValueError) as error:
        return f"unavailable: {type(error).__name__}: {error}"


def task_record(tid: int) -> dict[str, object]:
    path = Path("/proc") / str(tid)
    status = {}
    for line in read_text(path / "status").splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            if name in STATUS_KEYS:
                status[name] = value.strip()
    return {
        "tid": tid,
        "status": status,
        "wchan": read_text(path / "wchan").strip(),
        "syscall": read_text(path / "syscall").strip(),
        "children": read_text(path / "task" / str(tid) / "children").strip(),
    }


def snapshot(root_pid: int, elapsed_seconds: float) -> dict[str, object]:
    pending = [root_pid]
    seen: set[int] = set()
    processes = []
    while pending and len(seen) < 256:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        task_dir = Path("/proc") / str(pid) / "task"
        try:
            tids = sorted(int(path.name) for path in task_dir.iterdir() if path.name.isdigit())
        except OSError:
            continue
        tasks = [task_record(tid) for tid in tids[:512]]
        for task in tasks:
            for word in str(task["children"]).split():
                if word.isdigit():
                    pending.append(int(word))
        processes.append({"pid": pid, "tasks": tasks})
    return {"elapsed_seconds": round(elapsed_seconds, 3), "processes": processes,
            "process_limit_hit": bool(pending)}


def run_case(command: list[str], environment: dict[str, str], output: Path,
             attempt: int, deadline: float, snapshot_after: float) -> dict[str, object]:
    stdout = output / f"attempt-{attempt:03}.stdout"
    stderr = output / f"attempt-{attempt:03}.stderr"
    snapshots = []
    started = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   env=environment, start_new_session=True)
        next_snapshot = snapshot_after
        timed_out = False
        while process.poll() is None:
            elapsed = time.monotonic() - started
            if elapsed >= next_snapshot:
                snapshots.append(snapshot(process.pid, elapsed))
                next_snapshot *= 2
            if elapsed >= deadline:
                timed_out = True
                snapshots.append(snapshot(process.pid, elapsed))
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=0.3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                break
            time.sleep(0.02)
        actual_returncode = process.wait()
    record = {
        "attempt": attempt,
        "pid": process.pid,
        "status": 124 if timed_out else actual_returncode,
        "actual_returncode": actual_returncode,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "stdout_sha256": digest(stdout),
        "stderr_sha256": digest(stderr),
        "snapshots": snapshots,
    }
    (output / f"attempt-{attempt:03}.json").write_text(
        json.dumps(record, sort_keys=True, indent=2) + "\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--entry", choices=("kernel", "direct"), required=True)
    parser.add_argument("--mode", choices=(
        "main-wait", "main-wait-guarded", "main-wait-race-window",
        "main-wait-guarded-race-window",
    ), required=True)
    parser.add_argument("--attempts", type=int, default=20)
    parser.add_argument("--deadline", type=float, default=35)
    parser.add_argument("--snapshot-after", type=float, default=1)
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--stop-on-timeout", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    output = arguments.output.absolute()
    if not root.is_relative_to(WORK) or not output.parent.resolve(strict=True).is_relative_to(WORK):
        parser.error("root and output must stay inside this checkout's .work")
    if output.exists():
        parser.error("output already exists")
    if not 1 <= arguments.attempts <= 100 or not 2 <= arguments.deadline <= 120:
        parser.error("attempts or deadline out of bounded range")
    if not 0 < arguments.snapshot_after < arguments.deadline:
        parser.error("snapshot threshold must precede the deadline")
    regular(root / "receiver")
    interpreter = root / "lib/ld-crabc-x86_64.so.1"
    if arguments.entry == "direct":
        regular(interpreter)
    chroot = shutil.which("chroot")
    if chroot is None:
        parser.error("chroot unavailable")
    command = [chroot, str(root)]
    command += (["/receiver"] if arguments.entry == "kernel"
                else ["/lib/ld-crabc-x86_64.so.1", "/receiver"])
    command.append(arguments.mode)
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if arguments.trace:
        environment["CRABC_SIGNAL_FORK_TRACE"] = "1"
    output.mkdir(parents=True)
    records = []
    for attempt in range(1, arguments.attempts + 1):
        record = run_case(command, environment, output, attempt,
                          arguments.deadline, arguments.snapshot_after)
        records.append(record)
        print(f"attempt={attempt} status={record['status']} elapsed={record['elapsed_seconds']} "
              f"snapshots={len(record['snapshots'])}", flush=True)
        if arguments.stop_on_timeout and record["status"] == 124:
            break
    summary = {
        "schema": "crabc.x86_64-native-signal-precreate-capture/v1",
        "root": str(root),
        "receiver_sha256": digest(root / "receiver"),
        "interpreter_sha256": digest(interpreter) if arguments.entry == "direct" else None,
        "entry": arguments.entry,
        "mode": arguments.mode,
        "trace": arguments.trace,
        "attempts": len(records),
        "statuses": [record["status"] for record in records],
    }
    (output / "summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
