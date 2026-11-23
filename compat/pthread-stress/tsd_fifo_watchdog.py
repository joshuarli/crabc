#!/usr/bin/env python3
"""External watchdog for the SCHED_FIFO pthread-key progress fixture.

The watchdog runs on a CPU other than the fixture's, in its own process, with
the ordinary scheduling policy. It starts the fixture in a new session pinned
to one CPU, watches the shared progress counters, and on a stall or deadline
kills the fixture's whole process group. The kernel's RLIMIT_RTTIME backstop is
also set so a runaway real-time task is killed even if this process dies.

Exit status: 0 progress to completion, 1 no progress or deadline, 77 SCHED_FIFO
unavailable, 3 watchdog failure (including an unkillable fixture), 4 fixture
failure.
"""
import argparse
import mmap
import os
import resource
import signal
import struct
import subprocess
import sys
import tempfile
import time

SHARED = struct.Struct("<QQQII")
PHASES = {1: "setup", 2: "fifo", 3: "done", 4: "unavailable", 5: "failed"}


def read_shared(view):
    owner_ops, waiter_rounds, waiter_ops, phase, stop = SHARED.unpack_from(view, 0)
    return owner_ops, waiter_rounds, waiter_ops, phase, stop


def task_table(pid):
    rows = []
    try:
        tids = sorted(int(name) for name in os.listdir(f"/proc/{pid}/task"))
    except OSError:
        return rows
    for tid in tids:
        try:
            with open(f"/proc/{pid}/task/{tid}/stat") as stream:
                text = stream.read()
        except OSError:
            continue
        fields = text.rpartition(")")[2].split()
        rows.append(
            {
                "tid": tid,
                "state": fields[0],
                "utime": int(fields[11]),
                "stime": int(fields[12]),
                "cpu": int(fields[36]),
                "rt_priority": int(fields[37]),
                "policy": int(fields[38]),
            }
        )
    return rows


def read_lock(pid, address, size):
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as stream:
            stream.seek(address)
            return int.from_bytes(stream.read(size), "little")
    except OSError as error:
        return f"unreadable({error.strerror})"


def group_members(pgid):
    members = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat") as stream:
                fields = stream.read().rpartition(")")[2].split()
        except OSError:
            continue
        if int(fields[2]) == pgid and fields[0] != "Z":
            members.append(int(name))
    return members


def kill_group(pgid, process):
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.05)
        except subprocess.TimeoutExpired:
            pass
        if not group_members(pgid):
            return True
    return False


def parse_lock(text):
    name, address, size = text.split(":")
    return name, int(address, 16), int(size)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--scenario", choices=("getset", "delete", "registry", "signal", "signal-worker"), required=True)
    parser.add_argument("--fifo-cpu", type=int)
    parser.add_argument("--watchdog-cpu", type=int)
    parser.add_argument("--stall-ms", type=int, default=300)
    parser.add_argument("--total-ms", type=int, default=6000)
    parser.add_argument("--rttime-us", type=int, default=4_000_000)
    parser.add_argument("--rounds", type=int, default=4000)
    parser.add_argument("--burst", type=int, default=64)
    parser.add_argument("--budget-ms", type=int, default=1500)
    parser.add_argument("--lock", action="append", default=[], type=parse_lock, help="NAME:HEXADDR:SIZE")
    arguments = parser.parse_args()

    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 2:
        print("watchdog: needs at least two allowed CPUs", file=sys.stderr)
        return 3
    fifo_cpu = arguments.fifo_cpu if arguments.fifo_cpu is not None else cpus[-1]
    watchdog_cpu = arguments.watchdog_cpu if arguments.watchdog_cpu is not None else cpus[0]
    if fifo_cpu == watchdog_cpu or fifo_cpu not in cpus or watchdog_cpu not in cpus:
        print("watchdog: the FIFO CPU and watchdog CPU must be distinct allowed CPUs", file=sys.stderr)
        return 3
    os.sched_setaffinity(0, {watchdog_cpu})

    def confine():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_RTTIME, (arguments.rttime_us, arguments.rttime_us))
        os.sched_setaffinity(0, {fifo_cpu})

    with tempfile.NamedTemporaryFile(prefix="tsd-fifo-progress.") as progress:
        progress.truncate(mmap.PAGESIZE)
        view = mmap.mmap(progress.fileno(), mmap.PAGESIZE)
        command = [
            arguments.binary,
            progress.name,
            arguments.scenario,
            str(arguments.rounds),
            str(arguments.burst),
            str(arguments.budget_ms),
        ]
        started = time.monotonic()
        process = subprocess.Popen(command, preexec_fn=confine, stdin=subprocess.DEVNULL)
        pgid = process.pid
        last = read_shared(view)
        last_change = started
        verdict = "completed"
        detail = ""
        try:
            while True:
                status = process.poll()
                current = read_shared(view)
                now = time.monotonic()
                if current[:3] != last[:3]:
                    last, last_change = current, now
                if status is not None:
                    break
                if current[3] == 2 and now - last_change > arguments.stall_ms / 1000:
                    verdict = "NO_PROGRESS"
                    locks = {name: read_lock(process.pid, address, size) for name, address, size in arguments.lock}
                    detail = f" stalled_ms={int((now - last_change) * 1000)} locks={locks} tasks={task_table(process.pid)}"
                    break
                if now - started > arguments.total_ms / 1000:
                    verdict = "DEADLINE"
                    detail = f" tasks={task_table(process.pid)}"
                    break
                time.sleep(0.01)
        finally:
            killed = kill_group(pgid, process)
        final = read_shared(view)
        code = process.returncode
        print(
            f"RESULT scenario={arguments.scenario} verdict={verdict} exit={code} "
            f"phase={PHASES.get(final[3], final[3])} owner_ops={final[0]} "
            f"waiter_rounds={final[1]} waiter_ops={final[2]} fifo_cpu={fifo_cpu} "
            f"watchdog_cpu={watchdog_cpu} elapsed_ms={int((time.monotonic() - started) * 1000)}{detail}"
        )
        view.close()
    if not killed:
        print("watchdog: fixture process group survived SIGKILL", file=sys.stderr)
        return 3
    if verdict != "completed":
        return 1
    if code == 77:
        return 77
    if code != 0:
        return 4 if code is not None and code > 0 else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
