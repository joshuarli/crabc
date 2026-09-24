#!/usr/bin/env python3
"""Count and compare traced programs' system calls from `strace -f` transcripts.

The runner traces `chroot ROOT PROGRAM ...` so the transcript also holds the
chroot helper's own calls. Counting starts at the first successful `execve`
whose path is PROGRAM (the consumer, or the interpreter for direct entry), and
covers that process and every descendant it creates afterwards. The result is
a JSON object mapping syscall names to counts; resumed and signal lines are
not separate calls.

`compare` takes one workload traced for pinned musl and for a candidate in the
same root, each with a baseline selector that opens no directory. It
subtracts each baseline so startup (loader, TLS, allocator initialization)
cancels, then requires the candidate's workload to make exactly musl's
directory-stream, descriptor-flag and file-status calls, and no more memory
mapping calls than musl. musl's passwd lookup also probes nscd through
`socket`/`connect`/`close`, which the owned runtime deliberately does not, so
closes are compared net of sockets.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

LINE = re.compile(r"^(?P<pid>\d+)\s+(?P<body>.*)$")
CALL = re.compile(r"^(?P<name>[a-z_][a-z0-9_]*)\(")
EXECVE = re.compile(r'^execve\("(?P<path>[^"]*)",.*\)\s+=\s+0$')
CLONE = re.compile(r"^(?:clone3?|fork|vfork)\(.*\)\s+=\s+(?P<child>\d+)$")


def profile(transcript: str, program: str) -> Counter:
    counts: Counter = Counter()
    traced: set[str] = set()
    for raw in transcript.splitlines():
        match = LINE.match(raw)
        if not match:
            continue
        pid, body = match.group("pid"), match.group("body")
        if pid not in traced:
            executed = EXECVE.match(body)
            if executed and executed.group("path") == program and not traced:
                traced.add(pid)
                counts["execve"] += 1
            continue
        if body.startswith(("<...", "+++", "---")):
            continue
        call = CALL.match(body)
        if not call:
            continue
        counts[call.group("name")] += 1
        spawned = CLONE.match(body)
        if spawned:
            traced.add(spawned.group("child"))
    if not traced:
        raise SystemExit(f"syscall profile: no successful execve of {program}")
    return counts


# Kernel spellings that one C operation may use: musl's x86 `open`/`lstat`
# and the owned runtime's `openat`/`newfstatat` are the same file operation.
EQUAL_GROUPS = {
    "open": ("open", "openat"),
    "file-status": ("fstat", "newfstatat", "stat", "lstat", "statx"),
    "getdents64": ("getdents64",),
    "fcntl": ("fcntl",),
}
MAPPING = ("mmap", "munmap", "mremap")


def workload(counts: Counter, baseline: Counter) -> Counter:
    result = Counter(counts)
    result.subtract(baseline)
    return result


def compare(oracle: Counter, candidate: Counter) -> dict[str, object]:
    def total(counts: Counter, names: tuple[str, ...]) -> int:
        return sum(counts[name] for name in names)

    report: dict[str, object] = {"equal": {}, "mapping": {}, "close_net_of_socket": {}}
    failures = []
    for group, names in EQUAL_GROUPS.items():
        pair = {"musl": total(oracle, names), "candidate": total(candidate, names)}
        report["equal"][group] = pair
        if pair["musl"] != pair["candidate"]:
            failures.append(f"{group} {pair}")
    closes = {label: counts["close"] - counts["socket"] for label, counts in
              (("musl", oracle), ("candidate", candidate))}
    report["close_net_of_socket"] = closes
    if closes["musl"] != closes["candidate"]:
        failures.append(f"close {closes}")
    mapping = {"musl": total(oracle, MAPPING), "candidate": total(candidate, MAPPING)}
    report["mapping"] = mapping
    if mapping["candidate"] > mapping["musl"]:
        failures.append(f"mapping {mapping}")
    report["failures"] = failures
    return report


def main(arguments: list[str]) -> int:
    if len(arguments) == 2:
        counts = profile(Path(arguments[0]).read_text(errors="replace"), arguments[1])
        print(json.dumps(dict(sorted(counts.items())), sort_keys=True))
        return 0
    if len(arguments) == 7 and arguments[0] == "compare":
        oracle_program, oracle_baseline, oracle_workload, program, baseline, traced = arguments[1:]
        read = lambda path, name: profile(Path(path).read_text(errors="replace"), name)  # noqa: E731
        report = compare(workload(read(oracle_workload, oracle_program), read(oracle_baseline, oracle_program)),
                         workload(read(traced, program), read(baseline, program)))
        print(json.dumps(report, sort_keys=True))
        return 1 if report["failures"] else 0
    print("usage: owned_syscall_profile.py TRANSCRIPT PROGRAM\n"
          "       owned_syscall_profile.py compare ORACLE_PROGRAM ORACLE_BASELINE ORACLE_WORKLOAD "
          "PROGRAM BASELINE WORKLOAD", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
