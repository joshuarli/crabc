#!/usr/bin/env python3
"""Compare installed musl and owned resolver cancellation over loopback DNS."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
APIS = ("query", "send", "classic")
SCENARIOS = ("network-udp-wait", "network-tcp-wait",
             "network-retry-timeout", "network-failover")
FIELDS = frozenset(("canceled", "returned", "cleanup", "leaked", "success",
                    "state", "errno", "h_errno", "cleanup_errno",
                    "cleanup_h_errno", "parent_h_errno_same"))


def observe(raw: bytes) -> dict[str, int]:
    fields = dict(part.split("=", 1) for part in raw.decode("ascii").split())
    if fields.keys() != FIELDS:
        raise RuntimeError(f"unexpected network observation: {fields}")
    return {key: int(value) for key, value in fields.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--dynamic", action="store_true")
    options = parser.parse_args()
    work = options.work.resolve(strict=True)
    if not work.is_relative_to(ROOT / ".work") or options.work.is_symlink():
        raise RuntimeError("network evidence must use a physical checkout .work directory")
    execution = work / "execution-root"
    witness = ROOT / "compat/x86_64/run_pthread_wait_witness.py"
    entries = [("oracle", ["/oracle"])]
    if options.static:
        entries += [(mode, ["/" + mode]) for mode in ("static-et-exec", "static-pie")]
    if options.dynamic:
        for mode in ("dynamic-pie", "dynamic-non-pie"):
            entries += [(mode + "-kernel", ["/" + mode]),
                        (mode + "-direct", ["/lib/ld-crabc-x86_64.so.1", "/" + mode])]
    oracle = {}
    observations = []
    differences = []
    for label, entry in entries:
        for scenario in SCENARIOS:
            for api in APIS:
                name = f"network-{label}-{api}-{scenario}"
                command = [sys.executable, "-B", str(witness), str(execution),
                           *entry, scenario, api]
                try:
                    result = subprocess.run(command, capture_output=True, timeout=10)
                    status, stdout, stderr = result.returncode, result.stdout, result.stderr
                except subprocess.TimeoutExpired as error:
                    status, stdout, stderr = 124, error.stdout or b"", error.stderr or b""
                (work / (name + ".stdout")).write_bytes(stdout)
                (work / (name + ".stderr")).write_bytes(stderr)
                row = {"entry": label, "api": api, "scenario": scenario,
                       "exit_status": status}
                observations.append(row)
                (work / "network-execution-status.json").write_text(
                    json.dumps(observations, indent=2) + "\n")
                if status:
                    raise RuntimeError(f"{name} exited {status}: {stderr.decode(errors='replace')}")
                current = observe(stdout)
                key = (api, scenario)
                if label == "oracle":
                    oracle[key] = current
                elif current != oracle[key]:
                    differences.append({"entry": label, "api": api, "scenario": scenario,
                                        "owned": current, "musl": oracle[key]})
                    print(f"{name}: DIFFER", flush=True)
                    continue
                print(f"{name}: PASS", flush=True)
    (work / "network-differences.json").write_text(json.dumps(differences, indent=2) + "\n")
    if differences:
        raise RuntimeError(f"{len(differences)} controlled-network observations differ; see {work / 'network-differences.json'}")
    print(f"owned resolver controlled network: PASS ({len(observations)} cases); evidence: {work}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        raise SystemExit(f"owned resolver controlled network: ERROR: {error}")
