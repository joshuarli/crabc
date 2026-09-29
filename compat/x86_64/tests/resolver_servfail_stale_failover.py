#!/usr/bin/env python3
"""Compare SERVFAIL resend and late reply association in a local DNS network."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

import resolver_stale_reply_failover as base


ROOT = Path(__file__).resolve().parents[3]


class DnsFixture(base.DnsFixture):
    def __init__(self) -> None:
        super().__init__()
        self.reply_state = {1: "awaiting_initial_queries", 28: "awaiting_initial_queries"}
        self.initial_second: dict[int, bytes] = {}

    def release(self, record_type: int) -> None:
        if any((role, record_type) not in self.pending for role in ("first", "second")):
            return
        first_query, first_peer = self.pending[("first", record_type)]
        second_query, second_peer = self.pending[("second", record_type)]
        if self.reply_state[record_type] == "awaiting_initial_queries":
            self.initial_second[record_type] = second_query
            _, _, end = base.question(second_query)
            servfail = second_query[:2] + b"\x81\x82\0\x01\0\0\0\0\0\0" + second_query[12:end]
            self.udp_by_role("second").sendto(servfail, second_peer)
            self.event("second", "servfail", record_type, second_query, servfail)
            self.reply_state[record_type] = "awaiting_resend"
            return
        if (self.reply_state[record_type] != "awaiting_resend"
                or self.events[-1]["role"] != "second"
                or self.events[-1]["action"] != "query"):
            return
        if second_query != self.initial_second[record_type]:
            raise ValueError("SERVFAIL resend changed the DNS question or transaction ID")
        self.reply_state[record_type] = "released"
        if record_type == 1:
            spoof = base.answer(first_query, "203.0.113.99")
            self.spoof.sendto(spoof, first_peer)
            self.event("spoof", "same-id-wrong-source", record_type, first_query, spoof)
            late = base.answer(first_query, "198.51.100.41")
            self.udp_by_role("first").sendto(late, first_peer)
            self.event("first", "late-valid", record_type, first_query, late)
        else:
            stale = base.answer(first_query, "2001:db8::99", wrong_id=True)
            self.udp_by_role("first").sendto(stale, first_peer)
            self.event("first", "late-wrong-id", record_type, first_query, stale)
            valid = base.answer(second_query, "2001:db8::42")
            self.udp_by_role("second").sendto(valid, second_peer)
            self.event("second", "valid", record_type, second_query, valid)


def route_complete(events: list[dict[str, object]]) -> bool:
    if len(events) != 12:
        return False
    for record_type, terminal in (
        (1, (("spoof", "same-id-wrong-source"), ("first", "late-valid"))),
        (28, (("first", "late-wrong-id"), ("second", "valid"))),
    ):
        selected = [event for event in events if event["type"] == record_type]
        expected = [("first", "query"), ("second", "query"),
                    ("second", "servfail"), ("second", "query"), *terminal]
        if [(event["role"], event["action"]) for event in selected] != expected:
            return False
        if any(event["name"] != base.QUERY_NAME for event in selected):
            return False
        query_id = selected[0]["query_id"]
        if any(selected[index]["query_id"] != query_id for index in (1, 2, 3)):
            return False
        if selected[2]["reply_id"] != query_id:
            return False
        if record_type == 1:
            if selected[4]["reply_id"] != query_id or selected[5]["reply_id"] != query_id:
                return False
        elif selected[4]["reply_id"] == query_id or selected[5]["reply_id"] != query_id:
            return False
    return True


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_arm(binary: Path, root: Path) -> dict[str, object]:
    root.mkdir()
    (root / "etc").mkdir()
    shutil.copy2(binary, root / "workload")
    (root / "etc/hosts").write_bytes(b"127.0.0.1 localhost\n::1 localhost\n")
    (root / "etc/resolv.conf").write_bytes(base.RESOLV_CONF)
    with DnsFixture() as fixture:
        started = time.monotonic()
        try:
            result = subprocess.run(["/usr/sbin/chroot", str(root), "/workload"],
                                    capture_output=True, timeout=5, check=False)
            status: int | str = result.returncode
            stdout, stderr = result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            status = "timeout"
            stdout, stderr = error.stdout or b"", error.stderr or b""
        elapsed_ms = round((time.monotonic() - started) * 1000)
        time.sleep(0.1)
    return {"status": status, "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"), "elapsed_ms": elapsed_ms,
            "events": fixture.events, "fixture_errors": fixture.errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--static-sysroot", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    base.isolated_network()
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / ".work") or work.exists():
        parser.error("work must be a fresh checkout-local .work path")
    work.mkdir(parents=True)
    arms = {label: run_arm(binary.resolve(strict=True), work / label)
            for label, binary in (("oracle", args.oracle), ("candidate", args.candidate))}
    observed = all(arm["status"] == 0 and arm["stdout"] == "" and arm["stderr"] == ""
                   and arm["elapsed_ms"] <= 1500 and not arm["fixture_errors"]
                   and route_complete(arm["events"]) for arm in arms.values())
    same = all(arms["oracle"][field] == arms["candidate"][field]
               for field in ("status", "stdout", "stderr"))
    manifest = json.loads((args.static_sysroot / "share/crabc/manifest.json").read_bytes())
    passed = observed and same
    report = {"source_sha256": manifest["source_sha256"],
              "core_resolver_sha256": digest(ROOT / "crabc-core/src/resolver.rs"),
              "workload_sha256": digest(ROOT / "compat/x86_64/tests/resolver_servfail_stale_failover.c"),
              "fixture_sha256": digest(Path(__file__)),
              "fixture_base_sha256": digest(Path(base.__file__)),
              "oracle_sha256": digest(args.oracle), "candidate_sha256": digest(args.candidate),
              "behavior_observed": observed, "raw_equal": same, "passed": passed,
              "arms": arms}
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": passed, "behavior_observed": observed,
                      "raw_equal": same, "report": str(work / "report.json")}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
