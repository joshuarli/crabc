#!/usr/bin/env python3
"""Selected pinned-native smoke for the x86 performance memory collector.

This is deliberately separate from ``--implementation-smoke``: that route
validates one timed pair and intentionally omits cgroup/ptrace diagnostics.
Here the adapter builds only a finite cross-family observer selection, then
uses the real private cgroup-v2, pre-``execve`` ptrace migration, raw proc
snapshots, and R/C checkpoints.  It is correctness evidence for the collector
boundary, never a 31-pair benchmark or release result.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT / "compat/perf") not in sys.path:
    sys.path.insert(0, str(ROOT / "compat/perf"))

import run_x86_64 as runner


# The three legacy source-family envelopes, dynamic-TLS worker checkpoint,
# 32-MiB live allocation, external loopback peer, and guard-page primitive
# together cover the native observer and collector boundaries without turning
# this smoke into a 114-row scorecard campaign.
SMOKE_ROWS = (
    "allocator_4k",
    "startup_constructor_destructor",
    "startup_dependency_graph",
    "loader_dynamic_tls_growth",
    "allocator_live_32m",
    "loopback_tcp_ipv4_4k",
    "memmem_guard63",
)


class SmokeError(RuntimeError):
    """The selected collector boundary did not produce complete evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeError(message)


def fresh_work(path: Path) -> Path:
    boundary = (ROOT / ".work/x86_64").resolve(strict=True)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = Path(candidate.absolute())
    try:
        candidate.relative_to(boundary)
    except ValueError as error:
        raise SmokeError(f"smoke work directory escapes {boundary}: {candidate}") from error
    require(not candidate.exists() and not candidate.is_symlink(),
            f"smoke work directory must be fresh: {candidate}")
    candidate.mkdir(mode=0o700)
    return candidate


def selected_rows() -> tuple[runner.performance_profile.PerformanceRow, ...]:
    rows = {row.name: row for row in runner.performance_rows(ROOT)}
    require(set(SMOKE_ROWS) <= set(rows), "collector smoke row roster is absent")
    selected = tuple(rows[name] for name in SMOKE_ROWS)
    require({row.memory_artifact for row in selected} >= {
        "x86_64_memory_observer_workload",
        "x86_64_memory_observer_constructor",
        "x86_64_memory_observer_graph",
        "x86_64_memory_observer_clock_allocator",
        "x86_64_memory_observer_network",
        "x86_64_memory_observer_primitive",
    }, "collector smoke does not cover every observer artifact family")
    require("tls-worker-complete" in rows["loader_dynamic_tls_growth"].memory_phases,
            "collector smoke lacks the TLS worker checkpoint")
    return selected


def validate_result(
    rows: tuple[runner.performance_profile.PerformanceRow, ...],
    results: Mapping[str, Any],
    cleanup: Mapping[str, Any],
) -> None:
    require(set(results) == set(SMOKE_ROWS), "collector smoke result roster differs")
    expected_leaves: set[str] = set()
    for row in rows:
        item = results[row.name]
        require(isinstance(item, dict) and item.get("invocation", {}).get("phases") == list(row.memory_phases),
                f"{row.name}: observer invocation phases differ")
        for lane in ("musl", "crabc"):
            result = item.get(lane)
            require(isinstance(result, dict) and result.get("status") == "ok",
                    f"{row.name}/{lane}: observer collection failed: {result!r}")
            migration = result.get("migration")
            require(isinstance(migration, dict) and migration.get("event") == "syscall-entry-execve"
                    and migration.get("threads") == 1 and migration.get("syscall", {}).get("entry") is True,
                    f"{row.name}/{lane}: pre-exec migration proof differs")
            expected_leaves.add(str(migration.get("probe")))
            checkpoints = result.get("checkpoints")
            require(isinstance(checkpoints, list)
                    and [checkpoint.get("phase") for checkpoint in checkpoints] == list(row.memory_phases),
                    f"{row.name}/{lane}: R/C checkpoint order differs")
            for checkpoint in checkpoints:
                require(checkpoint.get("ready") == "R" and checkpoint.get("continue") == "C"
                        and isinstance(checkpoint.get("memory", {}).get("pss_kib"), int)
                        and isinstance(checkpoint.get("memory", {}).get("raw"), dict)
                        and isinstance(checkpoint.get("mappings", {}).get("raw"), dict),
                        f"{row.name}/{lane}: checkpoint raw PSS/maps evidence differs")
            cgroup = result.get("cgroup_memory")
            require(isinstance(cgroup, dict) and cgroup.get("status") == "ok"
                    and isinstance(cgroup.get("memory_peak_after_exit_bytes"), int)
                    and isinstance(cgroup.get("raw"), dict),
                    f"{row.name}/{lane}: post-exit cgroup evidence differs")
            if row.name == "loopback_tcp_ipv4_4k":
                peer = result.get("peer")
                require(isinstance(peer, dict) and peer.get("status") == "complete"
                        and peer.get("row", {}).get("id") == row.name,
                        f"{row.name}/{lane}: owned loopback peer evidence differs")
            else:
                require(result.get("peer") is None, f"{row.name}/{lane}: unexpected peer evidence")
        require(item.get("comparison", {}).get("status") == "ok",
                f"{row.name}: observer comparison is incomplete")
    require(set(cleanup.get("owned_leaves", ())) == expected_leaves
            and cleanup.get("remaining_leaves") == [] and cleanup.get("unmount_status") == 0,
            "collector smoke cgroup cleanup differs")


def run(args: argparse.Namespace) -> Path:
    require(runner.git_clean(ROOT), "collector smoke requires a clean source revision")
    work = fresh_work(args.work)
    report = work / "memory-collector-smoke.json"
    selected = selected_rows()
    environment_args = SimpleNamespace(
        dynamic_product=args.dynamic_product,
        musl_root=Path(runner.DEFAULT_MUSL_ROOT),
        musl_cc=runner.DEFAULT_MUSL_CC,
        cpu=args.cpu,
        timeout=args.timeout,
        samples=1,
        warmup=0,
        seed=0,
        label="memory-collector-smoke",
    )
    state: runner.BuildState | None = None
    session: runner.CgroupSession | None = None
    cleanup: dict[str, Any] = {"status": "not-created"}
    result: dict[str, Any] = {
        "schema": "crabc.perf.x86_64-memory-collector-smoke/v1",
        "status": "failed",
        "rows": list(SMOKE_ROWS),
        "source_revision": runner.git_revision(ROOT),
        "work": runner.recorded_path(ROOT, work),
    }
    try:
        product, musl_root, musl_cc, cpu, allowed_affinity, peer_cpu = runner.validate_environment(environment_args, ROOT)
        require(peer_cpu is not None, "collector smoke requires a peer CPU distinct from the benchmark CPU")
        state = runner.BuildState(root=ROOT, work=work, product=product, musl_cc=musl_cc, raw_root=work / "raw/build")
        runner.make_generated_sources(state, selected)
        sources, _headers = runner.source_roster(ROOT, state, selected, include_memory_observers=True)
        runner.compile_required_objects(state, sources, selected)
        runner.link_required_artifacts(state, selected)
        lanes = {
            "musl": runner.stage_lane(work, state, name="musl", selected=selected, product=product, musl_root=musl_root),
            "crabc": runner.stage_lane(work, state, name="crabc", selected=selected, product=product, musl_root=musl_root),
        }
        session = runner.CgroupSession.create(work)
        observations = runner.collect_memory_observers(
            ROOT, lanes, selected, session, work / "raw/execution", args.timeout,
            cpu, peer_cpu, allowed_affinity,
        )
        result.update({
            "product": runner.record_product(ROOT, product),
            "host": runner.host_snapshot(cpu, allowed_affinity, peer_cpu),
            "observations": observations,
        })
    except (runner.AdapterError, runner.CgroupUnsupported, OSError, SmokeError) as error:
        result["failure"] = str(error)
    finally:
        if session is not None:
            cleanup = session.close()
        # The Docker process commonly creates this disposable smoke tree under
        # umask 077.  It is ordinary diagnostic/build output, not a sealed
        # supplied product, so make the entire retained tree host-readable
        # before publishing its report.  Individual raw identities are sealed
        # only after this normalization.
        runner.normalize_retained_tree(ROOT, work)
        result["cleanup"] = cleanup
        try:
            if "observations" in result:
                validate_result(selected, result["observations"], cleanup)
                result["status"] = "ok"
        except SmokeError as error:
            result["failure"] = str(error)
        runner.write_json(report, runner.json_with_recorded_paths(ROOT, result))
    if result["status"] != "ok":
        raise SmokeError(str(result.get("failure", "memory collector smoke failed")))
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--dynamic-product", type=Path, required=True)
    result.add_argument("--work", type=Path, required=True)
    result.add_argument("--timeout", type=float, default=30.0)
    result.add_argument("--cpu", type=int, default=None)
    return result


def main() -> int:
    try:
        report = run(parser().parse_args())
    except (SmokeError, runner.AdapterError, OSError) as error:
        print(f"x86_64 memory collector smoke: {error}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
