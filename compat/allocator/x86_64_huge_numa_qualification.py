#!/usr/bin/env python3
"""Native 1-GiB huge-page and physical multi-NUMA qualification.

The existing huge-reservation and huge-registry lanes deliberately simulate a
successful primitive.  They remain the source-policy and ownership evidence.
This collector composes those lanes with one short, source-shaped hardware
workload per implementation: pinned C calls
``mi_reserve_huge_os_pages_at(1, node, 0)`` for two supplied nodes, while the
existing Rust ``HugeOsAllocation::allocate_for_process`` primitive does the
same.  Both children retain their mappings long enough to inspect the kernel's
own ``/proc/self/numa_maps`` entry and then return the pages before the other
implementation starts.

It never provisions huge pages, changes cgroups, rents a host, or weakens the
Docker default security policy.  Its one permission preflight sets
MPOL_PREFERRED only on a private ordinary anonymous mapping and immediately
unmaps it.  Absent external resources produce a durable
``pending_external_resources`` report and exit 3, not a simulated pass.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shutil
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SPEC = importlib.util.spec_from_file_location("allocator_run", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
run = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run
SPEC.loader.exec_module(run)

SCHEMA = "crabc-mimalloc-x86_64-huge-numa-hardware-qualification"
FORMAT = 1
REPORT = ROOT / "compat/reports/allocator/x86_64/huge-numa-hardware-qualification.json"
PRODUCT_DIRECTORY = REPORT.parent / "huge-numa-hardware-products"
FIXTURE = ROOT / "compat/allocator/m2_huge_numa_qualification_x86_64.c"
MBIND_PERMISSION_FIXTURE = ROOT / "compat/allocator/m2_huge_numa_permission_x86_64.c"
RUST_TEST = "os::tests::hardware_huge_page_numa_qualification_workload"
HUGE_PAGE_BYTES = 1024 * 1024 * 1024
HUGE_PAGE_KIB = 1024 * 1024
CAP_IPC_LOCK = 14
MAXIMUM_SOURCE_NUMA_NODE = 62
NODE_ONLINE = Path("/sys/devices/system/node/online")
NODE_ROOT = Path("/sys/devices/system/node")
GLOBAL_HUGE_ROOT = Path("/sys/kernel/mm/hugepages/hugepages-1048576kB")
CGROUP_ROOT = Path("/sys/fs/cgroup")

EXISTING_WORKLOADS = (
    (
        "source-policy-and-retained-cleanup",
        ROOT / "compat/allocator/x86_64_huge_reservation_evidence.py",
        ROOT / "compat/reports/allocator/x86_64/huge-reservation.json",
    ),
    (
        "registry-publication-provenance",
        ROOT / "compat/allocator/x86_64_huge_registry_evidence.py",
        ROOT / "compat/reports/allocator/x86_64/huge-registry.json",
    ),
)

CURRENT_INPUTS = (
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "compat/allocator/run.py",
    "compat/allocator/x86_64_huge_numa_qualification.py",
    "compat/allocator/m2_huge_numa_qualification_x86_64.c",
    "compat/allocator/m2_huge_numa_permission_x86_64.c",
    "compat/allocator/README.md",
    "compat/allocator/tests/test_x86_64_runner.py",
    "compat/allocator/tests/test_x86_64_huge_numa_qualification.py",
    "compat/allocator/x86_64_huge_reservation_evidence.py",
    "compat/allocator/x86_64_huge_registry_evidence.py",
    "compat/allocator/run-x86_64.sh",
    "crabc-core/Cargo.toml",
    "crabc-core/src/mm.rs",
    "crabc-core/src/mm_x86_64.rs",
    "crabc-core/src/syscall.rs",
    "crabc-core/src/syscall_x86_64.rs",
    "crabc-mimalloc/Cargo.toml",
    "crabc-mimalloc/src/arena_huge.rs",
    "crabc-mimalloc/src/os.rs",
)
PINNED_C_SOURCES = (
    "include/mimalloc/internal.h",
    "src/arena.c",
    "src/os.c",
    "src/prim/unix/prim.c",
    "src/static.c",
)


def error(message: str) -> run.HarnessError:
    return run.HarnessError(message)


def parse_integer_set(value: str, *, subject: str) -> set[int]:
    """Parse Linux's compact ``0-3,8`` CPU/node-list grammar."""

    result: set[int] = set()
    if not value.strip():
        raise error(f"{subject} is empty")
    for item in value.strip().split(","):
        if not item:
            raise error(f"{subject} has an empty list item")
        if "-" in item:
            first, separator, last = item.partition("-")
            if not separator or not first.isdecimal() or not last.isdecimal():
                raise error(f"{subject} has an invalid range {item!r}")
            lower, upper = int(first), int(last)
            if lower > upper:
                raise error(f"{subject} has a descending range {item!r}")
            result.update(range(lower, upper + 1))
        elif item.isdecimal():
            result.add(int(item))
        else:
            raise error(f"{subject} has an invalid node {item!r}")
    return result


def proc_status_fields() -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key] = value.strip()
    return fields


def read_counter(path: Path, subject: str) -> int:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as failure:
        raise error(f"cannot read {subject}: {failure}") from failure
    if not value.isdecimal():
        raise error(f"{subject} is not a nonnegative integer: {value!r}")
    return int(value)


def node_pool(node: int) -> dict[str, Any]:
    root = NODE_ROOT / f"node{node}" / "hugepages" / "hugepages-1048576kB"
    counters: dict[str, int | None] = {}
    for name in ("nr_hugepages", "free_hugepages", "resv_hugepages", "surplus_hugepages"):
        path = root / name
        counters[name] = read_counter(path, f"node {node} 1-GiB {name}") if path.is_file() else None
    return {"node": node, "path": str(root), **counters}


def global_pool() -> dict[str, int | None]:
    result: dict[str, int | None] = {"path": str(GLOBAL_HUGE_ROOT)}
    for name in ("nr_hugepages", "free_hugepages", "resv_hugepages", "surplus_hugepages"):
        path = GLOBAL_HUGE_ROOT / name
        result[name] = read_counter(path, f"global 1-GiB {name}") if path.is_file() else None
    return result


def cgroup_hugetlb_headroom() -> dict[str, Any]:
    """Record, rather than assume, a v2 huge-TLB cgroup limit.

    Some root cgroups do not expose the controller.  That absence cannot prove
    a limit, but it also cannot be treated as a zero-byte limit; the per-node
    pools remain mandatory either way.
    """

    for name in ("hugetlb.1GB.max", "hugetlb.1024MB.max", "hugetlb.1048576kB.max"):
        limit_path = CGROUP_ROOT / name
        if not limit_path.is_file():
            continue
        current_path = limit_path.with_name(limit_path.name[:-4] + "current")
        raw_limit = limit_path.read_text(encoding="utf-8").strip()
        raw_current = current_path.read_text(encoding="utf-8").strip() if current_path.is_file() else None
        if raw_limit == "max":
            return {"status": "unlimited", "limit_path": str(limit_path), "current_path": str(current_path),
                    "limit": "max", "current": raw_current, "headroom_bytes": "unlimited"}
        if not raw_limit.isdecimal() or raw_current is None or not raw_current.isdecimal():
            return {"status": "invalid", "limit_path": str(limit_path), "current_path": str(current_path),
                    "limit": raw_limit, "current": raw_current, "headroom_bytes": None}
        limit, current = int(raw_limit), int(raw_current)
        return {"status": "bounded", "limit_path": str(limit_path), "current_path": str(current_path),
                "limit": limit, "current": current, "headroom_bytes": max(0, limit - current)}
    return {"status": "not-exposed", "limit_path": None, "current_path": None,
            "limit": None, "current": None, "headroom_bytes": None}


def ordinary_memory_limits() -> dict[str, Any]:
    """Retain limits relevant to, but not a measured floor for, ordinary RAM."""

    process_limits: dict[str, int | str] = {}
    for name in ("RLIMIT_AS", "RLIMIT_DATA", "RLIMIT_MEMLOCK"):
        limit = resource.getrlimit(getattr(resource, name))[0]
        process_limits[name] = "unlimited" if limit == resource.RLIM_INFINITY else limit
    limit_path = CGROUP_ROOT / "memory.max"
    current_path = CGROUP_ROOT / "memory.current"
    raw_limit = limit_path.read_text(encoding="utf-8").strip() if limit_path.is_file() else None
    raw_current = current_path.read_text(encoding="utf-8").strip() if current_path.is_file() else None
    cgroup_status = (
        "not-exposed" if raw_limit is None
        else "unlimited" if raw_limit == "max"
        else "bounded" if raw_limit.isdecimal() and raw_current is not None and raw_current.isdecimal()
        else "invalid"
    )
    return {
        "ordinary_memory_budget": "unmeasured: the existing source workloads do not establish a numeric compiler/runtime RAM floor",
        "process_rlimits": process_limits,
        "cgroup_memory": {
            "status": cgroup_status,
            "limit_path": str(limit_path) if raw_limit is not None else None,
            "current_path": str(current_path) if raw_current is not None else None,
            "limit": raw_limit,
            "current": raw_current,
        },
    }


def gate(identifier: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"id": identifier, "status": "passed" if passed else "pending", "detail": detail}


def refresh_preflight_status(preflight: dict[str, Any]) -> None:
    if preflight.get("technical_failures") or any(item["status"] == "failed" for item in preflight["gates"]):
        preflight["status"] = "failed"
    elif all(item["status"] == "passed" for item in preflight["gates"]):
        preflight["status"] = "ready"
    else:
        preflight["status"] = "pending_external_resources"


def qualification_requirements() -> dict[str, Any]:
    return {
        "hardware_footprint": {
            "mapping_size_bytes": HUGE_PAGE_BYTES,
            "mapping_size_kib": HUGE_PAGE_KIB,
            "concurrent_mappings": 2,
            "reserved_hugetlb_bytes": 2 * HUGE_PAGE_BYTES,
            "reservation_shape": "one free 1-GiB hugetlb page on each of two distinct process-visible NUMA nodes; C and Rust workloads run sequentially",
            "ordinary_overhead": "unmeasured: build artifacts, compiler memory, test executable memory, and ordinary process memory are outside the 2-GiB hugetlb reservation; the report retains the active cgroup and RLIMIT evidence but does not invent a numeric floor",
        },
        "topology": {
            "minimum_distinct_memory_nodes": 2,
            "selection": "the collector selects any two online nodes in both /proc/self/status Mems_allowed_list and cgroup cpuset.mems.effective, with IDs 0 through 62",
            "cpu_affinity": "not required: the pinned source chooses memory-node preference; this job does not impose a CPU-per-node contract",
        },
        "permissions": {
            "container_capability": "CAP_IPC_LOCK; the canonical launcher adds it only for this job",
            "numa_observation": "readable /proc/self/numa_maps",
            "mbind": "the container's approved security policy must allow the source MPOL_PREFERRED mbind syscall; seccomp mode alone does not reveal whether that rule is present",
        },
        "nonclaims": [
            "allocator M2 completion or backend promotion",
            "general arena lifecycle, public mi_* coverage, or crabc runtime integration",
            "AArch64 evidence or public x86-64 platform support",
        ],
    }


def collect_preflight() -> dict[str, Any]:
    status = proc_status_fields()
    online = parse_integer_set(NODE_ONLINE.read_text(encoding="utf-8"), subject="node_online")
    allowed_raw = status.get("Mems_allowed_list")
    if allowed_raw is None:
        raise error("/proc/self/status has no Mems_allowed_list")
    allowed = parse_integer_set(allowed_raw, subject="Mems_allowed_list")
    cpuset_path = CGROUP_ROOT / "cpuset.mems.effective"
    if cpuset_path.is_file():
        cgroup_allowed = parse_integer_set(cpuset_path.read_text(encoding="utf-8"), subject="cpuset.mems.effective")
        cgroup_state: dict[str, Any] = {"path": str(cpuset_path), "nodes": sorted(cgroup_allowed)}
    else:
        cgroup_allowed = allowed
        cgroup_state = {"path": None, "nodes": None, "detail": "cpuset.mems.effective is not exposed"}
    visible = sorted(online & allowed & cgroup_allowed)
    pools: list[dict[str, Any]] = []
    pool_errors: dict[int, str] = {}
    for node in visible:
        try:
            pools.append(node_pool(node))
        except run.HarnessError as failure:
            pool_errors[node] = str(failure)
    ready_nodes = [
        pool["node"] for pool in pools
        if pool["node"] <= MAXIMUM_SOURCE_NUMA_NODE
        and pool["nr_hugepages"] is not None and pool["free_hugepages"] is not None
        and pool["nr_hugepages"] >= 1 and pool["free_hugepages"] >= 1
    ]
    selected = ready_nodes[:2]
    cap_eff = status.get("CapEff", "")
    try:
        cap_eff_value = int(cap_eff, 16)
    except ValueError:
        cap_eff_value = 0
    cap_ipc_lock = bool(cap_eff_value & (1 << CAP_IPC_LOCK))
    numa_maps = Path("/proc/self/numa_maps")
    hugetlb = cgroup_hugetlb_headroom()
    headroom = hugetlb["headroom_bytes"]
    cgroup_limit_ok = (
        hugetlb["status"] in {"not-exposed", "unlimited"}
        or (hugetlb["status"] == "bounded" and isinstance(headroom, int) and headroom >= 2 * HUGE_PAGE_BYTES)
    )
    gates = [
        gate("native-linux-x86-64", os.uname().sysname == "Linux" and os.uname().machine == "x86_64",
             f"system={os.uname().sysname} machine={os.uname().machine}"),
        gate("two-process-visible-memory-nodes", len(visible) >= 2,
             f"online={sorted(online)} status_allowed={sorted(allowed)} cgroup_allowed={cgroup_state['nodes']} visible={visible}"),
        gate("two-source-valid-nodes-with-free-1gib-pages", len(selected) == 2,
             f"selected={selected}; each selected node requires nr_hugepages >= 1 and free_hugepages >= 1; pool_errors={pool_errors}"),
        gate("hugetlb-cgroup-headroom", cgroup_limit_ok,
             f"cgroup 1-GiB huge-TLB state={hugetlb['status']} headroom_bytes={headroom}; required={2 * HUGE_PAGE_BYTES}"),
        gate("container-cap-ipc-lock", cap_ipc_lock,
             f"CapEff={cap_eff or 'absent'}; CAP_IPC_LOCK bit={CAP_IPC_LOCK}"),
        gate("numa-maps-observer", numa_maps.is_file() and os.access(numa_maps, os.R_OK),
             f"path={numa_maps} readable={numa_maps.is_file() and os.access(numa_maps, os.R_OK)}"),
    ]
    result: dict[str, Any] = {
        "status": "pending_external_resources",
        "gates": gates,
        "selected_nodes": selected,
        "node_online": sorted(online),
        "process_mems_allowed": sorted(allowed),
        "cgroup_mems_allowed": cgroup_state,
        "process_cpus_allowed": status.get("Cpus_allowed_list"),
        "global_1gib_pool": global_pool(),
        "per_node_1gib_pools": pools,
        "pool_read_errors": pool_errors,
        "cgroup_hugetlb": hugetlb,
        "ordinary_memory_limits": ordinary_memory_limits(),
        "capabilities": {"effective_hex": cap_eff, "cap_ipc_lock": cap_ipc_lock},
        "security": {"seccomp_mode": status.get("Seccomp"), "no_new_privs": status.get("NoNewPrivs"),
                     "mbind_rule": "not inferred from seccomp mode; observed by the hardware workload"},
        "numa_maps_path": str(numa_maps),
        "mbind_probe_nodes": [node for node in visible if node <= MAXIMUM_SOURCE_NUMA_NODE],
        "technical_failures": [],
    }
    refresh_preflight_status(result)
    return result


def parse_mbind_permission_probe(output: str) -> dict[str, int]:
    expression = re.compile(r"^CRABC_MI_HUGE_NUMA_MBIND_PROBE\.(node|page_bytes|result|errno|unmap_result|unmap_errno)=(-?[0-9]+)$")
    fields: dict[str, int] = {}
    for line in output.splitlines():
        match = expression.fullmatch(line)
        if match is None:
            continue
        key, value = match.group(1), int(match.group(2))
        if key in fields:
            raise error(f"mbind permission probe duplicated {key}")
        fields[key] = value
    expected = {"node", "page_bytes", "result", "errno", "unmap_result", "unmap_errno"}
    if set(fields) != expected:
        raise error("mbind permission probe did not emit its complete raw result")
    if fields["page_bytes"] <= 0 or fields["unmap_result"] != 0 or fields["unmap_errno"] != 0:
        raise error("mbind permission probe did not release its ordinary private page")
    if (fields["result"] == 0) != (fields["errno"] == 0):
        raise error("mbind permission probe has an inconsistent raw errno")
    return fields


def run_mbind_permission_probe(preflight: dict[str, Any]) -> None:
    """Test the one exact syscall without inferring its rule from Seccomp:2.

    The probe runs at most once per job invocation, maps one ordinary private
    page, calls the source-shaped flags=0 MPOL_PREFERRED form, and verifies its
    own immediate unmap.  It is intentionally outside the 2-GiB huge-page
    footprint and never retries a permission denial.
    """

    candidates = list(preflight["mbind_probe_nodes"])
    if not candidates:
        preflight["mbind_permission_probe"] = {"status": "not-run", "reason": "no source-valid process-visible NUMA node"}
        preflight["gates"].append(gate("mbind-mpol-preferred-flags-zero", False,
                                        "not run: no process-visible source-valid NUMA node"))
        refresh_preflight_status(preflight)
        return
    node = candidates[0]
    probe: dict[str, Any] = {"status": "failed", "node": node}
    preflight["mbind_permission_probe"] = probe
    try:
        compiler = run.require_tool("musl-gcc")
        with run.temporary_directory("huge-numa-mbind-permission-") as temporary_name:
            temporary = Path(temporary_name)
            binary = temporary / "huge-numa-mbind-permission"
            build = run.command_record(
                [compiler, "-std=c11", "-O2", str(MBIND_PERMISSION_FIXTURE), "-o", str(binary)],
                cwd=ROOT,
                timeout_seconds=300,
            )
            probe["build"] = build
            run.require_success(build, "ordinary-page mbind permission probe build")
            execution = run.command_record(
                [str(binary), str(node)], cwd=ROOT, timeout_seconds=300,
            )
            probe["execution"] = execution
            run.require_success(execution, "ordinary-page mbind permission probe execution")
            raw = parse_mbind_permission_probe(execution["stdout"])
    except (run.HarnessError, OSError, ValueError) as failure:
        probe["reason"] = str(failure)
        preflight["technical_failures"].append(f"mbind permission probe could not run: {failure}")
        preflight["gates"].append({"id": "mbind-mpol-preferred-flags-zero", "status": "failed",
                                    "detail": f"probe could not run: {failure}"})
        refresh_preflight_status(preflight)
        return
    expected_page_size = os.sysconf("SC_PAGE_SIZE")
    if raw["node"] != node or raw["page_bytes"] != expected_page_size:
        detail = (
            f"probe identity drift: requested_node={node} observed_node={raw['node']} "
            f"expected_page_bytes={expected_page_size} observed_page_bytes={raw['page_bytes']}"
        )
        probe.update({"status": "failed", "raw": raw, "reason": detail})
        preflight["technical_failures"].append(detail)
        preflight["gates"].append({"id": "mbind-mpol-preferred-flags-zero", "status": "failed", "detail": detail})
        refresh_preflight_status(preflight)
        return
    passed = raw["result"] == 0
    detail = (
        f"ordinary private-page mbind node={node} result={raw['result']} errno={raw['errno']}; "
        "this is the observed syscall result, not an inference from seccomp mode"
    )
    probe.update({"status": "passed" if passed else "nonzero-result", "raw": raw})
    preflight["gates"].append(gate("mbind-mpol-preferred-flags-zero", passed, detail))
    refresh_preflight_status(preflight)


def source_state(*, require_clean: bool) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    revision = run.command_record([run.require_tool("git"), "rev-parse", "--verify", "HEAD"], cwd=ROOT, env=environment)
    status = run.command_record([run.require_tool("git"), "status", "--porcelain=v1", "--untracked-files=all", "-z"], cwd=ROOT, env=environment)
    run.require_success(revision, "qualification source revision")
    run.require_success(status, "qualification source status")
    raw_status = status["stdout"].encode("utf-8")
    result = {
        "revision": revision["stdout"].strip(),
        "worktree_clean": raw_status == b"",
        "worktree_status": {"bytes": len(raw_status), "hex": raw_status.hex(), "sha256": hashlib.sha256(raw_status).hexdigest()},
    }
    if not re.fullmatch(r"[0-9a-f]{40}", result["revision"]):
        raise error("qualification source revision is not a Git object ID")
    if require_clean and not result["worktree_clean"]:
        raise error("hardware qualification requires a clean committed source checkout")
    return result


def extract_definition(source: Path, signature: str) -> dict[str, Any]:
    text = source.read_text(encoding="utf-8")
    definition = re.search(re.escape(signature) + r"[^;{]*\{", text)
    if definition is None:
        raise error(f"pinned source lacks {signature}")
    start = definition.start()
    cursor = definition.end()
    depth = 1
    while depth:
        if cursor >= len(text):
            raise error(f"pinned source has an unterminated {signature}")
        if text[cursor] == "{":
            depth += 1
        elif text[cursor] == "}":
            depth -= 1
        cursor += 1
    body = text[start:cursor]
    return {
        "signature": signature,
        "start_line": text[:start].count("\n") + 1,
        "end_line": text[:cursor].count("\n") + 1,
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
    }


def parse_trace(output: str, language: str) -> list[dict[str, int]]:
    prefix = f"CRABC_MI_HUGE_NUMA_{language}_MAP"
    begin = f"CRABC_MI_HUGE_NUMA_{language}_TRACE_BEGIN"
    end = f"CRABC_MI_HUGE_NUMA_{language}_TRACE_END"
    lines = output.splitlines()
    try:
        start = lines.index(begin)
        finish = lines.index(end, start + 1)
    except ValueError as failure:
        raise error(f"{language} huge-NUMA trace markers are absent") from failure
    if begin in lines[start + 1:] or end in lines[finish + 1:]:
        raise error(f"{language} huge-NUMA trace markers are duplicated")
    rows: dict[int, dict[str, int]] = {}
    fields = (
        {"observed_node", "kernel_page_kib", "mapping_address"}
        if language == "C" else
        {"requested_node", "observed_node", "kernel_page_kib", "mapping_address"}
    )
    expression = re.compile(
        rf"^{re.escape(prefix)}\.(\d+)\.({'|'.join(sorted(fields))})=([0-9]+)$"
    )
    for line in lines[start + 1:finish]:
        match = expression.fullmatch(line)
        if match is None:
            raise error(f"{language} huge-NUMA trace has an unexpected line: {line!r}")
        index, field, value = int(match.group(1)), match.group(2), int(match.group(3))
        row = rows.setdefault(index, {})
        if field in row:
            raise error(f"{language} huge-NUMA trace duplicates {field} for mapping {index}")
        row[field] = value
    if sorted(rows) != [0, 1] or any(set(row) != fields for row in rows.values()):
        raise error(f"{language} huge-NUMA trace must contain exactly two complete mappings")
    return [rows[0], rows[1]]


def validate_trace(rows: list[dict[str, int]], selected_nodes: list[int], language: str) -> None:
    if len(selected_nodes) != 2 or len(set(selected_nodes)) != 2:
        raise error("qualification needs exactly two selected NUMA nodes")
    for row in rows:
        if row["kernel_page_kib"] != HUGE_PAGE_KIB:
            raise error(f"{language} huge mapping is not backed by a one-GiB kernel page")
        if row["mapping_address"] == 0:
            raise error(f"{language} huge mapping lacks a live mapping identity")
    if len({row["mapping_address"] for row in rows}) != 2:
        raise error(f"{language} huge-NUMA trace reuses one mapping identity")
    if language == "C":
        if {row["observed_node"] for row in rows} != set(selected_nodes):
            raise error("pinned C huge mappings do not cover the exact requested NUMA-node set")
        return
    if [row["requested_node"] for row in rows] != selected_nodes:
        raise error("Rust huge-NUMA trace did not retain the selected node order")
    for row in rows:
        if row["observed_node"] != row["requested_node"]:
            raise error("Rust huge mapping did not land on its requested NUMA node")


def pools_for_nodes(preflight: Mapping[str, Any], nodes: list[int]) -> dict[int, tuple[int, int]]:
    records = {record["node"]: record for record in preflight["per_node_1gib_pools"]}
    result: dict[int, tuple[int, int]] = {}
    for node in nodes:
        record = records.get(node)
        if record is None or not isinstance(record.get("nr_hugepages"), int) or not isinstance(record.get("free_hugepages"), int):
            raise error(f"no readable one-GiB pool record for selected node {node}")
        result[node] = (record["nr_hugepages"], record["free_hugepages"])
    return result


def require_pool_restored(before: Mapping[str, Any], after: Mapping[str, Any], nodes: list[int], subject: str) -> None:
    if pools_for_nodes(before, nodes) != pools_for_nodes(after, nodes):
        raise error(f"one-GiB huge-page pool changed across {subject}; exclusive resource evidence is invalid")


def checked(command: list[str], description: str, *, env: Mapping[str, str] | None = None,
            timeout_seconds: int = 1200) -> dict[str, Any]:
    record = run.command_record(command, cwd=ROOT, env=env, timeout_seconds=timeout_seconds)
    run.require_success(record, description)
    return record


def recorded_checked(
    receipt: dict[str, Any],
    key: str,
    command: list[str],
    description: str,
    *,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = 1200,
) -> dict[str, Any]:
    """Keep the reached command receipt even if its success check fails."""

    record = run.command_record(command, cwd=ROOT, env=env, timeout_seconds=timeout_seconds)
    receipt[key] = record
    run.require_success(record, description)
    return record


def retain_executed_product(source: Path, name: str) -> dict[str, Any]:
    """Copy an executable into generated evidence before executing that copy."""

    if not source.is_file():
        raise error(f"executed product is absent before retention: {source}")
    PRODUCT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    destination = PRODUCT_DIRECTORY / name
    shutil.copy2(source, destination)
    return run.artifact_record(destination)


def cargo_test_executable(cargo_json: str) -> Path:
    """Select Cargo's sole `crabc-mimalloc` lib-test executable from JSON."""

    candidates: list[Path] = []
    for line in cargo_json.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError as failure:
            raise error("Cargo --message-format=json emitted malformed JSON") from failure
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        executable = message.get("executable")
        if (
            isinstance(target, dict)
            and target.get("name") == "crabc_mimalloc"
            and isinstance(target.get("kind"), list)
            and "lib" in target["kind"]
            and isinstance(executable, str)
        ):
            candidates.append(Path(executable))
    if len(candidates) != 1:
        raise error(f"Cargo produced {len(candidates)} crabc-mimalloc lib-test executables, expected exactly one")
    return candidates[0]


def run_existing_workloads(progress: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    progress["existing_workloads"] = records
    python = run.require_tool("python3")
    for identifier, producer, receipt in EXISTING_WORKLOADS:
        entry: dict[str, Any] = {"id": identifier}
        records.append(entry)
        command = recorded_checked(
            entry,
            "command",
            [python, str(producer.relative_to(ROOT))],
            f"existing huge workload {identifier}",
        )
        if not receipt.is_file():
            raise error(f"existing huge workload {identifier} did not write {receipt}")
        entry["receipt"] = run.artifact_record(receipt)
    return records


def run_hardware_workload(preflight: Mapping[str, Any], source: Path, progress: dict[str, Any]) -> dict[str, Any]:
    nodes = list(preflight["selected_nodes"])
    compiler = run.require_tool("musl-gcc")
    hardware: dict[str, Any] = {"selected_nodes": nodes}
    progress["hardware_workload"] = hardware
    with run.temporary_directory("huge-numa-qualification-") as temporary_name:
        temporary = Path(temporary_name)
        binary = temporary / "huge-numa-qualification-c"
        c: dict[str, Any] = {}
        hardware["c"] = c
        recorded_checked(c, "build", [
            compiler, "-std=c11", "-O2", "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-I", str(source / "include"), "-I", str(source / "src"),
            *run.CONFIGURATION_PROFILES["release"], str(FIXTURE), "-pthread", "-o", str(binary),
        ], "pinned C huge-NUMA workload build")
        c_product = PRODUCT_DIRECTORY / "huge-numa-c"
        c["executed_product"] = retain_executed_product(binary, c_product.name)
        header = recorded_checked(c, "elf_header", [run.require_tool("readelf"), "-h", str(c_product)],
                                  "C huge-NUMA ELF identity")
        c["elf"] = run.parse_elf_identity(header["stdout"], "x86_64")
        c_run = recorded_checked(c, "execution", [str(c_product), str(nodes[0]), str(nodes[1])],
                                 "pinned C huge-NUMA workload execution")
        c_rows = parse_trace(c_run["stdout"], "C")
        validate_trace(c_rows, nodes, "C")
        c["trace"] = c_rows
        after_c = collect_preflight()
        require_pool_restored(preflight, after_c, nodes, "the pinned C workload")
        hardware["after_c_preflight"] = after_c
        environment = dict(os.environ)
        environment["CRABC_MIMALLOC_HUGE_NUMA_NODES"] = f"{nodes[0]},{nodes[1]}"
        rust: dict[str, Any] = {"test": RUST_TEST}
        hardware["rust"] = rust
        cargo_build = recorded_checked(rust, "cargo_no_run", [
            run.require_tool("cargo"), "test", "--locked", "--target", "x86_64-unknown-linux-musl",
            "-p", "crabc-mimalloc", "--lib", "--no-default-features", "--no-run", "--message-format=json",
        ], "Rust huge-NUMA test executable build", env=environment)
        rust_binary = cargo_test_executable(cargo_build["stdout"])
        rust_product = PRODUCT_DIRECTORY / "huge-numa-rust-test"
        rust["executed_product"] = retain_executed_product(rust_binary, rust_product.name)
        rust_header = recorded_checked(rust, "elf_header", [run.require_tool("readelf"), "-h", str(rust_product)],
                                       "Rust huge-NUMA ELF identity")
        rust["elf"] = run.parse_elf_identity(rust_header["stdout"], "x86_64")
        rust_run = recorded_checked(rust, "execution", [
            str(rust_product), RUST_TEST, "--exact", "--nocapture", "--test-threads=1",
        ], "Rust huge-NUMA workload execution", env=environment)
        rust_rows = parse_trace(rust_run["stdout"] + "\n" + rust_run["stderr"], "RUST")
        validate_trace(rust_rows, nodes, "RUST")
        rust["trace"] = rust_rows
        after_rust = collect_preflight()
        require_pool_restored(preflight, after_rust, nodes, "the Rust workload")
        hardware["after_rust_preflight"] = after_rust
    return hardware


def execution_identity() -> dict[str, str]:
    image_id = os.environ.get("CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID", "")
    if not image_id:
        raise error("canonical allocator launcher did not provide CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID")
    return {"allocator_evidence_image_id": image_id}


def success_report(preflight: Mapping[str, Any], progress: dict[str, Any]) -> dict[str, Any]:
    before = source_state(require_clean=True)
    progress["source_before"] = before
    pin = run.load_pin()
    progress["upstream_pin"] = pin
    archive = run.fetch_archive(pin, True)
    progress["upstream_archive"] = run.artifact_record(archive)
    with run.temporary_directory("huge-numa-pinned-source-") as temporary_name:
        source = run.safe_extract(archive, Path(temporary_name) / "source", pin["archive_root"])
        compiler = run.require_tool("musl-gcc")
        toolchains: dict[str, Any] = {"image": execution_identity()}
        progress["toolchains"] = toolchains
        recorded_checked(toolchains, "musl_gcc", [compiler, "--version"], "pinned C compiler identity")
        recorded_checked(toolchains, "rustc", [run.require_tool("rustc"), "-Vv"], "Rust compiler identity")
        recorded_checked(toolchains, "cargo", [run.require_tool("cargo"), "-V"], "Cargo identity")
        existing = run_existing_workloads(progress)
        hardware = run_hardware_workload(preflight, source, progress)
        pinned_sources = run.source_file_records(source, PINNED_C_SOURCES)
        anchors = [
            {"member": "src/arena.c", **extract_definition(source / "src/arena.c", "int mi_reserve_huge_os_pages_at(")},
            {"member": "src/os.c", **extract_definition(source / "src/os.c", "void* _mi_os_alloc_huge_os_pages(")},
            {"member": "src/prim/unix/prim.c", **extract_definition(source / "src/prim/unix/prim.c", "int _mi_prim_alloc_huge_os_pages(")},
        ]
    after = source_state(require_clean=True)
    progress["source_after"] = after
    if before != after:
        raise error("source changed during hardware huge-NUMA qualification")
    return {
        "schema": SCHEMA,
        "format": FORMAT,
        "status": "passed",
        "architecture": "x86_64",
        "execution": {**run.require_native_x86_64(), **execution_identity()},
        "requirements": qualification_requirements(),
        "preflight": preflight,
        "source": {"before": before, "after": after, "unchanged_during_execution": True,
                   "current_inputs": run.source_file_records(ROOT, CURRENT_INPUTS)},
        "upstream": {"pin": pin, "archive": run.artifact_record(archive),
                     "source_files": pinned_sources, "source_anchors": anchors},
        "toolchains": toolchains,
        "existing_workloads": existing,
        "hardware_workload": hardware,
    }


def pending_report(preflight: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "format": FORMAT,
        "status": "pending_external_resources",
        "architecture": "x86_64",
        "execution": {**run.require_native_x86_64(), **execution_identity()},
        "requirements": qualification_requirements(),
        "preflight": preflight,
        "source_observation": source_state(require_clean=False),
        "reason": "the source-shaped hardware workload was not started because one or more external resource gates are pending",
    }


def main() -> int:
    run.require_native_x86_64()
    preflight = collect_preflight()
    run_mbind_permission_probe(preflight)
    if preflight["status"] == "failed":
        run.write_json(REPORT, {
            "schema": SCHEMA, "format": FORMAT, "status": "failed", "architecture": "x86_64",
            "execution": {**run.require_native_x86_64(), **execution_identity()}, "requirements": qualification_requirements(),
            "preflight": preflight,
        })
        REPORT.chmod(0o644)
        print(f"allocator huge-NUMA qualification: FAIL technical preflight ({REPORT})")
        return 1
    if preflight["status"] != "ready":
        run.write_json(REPORT, pending_report(preflight))
        REPORT.chmod(0o644)
        print(f"allocator huge-NUMA qualification: PENDING external resources ({REPORT})")
        return 3
    progress: dict[str, Any] = {}
    try:
        report = success_report(preflight, progress)
    except (run.HarnessError, OSError, ValueError) as failure:
        run.write_json(REPORT, {
            "schema": SCHEMA, "format": FORMAT, "status": "failed", "architecture": "x86_64",
            "execution": {**run.require_native_x86_64(), **execution_identity()}, "requirements": qualification_requirements(),
            "preflight": preflight, "progress": progress, "error": str(failure),
        })
        REPORT.chmod(0o644)
        print(f"allocator huge-NUMA qualification: FAIL: {failure}")
        return 1
    run.write_json(REPORT, report)
    REPORT.chmod(0o644)
    print(f"allocator huge-NUMA qualification: PASS ({REPORT})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
