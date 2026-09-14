#!/usr/bin/env python3
"""Run a deliberately bounded native Linux/x86-64 lifecycle evidence lane.

This judge exercises only the current crate-private lifecycle and concurrency
protocols that have focused Rust tests, plus one process-isolated integration
witness for the private runtime first-arena route. It is intentionally separate from
``run.py``: that runner owns the AArch64 production-oracle contract, whereas
this file records a native x86-64 laboratory result without implying public
``mi_*``, libc, loader, or crabc-rs support.

The lane is fail-closed on the canonical dispatcher provenance.  An x86-64
Docker guest alone is insufficient because it can be QEMU-emulated; the
dispatcher must attest a native x86-64 host through ``CRABC_EXECUTION_MODE``
and ``CRABC_HOST_ARCH``.  Every Cargo invocation also fixes the musl target,
uses ``--locked``, and writes to one disposable target directory outside the
workspace.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-musl"
REPORT = ROOT / "compat/reports/allocator/x86_64/lifecycle-concurrency.json"
RUNTIME_FIRST_ARENA_REPORT = (
    ROOT / "compat/reports/allocator/x86_64/lifecycle-runtime-process-policy-first-arena.json"
)
LOCKFILE = ROOT / "Cargo.lock"
INITIAL_TLD_NUMA_FIXTURE = ROOT / "compat/allocator/x86_64_initial_tld_numa_oracle.c"
RUNTIME_THP_CONFIGURATION_FIXTURE = (
    ROOT / "compat/allocator/x86_64_runtime_thp_configuration_oracle.c"
)
INITIAL_TLD_NUMA_TRACE_BEGIN = "CRABC_MI_INITIAL_TLD_NUMA_TRACE_BEGIN"
INITIAL_TLD_NUMA_TRACE_END = "CRABC_MI_INITIAL_TLD_NUMA_TRACE_END"
RUNTIME_INITIAL_TLD_NUMA_TRACE_BEGIN = "CRABC_MI_RUNTIME_INITIAL_TLD_NUMA_TRACE_BEGIN"
RUNTIME_INITIAL_TLD_NUMA_TRACE_END = "CRABC_MI_RUNTIME_INITIAL_TLD_NUMA_TRACE_END"
RUNTIME_THP_CONFIGURATION_IMAGE_IDS = ("disabled", "mode-two")
RUNTIME_THP_CONFIGURATION_TRACE_BEGIN = {
    "disabled": "CRABC_MI_RUNTIME_THP_DISABLED_TRACE_BEGIN",
    "mode-two": "CRABC_MI_RUNTIME_THP_MODE_TWO_TRACE_BEGIN",
}
RUNTIME_THP_CONFIGURATION_TRACE_END = {
    "disabled": "CRABC_MI_RUNTIME_THP_DISABLED_TRACE_END",
    "mode-two": "CRABC_MI_RUNTIME_THP_MODE_TWO_TRACE_END",
}
RUNTIME_THP_CONFIGURATION_C_TRACE_BEGIN = {
    "disabled": "CRABC_MI_RUNTIME_THP_C_DISABLED_TRACE_BEGIN",
    "mode-two": "CRABC_MI_RUNTIME_THP_C_MODE_TWO_TRACE_BEGIN",
}
RUNTIME_THP_CONFIGURATION_C_TRACE_END = {
    "disabled": "CRABC_MI_RUNTIME_THP_C_DISABLED_TRACE_END",
    "mode-two": "CRABC_MI_RUNTIME_THP_C_MODE_TWO_TRACE_END",
}

# `src/init.c` is included into the fixture to retain source-private access to
# `mi_process_tld_main`; each remaining normal-release object stays linked
# once. `src/arena.c` remains an ordinary linked source object, so the direct
# fixture's one `mi_malloc` reaches the real regular first-arena initializer.
# This is intentionally separate from the wider M2 VM fixture because this
# lifecycle lane records one option-aware TLD/regular-first-arena transition.
INITIAL_TLD_NUMA_C_ORACLE_LINK_SOURCES = (
    "src/alloc.c",
    "src/alloc-aligned.c",
    "src/alloc-posix.c",
    "src/arena.c",
    "src/bitmap.c",
    "src/heap.c",
    "src/libc.c",
    "src/options.c",
    "src/os.c",
    "src/page-map.c",
    "src/page.c",
    "src/random.c",
    "src/stats.c",
    "src/subproc.c",
    "src/theap.c",
    "src/threadlocal.c",
    "src/prim/prim.c",
    "src/prim/prim-tls.c",
)
INITIAL_TLD_NUMA_C_ORACLE_SOURCE_FILES = (
    "include/mimalloc.h",
    "include/mimalloc/internal.h",
    "include/mimalloc/prim.h",
    "src/init.c",
    *INITIAL_TLD_NUMA_C_ORACLE_LINK_SOURCES,
    "src/prim/unix/prim.c",
)
# The source-environment fixture directly includes both source units so its
# scalar configuration observation remains in their original translation unit.
RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES = tuple(
    source
    for source in INITIAL_TLD_NUMA_C_ORACLE_LINK_SOURCES
    if source not in {"src/os.c", "src/init.c"}
)
RUNTIME_THP_CONFIGURATION_C_ORACLE_SOURCE_FILES = (
    "include/mimalloc.h",
    "include/mimalloc/internal.h",
    "include/mimalloc/prim.h",
    "src/os.c",
    "src/init.c",
    *RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES,
    "src/prim/unix/prim.c",
)
INITIAL_TLD_NUMA_C_TRACE_KEYS = (
    "source_option_applied",
    "arena_is_numa_local_option_applied",
    "configured_numa_node_count",
    "resolved_numa_node_count",
    "ticket_zero_tld",
    "default_theap_uses_ticket_zero_tld",
    "ticket_zero_tld_numa_node",
    "ticket_zero_tld_numa_in_range",
    "regular_first_arena_is_os",
    "regular_first_arena_numa_node",
    "regular_first_arena_numa_in_range",
    "regular_first_arena_retained_after_free",
)
RUNTIME_INITIAL_TLD_NUMA_TRACE_KEYS = (
    "vm_policy_arena_is_numa_local",
    "vm_policy_use_numa_nodes",
    "vm_policy_numa_node_count_cache",
    "ticket_zero_tld_numa_node",
    "process_arena_numa_node",
)
RUNTIME_THP_CONFIGURATION_C_TRACE_KEYS = (
    "selected_allow_thp_raw",
    "config_has_transparent_huge_pages",
)
RUNTIME_THP_CONFIGURATION_TRACE_KEYS = (
    "selected_allow_thp_raw",
    "vm_policy_allow_thp",
    "ready_memory_config_has_transparent_huge_pages",
)
RUNTIME_THP_CONFIGURATION_C_IMAGES = (
    ("disabled", "-DCRABC_RUNTIME_THP_IMAGE_DISABLED=1"),
    ("mode-two", "-DCRABC_RUNTIME_THP_IMAGE_MODE_TWO=1"),
)

# The focused receipt names every local input whose current bytes participate
# in its C build, Rust product, or evidence collection.  The clean Git root
# tree binds the rest of the workspace; the focused crate tree gives a direct
# observable identity for the complete Rust allocator candidate rather than
# treating only this test's source file as the runtime product.
CANDIDATE_SOURCE_INPUTS = (
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "crabc-mimalloc/Cargo.toml",
    "crabc-mimalloc/src/lib.rs",
    "crabc-mimalloc/src/arena.rs",
    "crabc-mimalloc/src/main_theap.rs",
    "crabc-mimalloc/src/os.rs",
    "crabc-mimalloc/src/process_arena.rs",
    "crabc-mimalloc/src/process_init.rs",
    "crabc-mimalloc/src/runtime_lifecycle.rs",
    "crabc-mimalloc/tests/native_runtime_first_arena_policy.rs",
    "compat/allocator/run-x86_64.sh",
    "compat/allocator/run.py",
    "compat/allocator/x86_64_initial_tld_numa_oracle.c",
    "compat/allocator/x86_64_runtime_thp_configuration_oracle.c",
    "compat/allocator/x86_64_lifecycle_evidence.py",
)
CANDIDATE_SOURCE_GIT_READ_ENVIRONMENT = {"GIT_OPTIONAL_LOCKS": "0"}

TEST_RESULT = re.compile(
    r"test result: (?P<status>ok|FAILED)\. "
    r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
    r"(?P<filtered>\d+) filtered out;"
)
RUSTC_HOST = re.compile(r"^host: (?P<target>\S+)$", re.MULTILINE)


class EvidenceError(RuntimeError):
    """A failed evidence precondition or bounded test lane."""


@dataclass(frozen=True)
class TestLane:
    """One intentionally narrow current-engine test selection."""

    identifier: str
    kind: str
    test_filter: str
    exact_filter: bool
    features: tuple[str, ...]
    expected_pass_count: int
    source_tests: tuple[str, ...]
    bounded_behavior: tuple[str, ...]


# These selections are named rather than discovered.  Adding a new test to a
# module cannot silently enlarge a lifecycle claim: a reviewer must add a
# source-specific behavior statement and expected pass count here first.
TEST_LANES = (
    TestLane(
        identifier="runtime-process-policy-first-arena",
        kind="native-integration",
        test_filter="runtime_process_uses_source_vm_policy_for_ticket_zero_first_arena_and_client_cleanup",
        exact_filter=True,
        features=("native-runtime-test-audit",),
        expected_pass_count=1,
        source_tests=(
            "native_runtime_first_arena_policy::runtime_process_uses_source_vm_policy_for_ticket_zero_first_arena_and_client_cleanup",
        ),
        bounded_behavior=(
            "one fresh native process reads a non-default raw source environment and initializes RuntimeProcessStorage through its retained policy/PageMap binding",
            "the actual ticket-zero TLD consumes mimalloc_use_numa_nodes=3 through that retained policy and stores one normalized node before the first client allocation",
            "the original ticket-zero allocation reaches begin_for_process, maps one committed 128-MiB regular arena, then the source arena initializer resolves arena_is_numa_local through that same policy after metadata preparation",
            "the exact client free removes its PageMap registration while the selected regular arena mapping and normalized stored node remain retained",
        ),
    ),
    TestLane(
        identifier="runtime-source-environment-thp-ready-configuration-admission",
        kind="native-integration",
        test_filter="runtime_process_admits_source_allow_thp_images_with_retained_ready_configuration",
        exact_filter=True,
        features=("native-runtime-test-audit",),
        expected_pass_count=1,
        source_tests=(
            "native_runtime_first_arena_policy::runtime_process_admits_source_allow_thp_images_with_retained_ready_configuration",
        ),
        bounded_behavior=(
            "two clean child source environments retain mimalloc_allow_thp raw values zero and two through normal RuntimeProcessStorage initialization",
            "after the first ticket-zero allocation, the scalar audit reads the retained READY memory configuration and the same retained VM policy without a new detector read",
            "the disabled image records a disabled READY configuration while the mode-two image records its current C/Rust-equal configuration observation without assuming a host THP mode",
        ),
    ),
    TestLane(
        identifier="compiler-tls-fresh-native-thread",
        kind="native-unit",
        test_filter="compiler_tls::tests::fresh_native_thread_starts_with_the_source_root_images",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "compiler_tls::tests::fresh_native_thread_starts_with_the_source_root_images",
        ),
        bounded_behavior=(
            "one spawned native thread starts with the immutable compiler-TLS root images",
            "the direct thread-pointer identity and source-helper TLS address remain aligned",
        ),
    ),
    TestLane(
        identifier="compiler-tls-explicit-reset",
        kind="native-unit",
        test_filter="compiler_tls::tests::native_thread_roots_install_and_reset_without_a_stale_fallback",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "compiler_tls::tests::native_thread_roots_install_and_reset_without_a_stale_fallback",
        ),
        bounded_behavior=(
            "one spawned native thread can install each private root and explicitly reset it",
            "post-reset regular access stays empty instead of reviving a stale fallback",
        ),
    ),
    TestLane(
        identifier="compiler-tls-overlapping-native-threads",
        kind="native-unit",
        test_filter="compiler_tls::tests::compiler_tls_roots_are_isolated_while_native_threads_overlap",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "compiler_tls::tests::compiler_tls_roots_are_isolated_while_native_threads_overlap",
        ),
        bounded_behavior=(
            "two overlapping native threads retain distinct direct thread-pointer identities and TLS addresses",
            "resetting one thread's roots does not overwrite the other thread's installed roots",
        ),
    ),
    TestLane(
        identifier="main-heap-thread-overlapping-later-theaps",
        kind="native-unit",
        test_filter="main_heap_thread::tests::overlapping_later_threads_link_distinct_metadata_theaps_to_one_main_heap",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "main_heap_thread::tests::overlapping_later_threads_link_distinct_metadata_theaps_to_one_main_heap",
        ),
        bounded_behavior=(
            "two overlapping later native workers link distinct metadata Theaps to one ticket-zero static main Heap",
            "static main teardown remains gated until both shared-list owners finish and the shared count returns to zero",
        ),
    ),
    TestLane(
        identifier="owned-tls-key-registry-concurrent-claim-release",
        kind="native-unit",
        test_filter="owned_tls_key_registry::tests::concurrent_claims_are_unique_and_explicit_releases_restore_lowest_order",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "owned_tls_key_registry::tests::concurrent_claims_are_unique_and_explicit_releases_restore_lowest_order",
        ),
        bounded_behavior=(
            "four scoped workers each claim 32 distinct private registry keys",
            "explicit releases restore the lowest source-order key before registry shutdown",
        ),
    ),
    TestLane(
        identifier="dynamic-arena-singleton-detached-post-exit-owner",
        kind="native-unit",
        test_filter="dynamic_theap::tests::x86_64_dynamic_arena_singleton_post_exit_route_moves_after_source_teardown",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "dynamic_theap::tests::x86_64_dynamic_arena_singleton_post_exit_route_moves_after_source_teardown",
        ),
        bounded_behavior=(
            "one injected pre-mutation dynamic key-lock refusal returns only a retry source; its source-thread retry then tears down regular TLS backing, cached root, Theap, TLD, and key before returning a detached arena-singleton owner",
            "a joined receiver with whole-PageMap exclusion consumes that owner's one exact client free and releases its PageMap entry, dynamic arena bit, metadata, arena span, image, and inert Heap binding",
            "the source-bound dynamic attachment and ordinary singleton handoff remain outside this Send-only post-exit route",
        ),
    ),
    TestLane(
        identifier="remote-free-joined-multi-producer",
        kind="native-unit",
        test_filter="remote_free::tests::std_multi_producer_pushes_are_all_collected_once",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "remote_free::tests::std_multi_producer_pushes_are_all_collected_once",
        ),
        bounded_behavior=(
            "eight scoped producers publish 64 blocks each to one live owner-associated test page",
            "the sole owner joins producers and collects all 512 blocks exactly once",
        ),
    ),
    TestLane(
        identifier="remote-free-owner-collection-race",
        kind="native-unit",
        test_filter="remote_free::tests::owner_collection_races_a_producer_without_losing_or_double_collecting_blocks",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "remote_free::tests::owner_collection_races_a_producer_without_losing_or_double_collecting_blocks",
        ),
        bounded_behavior=(
            "a sole owner repeatedly collects while one scoped producer publishes 128 blocks",
            "the bounded live owner-associated protocol neither loses nor double-collects those blocks",
        ),
    ),
    TestLane(
        identifier="remote-free-finite-loom-head-protocols",
        kind="finite-loom",
        test_filter="remote_free::loom_tests",
        exact_filter=False,
        features=("loom",),
        expected_pass_count=5,
        source_tests=(
            "remote_free::loom_tests::loom_multiple_remote_publishers_preserve_owner_bit_and_collect_every_block_once",
            "remote_free::loom_tests::loom_owner_collection_racing_publication_loses_no_block_and_keeps_owner_bit",
            "remote_free::loom_tests::loom_bitmap_adopter_racing_abandoned_publisher_has_one_owner_and_correct_bitmap_responsibility",
            "remote_free::loom_tests::loom_abandoned_unown_racing_publisher_either_transfers_or_retains_collection_obligation",
            "remote_free::loom_tests::loom_expected_head_unown_racing_allow_collect_publisher_preserves_the_head_or_collection",
        ),
        bounded_behavior=(
            "Loom explores the modeled two-producer live-head publication and collection interleavings",
            "Loom explores the modeled abandoned-head claim and unown transitions with one owner bit",
            "the model covers only integer head/link identities and the production atomic transition helpers",
        ),
    ),
)

EXCLUSIONS = (
    "No public mi_*, malloc-family, crabc-libc, dynamic-linker, or crabc-rs x86-64 runtime support is exercised or claimed.",
    "No complete process or pthread/TLS callback lifecycle is exercised or claimed.",
    "No general allocation/free routing, cross-thread client API, owner-exit traversal, adoption, or whole-allocator stress regime is exercised or claimed.",
    "The Loom lane does not model page identity, arena lookup, bitmap fields, retirement/release, compiler TLS, or owner-local used/local_free mutation.",
    "No C-oracle differential, fault injection, fork, interposition, sanitizer, performance, or API-surface conclusion follows from these Rust tests.",
)

RUNTIME_FIRST_ARENA_EXCLUSIONS = (
    "No public mi_*, malloc-family, crabc-libc, dynamic-linker, or crabc-rs x86-64 runtime support is exercised or claimed.",
    "No complete process or pthread/TLS callback lifecycle is exercised or claimed.",
    "No general allocation/free routing, cross-thread client API, owner-exit traversal, adoption, or whole-allocator stress regime is exercised or claimed.",
    "The direct C oracles cover only pinned init.c/arena.c/os.c's configured ticket-zero TLD and one ordinary regular first-arena NUMA relation, plus two clean mimalloc_allow_thp source images' retained configuration bits after normal process initialization; they do not qualify host multi-node placement, THP hardware mode, huge-page behavior, or general allocator lifecycle parity.",
    "The source-THP images do not qualify arbitrary environment syntax or mutation, C/Rust detector implementation parity beyond their two observed retained bits, PRCTL outcomes, other production policy callers, arena policy, or minimum-purge semantics.",
    "No fault injection, interposition, sanitizer, performance, or API-surface conclusion follows from this focused C/Rust policy witness.",
)


def relative(path: Path) -> str:
    """Return a durable repository-relative path when possible."""

    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_bytes_record(payload: bytes) -> dict[str, Any]:
    """Retain raw Git output with an independently checkable byte identity."""

    return {
        "bytes": len(payload),
        "hex": payload.hex(),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def validate_source_bytes_record(value: object, subject: str) -> bytes:
    """Decode one bounded raw source-state record only after self-validation."""

    if not isinstance(value, Mapping) or set(value) != {"bytes", "hex", "sha256"}:
        raise EvidenceError(f"{subject} byte record is invalid")
    if (
        type(value.get("bytes")) is not int
        or value["bytes"] < 0
        or not isinstance(value.get("hex"), str)
        or not isinstance(value.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
    ):
        raise EvidenceError(f"{subject} byte record is invalid")
    try:
        payload = bytes.fromhex(value["hex"])
    except ValueError as error:
        raise EvidenceError(f"{subject} byte record has invalid hexadecimal") from error
    if len(payload) != value["bytes"] or hashlib.sha256(payload).hexdigest() != value["sha256"]:
        raise EvidenceError(f"{subject} byte record drifted")
    return payload


def candidate_source_git_output(arguments: Sequence[str], subject: str) -> bytes:
    """Run one read-only Git query without allowing an index refresh."""

    git = shutil.which("git")
    if git is None:
        raise EvidenceError("candidate source receipt requires Git")
    environment = dict(os.environ)
    environment.update(CANDIDATE_SOURCE_GIT_READ_ENVIRONMENT)
    try:
        completed = subprocess.run(
            [git, *arguments],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError(f"candidate source receipt cannot read {subject}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceError(f"candidate source receipt cannot read {subject}: {detail}")
    return completed.stdout


def candidate_source_git_identifier(payload: bytes, subject: str) -> str:
    """Parse exactly one SHA-1 object identifier emitted by Git."""

    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"candidate source {subject} is not ASCII") from error
    identifier = text.removesuffix("\n")
    if text != f"{identifier}\n" or re.fullmatch(r"[0-9a-f]{40}", identifier) is None:
        raise EvidenceError(f"candidate source {subject} is not one Git object identifier")
    return identifier


def candidate_source_input_path(name: str) -> Path:
    """Resolve one fixed tracked input without accepting links or escapes."""

    relative_path = Path(name)
    if relative_path.is_absolute() or not relative_path.parts or any(
        part in {"", ".", ".."} for part in relative_path.parts
    ):
        raise EvidenceError(f"candidate source input path is invalid: {name!r}")
    root = ROOT.resolve()
    path = ROOT
    for part in relative_path.parts:
        path /= part
        if path.is_symlink():
            raise EvidenceError(f"candidate source input is a symlink: {name}")
    try:
        path.resolve().relative_to(root)
    except ValueError as error:
        raise EvidenceError(f"candidate source input escapes the checkout: {name}") from error
    if not path.is_file():
        raise EvidenceError(f"candidate source input is absent: {name}")
    return path


def candidate_source_head_blob(revision: str, name: str) -> str:
    """Return one fixed revision's blob for a candidate input."""

    record = candidate_source_git_output(("ls-tree", "-z", revision, "--", name), name)
    if not record.endswith(b"\0") or record.count(b"\0") != 1:
        raise EvidenceError(f"candidate source HEAD entry is invalid: {name}")
    metadata, separator, recorded_name = record[:-1].partition(b"\t")
    fields = metadata.split(b" ")
    if (
        not separator
        or recorded_name != name.encode("ascii")
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise EvidenceError(f"candidate source HEAD entry is invalid: {name}")
    try:
        blob = fields[2].decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"candidate source HEAD entry is invalid: {name}") from error
    if re.fullmatch(r"[0-9a-f]{40}", blob) is None:
        raise EvidenceError(f"candidate source HEAD entry is invalid: {name}")
    return blob


def candidate_source_input_record(revision: str, name: str) -> dict[str, Any]:
    """Hash one live candidate input and bind it to the captured HEAD blob."""

    path = candidate_source_input_path(name)
    try:
        before = path.stat()
        payload = path.read_bytes()
        after = path.stat()
    except OSError as error:
        raise EvidenceError(f"candidate source input cannot be read: {name}") from error
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_size != len(payload)
        or after.st_size != len(payload)
    ):
        raise EvidenceError(f"candidate source input changed while being read: {name}")
    head_blob = candidate_source_head_blob(revision, name)
    working_blob = candidate_source_git_identifier(
        candidate_source_git_output(("hash-object", "--no-filters", name), name),
        f"working input {name}",
    )
    if working_blob != head_blob:
        raise EvidenceError(f"candidate source input differs from HEAD: {name}")
    return {
        "bytes": len(payload),
        "git_blob": head_blob,
        "path": name,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def validate_candidate_source_snapshot(value: object, subject: str) -> dict[str, Any]:
    """Require one clean exact candidate source snapshot before trusting it."""

    if not isinstance(value, Mapping) or set(value) != {
        "format",
        "git",
        "inputs",
        "rust_allocator_tree",
    }:
        raise EvidenceError(f"{subject} snapshot schema drifted")
    if type(value.get("format")) is not int or value["format"] != 1:
        raise EvidenceError(f"{subject} snapshot format drifted")
    git = value.get("git")
    if not isinstance(git, Mapping) or set(git) != {
        "revision",
        "tree",
        "worktree_clean",
        "worktree_status",
    }:
        raise EvidenceError(f"{subject} Git state is invalid")
    for key in ("revision", "tree"):
        if not isinstance(git.get(key), str) or re.fullmatch(r"[0-9a-f]{40}", git[key]) is None:
            raise EvidenceError(f"{subject} Git {key} is invalid")
    status = validate_source_bytes_record(git.get("worktree_status"), f"{subject} worktree status")
    if type(git.get("worktree_clean")) is not bool or git["worktree_clean"] != (status == b""):
        raise EvidenceError(f"{subject} Git cleanliness is contradictory")
    if not git["worktree_clean"]:
        raise EvidenceError(f"{subject} requires a clean Git source")

    allocator_tree = value.get("rust_allocator_tree")
    if (
        not isinstance(allocator_tree, Mapping)
        or set(allocator_tree) != {"object_id", "path"}
        or allocator_tree.get("path") != "crabc-mimalloc"
        or not isinstance(allocator_tree.get("object_id"), str)
    ):
        raise EvidenceError(f"{subject} Rust allocator tree is invalid")
    if re.fullmatch(r"[0-9a-f]{40}", allocator_tree["object_id"]) is None:
        raise EvidenceError(f"{subject} Rust allocator tree is invalid")

    inputs = value.get("inputs")
    if not isinstance(inputs, list) or [record.get("path") for record in inputs if isinstance(record, Mapping)] != list(CANDIDATE_SOURCE_INPUTS):
        raise EvidenceError(f"{subject} candidate input roster drifted")
    if len(inputs) != len(CANDIDATE_SOURCE_INPUTS):
        raise EvidenceError(f"{subject} candidate input roster drifted")
    for record in inputs:
        if not isinstance(record, Mapping) or set(record) != {"bytes", "git_blob", "path", "sha256"}:
            raise EvidenceError(f"{subject} candidate input record is invalid")
        if (
            type(record.get("bytes")) is not int
            or record["bytes"] < 0
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or not isinstance(record.get("git_blob"), str)
            or re.fullmatch(r"[0-9a-f]{40}", record["git_blob"]) is None
        ):
            raise EvidenceError(f"{subject} candidate input record is invalid")
    return {
        "format": value["format"],
        "git": dict(git),
        "inputs": [dict(record) for record in inputs],
        "rust_allocator_tree": dict(allocator_tree),
    }


def candidate_source_git_state() -> tuple[str, str, bytes]:
    """Read one current revision/tree/status tuple without refreshing Git's index."""

    revision = candidate_source_git_identifier(
        candidate_source_git_output(("rev-parse", "--verify", "HEAD"), "HEAD"), "HEAD"
    )
    tree = candidate_source_git_identifier(
        candidate_source_git_output(
            ("rev-parse", "--verify", f"{revision}^{{tree}}"), "HEAD tree"
        ),
        "HEAD tree",
    )
    status = candidate_source_git_output(
        ("status", "--porcelain=v1", "--untracked-files=all", "-z"), "worktree status"
    )
    return revision, tree, status


def capture_candidate_source_snapshot() -> dict[str, Any]:
    """Capture the exact clean workspace that will build and run the witness."""

    revision, tree, status = candidate_source_git_state()
    if status != b"":
        raise EvidenceError("candidate source requires a clean Git source")
    allocator_tree = candidate_source_git_identifier(
        candidate_source_git_output(
            ("rev-parse", "--verify", f"{revision}:crabc-mimalloc"), "Rust allocator tree"
        ),
        "Rust allocator tree",
    )
    if candidate_source_git_output(
        ("cat-file", "-t", f"{revision}:crabc-mimalloc"), "Rust allocator tree type"
    ) != b"tree\n":
        raise EvidenceError("candidate source Rust allocator entry is not a tree")
    inputs = [candidate_source_input_record(revision, name) for name in CANDIDATE_SOURCE_INPUTS]
    if candidate_source_git_state() != (revision, tree, status):
        raise EvidenceError("candidate source changed while being sealed")
    snapshot = {
        "format": 1,
        "git": {
            "revision": revision,
            "tree": tree,
            "worktree_clean": status == b"",
            "worktree_status": source_bytes_record(status),
        },
        "rust_allocator_tree": {
            "object_id": allocator_tree,
            "path": "crabc-mimalloc",
        },
        "inputs": inputs,
    }
    return validate_candidate_source_snapshot(snapshot, "candidate source")


def candidate_source_attestation(before: object, after: object) -> dict[str, Any]:
    """Bind the focused receipt to one unchanged clean candidate workspace."""

    source_before = validate_candidate_source_snapshot(before, "candidate source before")
    source_after = validate_candidate_source_snapshot(after, "candidate source after")
    if source_before != source_after:
        raise EvidenceError("candidate source changed during execution")
    return {
        "after": source_after,
        "before": source_before,
        "git_read_environment": dict(CANDIDATE_SOURCE_GIT_READ_ENVIRONMENT),
        "unchanged_during_execution": True,
    }


_ALLOCATOR_HARNESS: Any | None = None


def allocator_harness() -> Any:
    """Load the existing pinned-source owner without duplicating its contract."""

    global _ALLOCATOR_HARNESS
    if _ALLOCATOR_HARNESS is not None:
        return _ALLOCATOR_HARNESS
    path = ROOT / "compat/allocator/run.py"
    spec = importlib.util.spec_from_file_location("crabc_lifecycle_allocator_harness", path)
    if spec is None or spec.loader is None:
        raise EvidenceError("pinned allocator source harness is unavailable")
    harness = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = harness
    try:
        spec.loader.exec_module(harness)
    except Exception as error:
        raise EvidenceError("pinned allocator source harness could not load") from error
    _ALLOCATOR_HARNESS = harness
    return harness


def pinned_mimalloc_pin() -> dict[str, str]:
    """Read the fixed source identity through its existing oracle owner."""

    harness = allocator_harness()
    try:
        return harness.load_pin()
    except harness.HarnessError as error:
        raise EvidenceError(f"invalid pinned mimalloc source declaration: {error}") from error


def parse_scalar_trace(output: str, *, begin: str, end: str, keys: Sequence[str], source: str) -> dict[str, int]:
    """Parse one exact, unsigned scalar trace without accepting extra rows."""

    lines = output.splitlines()
    begin_indexes = [index for index, line in enumerate(lines) if line == begin]
    end_indexes = [index for index, line in enumerate(lines) if line == end]
    if len(begin_indexes) != 1 or len(end_indexes) != 1 or begin_indexes[0] >= end_indexes[0]:
        raise EvidenceError(f"{source} did not emit one ordered scalar trace")
    values: dict[str, int] = {}
    for line in lines[begin_indexes[0] + 1 : end_indexes[0]]:
        name, separator, raw_value = line.partition("=")
        if not separator or not name or not raw_value.isdecimal() or name in values:
            raise EvidenceError(f"{source} emitted an invalid scalar trace row: {line!r}")
        values[name] = int(raw_value)
    expected = set(keys)
    if set(values) != expected:
        raise EvidenceError(
            f"{source} scalar trace keys drifted: missing {sorted(expected - set(values))}; "
            f"unexpected {sorted(set(values) - expected)}"
        )
    return values


def normalize_c_oracle_command(command: Sequence[str], source: Path, binary: Path) -> list[str]:
    """Retain an exact replay shape without persisting a temporary extraction path."""

    normalized: list[str] = []
    for argument in command:
        if argument == str(binary):
            normalized.append("<initial-tld-numa-oracle-binary>")
        elif argument.startswith(f"{source}/"):
            normalized.append(f"<pinned-mimalloc-source>/{Path(argument).relative_to(source).as_posix()}")
        else:
            normalized.append(argument)
    return normalized


def text_sha256(value: str) -> str:
    """Hash raw command text without normalizing its evidence bytes."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_initial_tld_numa_c_trace(trace: Mapping[str, int]) -> None:
    """Require the pinned C TLD and first regular arena to consume one policy."""

    if set(trace) != set(INITIAL_TLD_NUMA_C_TRACE_KEYS):
        raise EvidenceError("pinned C initial-TLD NUMA trace schema drifted")
    if any(type(trace.get(key)) is not int for key in INITIAL_TLD_NUMA_C_TRACE_KEYS):
        raise EvidenceError("pinned C initial-TLD NUMA trace requires exact integer scalars")
    for key in (
        "source_option_applied",
        "arena_is_numa_local_option_applied",
        "ticket_zero_tld",
        "default_theap_uses_ticket_zero_tld",
        "ticket_zero_tld_numa_in_range",
        "regular_first_arena_is_os",
        "regular_first_arena_numa_in_range",
        "regular_first_arena_retained_after_free",
    ):
        if trace[key] != 1:
            raise EvidenceError(f"pinned C initial-TLD NUMA relation failed: {key}")
    if trace["configured_numa_node_count"] != 3 or trace["resolved_numa_node_count"] != 3:
        raise EvidenceError("pinned C initial-TLD NUMA count did not retain use_numa_nodes=3")
    if trace["ticket_zero_tld_numa_node"] >= trace["resolved_numa_node_count"]:
        raise EvidenceError("pinned C initial-TLD NUMA node was not normalized below its policy count")
    if trace["regular_first_arena_numa_node"] >= trace["resolved_numa_node_count"]:
        raise EvidenceError("pinned C first regular arena NUMA node was not normalized below its policy count")


def run_initial_tld_numa_c_oracle() -> dict[str, Any]:
    """Build and run the exact direct-include source oracle in one child image."""

    # `run.py` owns the cache, tag attestation, extraction validation, release
    # flags, and command records for every pinned-C oracle.  This focused lane
    # deliberately reuses that owner instead of accepting a second cache or
    # duplicate source-extraction policy.
    harness = allocator_harness()
    pin = pinned_mimalloc_pin()
    try:
        archive = harness.fetch_archive(pin, offline=True)
        compiler = harness.require_tool("musl-gcc")
        artifacts = harness.ARTIFACT_ROOT / "x86_64/initial-tld-numa"
        artifacts.mkdir(parents=True, exist_ok=True)
        binary = artifacts / "initial-tld-numa-oracle"

        with harness.temporary_directory(
            prefix="crabc-mimalloc-x86_64-initial-tld-numa-source-"
        ) as temporary:
            source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
            command = [
                compiler,
                "-std=c11",
                "-fPIC",
                "-ftls-model=initial-exec",
                "-DMI_SHARED_LIB",
                "-DMI_SHARED_LIB_EXPORT",
                "-DMI_LIBC_MUSL=1",
                "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
                "-I",
                str(source / "include"),
                "-I",
                str(source / "src"),
                *harness.CONFIGURATION_PROFILES["release"],
                str(INITIAL_TLD_NUMA_FIXTURE),
                *(str(source / name) for name in INITIAL_TLD_NUMA_C_ORACLE_LINK_SOURCES),
                "-pthread",
                "-o",
                str(binary),
            ]
            build = harness.command_record(command, cwd=source, timeout_seconds=300)
            harness.require_success(build, "pinned C initial-TLD NUMA oracle build")
            run_record = harness.command_record(
                [str(binary)], cwd=source, timeout_seconds=120, env={}
            )
            harness.require_success(run_record, "pinned C initial-TLD NUMA oracle")
            trace = parse_scalar_trace(
                str(run_record["stdout"]),
                begin=INITIAL_TLD_NUMA_TRACE_BEGIN,
                end=INITIAL_TLD_NUMA_TRACE_END,
                keys=INITIAL_TLD_NUMA_C_TRACE_KEYS,
                source="pinned C initial-TLD NUMA oracle",
            )
            validate_initial_tld_numa_c_trace(trace)
            source_files = harness.source_file_records(
                source, INITIAL_TLD_NUMA_C_ORACLE_SOURCE_FILES
            )
            normalized_compile_command = normalize_c_oracle_command(command, source, binary)
    except harness.HarnessError as error:
        raise EvidenceError(f"pinned C initial-TLD NUMA oracle failed: {error}") from error

    if not binary.is_file():
        raise EvidenceError("pinned C initial-TLD NUMA oracle binary was not retained")
    trace_payload = json.dumps(trace, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "binary": harness.artifact_record(binary),
        "build": {
            "command": normalized_compile_command,
            "status": build["status"],
            "stderr_sha256": text_sha256(str(build["stderr"])),
            "stdout_sha256": text_sha256(str(build["stdout"])),
        },
        "fixture": {
            "bytes": INITIAL_TLD_NUMA_FIXTURE.stat().st_size,
            "path": relative(INITIAL_TLD_NUMA_FIXTURE),
            "sha256": sha256_file(INITIAL_TLD_NUMA_FIXTURE),
        },
        "run": {
            "command": ["<initial-tld-numa-oracle-binary>"],
            "status": run_record["status"],
            "stderr_sha256": text_sha256(str(run_record["stderr"])),
            "stdout_sha256": text_sha256(str(run_record["stdout"])),
        },
        "source_files": source_files,
        "trace": trace,
        "trace_sha256": hashlib.sha256(trace_payload).hexdigest(),
        "upstream": {
            "archive_sha256": pin["sha256"],
            "revision": pin["revision"],
        },
    }


def validate_runtime_thp_configuration_c_trace(
    image_id: str, trace: Mapping[str, int]
) -> None:
    """Require one direct C image's raw option and retained configuration."""

    if image_id not in RUNTIME_THP_CONFIGURATION_IMAGE_IDS:
        raise EvidenceError("pinned C runtime THP image is unknown")
    if set(trace) != set(RUNTIME_THP_CONFIGURATION_C_TRACE_KEYS):
        raise EvidenceError("pinned C runtime THP trace schema drifted")
    if any(type(trace.get(key)) is not int for key in RUNTIME_THP_CONFIGURATION_C_TRACE_KEYS):
        raise EvidenceError("pinned C runtime THP trace requires exact integer scalars")
    if trace["config_has_transparent_huge_pages"] not in {0, 1}:
        raise EvidenceError("pinned C runtime THP configuration observation is not boolean")
    expected_raw = 0 if image_id == "disabled" else 2
    if trace["selected_allow_thp_raw"] != expected_raw:
        raise EvidenceError("pinned C runtime THP image did not retain its selected raw option")
    if image_id == "disabled" and trace["config_has_transparent_huge_pages"] != 0:
        raise EvidenceError("pinned C runtime disabled THP image did not clear its configuration")


def normalize_runtime_thp_configuration_c_command(
    command: Sequence[str], source: Path, binary: Path, image_id: str
) -> list[str]:
    """Retain one direct C replay shape without a temporary source path."""

    normalized: list[str] = []
    for argument in command:
        if argument == str(binary):
            normalized.append(f"<runtime-thp-configuration-{image_id}-oracle-binary>")
        elif argument.startswith(f"{source}/"):
            normalized.append(
                f"<pinned-mimalloc-source>/{Path(argument).relative_to(source).as_posix()}"
            )
        else:
            normalized.append(argument)
    return normalized


def run_runtime_thp_configuration_c_oracle() -> dict[str, Any]:
    """Build the two fixed direct `os.c`/`init.c` source configuration images."""

    harness = allocator_harness()
    pin = pinned_mimalloc_pin()
    try:
        archive = harness.fetch_archive(pin, offline=True)
        compiler = harness.require_tool("musl-gcc")
        artifacts = harness.ARTIFACT_ROOT / "x86_64/runtime-thp-configuration"
        artifacts.mkdir(parents=True, exist_ok=True)
        images: list[dict[str, Any]] = []
        with harness.temporary_directory(
            prefix="crabc-mimalloc-x86_64-runtime-thp-configuration-source-"
        ) as temporary:
            source = harness.safe_extract(archive, Path(temporary), pin["archive_root"])
            for image_id, image_define in RUNTIME_THP_CONFIGURATION_C_IMAGES:
                binary = artifacts / f"runtime-thp-configuration-{image_id}-oracle"
                command = [
                    compiler,
                    "-std=c11",
                    "-fPIC",
                    "-ftls-model=initial-exec",
                    "-DMI_SHARED_LIB",
                    "-DMI_SHARED_LIB_EXPORT",
                    "-DMI_LIBC_MUSL=1",
                    "-DMI_PRIM_HAS_PROCESS_ATTACH=1",
                    "-I",
                    str(source / "include"),
                    "-I",
                    str(source / "src"),
                    *harness.CONFIGURATION_PROFILES["release"],
                    image_define,
                    str(RUNTIME_THP_CONFIGURATION_FIXTURE),
                    *(str(source / name) for name in RUNTIME_THP_CONFIGURATION_C_ORACLE_LINK_SOURCES),
                    "-pthread",
                    "-o",
                    str(binary),
                ]
                build = harness.command_record(command, cwd=source, timeout_seconds=300)
                harness.require_success(build, f"pinned C runtime THP {image_id} oracle build")
                run_record = harness.command_record(
                    [str(binary)], cwd=source, timeout_seconds=120, env={}
                )
                harness.require_success(run_record, f"pinned C runtime THP {image_id} oracle")
                trace = parse_scalar_trace(
                    str(run_record["stdout"]),
                    begin=RUNTIME_THP_CONFIGURATION_C_TRACE_BEGIN[image_id],
                    end=RUNTIME_THP_CONFIGURATION_C_TRACE_END[image_id],
                    keys=RUNTIME_THP_CONFIGURATION_C_TRACE_KEYS,
                    source=f"pinned C runtime THP {image_id} oracle",
                )
                validate_runtime_thp_configuration_c_trace(image_id, trace)
                if not binary.is_file():
                    raise EvidenceError(f"pinned C runtime THP {image_id} binary was not retained")
                images.append(
                    {
                        "binary": harness.artifact_record(binary),
                        "build": {
                            "command": normalize_runtime_thp_configuration_c_command(
                                command, source, binary, image_id
                            ),
                            "status": build["status"],
                            "stderr_sha256": text_sha256(str(build["stderr"])),
                            "stdout_sha256": text_sha256(str(build["stdout"])),
                        },
                        "id": image_id,
                        "run": {
                            "command": [f"<runtime-thp-configuration-{image_id}-oracle-binary>"],
                            "status": run_record["status"],
                            "stderr_sha256": text_sha256(str(run_record["stderr"])),
                            "stdout_sha256": text_sha256(str(run_record["stdout"])),
                        },
                        "trace": trace,
                        "trace_sha256": hashlib.sha256(
                            json.dumps(trace, sort_keys=True, separators=(",", ":")).encode("utf-8")
                        ).hexdigest(),
                    }
                )
            source_files = harness.source_file_records(
                source, RUNTIME_THP_CONFIGURATION_C_ORACLE_SOURCE_FILES
            )
    except harness.HarnessError as error:
        raise EvidenceError(f"pinned C runtime THP configuration oracle failed: {error}") from error

    return {
        "fixture": {
            "bytes": RUNTIME_THP_CONFIGURATION_FIXTURE.stat().st_size,
            "path": relative(RUNTIME_THP_CONFIGURATION_FIXTURE),
            "sha256": sha256_file(RUNTIME_THP_CONFIGURATION_FIXTURE),
        },
        "images": images,
        "source_files": source_files,
        "upstream": {"archive_sha256": pin["sha256"], "revision": pin["revision"]},
    }


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise EvidenceError(f"required pinned-image tool is unavailable: {name}")
    return path


def run(command: Sequence[str], *, env: Mapping[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=dict(env) if env is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    combined = f"{completed.stdout}{completed.stderr}"
    if completed.returncode != 0:
        raise EvidenceError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{combined.strip()}"
        )
    return combined


def require_native_x86_64() -> dict[str, str]:
    """Require host attestation and the matching Linux/x86-64 guest."""

    execution_mode = os.environ.get("CRABC_EXECUTION_MODE")
    host_architecture = os.environ.get("CRABC_HOST_ARCH")
    if execution_mode != "native" or host_architecture not in {"x86_64", "amd64"}:
        raise EvidenceError(
            "x86-64 lifecycle evidence requires canonical native provenance: "
            "CRABC_EXECUTION_MODE=native and CRABC_HOST_ARCH=x86_64 (or amd64)"
        )
    system = platform.system()
    machine = platform.machine().lower()
    if system != "Linux" or machine not in {"x86_64", "amd64"}:
        raise EvidenceError(
            "x86-64 lifecycle evidence requires the native Linux/x86-64 development image; "
            f"observed {system}/{platform.machine()}"
        )
    return {"execution_mode": "native", "host_architecture": host_architecture}


def toolchain_record(cargo: str, rustc: str) -> dict[str, str]:
    """Prove the native compiler host before running the fixed target tests."""

    rustc_version = run([rustc, "-vV"])
    host_match = RUSTC_HOST.search(rustc_version)
    if host_match is None or host_match.group("target") != TARGET:
        observed = host_match.group("target") if host_match is not None else "<missing>"
        raise EvidenceError(
            f"x86-64 lifecycle evidence requires rustc host {TARGET}, observed {observed}"
        )
    cargo_version = run([cargo, "--version"]).strip()
    release = next(
        (line.removeprefix("release: ") for line in rustc_version.splitlines() if line.startswith("release: ")),
        "<missing>",
    )
    return {
        "cargo": cargo_version,
        "rustc_host": TARGET,
        "rustc_release": release,
    }


def cargo_test_command(cargo: str, lane: TestLane, target_dir: Path) -> list[str]:
    """Build one locked, exact target-specific test command for ``lane``."""

    command = [
        cargo,
        "test",
        "--locked",
        "--target",
        TARGET,
        "--target-dir",
        str(target_dir),
        "-p",
        "crabc-mimalloc",
    ]
    if lane.kind == "native-integration":
        command.extend(("--test", "native_runtime_first_arena_policy"))
    else:
        command.append("--lib")
    if lane.features:
        command.extend(("--features", ",".join(lane.features)))
    command.append(lane.test_filter)
    command.extend(("--", "--test-threads=1"))
    if lane.kind == "native-integration":
        # Each integration child forwards only its named scalar trace. This
        # binds the selected ordinary runtime execution without retaining an
        # allocation address or a lifecycle capability.
        command.append("--nocapture")
    if lane.exact_filter:
        command.append("--exact")
    return command


def normalized_command(command: Sequence[str], target_dir: Path) -> list[str]:
    """Keep the durable report deterministic while retaining target isolation."""

    return [
        "<isolated-temporary-target-dir>" if part == str(target_dir) else part
        for part in command
    ]


def parse_test_result(output: str, lane: TestLane) -> dict[str, int]:
    matches = list(TEST_RESULT.finditer(output))
    if len(matches) != 1:
        raise EvidenceError(
            f"{lane.identifier} produced {len(matches)} lib-test summaries, expected exactly one"
        )
    match = matches[0]
    result = {
        "passed": int(match.group("passed")),
        "failed": int(match.group("failed")),
        "ignored": int(match.group("ignored")),
        "measured": int(match.group("measured")),
        "filtered_out": int(match.group("filtered")),
    }
    if match.group("status") != "ok" or result["failed"] != 0:
        raise EvidenceError(f"{lane.identifier} did not pass: {result}")
    if result["passed"] != lane.expected_pass_count:
        raise EvidenceError(
            f"{lane.identifier} passed {result['passed']} tests, "
            f"expected exactly {lane.expected_pass_count}"
        )
    return result


def parse_runtime_initial_tld_numa_trace(output: str) -> dict[str, int]:
    """Read the normal-runtime TLD and first-regular-arena scalar trace."""

    trace = parse_scalar_trace(
        output,
        begin=RUNTIME_INITIAL_TLD_NUMA_TRACE_BEGIN,
        end=RUNTIME_INITIAL_TLD_NUMA_TRACE_END,
        keys=RUNTIME_INITIAL_TLD_NUMA_TRACE_KEYS,
        source="Rust runtime initial-TLD NUMA witness",
    )
    if trace["vm_policy_arena_is_numa_local"] != 1:
        raise EvidenceError("Rust runtime did not retain mimalloc_arena_is_numa_local=1")
    if trace["vm_policy_use_numa_nodes"] != 3:
        raise EvidenceError("Rust runtime did not retain mimalloc_use_numa_nodes=3")
    if trace["vm_policy_numa_node_count_cache"] != 3:
        raise EvidenceError("Rust initial TLD did not resolve its retained NUMA policy count")
    if trace["ticket_zero_tld_numa_node"] >= trace["vm_policy_numa_node_count_cache"]:
        raise EvidenceError("Rust initial TLD NUMA node was not normalized below its policy count")
    if trace["process_arena_numa_node"] >= trace["vm_policy_numa_node_count_cache"]:
        raise EvidenceError("Rust first regular arena NUMA node was not normalized below its policy count")
    return trace


def parse_runtime_thp_configuration_trace(output: str) -> dict[str, dict[str, int]]:
    """Read the two fixed normal-runtime source-environment THP observations."""

    images = {
        image_id: parse_scalar_trace(
            output,
            begin=RUNTIME_THP_CONFIGURATION_TRACE_BEGIN[image_id],
            end=RUNTIME_THP_CONFIGURATION_TRACE_END[image_id],
            keys=RUNTIME_THP_CONFIGURATION_TRACE_KEYS,
            source=f"Rust runtime THP {image_id} witness",
        )
        for image_id in RUNTIME_THP_CONFIGURATION_IMAGE_IDS
    }
    if images["disabled"] != {
        "selected_allow_thp_raw": 0,
        "vm_policy_allow_thp": 0,
        "ready_memory_config_has_transparent_huge_pages": 0,
    }:
        raise EvidenceError("Rust runtime disabled THP image did not retain its required READY state")
    mode_two = images["mode-two"]
    if (
        mode_two["selected_allow_thp_raw"] != 2
        or mode_two["vm_policy_allow_thp"] != 1
        or mode_two["ready_memory_config_has_transparent_huge_pages"] not in {0, 1}
    ):
        raise EvidenceError("Rust runtime mode-two THP image did not retain its selected observation")
    return images


def run_lane(cargo: str, lane: TestLane, target_dir: Path) -> dict[str, Any]:
    command = cargo_test_command(cargo, lane, target_dir)
    output = run(command)
    result = parse_test_result(output, lane)
    record: dict[str, Any] = {
        "id": lane.identifier,
        "kind": lane.kind,
        "cargo_command": normalized_command(command, target_dir),
        "expected_pass_count": lane.expected_pass_count,
        "observed": result,
        "source_tests": list(lane.source_tests),
        "bounded_behavior": list(lane.bounded_behavior),
    }
    if lane.identifier == "runtime-process-policy-first-arena":
        record["initial_tld_numa_trace"] = parse_runtime_initial_tld_numa_trace(output)
    if lane.identifier == "runtime-source-environment-thp-ready-configuration-admission":
        record["runtime_thp_configuration_trace"] = parse_runtime_thp_configuration_trace(output)
    return record


def report_from_results(
    *,
    provenance: Mapping[str, str],
    toolchain: Mapping[str, str],
    lockfile_sha256: str,
    lanes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Construct the stable, deliberately incomplete evidence record."""

    expected = sum(int(lane["expected_pass_count"]) for lane in lanes)
    observed = sum(int(lane["observed"]["passed"]) for lane in lanes)
    report: dict[str, Any] = {
        "format": 1,
        "kind": "mimalloc-x86_64-bounded-lifecycle-concurrency-evidence",
        "profile": "linux-x86_64-private-engine-lifecycle-concurrency-foundation",
        "status": "passed",
        "target": {
            "architecture": "x86_64",
            "endianness": "little",
            "rust_target": TARGET,
            "system": "linux",
        },
        "native_execution_provenance": dict(provenance),
        "toolchain": dict(toolchain),
        "cargo": {
            "lockfile": {"path": relative(LOCKFILE), "sha256": lockfile_sha256},
            "locked": True,
            "target_dir": {
                "isolated": True,
                "retained": False,
                "value": "<isolated-temporary-target-dir>",
            },
        },
        "lanes": [dict(lane) for lane in lanes],
        "summary": {
            "expected_pass_count": expected,
            "observed_pass_count": observed,
            "lane_count": len(lanes),
        },
        "scope": {
            "boundary": "crate-private crabc-mimalloc engine, finite Loom, and one process-isolated private first-arena runtime witness only",
            "public_runtime_support": False,
            "claim": "bounded lifecycle and concurrency foundation",
        },
        "exclusions": list(EXCLUSIONS),
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    """Reject accidental broadening or a partial test result before publication."""

    required = {
        "cargo",
        "exclusions",
        "format",
        "kind",
        "lanes",
        "native_execution_provenance",
        "profile",
        "scope",
        "status",
        "summary",
        "target",
        "toolchain",
    }
    if set(report) != required:
        raise EvidenceError(f"lifecycle report schema drifted: {sorted(set(report) ^ required)}")
    if report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("lifecycle report must record a passed format-1 result")
    if report["kind"] != "mimalloc-x86_64-bounded-lifecycle-concurrency-evidence":
        raise EvidenceError("lifecycle report kind drifted")
    if report["profile"] != "linux-x86_64-private-engine-lifecycle-concurrency-foundation":
        raise EvidenceError("lifecycle report profile drifted")
    if report["target"] != {
        "architecture": "x86_64",
        "endianness": "little",
        "rust_target": TARGET,
        "system": "linux",
    }:
        raise EvidenceError("lifecycle report target drifted")
    if report["native_execution_provenance"] not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("lifecycle report lacks canonical native x86-64 provenance")
    scope = report["scope"]
    if not isinstance(scope, Mapping) or scope.get("public_runtime_support") is not False:
        raise EvidenceError("lifecycle report must preserve the non-public runtime boundary")
    if scope.get("claim") != "bounded lifecycle and concurrency foundation":
        raise EvidenceError("lifecycle report claim drifted")
    if tuple(report["exclusions"]) != EXCLUSIONS:
        raise EvidenceError("lifecycle report exclusions drifted")

    cargo = report["cargo"]
    if not isinstance(cargo, Mapping) or cargo.get("locked") is not True:
        raise EvidenceError("lifecycle report must retain Cargo --locked evidence")
    target_dir = cargo.get("target_dir")
    if target_dir != {
        "isolated": True,
        "retained": False,
        "value": "<isolated-temporary-target-dir>",
    }:
        raise EvidenceError("lifecycle report target-directory isolation drifted")

    lanes = report["lanes"]
    if not isinstance(lanes, list) or len(lanes) != len(TEST_LANES):
        raise EvidenceError("lifecycle report lane count drifted")
    expected_ids = [lane.identifier for lane in TEST_LANES]
    if [lane.get("id") for lane in lanes if isinstance(lane, Mapping)] != expected_ids:
        raise EvidenceError("lifecycle report lane selections drifted")

    expected_total = 0
    observed_total = 0
    for configured, observed in zip(TEST_LANES, lanes, strict=True):
        if not isinstance(observed, Mapping):
            raise EvidenceError(f"{configured.identifier} report is not an object")
        if observed.get("expected_pass_count") != configured.expected_pass_count:
            raise EvidenceError(f"{configured.identifier} expected count drifted")
        command = observed.get("cargo_command")
        if not isinstance(command, list) or "--locked" not in command:
            raise EvidenceError(f"{configured.identifier} is missing Cargo --locked")
        target_index = command.index("--target") + 1 if "--target" in command else -1
        if target_index < 1 or command[target_index] != TARGET:
            raise EvidenceError(f"{configured.identifier} is not locked to {TARGET}")
        target_dir_index = command.index("--target-dir") + 1 if "--target-dir" in command else -1
        if target_dir_index < 1 or command[target_dir_index] != "<isolated-temporary-target-dir>":
            raise EvidenceError(f"{configured.identifier} does not use the isolated target directory")
        result = observed.get("observed")
        if not isinstance(result, Mapping) or result.get("failed") != 0:
            raise EvidenceError(f"{configured.identifier} does not record a clean test result")
        if result.get("passed") != configured.expected_pass_count:
            raise EvidenceError(f"{configured.identifier} observed count drifted")
        if configured.identifier == "runtime-process-policy-first-arena":
            runtime_trace = observed.get("initial_tld_numa_trace")
            if not isinstance(runtime_trace, Mapping):
                raise EvidenceError("runtime first-arena lane lacks its initial-TLD NUMA trace")
            if (
                set(runtime_trace) != set(RUNTIME_INITIAL_TLD_NUMA_TRACE_KEYS)
                or type(runtime_trace.get("vm_policy_arena_is_numa_local")) is not int
                or type(runtime_trace.get("vm_policy_use_numa_nodes")) is not int
                or type(runtime_trace.get("vm_policy_numa_node_count_cache")) is not int
                or type(runtime_trace.get("ticket_zero_tld_numa_node")) is not int
                or type(runtime_trace.get("process_arena_numa_node")) is not int
                or runtime_trace.get("vm_policy_arena_is_numa_local") != 1
                or runtime_trace.get("vm_policy_use_numa_nodes") != 3
                or runtime_trace.get("vm_policy_numa_node_count_cache") != 3
                or runtime_trace["ticket_zero_tld_numa_node"] < 0
                or runtime_trace["ticket_zero_tld_numa_node"] >= 3
                or runtime_trace["process_arena_numa_node"] < 0
                or runtime_trace["process_arena_numa_node"] >= 3
            ):
                raise EvidenceError("runtime first-arena lane NUMA trace drifted")
        if configured.identifier == "runtime-source-environment-thp-ready-configuration-admission":
            runtime_thp_trace = observed.get("runtime_thp_configuration_trace")
            if (
                not isinstance(runtime_thp_trace, Mapping)
                or tuple(runtime_thp_trace) != RUNTIME_THP_CONFIGURATION_IMAGE_IDS
                or any(
                    not isinstance(runtime_thp_trace.get(image_id), Mapping)
                    or set(runtime_thp_trace[image_id]) != set(RUNTIME_THP_CONFIGURATION_TRACE_KEYS)
                    for image_id in RUNTIME_THP_CONFIGURATION_IMAGE_IDS
                )
            ):
                raise EvidenceError("runtime THP configuration lane lacks its image traces")
            reconstructed = "\n".join(
                row
                for image_id in RUNTIME_THP_CONFIGURATION_IMAGE_IDS
                for row in (
                    RUNTIME_THP_CONFIGURATION_TRACE_BEGIN[image_id],
                    *(
                        f"{key}={runtime_thp_trace[image_id][key]}"
                        for key in RUNTIME_THP_CONFIGURATION_TRACE_KEYS
                    ),
                    RUNTIME_THP_CONFIGURATION_TRACE_END[image_id],
                )
            )
            if parse_runtime_thp_configuration_trace(reconstructed) != runtime_thp_trace:
                raise EvidenceError("runtime THP configuration lane trace drifted")
        expected_total += configured.expected_pass_count
        observed_total += int(result["passed"])

    summary = report["summary"]
    if summary != {
        "expected_pass_count": expected_total,
        "observed_pass_count": observed_total,
        "lane_count": len(TEST_LANES),
    }:
        raise EvidenceError("lifecycle report summary drifted")
    if observed_total != expected_total:
        raise EvidenceError("lifecycle report records an incomplete test selection")


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        # Docker runs the native producer as root while the retained evidence
        # is reviewed from the ordinary checkout owner. Keep the atomically
        # published report readable without changing its content or directory
        # ownership policy.
        path.chmod(0o644)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def run_evidence(report_path: Path = REPORT) -> dict[str, Any]:
    """Execute every fixed current-engine selection and publish one report."""

    provenance = require_native_x86_64()
    cargo = require_tool("cargo")
    rustc = require_tool("rustc")
    toolchain = toolchain_record(cargo, rustc)
    before_lockfile = sha256_file(LOCKFILE)

    # The target directory belongs to this invocation alone and is removed
    # even if a selected test fails.  It deliberately lives outside the
    # workspace so it cannot leak an architecture-neutral build cache into
    # another evidence lane.
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-lifecycle-") as temporary:
        target_dir = Path(temporary) / "target"
        lanes = [run_lane(cargo, lane, target_dir) for lane in TEST_LANES]

    after_lockfile = sha256_file(LOCKFILE)
    if after_lockfile != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite the required --locked commands")
    report = report_from_results(
        provenance=provenance,
        toolchain=toolchain,
        lockfile_sha256=before_lockfile,
        lanes=lanes,
    )
    atomic_write_json(report_path, report)
    return report


def runtime_first_arena_lane() -> TestLane:
    """Return the only lifecycle lane allowed to publish focused evidence."""

    for lane in TEST_LANES:
        if lane.identifier == "runtime-process-policy-first-arena":
            return lane
    raise EvidenceError("runtime first-arena lifecycle lane is not configured")


def runtime_thp_configuration_lane() -> TestLane:
    """Return the fixed normal-runtime THP source-environment admission lane."""

    for lane in TEST_LANES:
        if lane.identifier == "runtime-source-environment-thp-ready-configuration-admission":
            return lane
    raise EvidenceError("runtime THP configuration lifecycle lane is not configured")


def compare_initial_tld_numa_observations(
    c_oracle: Mapping[str, Any], rust_lane: Mapping[str, Any]
) -> dict[str, Any]:
    """Compare policy facts and node relations, never host node identity."""

    c_trace = c_oracle.get("trace")
    rust_trace = rust_lane.get("initial_tld_numa_trace")
    if not isinstance(c_trace, Mapping) or not isinstance(rust_trace, Mapping):
        raise EvidenceError("initial-TLD NUMA comparison is missing one raw observation")
    validate_initial_tld_numa_c_trace(c_trace)
    try:
        rust_arena_is_numa_local = int(rust_trace["vm_policy_arena_is_numa_local"])
        rust_option = int(rust_trace["vm_policy_use_numa_nodes"])
        rust_count = int(rust_trace["vm_policy_numa_node_count_cache"])
        rust_node = int(rust_trace["ticket_zero_tld_numa_node"])
        rust_arena_node = int(rust_trace["process_arena_numa_node"])
    except (KeyError, TypeError, ValueError) as error:
        raise EvidenceError("Rust initial-TLD NUMA observation is malformed") from error
    if rust_arena_is_numa_local != c_trace["arena_is_numa_local_option_applied"]:
        raise EvidenceError("C/Rust first-arena local-NUMA option values differ")
    if rust_option != c_trace["configured_numa_node_count"]:
        raise EvidenceError("C/Rust initial-TLD NUMA configured option values differ")
    if rust_count != c_trace["resolved_numa_node_count"]:
        raise EvidenceError("C/Rust initial-TLD NUMA policy counts differ")
    if rust_node < 0 or rust_node >= rust_count:
        raise EvidenceError("Rust initial-TLD NUMA node lies outside its policy count")
    if rust_arena_node < 0 or rust_arena_node >= rust_count:
        raise EvidenceError("Rust first regular arena NUMA node lies outside its policy count")
    return {
        "compared_value_count": 3,
        "arena_is_numa_local": rust_arena_is_numa_local,
        "configured_numa_node_count": rust_option,
        "policy_numa_node_count": rust_count,
        "c_ticket_zero_tld_numa_in_range": True,
        "rust_ticket_zero_tld_numa_in_range": True,
        "c_regular_first_arena_numa_in_range": True,
        "rust_regular_first_arena_numa_in_range": True,
        "c_regular_first_arena_retained_after_free": True,
        "status": "matched-normalized-policy-relations",
    }


def compare_runtime_thp_configuration_observations(
    c_oracle: Mapping[str, Any], rust_lane: Mapping[str, Any]
) -> dict[str, Any]:
    """Compare only the two retained source-option configuration relations."""

    c_images = c_oracle.get("images")
    rust_images = rust_lane.get("runtime_thp_configuration_trace")
    if not isinstance(c_images, list) or not isinstance(rust_images, Mapping):
        raise EvidenceError("runtime THP configuration comparison lacks one raw observation")
    if [image.get("id") for image in c_images if isinstance(image, Mapping)] != list(
        RUNTIME_THP_CONFIGURATION_IMAGE_IDS
    ):
        raise EvidenceError("runtime THP C image roster drifted")
    if tuple(rust_images) != RUNTIME_THP_CONFIGURATION_IMAGE_IDS:
        raise EvidenceError("runtime THP Rust image roster drifted")
    compared_images: list[dict[str, int | str]] = []
    for image_id, c_image in zip(RUNTIME_THP_CONFIGURATION_IMAGE_IDS, c_images, strict=True):
        if not isinstance(c_image, Mapping) or not isinstance(c_image.get("trace"), Mapping):
            raise EvidenceError("runtime THP C image trace is malformed")
        c_trace = c_image["trace"]
        validate_runtime_thp_configuration_c_trace(image_id, c_trace)
        rust_trace = rust_images[image_id]
        if not isinstance(rust_trace, Mapping) or set(rust_trace) != set(
            RUNTIME_THP_CONFIGURATION_TRACE_KEYS
        ):
            raise EvidenceError("runtime THP Rust image trace is malformed")
        if any(type(rust_trace.get(key)) is not int for key in RUNTIME_THP_CONFIGURATION_TRACE_KEYS):
            raise EvidenceError("runtime THP Rust image requires exact integer scalars")
        if (
            rust_trace["selected_allow_thp_raw"] != c_trace["selected_allow_thp_raw"]
            or rust_trace["ready_memory_config_has_transparent_huge_pages"]
            != c_trace["config_has_transparent_huge_pages"]
            or rust_trace["vm_policy_allow_thp"]
            != int(rust_trace["selected_allow_thp_raw"] != 0)
        ):
            raise EvidenceError("runtime THP C/Rust retained configuration relation changed")
        compared_images.append(
            {
                "config_has_transparent_huge_pages": c_trace[
                    "config_has_transparent_huge_pages"
                ],
                "id": image_id,
                "selected_allow_thp_raw": c_trace["selected_allow_thp_raw"],
            }
        )
    return {
        "compared_value_count": 4,
        "images": compared_images,
        "rust_boolean_projection_count": 2,
        "status": "matched-retained-ready-configuration",
    }


def validate_runtime_first_arena_policy_report(report: Mapping[str, Any]) -> None:
    """Validate receipt structure and self-consistency, not live candidate-source identity."""

    required = {
        "candidate_source",
        "c_oracle",
        "cargo",
        "comparison",
        "exclusions",
        "format",
        "kind",
        "lane",
        "native_execution_provenance",
        "profile",
        "runtime_thp_configuration",
        "scope",
        "status",
        "target",
        "toolchain",
    }
    if set(report) != required:
        raise EvidenceError("runtime first-arena report schema drifted")
    if (
        type(report.get("format")) is not int
        or report["format"] != 4
        or report.get("status") != "passed"
    ):
        raise EvidenceError("runtime first-arena report must record a passed format-4 result")
    if report.get("kind") != "mimalloc-x86_64-runtime-first-arena-policy-evidence":
        raise EvidenceError("runtime first-arena report kind drifted")
    if report.get("profile") != "linux-x86_64-private-engine-runtime-first-arena-policy-witness":
        raise EvidenceError("runtime first-arena report profile drifted")
    if report.get("target") != {
        "architecture": "x86_64",
        "endianness": "little",
        "rust_target": TARGET,
        "system": "linux",
    }:
        raise EvidenceError("runtime first-arena report target drifted")
    if report.get("native_execution_provenance") not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("runtime first-arena report lacks canonical native provenance")
    candidate_source = report.get("candidate_source")
    if not isinstance(candidate_source, Mapping) or set(candidate_source) != {
        "after",
        "before",
        "git_read_environment",
        "unchanged_during_execution",
    }:
        raise EvidenceError("runtime first-arena report candidate source seal is invalid")
    if (
        type(candidate_source.get("unchanged_during_execution")) is not bool
        or candidate_source["unchanged_during_execution"] is not True
    ):
        raise EvidenceError("runtime first-arena report candidate source must be unchanged")
    expected_candidate_source = candidate_source_attestation(
        candidate_source.get("before"), candidate_source.get("after")
    )
    if candidate_source != expected_candidate_source:
        raise EvidenceError("runtime first-arena report candidate source seal drifted")
    if tuple(report.get("exclusions", ())) != RUNTIME_FIRST_ARENA_EXCLUSIONS:
        raise EvidenceError("runtime first-arena exclusions drifted")
    scope = report.get("scope")
    if not isinstance(scope, Mapping) or scope != {
        "boundary": "one child-isolated pinned-C and one process-isolated private Rust TLD/regular-first-arena policy witness, plus two fixed child source-environment THP configuration images only",
        "public_runtime_support": False,
        "claim": "focused initial-TLD/regular-first-arena NUMA and retained runtime source-THP configuration witnesses",
    }:
        raise EvidenceError("runtime first-arena scope drifted")

    cargo = report.get("cargo")
    if not isinstance(cargo, Mapping) or cargo.get("locked") is not True:
        raise EvidenceError("runtime first-arena report must retain Cargo --locked evidence")
    if cargo.get("target_dir") != {
        "isolated": True,
        "retained": False,
        "value": "<isolated-temporary-target-dir>",
    }:
        raise EvidenceError("runtime first-arena Cargo target isolation drifted")

    lane = report.get("lane")
    configured = runtime_first_arena_lane()
    if not isinstance(lane, Mapping) or lane.get("id") != configured.identifier:
        raise EvidenceError("runtime first-arena report lane drifted")
    if lane.get("observed", {}).get("passed") != configured.expected_pass_count:
        raise EvidenceError("runtime first-arena report pass count drifted")
    rust_trace = lane.get("initial_tld_numa_trace")
    if not isinstance(rust_trace, Mapping):
        raise EvidenceError("runtime first-arena report lacks its raw initial-TLD NUMA observation")
    # Reuse the exact parser-level relation checks without accepting a trace
    # that merely happens to have the right outer Cargo summary.
    if set(rust_trace) != set(RUNTIME_INITIAL_TLD_NUMA_TRACE_KEYS):
        raise EvidenceError("runtime first-arena Rust NUMA trace schema drifted")
    if (
        type(rust_trace.get("vm_policy_arena_is_numa_local")) is not int
        or type(rust_trace.get("vm_policy_use_numa_nodes")) is not int
        or type(rust_trace.get("vm_policy_numa_node_count_cache")) is not int
        or type(rust_trace.get("ticket_zero_tld_numa_node")) is not int
        or type(rust_trace.get("process_arena_numa_node")) is not int
        or rust_trace.get("vm_policy_arena_is_numa_local") != 1
        or rust_trace.get("vm_policy_use_numa_nodes") != 3
        or rust_trace.get("vm_policy_numa_node_count_cache") != 3
        or rust_trace["ticket_zero_tld_numa_node"] < 0
        or rust_trace["ticket_zero_tld_numa_node"] >= 3
        or rust_trace["process_arena_numa_node"] < 0
        or rust_trace["process_arena_numa_node"] >= 3
    ):
        raise EvidenceError("runtime first-arena Rust NUMA trace relation drifted")

    c_oracle = report.get("c_oracle")
    if not isinstance(c_oracle, Mapping):
        raise EvidenceError("runtime first-arena report lacks its pinned C oracle")
    c_trace = c_oracle.get("trace")
    if not isinstance(c_trace, Mapping):
        raise EvidenceError("runtime first-arena C oracle trace is malformed")
    validate_initial_tld_numa_c_trace(c_trace)
    upstream = c_oracle.get("upstream")
    pin = pinned_mimalloc_pin()
    if upstream != {"archive_sha256": pin["sha256"], "revision": pin["revision"]}:
        raise EvidenceError("runtime first-arena C oracle pin drifted")
    fixture = c_oracle.get("fixture")
    if not isinstance(fixture, Mapping) or fixture.get("path") != relative(INITIAL_TLD_NUMA_FIXTURE):
        raise EvidenceError("runtime first-arena C fixture identity drifted")
    source_files = c_oracle.get("source_files")
    if not isinstance(source_files, list) or [record.get("path") for record in source_files if isinstance(record, Mapping)] != sorted(set(INITIAL_TLD_NUMA_C_ORACLE_SOURCE_FILES)):
        raise EvidenceError("runtime first-arena C source roster drifted")
    comparison = compare_initial_tld_numa_observations(c_oracle, lane)
    if report.get("comparison") != comparison:
        raise EvidenceError("runtime first-arena C/Rust normalized comparison drifted")

    runtime_thp = report.get("runtime_thp_configuration")
    if not isinstance(runtime_thp, Mapping) or set(runtime_thp) != {
        "c_oracle",
        "comparison",
        "lane",
    }:
        raise EvidenceError("runtime THP configuration record schema drifted")
    thp_lane = runtime_thp.get("lane")
    configured_thp_lane = runtime_thp_configuration_lane()
    if (
        not isinstance(thp_lane, Mapping)
        or thp_lane.get("id") != configured_thp_lane.identifier
        or thp_lane.get("observed", {}).get("passed") != configured_thp_lane.expected_pass_count
    ):
        raise EvidenceError("runtime THP configuration Rust lane drifted")
    thp_trace = thp_lane.get("runtime_thp_configuration_trace")
    if (
        not isinstance(thp_trace, Mapping)
        or tuple(thp_trace) != RUNTIME_THP_CONFIGURATION_IMAGE_IDS
        or any(
            not isinstance(thp_trace.get(image_id), Mapping)
            or set(thp_trace[image_id]) != set(RUNTIME_THP_CONFIGURATION_TRACE_KEYS)
            for image_id in RUNTIME_THP_CONFIGURATION_IMAGE_IDS
        )
    ):
        raise EvidenceError("runtime THP configuration report lacks its Rust image traces")
    # Reuse the finite parser's semantic relations after retaining the exact
    # object schema, so neither an omitted image nor a mode-two host assumption
    # can pass through the report validator.
    reconstructed = "\n".join(
        row
        for image_id in RUNTIME_THP_CONFIGURATION_IMAGE_IDS
        for row in (
            RUNTIME_THP_CONFIGURATION_TRACE_BEGIN[image_id],
            *(f"{key}={thp_trace[image_id][key]}" for key in RUNTIME_THP_CONFIGURATION_TRACE_KEYS),
            RUNTIME_THP_CONFIGURATION_TRACE_END[image_id],
        )
    )
    if parse_runtime_thp_configuration_trace(reconstructed) != thp_trace:
        raise EvidenceError("runtime THP configuration Rust image relations drifted")
    thp_c_oracle = runtime_thp.get("c_oracle")
    if not isinstance(thp_c_oracle, Mapping) or set(thp_c_oracle) != {
        "fixture",
        "images",
        "source_files",
        "upstream",
    }:
        raise EvidenceError("runtime THP configuration C oracle schema drifted")
    if thp_c_oracle.get("upstream") != {
        "archive_sha256": pin["sha256"],
        "revision": pin["revision"],
    }:
        raise EvidenceError("runtime THP configuration C oracle pin drifted")
    fixture = thp_c_oracle.get("fixture")
    if (
        not isinstance(fixture, Mapping)
        or fixture.get("path") != relative(RUNTIME_THP_CONFIGURATION_FIXTURE)
        or type(fixture.get("bytes")) is not int
        or fixture.get("bytes", 0) <= 0
        or not isinstance(fixture.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", fixture["sha256"]) is None
    ):
        raise EvidenceError("runtime THP configuration C fixture identity drifted")
    thp_source_files = thp_c_oracle.get("source_files")
    if (
        not isinstance(thp_source_files, list)
        or [record.get("path") for record in thp_source_files if isinstance(record, Mapping)]
        != sorted(set(RUNTIME_THP_CONFIGURATION_C_ORACLE_SOURCE_FILES))
        or len(thp_source_files) != len(set(RUNTIME_THP_CONFIGURATION_C_ORACLE_SOURCE_FILES))
    ):
        raise EvidenceError("runtime THP configuration C source roster drifted")
    thp_images = thp_c_oracle.get("images")
    if (
        not isinstance(thp_images, list)
        or [image.get("id") for image in thp_images if isinstance(image, Mapping)]
        != list(RUNTIME_THP_CONFIGURATION_IMAGE_IDS)
        or len(thp_images) != len(RUNTIME_THP_CONFIGURATION_IMAGE_IDS)
    ):
        raise EvidenceError("runtime THP configuration C image record drifted")
    for image_id, image in zip(RUNTIME_THP_CONFIGURATION_IMAGE_IDS, thp_images, strict=True):
        if (
            not isinstance(image, Mapping)
            or set(image) != {"binary", "build", "id", "run", "trace", "trace_sha256"}
            or image.get("id") != image_id
            or not isinstance(image.get("trace"), Mapping)
            or not isinstance(image.get("trace_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", image["trace_sha256"]) is None
        ):
            raise EvidenceError("runtime THP configuration C image schema drifted")
        validate_runtime_thp_configuration_c_trace(image_id, image["trace"])
    thp_comparison = compare_runtime_thp_configuration_observations(thp_c_oracle, thp_lane)
    if runtime_thp.get("comparison") != thp_comparison:
        raise EvidenceError("runtime THP configuration C/Rust comparison drifted")


def run_runtime_first_arena_policy_evidence(report_path: Path) -> dict[str, Any]:
    """Publish the one policy-bound runtime witness without a campaign claim."""

    candidate_source_before = capture_candidate_source_snapshot()
    provenance = require_native_x86_64()
    cargo = require_tool("cargo")
    rustc = require_tool("rustc")
    toolchain = toolchain_record(cargo, rustc)
    before_lockfile = sha256_file(LOCKFILE)
    lane = runtime_first_arena_lane()
    thp_lane = runtime_thp_configuration_lane()

    c_oracle = run_initial_tld_numa_c_oracle()
    thp_c_oracle = run_runtime_thp_configuration_c_oracle()
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-runtime-first-arena-") as temporary:
        target_dir = Path(temporary) / "target"
        result = run_lane(cargo, lane, target_dir)
        thp_result = run_lane(cargo, thp_lane, target_dir)

    after_lockfile = sha256_file(LOCKFILE)
    if after_lockfile != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite the required --locked command")
    candidate_source = candidate_source_attestation(
        candidate_source_before, capture_candidate_source_snapshot()
    )

    report: dict[str, Any] = {
        "format": 4,
        "kind": "mimalloc-x86_64-runtime-first-arena-policy-evidence",
        "profile": "linux-x86_64-private-engine-runtime-first-arena-policy-witness",
        "status": "passed",
        "target": {
            "architecture": "x86_64",
            "endianness": "little",
            "rust_target": TARGET,
            "system": "linux",
        },
        "native_execution_provenance": provenance,
        "toolchain": toolchain,
        "cargo": {
            "lockfile": {"path": relative(LOCKFILE), "sha256": before_lockfile},
            "locked": True,
            "target_dir": {
                "isolated": True,
                "retained": False,
                "value": "<isolated-temporary-target-dir>",
            },
        },
        "candidate_source": candidate_source,
        "c_oracle": c_oracle,
        "comparison": compare_initial_tld_numa_observations(c_oracle, result),
        "lane": result,
        "runtime_thp_configuration": {
            "c_oracle": thp_c_oracle,
            "comparison": compare_runtime_thp_configuration_observations(
                thp_c_oracle, thp_result
            ),
            "lane": thp_result,
        },
        "scope": {
            "boundary": "one child-isolated pinned-C and one process-isolated private Rust TLD/regular-first-arena policy witness, plus two fixed child source-environment THP configuration images only",
            "public_runtime_support": False,
            "claim": "focused initial-TLD/regular-first-arena NUMA and retained runtime source-THP configuration witnesses",
        },
        "exclusions": list(RUNTIME_FIRST_ARENA_EXCLUSIONS),
    }
    validate_runtime_first_arena_policy_report(report)
    atomic_write_json(report_path, report)
    return report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="write the selected evidence report here",
    )
    parser.add_argument(
        "--only-runtime-first-arena-policy",
        action="store_true",
        help="record the fixed first-arena witness without claiming the full campaign",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    focused = arguments.only_runtime_first_arena_policy
    report_path = arguments.report or (
        RUNTIME_FIRST_ARENA_REPORT if focused else REPORT
    )
    try:
        report = (
            run_runtime_first_arena_policy_evidence(report_path)
            if focused
            else run_evidence(report_path)
        )
    except EvidenceError as error:
        print(f"allocator x86-64 lifecycle/concurrency foundation: FAIL: {error}", file=sys.stderr)
        return 1
    if focused:
        observed = report["lane"]["observed"]["passed"]
        print(
            "allocator x86-64 runtime first-arena policy witness: PASS "
            f"({observed} bounded test; report: {relative(report_path)})"
        )
    else:
        summary = report["summary"]
        print(
            "allocator x86-64 lifecycle/concurrency foundation: PASS "
            f"({summary['observed_pass_count']} bounded tests across {summary['lane_count']} lanes; "
            f"report: {relative(report_path)})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
