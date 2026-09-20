#!/usr/bin/env python3
"""Native x86-64 differential for pinned automatic regular-arena reservation.

This private source oracle starts each observed phase in a fresh child image.
It never exercises crabc bootstrap or its ticket-zero page owner.  The C side
uses the pinned main thread only for the sequential phase; each concurrent
request initializes and validates its own source Theap/TLD before calling the
source's static ``mi_arenas_try_alloc``.  Rust exercises the existing private
``ProcessArenaBacking`` owner with the matching explicit ArenaSearch inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-automatic-arena-reservation-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/automatic-arena-reservation.json"
LOCKFILE = ROOT / "Cargo.lock"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/arena_owned.rs"
HOST_TEST_SOURCE = ROOT / "compat/allocator/tests/test_x86_64_automatic_arena_reservation_evidence.py"
SOURCE_MAP_TEST_SOURCE = ROOT / "compat/allocator/tests/test_x86_64_source_map.py"
SOURCE_MAP = ROOT / "compat/allocator/x86_64-source-map-v3.5.0.json"
M2_CONTRACT = ROOT / "compat/allocator/m2-memory-substrate-x86_64-v3.5.0.json"
ALLOCATOR_README = ROOT / "compat/allocator/README.md"
DISPATCHER_SOURCE = ROOT / "compat/allocator/run-x86_64.sh"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "arena::owned::tests::emit_x86_64_automatic_arena_reservation_trace"
TRACE_BEGIN = "CRABC_MI_AUTOMATIC_ARENA_RESERVATION_TRACE_BEGIN"
TRACE_END = "CRABC_MI_AUTOMATIC_ARENA_RESERVATION_TRACE_END"
NORMALIZED_TEMPORARY = "<temporary-automatic-arena-reservation>"
NORMALIZED_SOURCE = "<pinned-mimalloc-source>"

import importlib.util
spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The bounded automatic-reservation relation was not established."""


EXPECTED_TARGET = {
    "architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux",
}
EXPECTED_UPSTREAM = {
    "archive_root": "mimalloc-3.5.0", "revision": "18b08671c9302247bfb682286e6bf3cc1773f801", "version": "3.5.0",
}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_PROFILE = "linux-x86_64-private-automatic-regular-arena-reservation"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "automatic_reserve_lock_coalescing_claimed": False,
    "bootstrap_or_ready_path_changed": False,
    "concurrent_fresh_regular_arena_reservation_claimed": True,
    "simultaneous_reserve_lock_miss_or_coalescing_claimed": False,
    "default_backend_changed": False,
    "emulation_accepted": False,
    "metadata_or_os_aligned_publication_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "runtime_first_arena_claimed": False,
}
EXPECTED_COMPILE_DEFINITIONS = ("-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", "-DMI_PRIM_HAS_PROCESS_ATTACH=1")
EXPECTED_C_ELF = {"class": "ELF64", "endianness": "little", "machine": "Advanced Micro Devices X86-64"}
EXPECTED_SOURCE_ANCHORS = (
    ("include/mimalloc/atomic.h", 18, 20, "c0235bb455ffc28e3bb83afcfd5946fe44aa652808a892435f13a67efa232f52"),
    ("src/arena.c", 240, 335, "d7f4fe71718bd3baebb7c31b63a07d867a73eddab2f8efadd976bf940efa175f"),
    ("src/arena.c", 341, 406, "52181aaf7f41b28c1da4c6ac7bd6cc4f25a77738fd79a2cabd6522533257ec62"),
    ("src/arena.c", 497, 569, "c3ccfc5061f9fb83f48dd6e92133c59ec65bbd89dd7f1c6531dcf48e66686bd8"),
    ("src/arena.c", 1573, 1610, "e87fb778eb17439ab7dd21f0e6d53c3779802553c2b4310965bd9341b95a7946"),
    ("src/init.c", 236, 250, "25b55becf855281d82750d46dcd93ab6e8786453295b7eb34b4648ace45fc455"),
    ("src/init.c", 305, 360, "8b5a6af8d90da7f2cb33cf5c6211c9325234840d57a54c25be891e49e4d354e5"),
    ("src/init.c", 505, 533, "8eadfa1134c837f8a2e13ab433b20e2ef00d5c9895afc7232638f05c656ce6d8"),
    ("src/prim/unix/prim.c", 1011, 1040, "eef3c9b9715fec9a271f8a966febe73d3ff3113165c5bc9c930fa46c657aa87a"),
)

TRACE_VALUES = {
    "trace.automatic_arena.disallow.request_owner_inputs_valid": 1,
    "trace.automatic_arena.disallow.initial_registry_empty": 1,
    "trace.automatic_arena.disallow.initial_high_water_zero": 1,
    "trace.automatic_arena.disallow.miss_rejected": 1,
    "trace.automatic_arena.disallow.registry_unchanged": 1,
    "trace.automatic_arena.disallow.high_water_unchanged": 1,
    "trace.automatic_arena.sequential.request_owner_inputs_valid": 1,
    "trace.automatic_arena.sequential.four_claims_live": 1,
    "trace.automatic_arena.sequential.second_arena_created": 1,
    "trace.automatic_arena.sequential.high_water_delta": 2,
    "trace.automatic_arena.sequential.first_last_arena_distinct": 1,
    "trace.automatic_arena.sequential.ranges_distinct": 1,
    "trace.automatic_arena.sequential.released_ranges_free": 1,
    "trace.automatic_arena.concurrent.workers_ready_with_distinct_request_inputs": 8,
    "trace.automatic_arena.concurrent.workers_observed_exhausted_existing_ranges": 1,
    "trace.automatic_arena.concurrent.eight_new_arena_claims_live": 1,
    "trace.automatic_arena.concurrent.one_new_arena_reserved": 1,
    "trace.automatic_arena.concurrent.new_ranges_distinct": 1,
    "trace.automatic_arena.concurrent.retained_live_ranges_released": 1,
    "trace.automatic_arena.concurrent.released_ranges_free": 1,
    "trace.automatic_arena.valid": 1,
}


# ``static.c`` makes its complete pinned allocator translation unit visible to
# this white-box source oracle. The C side uses the pinned main thread only
# for the sequential phase. Each concurrent worker initializes and validates
# its own source Theap/TLD. The source-owned metadata arena is exhausted under
# `disallow_os_alloc` before eight actual automatic allocation calls are
# released. Rust supplies explicit private `ArenaSearch` inputs from an
# equivalently exhausted existing arena; it never claims a Rust Heap/TLD.
C_TRACE_PROBE = r'''
#include "static.c"

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private automatic-arena fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif
#if !MI_TLS_MODEL_LOCAL || MI_TLS_MODEL_PTHREADS || MI_TLS_MODEL_FIXED || MI_TLS_MODEL_WIN32
#error this fixture pins compiler-local default-Theap TLS separately from MI_USE_PTHREADS
#endif
#if !defined(MI_USE_PTHREADS)
#error this fixture requires the selected Unix private automatic-thread-done key
#endif

#define CLAIM_SLICES 256
#define SEQUENTIAL_CLAIMS 4
#define CONCURRENT_WORKERS 8

static mi_subproc_t* subprocess;

static bool root_is_current(mi_theap_t* theap) {
  return (theap != NULL && mi_theap_is_initialized(theap)
          && _mi_theap_default() == theap && _mi_theap_subproc(theap) == subprocess
          && _mi_theap_heap(theap) != NULL && _mi_theap_heap(theap)->subproc == subprocess
          && theap->tld != NULL && theap->tld->subproc == subprocess
          && theap->tld->thread_id == _mi_thread_id());
}

static void* claim_current(mi_theap_t* theap, size_t slices, mi_memid_t* memory) {
  mi_tld_t* const tld = theap->tld;
  return mi_arenas_try_alloc(_mi_theap_heap(theap), slices, MI_ARENA_SLICE_SIZE,
                             true, false, NULL, tld->thread_seq, tld->numa_node, memory);
}

static bool initialize_clean_process(mi_theap_t** theap_out, int64_t* high_water_out) {
  _mi_auto_process_init();
  subprocess = _mi_subproc_main();
  mi_theap_t* const theap = _mi_theap_default();
  if (subprocess == NULL || !root_is_current(theap)
      || mi_arenas_get_count(subprocess) != 0 || subprocess->stats.arena_count.total != 0) {
    fprintf(stderr, "automatic-arena init root=%d count=%zu high-water=%lld\\n",
            root_is_current(theap), subprocess == NULL ? 0 : mi_arenas_get_count(subprocess),
            (long long)(subprocess == NULL ? -1 : subprocess->stats.arena_count.total));
    return false;
  }
  mi_option_set(mi_option_arena_reserve, (long)(MI_ARENA_MIN_SIZE / MI_KiB));
  mi_option_set(mi_option_arena_eager_commit, 0);
  *theap_out = theap;
  *high_water_out = subprocess->stats.arena_count.total;
  return true;
}

static void emit(const char* key, int64_t value) { printf("%s=%lld\n", key, (long long)value); }

static bool disallow_and_sequential_phase(void) {
  mi_theap_t* theap = NULL;
  int64_t initial_high_water = 0;
  mi_memid_t memories[SEQUENTIAL_CLAIMS];
  void* claims[SEQUENTIAL_CLAIMS] = { 0 };
  mi_arena_t* owners[SEQUENTIAL_CLAIMS] = { 0 };
  size_t starts[SEQUENTIAL_CLAIMS] = { 0 };
  bool released = true;
  if (!initialize_clean_process(&theap, &initial_high_water)) return false;

  mi_option_set(mi_option_disallow_os_alloc, 1);
  mi_memid_t denied;
  void* const refused = claim_current(theap, CLAIM_SLICES, &denied);
  const bool reject_ok = (refused == NULL && mi_arenas_get_count(subprocess) == 0
                          && subprocess->stats.arena_count.total == initial_high_water);
  mi_option_set(mi_option_disallow_os_alloc, 0);
  if (!reject_ok) { fprintf(stderr, "automatic-arena disallow miss was not clean\\n"); return false; }

  for (size_t index = 0; index < SEQUENTIAL_CLAIMS; index++) {
    claims[index] = claim_current(theap, CLAIM_SLICES, &memories[index]);
    if (claims[index] == NULL || memories[index].memkind != MI_MEM_ARENA
        || !memories[index].initially_committed) {
      fprintf(stderr, "automatic-arena sequential claim %zu failed\\n", index); return false;
    }
    owners[index] = mi_memid_arena(memories[index]);
    starts[index] = memories[index].mem.arena.slice_index;
    if (owners[index] == NULL) { fprintf(stderr, "automatic-arena sequential owner %zu absent\\n", index); return false; }
  }
  const bool second = (mi_arenas_get_count(subprocess) == 2
                       && subprocess->stats.arena_count.total - initial_high_water == 2);
  const bool distinct_arenas = owners[0] != owners[SEQUENTIAL_CLAIMS - 1];
  bool distinct_ranges = true;
  for (size_t left = 0; left < SEQUENTIAL_CLAIMS; left++) {
    for (size_t right = left + 1; right < SEQUENTIAL_CLAIMS; right++) {
      if (claims[left] == claims[right]
          || (owners[left] == owners[right]
              && !(starts[left] + CLAIM_SLICES <= starts[right]
                   || starts[right] + CLAIM_SLICES <= starts[left]))) distinct_ranges = false;
    }
  }
  for (size_t index = 0; index < SEQUENTIAL_CLAIMS; index++) {
    _mi_arenas_free(subprocess, claims[index], CLAIM_SLICES * MI_ARENA_SLICE_SIZE, memories[index]);
    if (!mi_bbitmap_is_setN(owners[index]->slices_free, starts[index], CLAIM_SLICES)) released = false;
  }
  if (!second || !distinct_arenas || !distinct_ranges || !released) {
    fprintf(stderr, "automatic-arena sequential relation second=%d distinct-arenas=%d distinct-ranges=%d released=%d count=%zu high-water=%lld\\n",
            second, distinct_arenas, distinct_ranges, released, mi_arenas_get_count(subprocess),
            (long long)(subprocess->stats.arena_count.total - initial_high_water));
    return false;
  }

  emit("trace.automatic_arena.disallow.request_owner_inputs_valid", 1);
  emit("trace.automatic_arena.disallow.initial_registry_empty", 1);
  emit("trace.automatic_arena.disallow.initial_high_water_zero", initial_high_water == 0);
  emit("trace.automatic_arena.disallow.miss_rejected", 1);
  emit("trace.automatic_arena.disallow.registry_unchanged", 1);
  emit("trace.automatic_arena.disallow.high_water_unchanged", 1);
  emit("trace.automatic_arena.sequential.request_owner_inputs_valid", 1);
  emit("trace.automatic_arena.sequential.four_claims_live", 1);
  emit("trace.automatic_arena.sequential.second_arena_created", 1);
  emit("trace.automatic_arena.sequential.high_water_delta", 2);
  emit("trace.automatic_arena.sequential.first_last_arena_distinct", 1);
  emit("trace.automatic_arena.sequential.ranges_distinct", 1);
  emit("trace.automatic_arena.sequential.released_ranges_free", 1);
  return true;
}

typedef struct worker_state_s {
  bool root_valid;
  bool preclaim_miss;
  bool claim_live;
  bool released;
  mi_arena_t* arena;
  size_t slice_index;
  mi_threadid_t thread_id;
  size_t thread_seq;
} worker_state_t;

#define FILLER_LIMIT 2048

// These stack-owned gates establish the source order exactly: create worker
// pthreads before initialization, initialize each worker's own TLD/Theap,
// retain every range in their existing metadata arena while OS growth is
// disabled, let every worker observe the source search miss, then enable OS
// growth and release the actual `mi_arenas_try_alloc` calls. They do not prove
// that each caller sampled the internal reserve lock at the same instant.
static _Atomic size_t process_ready = 0;
static _Atomic size_t roots_ready = 0;
static _Atomic size_t filler_ready = 0;
static _Atomic size_t misses_ready = 0;
static _Atomic size_t calls_start = 0;
static _Atomic size_t claims_ready = 0;
static _Atomic size_t releases_start = 0;

static bool wait_for_workers(_Atomic size_t* value, size_t expected) {
  for (size_t spin = 0; spin < 10000000; spin++) {
    if (atomic_load_explicit(value, memory_order_acquire) == expected) return true;
    sched_yield();
  }
  return false;
}

static void* concurrent_worker(void* argument) {
  worker_state_t* const state = (worker_state_t*)argument;
  if (!wait_for_workers(&process_ready, 1)) return NULL;
  mi_theap_t* const theap = _mi_thread_init();
  state->root_valid = root_is_current(theap);
  if (state->root_valid) {
    state->thread_id = theap->tld->thread_id;
    state->thread_seq = theap->tld->thread_seq;
  }
  atomic_fetch_add_explicit(&roots_ready, 1, memory_order_release);
  if (!wait_for_workers(&filler_ready, 1)) return NULL;
  mi_memid_t missing;
  state->preclaim_miss = state->root_valid
      && mi_arenas_try_find_free(_mi_theap_heap(theap), 1, MI_ARENA_SLICE_SIZE,
                                  true, false, NULL, theap->tld->thread_seq,
                                  theap->tld->numa_node, &missing) == NULL;
  atomic_fetch_add_explicit(&misses_ready, 1, memory_order_release);
  if (!wait_for_workers(&calls_start, 1)) return NULL;
  mi_memid_t memory;
  void* const claim = state->root_valid ? claim_current(theap, 1, &memory) : NULL;
  state->claim_live = (claim != NULL && memory.memkind == MI_MEM_ARENA && memory.initially_committed);
  if (state->claim_live) {
    state->arena = mi_memid_arena(memory);
    state->slice_index = memory.mem.arena.slice_index;
  }
  atomic_fetch_add_explicit(&claims_ready, 1, memory_order_release);
  if (!wait_for_workers(&releases_start, 1)) return NULL;
  if (state->claim_live) {
    _mi_arenas_free(subprocess, claim, MI_ARENA_SLICE_SIZE, memory);
    state->released = mi_bbitmap_is_setN(state->arena->slices_free, state->slice_index, 1);
  }
  return NULL;
}

static bool concurrent_phase(void) {
  pthread_t threads[CONCURRENT_WORKERS];
  worker_state_t states[CONCURRENT_WORKERS] = { 0 };
  void* filler_claims[FILLER_LIMIT];
  mi_memid_t filler_memories[FILLER_LIMIT];
  mi_arena_t* filler_arena = NULL;
  mi_theap_t* main_theap = NULL;
  int64_t initial_high_water = 0;
  size_t filler_count = 0;
  for (size_t index = 0; index < CONCURRENT_WORKERS; index++) {
    if (pthread_create(&threads[index], NULL, concurrent_worker, &states[index]) != 0) {
      fprintf(stderr, "automatic-arena concurrent pthread_create %zu failed\\n", index); return false;
    }
  }
  if (!initialize_clean_process(&main_theap, &initial_high_water) || initial_high_water != 0) return false;
  atomic_store_explicit(&process_ready, 1, memory_order_release);
  if (!wait_for_workers(&roots_ready, CONCURRENT_WORKERS)) {
    fprintf(stderr, "automatic-arena concurrent roots-ready=%zu\\n",
            atomic_load_explicit(&roots_ready, memory_order_acquire));
    return false;
  }
  const size_t baseline_count = mi_arenas_get_count(subprocess);
  const int64_t baseline_high_water = subprocess->stats.arena_count.total;
  if (baseline_count != 1 || baseline_high_water != 1) {
    fprintf(stderr, "automatic-arena concurrent source-root baseline drifted count=%zu high-water=%lld\\n",
            baseline_count, (long long)baseline_high_water);
    return false;
  }
  mi_option_set(mi_option_disallow_os_alloc, 1);
  while (filler_count < FILLER_LIMIT) {
    void* const claim = claim_current(main_theap, 1, &filler_memories[filler_count]);
    if (claim == NULL) break;
    if (filler_memories[filler_count].memkind != MI_MEM_ARENA) return false;
    mi_arena_t* const owner = mi_memid_arena(filler_memories[filler_count]);
    if (owner == NULL || (filler_count != 0 && owner != filler_arena)) return false;
    filler_arena = owner;
    filler_claims[filler_count++] = claim;
  }
  mi_option_set(mi_option_disallow_os_alloc, 0);
  if (filler_count == 0 || filler_count == FILLER_LIMIT || filler_arena == NULL
      || mi_arenas_get_count(subprocess) != baseline_count
      || subprocess->stats.arena_count.total != baseline_high_water) {
    fprintf(stderr, "automatic-arena concurrent filler drifted count=%zu registry=%zu high-water=%lld\\n",
            filler_count, mi_arenas_get_count(subprocess), (long long)subprocess->stats.arena_count.total);
    return false;
  }
  atomic_store_explicit(&filler_ready, 1, memory_order_release);
  if (!wait_for_workers(&misses_ready, CONCURRENT_WORKERS)) {
    fprintf(stderr, "automatic-arena concurrent misses-ready=%zu\\n",
            atomic_load_explicit(&misses_ready, memory_order_acquire));
    return false;
  }
  atomic_store_explicit(&calls_start, 1, memory_order_release);
  if (!wait_for_workers(&claims_ready, CONCURRENT_WORKERS)) {
    fprintf(stderr, "automatic-arena concurrent claims-ready=%zu\\n",
            atomic_load_explicit(&claims_ready, memory_order_acquire));
    return false;
  }

  bool roots = true, misses = true, claims = true, same_new_arena = true, distinct = true;
  for (size_t left = 0; left < CONCURRENT_WORKERS; left++) {
    roots = roots && states[left].root_valid;
    misses = misses && states[left].preclaim_miss;
    claims = claims && states[left].claim_live;
    for (size_t right = left + 1; right < CONCURRENT_WORKERS; right++) {
      if (states[left].thread_id == states[right].thread_id
          || states[left].thread_seq == states[right].thread_seq
          || (states[left].arena == states[right].arena
              && !(states[left].slice_index + 1 <= states[right].slice_index
                   || states[right].slice_index + 1 <= states[left].slice_index))) distinct = false;
      if (states[left].arena != states[right].arena) same_new_arena = false;
    }
  }
  const bool one_new_arena = (mi_arenas_get_count(subprocess) == baseline_count + 1
      && subprocess->stats.arena_count.total == baseline_high_water + 1
      && states[0].arena != filler_arena);
  if (!roots || !misses || !claims || !same_new_arena || !distinct || !one_new_arena) {
    fprintf(stderr, "automatic-arena concurrent reservation roots=%d misses=%d claims=%d same-new=%d distinct=%d one-new=%d registry=%zu high-water=%lld\\n",
            roots, misses, claims, same_new_arena, distinct, one_new_arena,
            mi_arenas_get_count(subprocess), (long long)subprocess->stats.arena_count.total);
    return false;
  }
  atomic_store_explicit(&releases_start, 1, memory_order_release);
  bool released = true;
  for (size_t index = 0; index < CONCURRENT_WORKERS; index++) {
    if (pthread_join(threads[index], NULL) != 0) return false;
    released = released && states[index].released;
  }
  for (size_t index = 0; index < filler_count; index++) {
    _mi_arenas_free(subprocess, filler_claims[index], MI_ARENA_SLICE_SIZE, filler_memories[index]);
    released = released && mi_bbitmap_is_setN(filler_arena->slices_free,
        filler_memories[index].mem.arena.slice_index, 1);
  }
  if (!released) { fprintf(stderr, "automatic-arena concurrent retained-range release failed\\n"); return false; }

  emit("trace.automatic_arena.concurrent.workers_ready_with_distinct_request_inputs", CONCURRENT_WORKERS);
  emit("trace.automatic_arena.concurrent.workers_observed_exhausted_existing_ranges", 1);
  emit("trace.automatic_arena.concurrent.eight_new_arena_claims_live", 1);
  emit("trace.automatic_arena.concurrent.one_new_arena_reserved", 1);
  emit("trace.automatic_arena.concurrent.new_ranges_distinct", 1);
  emit("trace.automatic_arena.concurrent.retained_live_ranges_released", 1);
  emit("trace.automatic_arena.concurrent.released_ranges_free", 1);
  return true;
}

static bool run_child(const char* name, bool (*phase)(void)) {
  pid_t const child = fork();
  if (child < 0) return false;
  if (child == 0) {
    const bool ok = phase();
    fflush(stdout);
    _Exit(ok ? 0 : 2);
  }
  int status = 0;
  const bool ok = (waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  if (!ok) fprintf(stderr, "automatic-arena %s child status=%d\\n", name, status);
  return ok;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("CRABC_MI_AUTOMATIC_ARENA_RESERVATION_TRACE_BEGIN\n");
  const bool valid = run_child("disallow-sequential", disallow_and_sequential_phase)
      && run_child("concurrent", concurrent_phase);
  emit("trace.automatic_arena.valid", valid);
  printf("CRABC_MI_AUTOMATIC_ARENA_RESERVATION_TRACE_END\n");
  return valid ? 0 : 2;
}
'''


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required input is missing: {relative(path)}")
    return sha256_bytes(path.read_bytes())


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def exact(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        return set(left) == set(right) and all(exact(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def source_range(contents: bytes, start: int, end: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start < 1 or end < start or end > len(lines):
        raise EvidenceError("automatic-arena source anchor is outside its pinned member")
    return b"".join(lines[start - 1:end])


def schema_template() -> dict[str, Any]:
    return {
        "format": 1,
        "schema": "crabc-mimalloc-x86_64-automatic-arena-reservation-evidence",
        "profile": EXPECTED_PROFILE,
        "target": EXPECTED_TARGET,
        "upstream": EXPECTED_UPSTREAM,
        "scope": EXPECTED_SCOPE,
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "release_flags": list(run.CONFIGURATION_PROFILES["release"]),
        "source_anchors": [
            {"member": member, "start_line": start, "end_line": end, "sha256": digest}
            for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
        ],
        "c_probe_sha256": sha256_bytes(C_TRACE_PROBE.encode()),
        "rust_test": {"path": relative(RUST_TEST_SOURCE), "test_filter": RUST_TEST_FILTER, "target_arch": "x86_64"},
        "trace": {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": dict(TRACE_VALUES)},
    }


def load_schema(path: Path | None = None) -> dict[str, Any]:
    candidate = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read automatic-arena reservation schema") from error
    if not exact(schema, schema_template()):
        raise EvidenceError("automatic-arena reservation schema drifted")
    pin = run.load_pin()
    if pin["sha256"] != EXPECTED_ARCHIVE_SHA256 or any(pin[key] != value for key, value in EXPECTED_UPSTREAM.items()):
        raise EvidenceError("automatic-arena reservation pin drifted")
    return schema


def parse_trace(output: str, *, description: str) -> dict[str, int]:
    if output.count(TRACE_BEGIN) != 1 or output.count(TRACE_END) != 1:
        raise EvidenceError(f"{description} has an invalid trace delimiter count")
    body = output.split(TRACE_BEGIN, 1)[1].split(TRACE_END, 1)[0].strip()
    fields: dict[str, int] = {}
    order: list[str] = []
    for line in body.splitlines():
        match = re.fullmatch(r"([a-z0-9_.]+)=(-?(?:0|[1-9][0-9]*))", line.strip())
        if match is None:
            raise EvidenceError(f"{description} contains noncanonical trace text")
        key, rendered = match.groups()
        if key in fields:
            raise EvidenceError(f"{description} repeats a trace key")
        fields[key] = int(rendered)
        order.append(key)
    if order != list(TRACE_VALUES):
        raise EvidenceError(f"{description} trace field schema or order drifted")
    return fields


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    if not exact(dict(trace), TRACE_VALUES):
        raise EvidenceError(f"{description} differs from the fixed automatic-arena relation")


def compare(c_trace: Mapping[str, int], rust_trace: Mapping[str, int]) -> dict[str, Any]:
    validate_trace(c_trace, description="pinned C automatic-arena trace")
    validate_trace(rust_trace, description="Rust automatic-arena trace")
    if dict(c_trace) != dict(rust_trace):
        raise EvidenceError("pinned C and Rust automatic-arena relations differ")
    return {"compared_value_count": len(TRACE_VALUES), "status": "matched"}


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None = None) -> list[str]:
    normalized: list[str] = []
    for part in command:
        if source is not None and (part == str(source) or part.startswith(f"{source}/")):
            normalized.append(NORMALIZED_SOURCE + part[len(str(source)):])
        elif part == str(temporary) or part.startswith(f"{temporary}/"):
            normalized.append(NORMALIZED_TEMPORARY + part[len(str(temporary)):])
        else:
            normalized.append(part)
    return normalized


def c_command(compiler: str, source: Path, fixture: Path, binary: Path, schema: Mapping[str, Any]) -> list[str]:
    return [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
            "-I", str(source / "include"), "-I", str(source / "src"), *schema["release_flags"],
            str(fixture), "-pthread", "-o", str(binary)]


def rust_command(cargo: str, target_dir: Path) -> list[str]:
    return [cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir), "-p", "crabc-mimalloc",
            "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    if [item for item in command if item in EXPECTED_COMPILE_DEFINITIONS] != list(EXPECTED_COMPILE_DEFINITIONS):
        raise EvidenceError("automatic-arena C compile definitions drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command or command.count("static.c") != 0:
        raise EvidenceError("automatic-arena C static/TLS command drifted")


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for anchor in schema["source_anchors"]:
        contents = (source / anchor["member"]).read_bytes()
        observed = sha256_bytes(source_range(contents, anchor["start_line"], anchor["end_line"]))
        if observed != anchor["sha256"]:
            raise EvidenceError(f"automatic-arena pinned source anchor drifted: {anchor['member']}")
        records.append(dict(anchor))
    return records


def candidate_snapshot() -> dict[str, Any]:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    def text(arguments: list[str]) -> str:
        result = subprocess.run(["git", *arguments], cwd=ROOT, env=environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode != 0:
            raise EvidenceError(f"cannot record candidate source: {' '.join(arguments)}")
        return result.stdout.strip()
    inputs = [Path(__file__), SCHEMA_PATH, RUST_TEST_SOURCE, HOST_TEST_SOURCE, SOURCE_MAP_TEST_SOURCE,
              SOURCE_MAP, M2_CONTRACT, ALLOCATOR_README, DISPATCHER_SOURCE, LOCKFILE]
    return {"git_revision": text(["rev-parse", "HEAD"]), "git_tree": text(["rev-parse", "HEAD^{tree}"]),
            "git_status_porcelain": text(["status", "--porcelain=v1", "--untracked-files=all"]),
            "files": [{"path": relative(path), "sha256": sha256_file(path)} for path in inputs]}


def normalized_command_record(record: Mapping[str, Any], temporary: Path, source: Path | None = None) -> dict[str, Any]:
    """Retain one executed oracle command and its unedited captured streams."""

    if set(record) != {"command", "status", "stderr", "stdout"}:
        raise EvidenceError("automatic-arena oracle command record drifted")
    return {
        "command": normalize_command(record["command"], temporary, source),
        "status": record["status"],
        "stderr": record["stderr"],
        "stdout": record["stdout"],
    }


def build_c(compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]) -> dict[str, Any]:
    fixture, binary = temporary / "automatic-arena-reservation.c", temporary / "automatic-arena-reservation-c"
    fixture.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_command(compiler, source, fixture, binary, schema)
    validate_c_command(command, schema)
    build = run.command_record(command, cwd=source)
    run.require_success(build, "pinned C automatic-arena fixture build")
    header = run.command_record([readelf, "-h", str(binary)], cwd=source)
    run.require_success(header, "pinned C automatic-arena ELF identity")
    execution = run.command_record([str(binary)], cwd=source, timeout_seconds=180)
    run.require_success(execution, "pinned C automatic-arena fixture")
    trace = parse_trace(str(execution["stdout"]), description="pinned C automatic-arena trace")
    validate_trace(trace, description="pinned C automatic-arena trace")
    return {
        "build": normalized_command_record(build, temporary, source),
        "elf": run.parse_elf_identity(str(header["stdout"]), "x86_64"),
        "elf_header": normalized_command_record(header, temporary, source),
        "execution": normalized_command_record(execution, temporary, source),
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode()),
        "trace": trace,
    }


def build_rust(cargo: str, temporary: Path) -> dict[str, Any]:
    command = rust_command(cargo, temporary / "rust-target")
    environment = dict(os.environ)
    environment["CARGO_INCREMENTAL"] = "0"
    execution = run.command_record(command, cwd=ROOT, env=environment, timeout_seconds=300)
    run.require_success(execution, "Rust automatic-arena fixture")
    combined = str(execution["stdout"]) + "\n" + str(execution["stderr"])
    passed = run.parse_rust_test_count(combined)
    if passed != 1:
        raise EvidenceError("Rust automatic-arena test selection drifted")
    trace = parse_trace(combined, description="Rust automatic-arena trace")
    validate_trace(trace, description="Rust automatic-arena trace")
    return {
        "execution": normalized_command_record(execution, temporary),
        "passed_test_count": passed,
        "source": {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)},
        "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_TEMPORARY}/rust-target"},
        "test_filter": RUST_TEST_FILTER,
        "trace": trace,
    }


def validate_snapshot(snapshot: object) -> None:
    if not isinstance(snapshot, Mapping) or set(snapshot) != {
        "files", "git_revision", "git_status_porcelain", "git_tree",
    }:
        raise EvidenceError("automatic-arena candidate snapshot shape drifted")
    if not isinstance(snapshot["git_revision"], str) or not snapshot["git_revision"]:
        raise EvidenceError("automatic-arena candidate revision is missing")
    if not isinstance(snapshot["git_tree"], str) or not snapshot["git_tree"]:
        raise EvidenceError("automatic-arena candidate tree is missing")
    if not isinstance(snapshot["git_status_porcelain"], str):
        raise EvidenceError("automatic-arena candidate status is malformed")
    expected_paths = [
        relative(path) for path in [
            Path(__file__), SCHEMA_PATH, RUST_TEST_SOURCE, HOST_TEST_SOURCE,
            SOURCE_MAP_TEST_SOURCE, SOURCE_MAP, M2_CONTRACT, ALLOCATOR_README,
            DISPATCHER_SOURCE, LOCKFILE,
        ]
    ]
    files = snapshot["files"]
    if not isinstance(files, list) or [item.get("path") for item in files if isinstance(item, Mapping)] != expected_paths:
        raise EvidenceError("automatic-arena candidate input list drifted")
    if any(not isinstance(item, Mapping) or set(item) != {"path", "sha256"}
           or not isinstance(item["sha256"], str) or len(item["sha256"]) != 64
           for item in files):
        raise EvidenceError("automatic-arena candidate input hash is malformed")
    if not exact(snapshot, candidate_snapshot()):
        raise EvidenceError("automatic-arena candidate snapshot no longer matches current source")


def validate_command_record(record: object, *, description: str) -> Mapping[str, Any]:
    if not isinstance(record, Mapping) or set(record) != {"command", "status", "stderr", "stdout"}:
        raise EvidenceError(f"automatic-arena {description} record shape drifted")
    if not isinstance(record["command"], list) or not all(isinstance(item, str) for item in record["command"]):
        raise EvidenceError(f"automatic-arena {description} command is malformed")
    if record["status"] != 0 or not isinstance(record["stdout"], str) or not isinstance(record["stderr"], str):
        raise EvidenceError(f"automatic-arena {description} did not retain a successful raw command result")
    return record


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"candidate_source", "c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source_anchors", "status", "target", "upstream"}
    if set(report) != required or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("automatic-arena report identity drifted")
    if report["kind"] != "mimalloc-x86_64-automatic-regular-arena-reservation-evidence" or report["profile"] != EXPECTED_PROFILE or not exact(report["scope"], EXPECTED_SCOPE):
        raise EvidenceError("automatic-arena report scope/profile drifted")
    if not exact(report["target"], EXPECTED_TARGET) or not exact(report["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("automatic-arena report target/pin drifted")
    if report["provenance"] not in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"}):
        raise EvidenceError("automatic-arena report lacks native provenance")
    candidate = report["candidate_source"]
    if not isinstance(candidate, Mapping) or set(candidate) != {"after", "before", "unchanged_during_execution"} or candidate.get("unchanged_during_execution") is not True:
        raise EvidenceError("automatic-arena candidate attestation drifted")
    validate_snapshot(candidate.get("before"))
    validate_snapshot(candidate.get("after"))
    if candidate["before"] != candidate["after"]:
        raise EvidenceError("automatic-arena candidate changed during evidence")
    expected_anchors = [
        {"member": member, "start_line": start, "end_line": end, "sha256": digest}
        for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
    ]
    if not exact(report["source_anchors"], expected_anchors):
        raise EvidenceError("automatic-arena report source anchors drifted")
    c_probe, rust_probe = report["c_probe"], report["rust_probe"]
    if not isinstance(c_probe, Mapping) or set(c_probe) != {"build", "elf", "elf_header", "execution", "source_sha256", "trace"}:
        raise EvidenceError("automatic-arena C probe identity drifted")
    if c_probe["elf"] != EXPECTED_C_ELF or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode()):
        raise EvidenceError("automatic-arena C probe source/ELF drifted")
    build = validate_command_record(c_probe["build"], description="C build")
    validate_c_command(build["command"], schema_template())
    if Path(build["command"][0]).name != "musl-gcc":
        raise EvidenceError("automatic-arena C compiler identity drifted")
    expected_build = c_command(
        build["command"][0], Path(NORMALIZED_SOURCE),
        Path(NORMALIZED_TEMPORARY) / "automatic-arena-reservation.c",
        Path(NORMALIZED_TEMPORARY) / "automatic-arena-reservation-c",
        schema_template(),
    )
    if build["command"] != expected_build:
        raise EvidenceError("automatic-arena retained C build argv drifted")
    header = validate_command_record(c_probe["elf_header"], description="C ELF header")
    if (Path(header["command"][0]).name != "readelf"
            or header["command"] != [header["command"][0], "-h", f"{NORMALIZED_TEMPORARY}/automatic-arena-reservation-c"]):
        raise EvidenceError("automatic-arena retained C ELF argv drifted")
    try:
        elf = run.parse_elf_identity(header["stdout"], "x86_64")
    except run.HarnessError as error:
        raise EvidenceError("automatic-arena retained C ELF header is malformed") from error
    if elf != EXPECTED_C_ELF:
        raise EvidenceError("automatic-arena retained C ELF header drifted")
    execution = validate_command_record(c_probe["execution"], description="C execution")
    if execution["command"] != [f"{NORMALIZED_TEMPORARY}/automatic-arena-reservation-c"]:
        raise EvidenceError("automatic-arena retained C execution argv drifted")
    trace = parse_trace(execution["stdout"], description="retained pinned C automatic-arena trace")
    validate_trace(trace, description="retained pinned C automatic-arena trace")
    if not exact(c_probe["trace"], trace):
        raise EvidenceError("automatic-arena retained C trace drifted")
    if not isinstance(rust_probe, Mapping) or set(rust_probe) != {"execution", "passed_test_count", "source", "target_dir", "test_filter", "trace"}:
        raise EvidenceError("automatic-arena Rust probe identity drifted")
    rust_execution = validate_command_record(rust_probe["execution"], description="Rust execution")
    if Path(rust_execution["command"][0]).name != "cargo":
        raise EvidenceError("automatic-arena Rust cargo identity drifted")
    expected_rust = rust_command(rust_execution["command"][0], Path(NORMALIZED_TEMPORARY) / "rust-target")
    if rust_execution["command"] != expected_rust:
        raise EvidenceError("automatic-arena retained Rust argv drifted")
    if rust_probe["passed_test_count"] != 1 or rust_probe["test_filter"] != RUST_TEST_FILTER:
        raise EvidenceError("automatic-arena Rust selection drifted")
    if rust_probe["source"] != {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}:
        raise EvidenceError("automatic-arena Rust source identity drifted")
    if rust_probe["target_dir"] != {"isolated": True, "retained": False, "value": f"{NORMALIZED_TEMPORARY}/rust-target"}:
        raise EvidenceError("automatic-arena Rust target directory drifted")
    rust_combined = rust_execution["stdout"] + "\n" + rust_execution["stderr"]
    try:
        passed = run.parse_rust_test_count(rust_combined)
    except run.HarnessError as error:
        raise EvidenceError("automatic-arena retained Rust test summary is malformed") from error
    if passed != 1:
        raise EvidenceError("automatic-arena retained Rust test count drifted")
    rust_trace = parse_trace(rust_combined, description="retained Rust automatic-arena trace")
    validate_trace(rust_trace, description="retained Rust automatic-arena trace")
    if not exact(rust_probe["trace"], rust_trace):
        raise EvidenceError("automatic-arena retained Rust trace drifted")
    expected = compare(c_probe["trace"], rust_probe["trace"])
    if report["comparison"] != expected:
        raise EvidenceError("automatic-arena report comparison drifted")

def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    before = candidate_snapshot()
    try:
        provenance = run.require_native_x86_64()
        schema = load_schema()
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
        compiler, readelf, cargo = (run.require_tool(name) for name in ("musl-gcc", "readelf", "cargo"))
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    lock_before = sha256_file(LOCKFILE)
    with run.temporary_directory("crabc-mimalloc-x86_64-automatic-arena-") as directory:
        temporary = Path(directory)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c(compiler, readelf, source, temporary, schema)
        rust_probe = build_rust(cargo, temporary)
    if sha256_file(LOCKFILE) != lock_before:
        raise EvidenceError("Cargo.lock changed despite --locked automatic-arena evidence")
    report = {"format": 1, "kind": "mimalloc-x86_64-automatic-regular-arena-reservation-evidence", "profile": EXPECTED_PROFILE,
              "status": "passed", "target": EXPECTED_TARGET, "upstream": EXPECTED_UPSTREAM, "provenance": provenance,
              "candidate_source": {"before": before, "after": candidate_snapshot(), "unchanged_during_execution": True},
              "source_anchors": anchors, "c_probe": c_probe, "rust_probe": rust_probe, "comparison": compare(c_probe["trace"], rust_probe["trace"]), "scope": EXPECTED_SCOPE}
    validate_report(report)
    run.write_json(report_path, report)
    # The container runs this native fixture as root; retain a report the host
    # reviewer can read without mutating the source or rebuilding the oracle.
    report_path.chmod(0o644)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        result = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError, run.HarnessError) as error:
        print(f"allocator x86-64 automatic-arena reservation: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(f"allocator x86-64 automatic-arena reservation: PASS ({result['comparison']['compared_value_count']} values; report: {relative(arguments.report)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
