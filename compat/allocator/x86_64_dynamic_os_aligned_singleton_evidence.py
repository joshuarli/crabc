#!/usr/bin/env python3
"""Differentially prove one dynamic OS-aligned singleton owner-exit route.

The native pinned-C fixture creates exactly one 128 KiB-aligned singleton on
one worker heap, runs real ``mi_thread_done()``, joins that worker, and frees
the sole client from the consumer. It records only address-independent OS
page, PageMap, abandoned-list, ownership, and terminal-release facts.

This is narrow private Linux/x86-64 allocator-engine evidence. It is not a
public allocation API, public x86 crabc support, general thread teardown,
general remote-free routing, general abandonment/adoption, or AArch64
evidence.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_regular_small_evidence.py"
_spec = importlib.util.spec_from_file_location("regular_small_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-dynamic-os-aligned-singleton-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/dynamic-os-aligned-singleton.json"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
EXPECTED_PROFILE = "linux-x86_64-private-dynamic-os-aligned-singleton-owner-exit"
RUST_TEST_FILTER = (
    "dynamic_theap::tests::"
    "x86_64_dynamic_os_aligned_singleton_owner_exit_trace_matches_pinned_c"
)
TRACE_BEGIN = "CRABC_MI_DYNAMIC_OS_ALIGNED_SINGLETON_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DYNAMIC_OS_ALIGNED_SINGLETON_TRACE_END"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_os_abandoned_list_claimed": False,
    "general_remote_free_routing_claimed": False,
    "joined_consumer_free_only": True,
    "native_linux_x86_64_required": True,
    "one_dynamic_os_aligned_singleton_owner_exit_only": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_thread_done": True,
    "typed_rust_nonabandoning_fixture_only": True,
}
EXPECTED_SOURCE_ANCHORS = (
    ("src/alloc-aligned.c", 68, 100, "d7bdd0355ef0bbe827b9048b878566a90646c630e546801ba5eba3cabaa624fc"),
    ("src/alloc.c", 162, 187, "cbd14100a88de6861bb96b27efde4afa811eb5a6fddf0069ed41886416a37450"),
    ("src/os.c", 87, 97, "573591c153431ce34b2381b48b4388ffe98ff06082cadec452fb0698729b043f"),
    ("src/page.c", 920, 975, "263038a7dce36ce19a239467bcbbb8d974a23b723885a8943dbe81a0e2403084"),
    ("src/page.c", 1048, 1081, "eb9512a9dddcac45a0585fd989606f646cc594cc42ca9dfb307b0660a4e0d76b"),
    ("src/page-queue.c", 174, 200, "620ddab1ece9dbb396966bb80a84826e50efe276c0c111aa2d0ea961b3a82130"),
    ("src/page-queue.c", 344, 414, "ddebf8b0d20f18703ca17ee9010df377aa2a22772e6af63464a77c9fe1fa1cfd"),
    ("src/init.c", 377, 415, "05b7b59c218b4ac3e8987b31a7abd5f5c70aec2dca30561b7d42c227db445bc3"),
    ("src/theap.c", 24, 50, "2bfe38192f762cc9a923535fb821e2d43bf7d4fe53c5a59681e0de44876a4e12"),
    ("src/theap.c", 97, 152, "3aee766b8d6a6c8cd29b483a850d11a754c2afc2d6201b1fad06fc34dc715a69"),
    ("src/page.c", 291, 303, "d363079d5e484919082b5602cc3757a3e3a357e68594fc040d902232c7458bbf"),
    ("src/arena.c", 629, 652, "76a5f1f293124c314bf9b3d68e171ecf34c24eadd2c55689d16705e647bd9f8b"),
    ("src/arena.c", 1285, 1355, "a3bd1d34816a130934288a39ffe78bd54fcd2cb1d536ddfee4166e75282f77b4"),
    ("src/arena.c", 1383, 1424, "32711ba3ccb566d0aedf7132cd712fd3adb7e98a91fcbd90d60bd7f91383180b"),
    ("src/free.c", 365, 515, "4f31b0716f4b8086797a84d1bfc6ca21531d1316ca37bbea18e218937fc941c1"),
    ("src/page-map.c", 468, 510, "d0ad150ae8a42e3954052d0ee707b960901cf180417c20f54f3c3bd052b23ca5"),
    ("include/mimalloc/internal.h", 939, 943, "8664954e79850c3e732e05e19f061edad9bcbf17b5ca2c91f8b8c86500160543"),
)
EXPECTED_TRACE_VALUES = {
    "trace.dynamic_os_aligned_singleton.request_size": 7,
    "trace.dynamic_os_aligned_singleton.alignment": 131072,
    "trace.dynamic_os_aligned_singleton.os_memory_kind": 1,
    "trace.dynamic_os_aligned_singleton.singleton": 1,
    "trace.dynamic_os_aligned_singleton.reserved": 1,
    "trace.dynamic_os_aligned_singleton.used": 1,
    "trace.dynamic_os_aligned_singleton.full_singleton_before_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.huge_singleton_before_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.full_transition_eligible_before_owner_exit": 0,
    "trace.dynamic_os_aligned_singleton.huge_queue_singleton_before_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.full_queue_empty_before_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.aligned": 1,
    "trace.dynamic_os_aligned_singleton.page_map_published_before_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.owner_exit_transition_completed": 1,
    "trace.dynamic_os_aligned_singleton.os_abandoned_list_member_after_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.source_owner_unowned_after_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.page_map_published_after_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.terminal_free_after_owner_exit": 1,
    "trace.dynamic_os_aligned_singleton.os_abandoned_list_clear_after_final_free": 1,
    "trace.dynamic_os_aligned_singleton.page_map_clear_after_final_free": 1,
    "trace.dynamic_os_aligned_singleton.valid": 1,
}


C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private dynamic OS-aligned singleton fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0 || MI_PADDING != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif

typedef struct fixture_s {
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  mi_heap_t* heap;
  void* block;
  bool setup_valid;
  bool worker_ready;
  bool allow_thread_done;
  bool owner_done;
  bool full_singleton_before_owner_exit;
  bool huge_singleton_before_owner_exit;
  bool full_transition_eligible_before_owner_exit;
  bool huge_queue_singleton_before_owner_exit;
  bool full_queue_empty_before_owner_exit;
  int worker_failure_stage;
} fixture_t;

static void fixture_signal_ready(fixture_t* fixture, bool setup_valid) {
  if (pthread_mutex_lock(&fixture->mutex) != 0) return;
  fixture->setup_valid = setup_valid;
  fixture->worker_ready = true;
  (void)pthread_cond_broadcast(&fixture->condition);
  (void)pthread_mutex_unlock(&fixture->mutex);
}

static bool os_abandoned_list_is_exact_singleton(mi_heap_t* heap, mi_page_t* page) {
  bool matches = false;
  // The pinned source protects this list and its page links with this exact
  // lock. The worker is joined before this observation, but retain the source
  // synchronization boundary in the probe rather than relying on quiescence.
  mi_lock(&heap->os_abandoned_pages_lock) {
    matches = heap->os_abandoned_pages == page && page->prev == NULL && page->next == NULL;
  }
  return matches;
}

static bool os_abandoned_list_is_empty(mi_heap_t* heap) {
  bool empty = false;
  mi_lock(&heap->os_abandoned_pages_lock) {
    empty = heap->os_abandoned_pages == NULL;
  }
  return empty;
}

static void* owner_main(void* argument) {
  fixture_t* const fixture = (fixture_t*)argument;
  mi_heap_t* heap = NULL;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  int failure_stage = 0;

  mi_thread_init();
  heap = mi_heap_new();
  if (heap == NULL) { failure_stage = 1; goto failed; }
  theap = _mi_heap_theap(heap);
  if (theap == NULL) { failure_stage = 2; goto failed; }
  fixture->block = mi_heap_malloc_aligned(heap, 7, 128 * 1024);
  if (fixture->block == NULL) { failure_stage = 3; goto failed; }
  page = _mi_ptr_page(fixture->block);
  if (page == NULL) { failure_stage = 4; goto failed; }

  mi_page_queue_t* const full = &theap->pages[MI_BIN_FULL];
  mi_page_queue_t* const huge = &theap->pages[MI_BIN_HUGE];
  fixture->full_singleton_before_owner_exit =
      mi_page_is_singleton(page) && page->reserved == 1 && page->used == 1
      && mi_page_is_full(page);
  fixture->huge_singleton_before_owner_exit = mi_page_is_huge(page);
  fixture->full_transition_eligible_before_owner_exit =
      page->block_size > MI_SMALL_MAX_OBJ_SIZE;
  fixture->huge_queue_singleton_before_owner_exit =
      mi_page_is_huge(page) && !mi_page_is_in_full(page)
      && huge->first == page && huge->last == page && huge->count == 1;
  fixture->full_queue_empty_before_owner_exit =
      !mi_page_is_in_full(page) && full->first == NULL && full->last == NULL
      && full->count == 0;
  if (!mi_page_is_singleton(page)) { failure_stage = 5; goto failed; }
  if (page->reserved != 1) { failure_stage = 6; goto failed; }
  if (page->used != 1) { failure_stage = 7; goto failed; }
  if (!mi_page_is_full(page)) { failure_stage = 8; goto failed; }
  if (!fixture->huge_singleton_before_owner_exit) { failure_stage = 9; goto failed; }
  if (fixture->full_transition_eligible_before_owner_exit) { failure_stage = 10; goto failed; }
  if (!fixture->huge_queue_singleton_before_owner_exit) { failure_stage = 11; goto failed; }
  if (!fixture->full_queue_empty_before_owner_exit) { failure_stage = 12; goto failed; }

  fixture->heap = heap;
  fixture_signal_ready(fixture, true);
  if (pthread_mutex_lock(&fixture->mutex) != 0) return NULL;
  while (!fixture->allow_thread_done) {
    if (pthread_cond_wait(&fixture->condition, &fixture->mutex) != 0) {
      (void)pthread_mutex_unlock(&fixture->mutex);
      return NULL;
    }
  }
  (void)pthread_mutex_unlock(&fixture->mutex);

  mi_thread_done();
  if (pthread_mutex_lock(&fixture->mutex) != 0) return NULL;
  fixture->owner_done = true;
  (void)pthread_cond_broadcast(&fixture->condition);
  (void)pthread_mutex_unlock(&fixture->mutex);
  return NULL;

failed:
  if (fixture->block != NULL) {
    mi_free(fixture->block);
    fixture->block = NULL;
  }
  if (heap != NULL) mi_heap_destroy(heap);
  fixture->worker_failure_stage = failure_stage;
  fixture_signal_ready(fixture, false);
  return NULL;
}

int main(void) {
  fixture_t fixture = {
      .mutex = PTHREAD_MUTEX_INITIALIZER,
      .condition = PTHREAD_COND_INITIALIZER,
  };
  pthread_t owner;
  bool owner_started = false;
  bool owner_joined = false;
  mi_page_t* page = NULL;
  uintptr_t saved_block_address = 0;
  size_t reserved = 0;
  size_t used = 0;
  const size_t request_size = 7;
  const size_t alignment = 128 * 1024;
  bool valid = false;
  int stage = 0;
  int os_memory_kind = 0;
  int singleton = 0;
  int full_singleton_before_owner_exit = 0;
  int huge_singleton_before_owner_exit = 0;
  int full_transition_eligible_before_owner_exit = 0;
  int huge_queue_singleton_before_owner_exit = 0;
  int full_queue_empty_before_owner_exit = 0;
  int aligned = 0;
  int page_map_published_before_owner_exit = 0;
  int owner_exit_transition_completed = 0;
  int os_abandoned_list_member_after_owner_exit = 0;
  int source_owner_unowned_after_owner_exit = 0;
  int page_map_published_after_owner_exit = 0;
  int terminal_free_after_owner_exit = 0;
  int os_abandoned_list_clear_after_final_free = 0;
  int page_map_clear_after_final_free = 0;

  mi_thread_init();
  if (pthread_create(&owner, NULL, owner_main, &fixture) != 0) { stage = 1; goto output; }
  owner_started = true;
  if (pthread_mutex_lock(&fixture.mutex) != 0) { stage = 2; goto output; }
  while (!fixture.worker_ready) {
    if (pthread_cond_wait(&fixture.condition, &fixture.mutex) != 0) {
      (void)pthread_mutex_unlock(&fixture.mutex);
      stage = 3; goto output;
    }
  }
  const bool setup_valid = fixture.setup_valid;
  const int worker_failure_stage = fixture.worker_failure_stage;
  (void)pthread_mutex_unlock(&fixture.mutex);
  if (!setup_valid || fixture.heap == NULL || fixture.block == NULL) {
    stage = 100 + worker_failure_stage; goto output;
  }

  page = _mi_safe_ptr_page(fixture.block);
  if (page == NULL) { stage = 4; goto output; }
  saved_block_address = (uintptr_t)fixture.block;
  reserved = page->reserved;
  used = page->used;
  os_memory_kind = (page->memid.memkind == MI_MEM_OS);
  singleton = mi_page_is_singleton(page);
  full_singleton_before_owner_exit = fixture.full_singleton_before_owner_exit;
  huge_singleton_before_owner_exit = fixture.huge_singleton_before_owner_exit;
  full_transition_eligible_before_owner_exit = fixture.full_transition_eligible_before_owner_exit;
  huge_queue_singleton_before_owner_exit = fixture.huge_queue_singleton_before_owner_exit;
  full_queue_empty_before_owner_exit = fixture.full_queue_empty_before_owner_exit;
  aligned = (((uintptr_t)fixture.block & (alignment - 1)) == 0);
  page_map_published_before_owner_exit = (_mi_safe_ptr_page(fixture.block) == page);
  if (!os_memory_kind || !singleton || reserved != 1 || used != 1
      || !full_singleton_before_owner_exit || !huge_singleton_before_owner_exit
      || full_transition_eligible_before_owner_exit
      || !huge_queue_singleton_before_owner_exit || !full_queue_empty_before_owner_exit
      || !aligned || !page_map_published_before_owner_exit) {
    stage = 5; goto output;
  }

  if (pthread_mutex_lock(&fixture.mutex) != 0) { stage = 6; goto output; }
  fixture.allow_thread_done = true;
  (void)pthread_cond_broadcast(&fixture.condition);
  (void)pthread_mutex_unlock(&fixture.mutex);
  if (pthread_join(owner, NULL) != 0) { stage = 7; goto output; }
  owner_started = false;
  owner_joined = true;
  owner_exit_transition_completed = fixture.owner_done;
  if (!owner_exit_transition_completed) { stage = 8; goto output; }

  page = _mi_safe_ptr_page((const void*)saved_block_address);
  if (page == NULL) { stage = 9; goto output; }
  os_abandoned_list_member_after_owner_exit =
      os_abandoned_list_is_exact_singleton(fixture.heap, page);
  source_owner_unowned_after_owner_exit =
      mi_page_is_abandoned(page) && mi_page_thread_id(page) == MI_THREADID_ABANDONED
      && !mi_page_is_owned(page);
  page_map_published_after_owner_exit =
      _mi_safe_ptr_page((const void*)saved_block_address) == page;
  if (!os_abandoned_list_member_after_owner_exit || !source_owner_unowned_after_owner_exit
      || !page_map_published_after_owner_exit) { stage = 10; goto output; }

  mi_free((void*)saved_block_address);
  fixture.block = NULL;
  os_abandoned_list_clear_after_final_free = os_abandoned_list_is_empty(fixture.heap);
  page_map_clear_after_final_free =
      _mi_safe_ptr_page((const void*)saved_block_address) == NULL;
  terminal_free_after_owner_exit = os_abandoned_list_clear_after_final_free
      && page_map_clear_after_final_free;
  valid = request_size == 7 && alignment == 128 * 1024 && os_memory_kind && singleton
      && reserved == 1 && used == 1 && full_singleton_before_owner_exit
      && huge_singleton_before_owner_exit && !full_transition_eligible_before_owner_exit
      && huge_queue_singleton_before_owner_exit && full_queue_empty_before_owner_exit && aligned
      && page_map_published_before_owner_exit && owner_exit_transition_completed
      && owner_joined && os_abandoned_list_member_after_owner_exit
      && source_owner_unowned_after_owner_exit && page_map_published_after_owner_exit
      && terminal_free_after_owner_exit && os_abandoned_list_clear_after_final_free
      && page_map_clear_after_final_free;

output:
  printf("CRABC_MI_DYNAMIC_OS_ALIGNED_SINGLETON_TRACE_BEGIN\n");
#define OUT_N(k,v) printf("trace.dynamic_os_aligned_singleton.%s=%zu\n", k, (size_t)(v))
#define OUT_B(k,v) printf("trace.dynamic_os_aligned_singleton.%s=%d\n", k, (v) ? 1 : 0)
  OUT_N("request_size", request_size);
  OUT_N("alignment", alignment);
  OUT_B("os_memory_kind", os_memory_kind);
  OUT_B("singleton", singleton);
  OUT_N("reserved", reserved);
  OUT_N("used", used);
  OUT_B("full_singleton_before_owner_exit", full_singleton_before_owner_exit);
  OUT_B("huge_singleton_before_owner_exit", huge_singleton_before_owner_exit);
  OUT_B("full_transition_eligible_before_owner_exit", full_transition_eligible_before_owner_exit);
  OUT_B("huge_queue_singleton_before_owner_exit", huge_queue_singleton_before_owner_exit);
  OUT_B("full_queue_empty_before_owner_exit", full_queue_empty_before_owner_exit);
  OUT_B("aligned", aligned);
  OUT_B("page_map_published_before_owner_exit", page_map_published_before_owner_exit);
  OUT_B("owner_exit_transition_completed", owner_exit_transition_completed);
  OUT_B("os_abandoned_list_member_after_owner_exit", os_abandoned_list_member_after_owner_exit);
  OUT_B("source_owner_unowned_after_owner_exit", source_owner_unowned_after_owner_exit);
  OUT_B("page_map_published_after_owner_exit", page_map_published_after_owner_exit);
  OUT_B("terminal_free_after_owner_exit", terminal_free_after_owner_exit);
  OUT_B("os_abandoned_list_clear_after_final_free", os_abandoned_list_clear_after_final_free);
  OUT_B("page_map_clear_after_final_free", page_map_clear_after_final_free);
  OUT_B("valid", valid);
  printf("CRABC_MI_DYNAMIC_OS_ALIGNED_SINGLETON_TRACE_END\n");
  if (owner_started) {
    if (pthread_mutex_lock(&fixture.mutex) == 0) {
      fixture.allow_thread_done = true;
      (void)pthread_cond_broadcast(&fixture.condition);
      (void)pthread_mutex_unlock(&fixture.mutex);
    }
    (void)pthread_join(owner, NULL);
  }
  if (fixture.block != NULL) mi_free(fixture.block);
  if (fixture.heap != NULL) mi_heap_destroy(fixture.heap);
  if (!valid) fprintf(stderr, "dynamic OS-aligned singleton fixture stopped at stage %d\n", stage);
  return valid ? 0 : 2;
}
'''


DYNAMIC_OS_ALIGNED_SINGLETON_KIND = (
    "mimalloc-x86_64-dynamic-os-aligned-singleton-owner-exit-differential-evidence"
)
_BASE_SCHEMA_TEMPLATE = _base._schema_template


def _schema_template() -> dict:
    value = _BASE_SCHEMA_TEMPLATE()
    value["schema"] = "crabc-mimalloc-x86_64-dynamic-os-aligned-singleton-evidence"
    value["profile"] = EXPECTED_PROFILE
    value["harness_dependency"] = {
        "path": relative(BASE_PATH),
        "sha256": sha256_file(BASE_PATH),
    }
    value["scope"] = dict(EXPECTED_SCOPE)
    value["source_anchors"] = [
        {"member": member, "start_line": start, "end_line": end, "sha256": digest}
        for member, start, end, digest in EXPECTED_SOURCE_ANCHORS
    ]
    value["c_probe_sha256"] = sha256_bytes(C_TRACE_PROBE.encode("utf-8"))
    value["rust_test"] = {
        "path": "crabc-mimalloc/src/dynamic_theap.rs",
        "target_arch": "x86_64",
        "test_filter": RUST_TEST_FILTER,
    }
    value["trace"] = {
        "begin": TRACE_BEGIN,
        "end": TRACE_END,
        "expected_values": dict(EXPECTED_TRACE_VALUES),
    }
    return value


def c_trace_command(
    compiler: str, source: Path, probe_source: Path, probe_binary: Path, schema: dict
) -> list[str]:
    return [
        compiler,
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        *schema["compile_definitions"],
        "-I",
        str(source / "include"),
        "-I",
        str(source / "src"),
        *schema["release_flags"],
        str(probe_source),
        *(str(source / member) for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        str(probe_binary),
    ]


def validate_c_command(command: list[str], schema: dict) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in _base.run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(EXPECTED_COMPILE_DEFINITIONS) or definitions != list(
        schema["compile_definitions"]
    ):
        raise EvidenceError("dynamic OS-aligned singleton C command compile definitions drifted")
    if (
        flags != list(schema["release_flags"])
        or "-pthread" not in command
        or "-ftls-model=initial-exec" not in command
    ):
        raise EvidenceError("dynamic OS-aligned singleton C command release pthread/TLS selection drifted")


def validate_normalized_c_command(command: object, schema: dict) -> None:
    expected = [
        "-std=c11",
        "-fPIC",
        "-ftls-model=initial-exec",
        *schema["compile_definitions"],
        "-I",
        f"{NORMALIZED_PINNED_SOURCE}/include",
        "-I",
        f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"],
        f"{NORMALIZED_EVIDENCE_ROOT}/dynamic-os-aligned-singleton.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread",
        "-o",
        f"{NORMALIZED_EVIDENCE_ROOT}/dynamic-os-aligned-singleton-c",
    ]
    if (
        not isinstance(command, list)
        or not command
        or Path(command[0]).name != "musl-gcc"
        or command[1:] != expected
    ):
        raise EvidenceError("dynamic OS-aligned singleton report C command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: dict
) -> dict:
    probe_source = temporary / "dynamic-os-aligned-singleton.c"
    probe_binary = temporary / "dynamic-os-aligned-singleton-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        _base.run.require_success(
            _base.run.command_record(command, cwd=source),
            "pinned C dynamic OS-aligned singleton fixture build",
        )
        header = _base.run.command_record((readelf, "-h", str(probe_binary)), cwd=source)
        _base.run.require_success(header, "pinned C dynamic OS-aligned singleton fixture ELF identity")
        elf = _base.run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = _base.run.command_record((str(probe_binary),), cwd=source)
        _base.run.require_success(execution, "pinned C dynamic OS-aligned singleton fixture execution")
    except _base.run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C dynamic OS-aligned singleton trace")
    validate_trace(trace, description="pinned C dynamic OS-aligned singleton trace")
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/dynamic-os-aligned-singleton-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def report_from_results(*, schema, provenance, archive_sha256, anchors, c_probe, rust_probe):
    c_trace = c_probe.get("trace")
    rust_trace = rust_probe.get("trace")
    if not isinstance(c_trace, dict) or not isinstance(rust_trace, dict):
        raise EvidenceError("dynamic OS-aligned singleton report inputs lack trace records")
    report = {
        "c_probe": dict(c_probe),
        "comparison": compare_traces(c_trace, rust_trace),
        "format": 1,
        "kind": DYNAMIC_OS_ALIGNED_SINGLETON_KIND,
        "profile": schema["profile"],
        "provenance": dict(provenance),
        "rust_probe": dict(rust_probe),
        "scope": schema["scope"],
        "source": {
            "archive_sha256": archive_sha256,
            "anchors": [dict(anchor) for anchor in anchors],
            "release_flags": list(schema["release_flags"]),
            "release_source_set": list(schema["release_source_set"]),
        },
        "status": "passed",
        "target": schema["target"],
        "trace": schema["trace"],
        "upstream": schema["upstream"],
    }
    validate_report(report)
    return report


def validate_report(report: dict) -> None:
    required = {
        "c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe",
        "scope", "source", "status", "target", "trace", "upstream",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("dynamic OS-aligned singleton report schema drifted")
    if report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("dynamic OS-aligned singleton report format/status drifted")
    if report["kind"] != DYNAMIC_OS_ALIGNED_SINGLETON_KIND:
        raise EvidenceError("dynamic OS-aligned singleton report kind drifted")
    if not _base.exactly_matches(report["target"], EXPECTED_TARGET) or not _base.exactly_matches(
        report["upstream"], EXPECTED_UPSTREAM
    ):
        raise EvidenceError("dynamic OS-aligned singleton report target/upstream drifted")
    if report["profile"] != EXPECTED_PROFILE or not _base.exactly_matches(
        report["scope"], EXPECTED_SCOPE
    ):
        raise EvidenceError("dynamic OS-aligned singleton report private boundary drifted")
    if not any(
        _base.exactly_matches(report["provenance"], candidate)
        for candidate in (
            {"execution_mode": "native", "host_architecture": "x86_64"},
            {"execution_mode": "native", "host_architecture": "amd64"},
        )
    ):
        raise EvidenceError("dynamic OS-aligned singleton report lacks native x86-64 provenance")
    schema = load_schema()
    if not _base.exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("dynamic OS-aligned singleton report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {
        "archive_sha256", "anchors", "release_flags", "release_source_set"
    }:
        raise EvidenceError("dynamic OS-aligned singleton report source record is malformed")
    if source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise EvidenceError("dynamic OS-aligned singleton report archive identity drifted")
    if not _base.exactly_matches(source["anchors"], schema["source_anchors"]):
        raise EvidenceError("dynamic OS-aligned singleton report source anchors drifted")
    if not _base.exactly_matches(source["release_flags"], schema["release_flags"]):
        raise EvidenceError("dynamic OS-aligned singleton report release flags drifted")
    if not _base.exactly_matches(source["release_source_set"], schema["release_source_set"]):
        raise EvidenceError("dynamic OS-aligned singleton report source set drifted")
    c_probe = report["c_probe"]
    rust_probe = report["rust_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {
        "build_command", "elf", "run_command", "source_sha256", "trace"
    }:
        raise EvidenceError("dynamic OS-aligned singleton report C probe record drifted")
    if not isinstance(rust_probe, dict) or set(rust_probe) != {
        "cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"
    }:
        raise EvidenceError("dynamic OS-aligned singleton report Rust probe record drifted")
    if not _base.exactly_matches(c_probe["elf"], EXPECTED_C_ELF):
        raise EvidenceError("dynamic OS-aligned singleton report C ELF identity drifted")
    if c_probe["run_command"] != [
        f"{NORMALIZED_EVIDENCE_ROOT}/dynamic-os-aligned-singleton-c"
    ]:
        raise EvidenceError("dynamic OS-aligned singleton report C run command drifted")
    if c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("dynamic OS-aligned singleton report C source hash drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    if type(rust_probe["passed_test_count"]) is not int or rust_probe["passed_test_count"] != 1:
        raise EvidenceError("dynamic OS-aligned singleton report Rust test selection drifted")
    if not _base.exactly_matches(
        rust_probe["target_dir"],
        {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"},
    ):
        raise EvidenceError("dynamic OS-aligned singleton report Rust target directory drifted")
    validate_normalized_rust_command(rust_probe["cargo_command"])
    if not _base.exactly_matches(
        rust_probe["lockfile"], {"path": relative(LOCKFILE), "sha256": sha256_file(LOCKFILE)}
    ):
        raise EvidenceError("dynamic OS-aligned singleton report Rust lockfile identity drifted")
    if not _base.exactly_matches(
        rust_probe["source"], {"path": relative(RUST_TEST_SOURCE), "sha256": sha256_file(RUST_TEST_SOURCE)}
    ):
        raise EvidenceError("dynamic OS-aligned singleton report Rust source identity drifted")
    if not isinstance(c_probe["trace"], dict) or not isinstance(rust_probe["trace"], dict):
        raise EvidenceError("dynamic OS-aligned singleton report lacks C/Rust traces")
    if not _base.exactly_matches(
        report["comparison"], compare_traces(c_probe["trace"], rust_probe["trace"])
    ):
        raise EvidenceError("dynamic OS-aligned singleton report comparison drifted")


for _name in (
    "SCHEMA_PATH",
    "REPORT_DEFAULT",
    "EXPECTED_PROFILE",
    "RUST_TEST_FILTER",
    "TRACE_BEGIN",
    "TRACE_END",
    "EXPECTED_SCOPE",
    "EXPECTED_SOURCE_ANCHORS",
    "EXPECTED_TRACE_VALUES",
    "C_TRACE_PROBE",
    "RUST_TEST_SOURCE",
):
    setattr(_base, _name, globals()[_name])

_base._schema_template = _schema_template
_base.c_trace_command = c_trace_command
_base.validate_c_command = validate_c_command
_base.validate_normalized_c_command = validate_normalized_c_command
_base.build_c_trace = build_c_trace
_base.report_from_results = report_from_results
_base.validate_report = validate_report

for _name in (
    "EvidenceError",
    "sha256_bytes",
    "sha256_file",
    "relative",
    "load_schema",
    "validate_source_anchors",
    "parse_trace",
    "validate_trace",
    "compare_traces",
    "normalize_command",
    "c_trace_command",
    "validate_c_command",
    "validate_normalized_c_command",
    "rust_trace_command",
    "validate_normalized_rust_command",
    "run_evidence",
    "EXPECTED_TARGET",
    "EXPECTED_UPSTREAM",
    "EXPECTED_ARCHIVE_SHA256",
    "EXPECTED_COMPILE_DEFINITIONS",
    "EXPECTED_C_ELF",
    "LOCKFILE",
    "RUST_TEST_SOURCE",
    "TARGET",
    "NORMALIZED_EVIDENCE_ROOT",
    "NORMALIZED_PINNED_SOURCE",
):
    globals()[_name] = getattr(_base, _name)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, ValueError) as error:
        print(
            f"allocator x86-64 dynamic OS-aligned singleton differential: FAIL: {error}",
            file=os.sys.stderr,
        )
        return 1
    print(
        "allocator x86-64 dynamic OS-aligned singleton differential: PASS "
        f"({report['comparison']['compared_value_count']} logical values; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
