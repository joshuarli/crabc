#!/usr/bin/env python3
"""Prove the bounded native C detached arena-singleton post-exit route.

The pinned v3.5.0 C fixture allocates exactly one 524289-byte arena-backed
full singleton on a real worker pthread, calls ``mi_thread_done()``, joins the
worker, and performs exactly one terminal consumer ``mi_free``.  The report is
private x86-64 allocator evidence; it makes no public runtime or AArch64
claim, and it does not pretend that the Rust lifecycle test is a C ABI test.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / "compat/allocator/x86_64_dynamic_full_singleton_homogeneous_aggregate_evidence.py"
_spec = importlib.util.spec_from_file_location("dynamic_singleton_base", BASE_PATH)
assert _spec is not None and _spec.loader is not None
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
RUNNER = _base.RUNNER

SCHEMA_PATH = ROOT / "compat/allocator/x86_64-dynamic-arena-singleton-post-exit-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/dynamic-arena-singleton-post-exit.json"
RUST_TEST_SOURCE = ROOT / "crabc-mimalloc/src/dynamic_theap.rs"
LOCKFILE = ROOT / "Cargo.lock"
TARGET = "x86_64-unknown-linux-musl"
RUST_TEST_FILTER = "dynamic_theap::tests::x86_64_dynamic_arena_singleton_post_exit_trace_matches_pinned_c"
TRACE_BEGIN = "CRABC_MI_DYNAMIC_ARENA_SINGLETON_POST_EXIT_TRACE_BEGIN"
TRACE_END = "CRABC_MI_DYNAMIC_ARENA_SINGLETON_POST_EXIT_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"
STEM = "dynamic-arena-singleton-post-exit"

EXPECTED_TARGET = {"architecture": "x86_64", "endianness": "little", "rust_target": TARGET, "system": "linux"}
EXPECTED_UPSTREAM = {"archive_root": "mimalloc-3.5.0", "revision": "18b08671c9302247bfb682286e6bf3cc1773f801", "version": "3.5.0"}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_PROFILE = "linux-x86_64-private-dynamic-arena-singleton-post-exit"
EXPECTED_COMPILE_DEFINITIONS = ("-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1")
EXPECTED_C_ELF = {"class": "ELF64", "endianness": "little", "machine": "Advanced Micro Devices X86-64"}
EXPECTED_TLS = {"compiler_model": "initial-exec", "mimalloc_model": "MI_TLS_MODEL_LOCAL", "thread_pointer_path": "x86_64-fs-tls-slot-fallback"}
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "c_oracle_one_full_arena_singleton_only": True,
    "c_oracle_real_thread_done_join_and_terminal_consumer_free": True,
    "c_rust_common_facts_only": True,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_remote_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_mi_free_trigger": True,
    "rust_scoped_thread_and_join_observed": True,
}

# These are the pinned source regions used by the sibling full-singleton
# oracle. Keeping the source contract identical makes this probe a smaller
# shape of the already reviewed v3.5.0 release path.
EXPECTED_SOURCE_ANCHORS = _base.EXPECTED_SOURCE_ANCHORS

PREFIX = "trace.dynamic_arena_singleton_post_exit."
EXPECTED_TRACE_VALUES = {
    PREFIX + "request_size": 524289,
    PREFIX + "block_size": 589824,
    PREFIX + "capacity": 1,
    PREFIX + "reserved": 1,
    PREFIX + "slice_count": 9,
    PREFIX + "page_map_slice_count_before_free": 9,
    PREFIX + "source_thread_teardown_completed": 1,
    PREFIX + "source_thread_joined_before_free": 1,
    PREFIX + "source_unmapped_after_thread_done": 1,
    PREFIX + "source_unowned_after_thread_done": 1,
    PREFIX + "source_queue_detached_after_thread_done": 1,
    PREFIX + "source_used_after_thread_done": 1,
    PREFIX + "page_map_registered_before_free": 1,
    PREFIX + "page_map_all_slices_registered_before_free": 1,
    PREFIX + "arena_page_bitmap_set_before_free": 1,
    PREFIX + "terminal_free_completed": 1,
    PREFIX + "page_map_clear_after_terminal_free": 1,
    PREFIX + "arena_page_bitmap_clear_after_terminal_free": 1,
    PREFIX + "arena_slice_released_after_terminal_free": 1,
    PREFIX + "terminal_cleanup": 1,
    PREFIX + "valid": 1,
}


C_TRACE_PROBE = r'''
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#if !defined(__linux__) || !defined(__x86_64__)
#error this private fixture requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0 || MI_PADDING != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif
#if !defined(MI_TLS_MODEL_LOCAL) || MI_TLS_MODEL_LOCAL != 1 || defined(MI_TLS_MODEL_PTHREADS) || defined(MI_TLS_MODEL_FIXED) || defined(MI_TLS_MODEL_WIN32)
#error this fixture requires pinned Linux local compiler TLS
#endif
#if defined(MI_USE_BUILTIN_THREAD_POINTER) || defined(MI_PRIM_THREAD_POINTER) || defined(MI_NO_THREAD_POINTER) || !defined(MI_HAS_TLS_SLOT) || MI_HAS_TLS_SLOT != 1 || MI_INTPTR_SIZE != 8
#error this fixture requires the pinned x86_64 FS TLS-slot fallback
#endif
typedef struct fixture_s { pthread_mutex_t mutex; pthread_cond_t condition; mi_arena_id_t arena_id; mi_arena_pages_t* arena_pages; mi_arena_t* arena; void* block; mi_page_t* page; bool ready; bool setup_valid; bool allow_thread_done; bool worker_done; bool full; bool direct_empty; } fixture_t;
static void signal_ready(fixture_t* f, bool valid) { if (pthread_mutex_lock(&f->mutex) != 0) return; f->setup_valid = valid; f->ready = true; (void)pthread_cond_broadcast(&f->condition); (void)pthread_mutex_unlock(&f->mutex); }
static size_t page_map_count(mi_page_t* page, uintptr_t* start_out) { size_t area_size = 0; uint8_t* area = mi_page_area(page, &area_size); uint8_t* start = mi_page_slice_start(page); if (area == NULL || start == NULL || area < start || area_size > MI_LARGE_PAGE_SIZE) return 0; *start_out = (uintptr_t)start; return mi_slice_count_of_size(area_size) + (size_t)((area - start) / MI_ARENA_SLICE_SIZE); }
static bool map_span_is(uintptr_t start, size_t count, bool mapped) { for (size_t i = 0; i < count; i++) if ((_mi_safe_ptr_page((const void*)(start + i * MI_ARENA_SLICE_SIZE)) != NULL) != mapped) return false; return true; }
static bool map_span_is_page(const mi_page_t* page, uintptr_t start, size_t count) { if (page == NULL) return false; for (size_t i = 0; i < count; i++) if (_mi_safe_ptr_page((const void*)(start + i * MI_ARENA_SLICE_SIZE)) != page) return false; return true; }
static bool detached_unowned(mi_page_t* p) { return p != NULL && p->next == NULL && p->prev == NULL && !mi_page_is_in_full(p) && !mi_page_is_owned(p); }
static bool direct_cache_empty(const mi_theap_t* t) { if (t == NULL) return false; for (size_t i = 0; i < MI_PAGES_DIRECT; i++) if (t->pages_free_direct[i] != _mi_page_empty_get()) return false; return true; }
static void* worker_main(void* arg) {
  fixture_t* f = (fixture_t*)arg; const size_t request = MI_LARGE_MAX_OBJ_SIZE + 1; mi_heap_t* heap = mi_heap_new_in_arena(f->arena_id); if (heap == NULL) { signal_ready(f, false); return NULL; }
  f->block = mi_heap_malloc(heap, request); if (f->block == NULL) { signal_ready(f, false); return NULL; }
  f->page = _mi_ptr_page(f->block); mi_theap_t* t = _mi_heap_theap(heap); mi_arena_t* arena = f->page == NULL ? NULL : mi_memid_arena(f->page->memid); mi_arena_pages_t* ap = arena == NULL ? NULL : mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]); f->arena = arena; f->arena_pages = ap; f->full = f->page != NULL && mi_page_is_full(f->page); f->direct_empty = direct_cache_empty(t); f->setup_valid = f->page != NULL && arena != NULL && ap != NULL && f->full && mi_page_is_singleton(f->page) && f->page->block_size == 589824 && f->page->capacity == 1 && f->page->reserved == 1 && f->page->used == 1 && f->page->memid.memkind == MI_MEM_ARENA && f->direct_empty && mi_page_thread_free(f->page) == NULL;
  signal_ready(f, f->setup_valid); if (!f->setup_valid) return NULL;
  if (pthread_mutex_lock(&f->mutex) != 0) return NULL; while (!f->allow_thread_done) if (pthread_cond_wait(&f->condition, &f->mutex) != 0) { (void)pthread_mutex_unlock(&f->mutex); return NULL; } (void)pthread_mutex_unlock(&f->mutex);
  mi_thread_done(); if (pthread_mutex_lock(&f->mutex) == 0) { f->worker_done = true; (void)pthread_cond_broadcast(&f->condition); (void)pthread_mutex_unlock(&f->mutex); } return NULL;
}
int main(void) {
  fixture_t f = { .mutex = PTHREAD_MUTEX_INITIALIZER, .condition = PTHREAD_COND_INITIALIZER, .arena_id = _mi_arena_id_none() }; pthread_t worker; bool started = false, valid = false; uintptr_t start = 0; size_t slice_index = 0, map_count = 0; int arena_backed = 0, large_singleton = 0, thread_done = 0, joined = 0, unmapped = 0, unowned = 0, abandoned = 0, map_registered = 0, arena_set = 0, detached = 0, map_clear = 0, arena_clear = 0, slices_free = 0; size_t block_size = 0, capacity = 0, reserved = 0, slice_count = 0, used_exit = 0; const size_t request = MI_LARGE_MAX_OBJ_SIZE + 1;
  mi_thread_init(); mi_option_set(mi_option_page_reclaim_on_free, 0); mi_option_set(mi_option_page_full_retain, -1); if (mi_reserve_os_memory_ex(mi_arena_min_size(), true, false, true, &f.arena_id) != 0) goto output; if (pthread_create(&worker, NULL, worker_main, &f) != 0) goto output; started = true; if (pthread_mutex_lock(&f.mutex) != 0) goto output; while (!f.ready) if (pthread_cond_wait(&f.condition, &f.mutex) != 0) { (void)pthread_mutex_unlock(&f.mutex); goto output; } (void)pthread_mutex_unlock(&f.mutex); if (!f.setup_valid || f.page == NULL || f.arena == NULL || f.arena_pages == NULL) goto output;
  arena_backed = f.page->memid.memkind == MI_MEM_ARENA; large_singleton = f.page->block_size > MI_MEDIUM_MAX_OBJ_SIZE && mi_page_is_singleton(f.page); block_size = f.page->block_size; capacity = f.page->capacity; reserved = f.page->reserved; slice_count = f.page->memid.mem.arena.slice_count; if (!arena_backed || !large_singleton || block_size != 589824 || capacity != 1 || reserved != 1 || slice_count != 9 || !f.full || !f.direct_empty) goto output;
  if (pthread_mutex_lock(&f.mutex) != 0) goto output; f.allow_thread_done = true; (void)pthread_cond_broadcast(&f.condition); (void)pthread_mutex_unlock(&f.mutex); if (pthread_join(worker, NULL) != 0) goto output; started = false; joined = 1; thread_done = f.worker_done;
  mi_page_t* page = _mi_safe_ptr_page(f.block); if (page == NULL) goto output; mi_arena_pages_t* ap = f.arena_pages; mi_arena_t* arena = f.arena; slice_index = page->memid.mem.arena.slice_index; used_exit = page->used; map_count = page_map_count(page, &start); map_registered = map_count == 9 && map_span_is_page(page, start, 9); unmapped = !mi_page_is_abandoned_mapped(page); unowned = !mi_page_is_owned(page); abandoned = mi_page_is_abandoned(page); arena_set = mi_bitmap_is_setN(ap->pages, slice_index, 1); detached = detached_unowned(page); if (!map_registered || !unmapped || !unowned || !abandoned || !arena_set || !detached || used_exit != 1) goto output;
  mi_free(f.block); f.block = NULL; map_clear = map_span_is(start, 9, false); arena_clear = mi_bitmap_is_clearN(ap->pages, slice_index, 1); slices_free = mi_bbitmap_is_setN(arena->slices_free, slice_index, 9); valid = arena_backed && large_singleton && thread_done && joined && map_registered && map_clear && arena_clear && slices_free;
output:
  printf("CRABC_MI_DYNAMIC_ARENA_SINGLETON_POST_EXIT_TRACE_BEGIN\n");
  #define B(k,v) printf("trace.dynamic_arena_singleton_post_exit.%s=%d\n", k, (v) ? 1 : 0)
  #define N(k,v) printf("trace.dynamic_arena_singleton_post_exit.%s=%zu\n", k, (size_t)(v))
  N("request_size",request); N("block_size",block_size); N("capacity",capacity); N("reserved",reserved); N("slice_count",slice_count); N("page_map_slice_count_before_free",map_count); B("source_thread_teardown_completed",thread_done); B("source_thread_joined_before_free",joined); B("source_unmapped_after_thread_done",unmapped); B("source_unowned_after_thread_done",unowned); B("source_queue_detached_after_thread_done",detached); N("source_used_after_thread_done",used_exit); B("page_map_registered_before_free",map_registered); B("page_map_all_slices_registered_before_free",map_registered && map_count == slice_count); B("arena_page_bitmap_set_before_free",arena_set); B("terminal_free_completed",map_clear && arena_clear && slices_free); B("page_map_clear_after_terminal_free",map_clear); B("arena_page_bitmap_clear_after_terminal_free",arena_clear); B("arena_slice_released_after_terminal_free",slices_free); B("terminal_cleanup",map_clear && arena_clear && slices_free); B("valid",valid); printf("CRABC_MI_DYNAMIC_ARENA_SINGLETON_POST_EXIT_TRACE_END\n");
  if (started) (void)pthread_join(worker, NULL); return valid ? 0 : 1;
}
'''


def exactly_matches(observed, expected):
    """Compare JSON-shaped evidence values without bool/int coercion."""
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, Mapping):
        return observed.keys() == expected.keys() and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, (list, tuple)):
        return len(observed) == len(expected) and all(
            exactly_matches(actual, required)
            for actual, required in zip(observed, expected, strict=True)
        )
    return observed == expected


def _schema_template() -> dict:
    return {
        "schema": "crabc-mimalloc-x86_64-dynamic-arena-singleton-post-exit-evidence",
        "profile": EXPECTED_PROFILE,
        "target": EXPECTED_TARGET,
        "upstream": EXPECTED_UPSTREAM,
        "harness_dependency": {"path": _base.relative(BASE_PATH), "sha256": _base.sha256_file(BASE_PATH)},
        "scope": copy.deepcopy(EXPECTED_SCOPE),
        "tls": copy.deepcopy(EXPECTED_TLS),
        "source_anchors": [{"member": m, "start_line": s, "end_line": e, "sha256": d} for m, s, e, d in EXPECTED_SOURCE_ANCHORS],
        "compile_definitions": list(EXPECTED_COMPILE_DEFINITIONS),
        "release_flags": list(_base.RUNNER.CONFIGURATION_PROFILES["release"]),
        "release_source_set": list(_base._schema_template()["release_source_set"]),
        "c_probe_sha256": _base.sha256_bytes(C_TRACE_PROBE.encode()),
        "rust_test": {"path": _base.relative(RUST_TEST_SOURCE), "target_arch": "x86_64", "test_filter": RUST_TEST_FILTER},
        "trace": {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": dict(EXPECTED_TRACE_VALUES)},
    }


def load_schema(path=None):
    path = SCHEMA_PATH if path is None else Path(path)
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise _base.EvidenceError("cannot read dynamic-arena-singleton-post-exit schema") from error
    if not exactly_matches(schema, _schema_template()):
        raise _base.EvidenceError("dynamic-arena-singleton-post-exit checked-in schema drifted")
    pin = RUNNER.load_pin()
    if {k: pin[k] for k in ("archive_root", "revision", "version")} != EXPECTED_UPSTREAM or pin["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise _base.EvidenceError("dynamic-arena-singleton-post-exit upstream archive pin drifted")
    return schema


def validate_trace(trace, *, description):
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace)); unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES)); mismatches = [f"{k} (expected {EXPECTED_TRACE_VALUES[k]}, observed {trace[k]})" for k in sorted(set(trace) & set(EXPECTED_TRACE_VALUES)) if type(trace[k]) is not int or trace[k] != EXPECTED_TRACE_VALUES[k]]
    if missing or unexpected or mismatches:
        raise _base.EvidenceError(f"{description} differs from the fixed detached-arena trace: missing={missing}, unexpected={unexpected}, mismatches={mismatches}")


def parse_trace(output, *, description):
    try:
        return RUNNER.parse_address_independent_trace(output, begin=TRACE_BEGIN, end=TRACE_END, description=description)
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    """Return one inclusive pinned-source range without depending on a sibling helper."""
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise _base.EvidenceError("detached-arena source anchor range is invalid")
    return b"".join(lines[start_line - 1 : end_line])


def validate_worker_teardown_source(source: str) -> None:
    match = re.search(r"static void\* worker_main\s*\([^)]*\)\s*\{(?P<body>.*?)(?=\n\}\s*\nint main)", source, re.DOTALL)
    if match is None or match.group("body").count("mi_thread_done()") != 1:
        raise _base.EvidenceError("detached-arena C probe must call real mi_thread_done exactly once")
    body = match.group("body")
    forbidden = ("mi_free(", "mi_heap_destroy(", "mi_heap_collect(", "mi_abandon(", "_mi_page_free(", "pthread_exit(")
    found = [token for token in forbidden if token in body]
    if found:
        raise _base.EvidenceError("detached-arena worker contains forbidden teardown shortcut: " + ", ".join(found))
    post_done = body.split("mi_thread_done();", 1)[1]
    if "_mi_heap_theap(" in post_done or "f->heap" in post_done:
        raise _base.EvidenceError("detached-arena worker accesses Theap after mi_thread_done")
    join = source.find("pthread_join(worker")
    free = source.find("mi_free(f.block)")
    if join < 0 or free < 0 or join > free:
        raise _base.EvidenceError("detached-arena probe must join before its one consumer free")
    if source.count("mi_free(f.block)") != 1:
        raise _base.EvidenceError("detached-arena probe must have exactly one terminal consumer free")
    if "!mi_page_is_in_full(p)" not in source:
        raise _base.EvidenceError(
            "detached-arena probe must prove the source full queue is detached"
        )
    if "map_registered = map_count == 9 && map_span_is_page(page, start, 9);" not in source:
        raise _base.EvidenceError(
            "detached-arena probe must prove every PageMap slice still names its page"
        )
    if "map_clear = map_span_is(start, 9, false);" not in source:
        raise _base.EvidenceError(
            "detached-arena probe must prove every PageMap slice clears after terminal free"
        )


def validate_source_anchors(schema, source):
    for anchor in schema["source_anchors"]:
        contents = (source / str(anchor["member"])).read_bytes()
        observed = _base.sha256_bytes(
            source_range(contents, int(anchor["start_line"]), int(anchor["end_line"]))
        )
        if observed != anchor["sha256"]:
            raise _base.EvidenceError(f"pinned detached-arena source anchor drifted: {anchor['member']}")
    return [dict(a) for a in schema["source_anchors"]]


def c_trace_command(compiler, source, probe_source, probe_binary, schema):
    return [compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"), *schema["release_flags"], str(probe_source), *(str(source / member) for member in schema["release_source_set"]), "-pthread", "-o", str(probe_binary)]


def validate_c_command(command, schema):
    if [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS] != list(schema["compile_definitions"]):
        raise _base.EvidenceError("detached-arena C compile definitions drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise _base.EvidenceError("detached-arena C command lacks pthread/TLS contract")


def normalize_command(command, temporary, source):
    normalized = []
    for part in command:
        if str(part) == str(source) or str(part).startswith(str(source) + "/"):
            normalized.append(NORMALIZED_PINNED_SOURCE + str(part)[len(str(source)):])
        elif str(part) == str(temporary) or str(part).startswith(str(temporary) + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + str(part)[len(str(temporary)):])
        else:
            normalized.append(part)
    return normalized


def validate_normalized_c_command(command, schema):
    expected = ["-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"], "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src", *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}.c", *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]), "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc" or command[1:] != expected:
        raise _base.EvidenceError("detached-arena report C command drifted")


def build_c_trace(compiler, readelf, source, temporary, schema):
    probe_source = temporary / f"{STEM}.c"; probe_binary = temporary / f"{STEM}-c"; probe_source.write_text(C_TRACE_PROBE, encoding="utf-8"); validate_worker_teardown_source(C_TRACE_PROBE); command = c_trace_command(compiler, source, probe_source, probe_binary, schema)
    validate_c_command(command, schema)
    try:
        RUNNER.require_success(RUNNER.command_record(command, cwd=source), "pinned C detached-arena build")
        header = RUNNER.command_record((readelf, "-h", str(probe_binary)), cwd=source); RUNNER.require_success(header, "pinned C detached-arena ELF identity")
        elf = RUNNER.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = RUNNER.command_record((str(probe_binary),), cwd=source); RUNNER.require_success(execution, "pinned C detached-arena execution")
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]), description="pinned C detached-arena trace"); validate_trace(trace, description="pinned C detached-arena trace")
    return {"build_command": normalize_command(command, temporary, source), "elf": elf, "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"], "source_sha256": _base.sha256_bytes(C_TRACE_PROBE.encode()), "trace": trace}


def rust_test_command(cargo, target_dir):
    return [cargo, "test", "--locked", "--target", TARGET, "--target-dir", str(target_dir), "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]


def validate_normalized_rust_command(command):
    expected = ["test", "--locked", "--target", TARGET, "--target-dir", f"{NORMALIZED_EVIDENCE_ROOT}/rust-target", "-p", "crabc-mimalloc", "--lib", "--no-default-features", RUST_TEST_FILTER, "--", "--exact", "--nocapture", "--test-threads=1"]
    if not isinstance(command, list) or not command or Path(command[0]).name != "cargo" or command[1:] != expected:
        raise _base.EvidenceError("detached-arena report Rust command drifted")


def build_rust_probe(cargo, temporary):
    target_dir = temporary / "rust-target"; command = rust_test_command(cargo, target_dir); environment = os.environ.copy(); environment["CARGO_INCREMENTAL"] = "0"
    try:
        execution = RUNNER.command_record(command, cwd=ROOT, env=environment); RUNNER.require_success(execution, "Rust detached-arena lifecycle fixture")
        passed = RUNNER.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"]))
    except RUNNER.HarnessError as error:
        raise _base.EvidenceError(str(error)) from error
    if passed != 1:
        raise _base.EvidenceError(f"Rust detached-arena lifecycle fixture passed {passed} tests, expected one")
    trace = parse_trace(str(execution["stdout"]) + "\n" + str(execution["stderr"]), description="Rust detached-arena trace")
    validate_trace(trace, description="Rust detached-arena trace")
    return {"cargo_command": normalize_command(command, temporary, None), "lockfile": {"path": _base.relative(LOCKFILE), "sha256": _base.sha256_file(LOCKFILE)}, "passed_test_count": passed, "source": {"path": _base.relative(RUST_TEST_SOURCE), "sha256": _base.sha256_file(RUST_TEST_SOURCE)}, "target_dir": {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}, "trace": trace}


def report_from_results(*, schema, provenance, archive_sha256, anchors, c_probe, rust_probe):
    if not isinstance(c_probe.get("trace"), Mapping) or not isinstance(rust_probe.get("trace"), Mapping):
        raise _base.EvidenceError("detached-arena report inputs lack C/Rust traces")
    compare_traces(c_probe["trace"], rust_probe["trace"])
    report = {"c_probe": dict(c_probe), "comparison": {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}, "format": 1, "kind": "mimalloc-x86_64-dynamic-arena-singleton-post-exit-evidence", "profile": schema["profile"], "provenance": dict(provenance), "rust_probe": dict(rust_probe), "scope": schema["scope"], "source": {"archive_sha256": archive_sha256, "anchors": [dict(a) for a in anchors], "release_flags": list(schema["release_flags"]), "release_source_set": list(schema["release_source_set"])}, "status": "passed", "target": schema["target"], "trace": schema["trace"], "upstream": schema["upstream"]}
    validate_report(report); return report


def validate_report(report):
    required = {"c_probe", "comparison", "format", "kind", "profile", "provenance", "rust_probe", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required or report["format"] != 1 or report["status"] != "passed": raise _base.EvidenceError("detached-arena report schema drifted")
    if report["kind"] != "mimalloc-x86_64-dynamic-arena-singleton-post-exit-evidence" or report["profile"] != EXPECTED_PROFILE: raise _base.EvidenceError("detached-arena report identity drifted")
    if not exactly_matches(report["comparison"], {"compared_value_count": len(EXPECTED_TRACE_VALUES), "status": "matched"}): raise _base.EvidenceError("detached-arena report comparison drifted")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM) or not exactly_matches(report["scope"], EXPECTED_SCOPE): raise _base.EvidenceError("detached-arena report boundary drifted")
    if report["provenance"] not in ({"execution_mode": "native", "host_architecture": "x86_64"}, {"execution_mode": "native", "host_architecture": "amd64"}): raise _base.EvidenceError("detached-arena report lacks native x86 provenance")
    schema = load_schema(); source = report["source"]
    if not exactly_matches(report["trace"], schema["trace"]) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"} or source["archive_sha256"] != EXPECTED_ARCHIVE_SHA256 or not exactly_matches(source["anchors"], schema["source_anchors"]) or not exactly_matches(source["release_flags"], schema["release_flags"]) or not exactly_matches(source["release_source_set"], schema["release_source_set"]): raise _base.EvidenceError("detached-arena report source/trace contract drifted")
    c = report["c_probe"]; rust = report["rust_probe"]
    if set(c) != {"build_command", "elf", "run_command", "source_sha256", "trace"} or not exactly_matches(c["elf"], EXPECTED_C_ELF) or c["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/{STEM}-c"] or c["source_sha256"] != _base.sha256_bytes(C_TRACE_PROBE.encode()): raise _base.EvidenceError("detached-arena C probe record drifted")
    validate_normalized_c_command(c["build_command"], schema)
    if set(rust) != {"cargo_command", "lockfile", "passed_test_count", "source", "target_dir", "trace"} or rust["passed_test_count"] != 1: raise _base.EvidenceError("detached-arena Rust probe record drifted")
    validate_normalized_rust_command(rust["cargo_command"])
    if rust["source"] != {"path": _base.relative(RUST_TEST_SOURCE), "sha256": _base.sha256_file(RUST_TEST_SOURCE)} or rust["lockfile"] != {"path": _base.relative(LOCKFILE), "sha256": _base.sha256_file(LOCKFILE)} or rust["target_dir"] != {"isolated": True, "retained": False, "value": f"{NORMALIZED_EVIDENCE_ROOT}/rust-target"}: raise _base.EvidenceError("detached-arena Rust identity drifted")
    validate_trace(c["trace"], description="detached-arena report C trace")
    validate_trace(rust["trace"], description="detached-arena report Rust trace")
    compare_traces(c["trace"], rust["trace"])


def compare_traces(c_trace, rust_trace):
    validate_trace(c_trace, description="pinned C detached-arena trace")
    validate_trace(rust_trace, description="Rust detached-arena trace")
    mismatches = [f"{key} (C={c_trace[key]}, Rust={rust_trace[key]})" for key in sorted(EXPECTED_TRACE_VALUES) if c_trace[key] != rust_trace[key]]
    if mismatches:
        raise _base.EvidenceError("Rust detached-arena trace differs from pinned C: " + ", ".join(mismatches))


def require_native_x86_64():
    try: return RUNNER.require_native_x86_64()
    except RUNNER.HarnessError as error: raise _base.EvidenceError(str(error)) from error


def run_evidence(*, offline, report_path):
    provenance = require_native_x86_64(); schema = load_schema(); before_lockfile = _base.sha256_file(LOCKFILE)
    try: pin = RUNNER.load_pin(); archive = RUNNER.fetch_archive(pin, offline)
    except RUNNER.HarnessError as error: raise _base.EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-dynamic-arena-singleton-post-exit-") as temporary_name:
        temporary = Path(temporary_name)
        try: source = RUNNER.safe_extract(archive, temporary / "source", pin["archive_root"]); compiler = RUNNER.require_tool("musl-gcc"); readelf = RUNNER.require_tool("readelf"); cargo = RUNNER.require_tool("cargo")
        except RUNNER.HarnessError as error: raise _base.EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source); c_probe = build_c_trace(compiler, readelf, source, temporary, schema); rust_probe = build_rust_probe(cargo, temporary); report = report_from_results(schema=schema, provenance=provenance, archive_sha256=_base.sha256_file(archive), anchors=anchors, c_probe=c_probe, rust_probe=rust_probe)
    if _base.sha256_file(LOCKFILE) != before_lockfile: raise _base.EvidenceError("Cargo.lock changed despite --locked Rust command")
    RUNNER.write_json(report_path, report); return report


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--offline", action="store_true"); parser.add_argument("--report", type=Path, default=REPORT_DEFAULT); args = parser.parse_args()
    try: report = run_evidence(offline=args.offline, report_path=args.report)
    except (_base.EvidenceError, OSError, ValueError) as error: print("allocator x86-64 dynamic-arena-singleton-post-exit evidence: FAIL: " + str(error), file=os.sys.stderr); return 1
    print(f"allocator x86-64 dynamic-arena-singleton-post-exit evidence: PASS ({len(report['trace']['expected_values'])} C facts; report: {_base.relative(args.report)})"); return 0


if __name__ == "__main__":
    raise SystemExit(main())
