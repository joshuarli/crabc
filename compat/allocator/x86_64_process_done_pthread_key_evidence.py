#!/usr/bin/env python3
"""Observe the pinned C process-done private pthread-key boundary.

The native fixture initializes mimalloc, explicitly calls public
``mi_process_done()``, then creates and joins a new worker. That worker still
initializes a default Theap and allocates two medium clients, but the Unix
automatic thread-done key has already been deleted. Its natural return leaves
the page and its worker Theap owned; two later ``mi_free`` calls publish remote
frees without collecting or releasing that page. The same direct source
fixture then calls pinned ``_mi_os_purge_ex`` on one live raw mapping after
``mi_process_done`` and records the terminal preloading reset arm.

This is C-oracle-only native Linux/x86-64 evidence. It establishes neither a
Rust process-done implementation nor a public x86 runtime, allocator, libc,
or loader surface.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-process-done-pthread-key-evidence-v3.5.0.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/process-done-pthread-key.json"
TRACE_BEGIN = "CRABC_MI_PROCESS_DONE_PTHREAD_KEY_TRACE_BEGIN"
TRACE_END = "CRABC_MI_PROCESS_DONE_PTHREAD_KEY_TRACE_END"
NORMALIZED_EVIDENCE_ROOT = "<temporary-evidence-root>"
NORMALIZED_PINNED_SOURCE = "<temporary-pinned-mimalloc-source>"

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class EvidenceError(RuntimeError):
    """The process-done pthread-key probe could not prove its boundary."""


EXPECTED_TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "rust_target": "x86_64-unknown-linux-musl",
    "system": "linux",
}
EXPECTED_UPSTREAM = {
    "archive_root": "mimalloc-3.5.0",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "version": "3.5.0",
}
EXPECTED_ARCHIVE_SHA256 = "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305"
EXPECTED_PROFILE = "linux-x86_64-private-c-process-done-pthread-key"
EXPECTED_SCOPE = {
    "aarch64_status_reused": False,
    "after_process_done_worker_create_join_and_purge_only": True,
    "automatic_destructor_absence_observed": True,
    "explicit_public_mi_process_done_fixture_only": True,
    "late_free_remote_publication_and_terminal_purge_only": True,
    "mi_tls_model_local_required": True,
    "ordinary_medium_full_abandonment_observed": True,
    "post_process_done_no_callback_purge_only": True,
    "process_done_purge_reset_observed": True,
    "process_done_pthread_key_and_terminal_purge_only": True,
    "emulation_accepted": False,
    "general_abandonment_or_adoption_claimed": False,
    "general_lifecycle_claimed": False,
    "general_process_shutdown_claimed": False,
    "general_pthread_destructor_ordering_claimed": False,
    "general_remote_free_routing_claimed": False,
    "native_linux_x86_64_required": True,
    "no_explicit_thread_done_in_worker": True,
    "private_engine_evidence_only": True,
    "public_crabc_support": False,
    "public_mi_api_claimed": False,
    "public_x86_libc_or_ldso_support": False,
    "real_pinned_c_process_done_pthread_key": True,
    "rust_process_done_pthread_key_claimed": False,
    "worker_natural_return_only": True,
}
EXPECTED_COMPILE_DEFINITIONS = (
    "-DMI_SHARED_LIB",
    "-DMI_SHARED_LIB_EXPORT",
    "-DMI_LIBC_MUSL=1",
)
EXPECTED_C_ELF = {
    "class": "ELF64",
    "endianness": "little",
    "machine": "Advanced Micro Devices X86-64",
}
EXPECTED_SOURCE_ANCHORS = (
    ("include/mimalloc/atomic.h", 18, 20, "c0235bb455ffc28e3bb83afcfd5946fe44aa652808a892435f13a67efa232f52"),
    ("src/prim/unix/prim.c", 1011, 1040, "eef3c9b9715fec9a271f8a966febe73d3ff3113165c5bc9c930fa46c657aa87a"),
    ("src/init.c", 305, 360, "8b5a6af8d90da7f2cb33cf5c6211c9325234840d57a54c25be891e49e4d354e5"),
    ("src/init.c", 595, 648, "18bc636a2f41434dc59cb34b0505242d1762e3a7f5d6717c5bb906012d25a869"),
    ("src/os.c", 655, 680, "5bf5130ba1a0a05988e9bf818a1f6d45057c790d8337317553560d9d8968e1c1"),
    ("src/prim/unix/prim.c", 571, 597, "0c483f64cb62dfce8f6101943ce2c7cbecc83c03d5375ed378d9387fecd77781"),
    ("src/prim/prim-tls.c", 211, 250, "79dbeedce267f8671d082fad73bb141404192decb5d1191670fa6341aa75619b"),
    ("src/free.c", 223, 255, "53e59015c42883dfe56d1b920e5b2907a61df09c5da49b4abe3035db5dc76ff4"),
    ("src/page.c", 291, 388, "164b52805d60011e009131354a48e0a032843b2ed064865f75c8cb904ae1ebea"),
    ("src/arena.c", 1304, 1355, "d7328658d88aa8c24dabcd1a093e5857b6bc699b03677eb4e8ab3c7d160c6dbb"),
)
EXPECTED_TRACE_VALUES = {
    "trace.process_done_pthread_key.request_size": 10241,
    "trace.process_done_pthread_key.block_size": 12288,
    "trace.process_done_pthread_key.capacity": 2,
    "trace.process_done_pthread_key.reserved": 42,
    "trace.process_done_pthread_key.same_page": 1,
    "trace.process_done_pthread_key.process_initialized_before_done": 1,
    "trace.process_done_pthread_key.auto_key_valid_before_done": 1,
    "trace.process_done_pthread_key.cached_empty_after_done": 1,
    "trace.process_done_pthread_key.auto_key_invalid_after_done": 1,
    "trace.process_done_pthread_key.main_theap_initialized_after_done": 1,
    "trace.process_done_pthread_key.process_done_purge_page_size": 4096,
    "trace.process_done_pthread_key.process_done_purge_option_enabled": 1,
    "trace.process_done_pthread_key.process_done_purge_needs_recommit": 0,
    "trace.process_done_pthread_key.process_done_purge_advice_calls": 1,
    "trace.process_done_pthread_key.process_done_purge_reset_not_decommit": 1,
    "trace.process_done_pthread_key.process_done_purge_mapping_retained": 1,
    "trace.process_done_pthread_key.process_done_purge_mapping_released": 1,
    "trace.process_done_pthread_key.worker_theap_initialized_before_return": 1,
    "trace.process_done_pthread_key.worker_auto_key_invalid": 1,
    "trace.process_done_pthread_key.worker_returned_naturally": 1,
    "trace.process_done_pthread_key.join_completed": 1,
    "trace.process_done_pthread_key.page_owner_matches_worker_after_join": 1,
    "trace.process_done_pthread_key.worker_theap_initialized_after_join": 1,
    "trace.process_done_pthread_key.worker_tld_thread_id_retained_after_join": 1,
    "trace.process_done_pthread_key.page_owned_after_join": 1,
    "trace.process_done_pthread_key.page_abandoned_after_join": 0,
    "trace.process_done_pthread_key.page_mapped_abandoned_after_join": 0,
    "trace.process_done_pthread_key.page_thread_free_empty_after_join": 1,
    "trace.process_done_pthread_key.page_used_after_join": 2,
    "trace.process_done_pthread_key.survivor_live_after_first_late_free": 1,
    "trace.process_done_pthread_key.remote_free_published_after_first": 1,
    "trace.process_done_pthread_key.page_used_after_first_late_free": 2,
    "trace.process_done_pthread_key.remote_free_published_after_final": 1,
    "trace.process_done_pthread_key.page_used_after_final_late_free": 2,
    "trace.process_done_pthread_key.page_owner_retained_after_final_late_free": 1,
    "trace.process_done_pthread_key.page_abandoned_after_final_late_free": 0,
    "trace.process_done_pthread_key.page_mapping_retained_after_final_late_free": 1,
    "trace.process_done_pthread_key.full_page_join_completed": 1,
    "trace.process_done_pthread_key.full_page_ordinary_abandoning_options": 1,
    "trace.process_done_pthread_key.full_page_worker_auto_key_invalid": 1,
    "trace.process_done_pthread_key.full_page_worker_returned_naturally": 1,
    "trace.process_done_pthread_key.full_page_client_count": 42,
    "trace.process_done_pthread_key.full_page_capacity": 42,
    "trace.process_done_pthread_key.full_page_reserved": 42,
    "trace.process_done_pthread_key.full_page_used": 42,
    "trace.process_done_pthread_key.full_page_regular_queue_count": 1,
    "trace.process_done_pthread_key.full_page_full_queue_count": 0,
    "trace.process_done_pthread_key.full_page_pressure_uses_different_page": 1,
    "trace.process_done_pthread_key.full_page_abandoned": 1,
    "trace.process_done_pthread_key.full_page_mapped_abandoned": 0,
    "trace.process_done_pthread_key.full_page_owned": 0,
    "trace.process_done_pthread_key.full_page_full": 1,
    "trace.process_done_pthread_key.valid": 1,
}


C_TRACE_PROBE = r'''
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private process-done pthread-key fixture requires native Linux/x86_64
#endif
#if !defined(MI_USE_PTHREADS)
#error this fixture requires the pinned Unix automatic-thread-done key
#endif
#if !MI_TLS_MODEL_LOCAL
#error this fixture requires local compiler TLS distinct from the Unix automatic-done key
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif
#if MI_PAGE_MAP_FLAT != 0 || MI_ENCODE_FREELIST != 0
#error this fixture requires the native two-level map and unencoded release freelist
#endif

// `src/prim/unix/prim.c` owns this private automatic thread-done key. The
// fixture intentionally observes the key's invalid value after `mi_process_done`;
// it never calls the source's explicit thread-done entry point.
extern pthread_key_t _mi_heap_default_key;

/* Keep the exact `src/prim/unix/prim.c` advice observable only for the one
 * `_mi_os_purge_ex` call after real `mi_process_done`. Earlier source setup
 * remains uninstrumented, and the wrapper uses the kernel entry directly so
 * it cannot recurse through the C runtime after the source terminal guard. */
static bool capture_process_done_purge_advice = false;
static size_t process_done_purge_advice_calls = 0;
static int process_done_purge_advice = 0;

int madvise(void* start, size_t size, int advice) {
  if (capture_process_done_purge_advice) {
    process_done_purge_advice_calls++;
    process_done_purge_advice = advice;
  }
  return (int)syscall(SYS_madvise, start, size, advice);
}

typedef struct worker_context_s {
  void* block;
  void* survivor;
  mi_theap_t* theap;
  mi_threadid_t tld_thread_id;
  bool setup_valid;
  bool worker_theap_initialized_before_return;
  bool worker_auto_key_invalid;
  bool worker_returned_naturally;
  size_t block_size;
  size_t capacity;
  size_t reserved;
  int failure_stage;
} worker_context_t;

// The source `mi_page_to_full` branch is selected only after a medium page
// has reached its reservation and the next generic search sees it exhausted.
// Keep every client live while the worker observes that transition: freeing
// one here would turn this into a different abandoned-free experiment.
enum { FULL_PAGE_MAX_CLIENTS = 64 };

typedef struct full_page_context_s {
  void* clients[FULL_PAGE_MAX_CLIENTS];
  void* pressure;
  size_t client_count;
  size_t capacity;
  size_t reserved;
  size_t used;
  size_t regular_queue_count;
  size_t full_queue_count;
  bool setup_valid;
  bool ordinary_abandoning_options;
  bool worker_auto_key_invalid;
  bool worker_returned_naturally;
  bool pressure_uses_different_page;
  bool page_abandoned;
  bool page_mapped_abandoned;
  bool page_owned;
  bool page_full;
  int failure_stage;
} full_page_context_t;

static const size_t request_size = MI_SMALL_MAX_OBJ_SIZE + 1;

static void* worker_main(void* argument) {
  worker_context_t* const context = (worker_context_t*)argument;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  void* block = NULL;
  void* survivor = NULL;

  mi_thread_init();
  theap = _mi_theap_default();
  if (theap == NULL || !mi_theap_is_initialized(theap)) {
    context->failure_stage = 1;
    goto failed;
  }
  block = mi_malloc(request_size);
  survivor = mi_malloc(request_size);
  if (block == NULL || survivor == NULL || block == survivor) {
    context->failure_stage = 2;
    goto failed;
  }
  page = _mi_safe_ptr_page(block);
  if (page == NULL || _mi_safe_ptr_page(survivor) != page
      || page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->used != 2 || mi_page_is_full(page)
      || page->theap != theap || theap->tld == NULL) {
    context->failure_stage = 3;
    goto failed;
  }

  context->worker_theap_initialized_before_return = mi_theap_is_initialized(theap);
  context->worker_auto_key_invalid = (_mi_heap_default_key == MI_PTHREAD_KEY_INVALID);
  context->block_size = page->block_size;
  context->capacity = page->capacity;
  context->reserved = page->reserved;
  context->theap = theap;
  context->tld_thread_id = theap->tld->thread_id;
  context->block = block;
  context->survivor = survivor;
  context->setup_valid = (context->worker_theap_initialized_before_return
                          && context->worker_auto_key_invalid
                          && context->block_size == 12288
                          && context->capacity == 2
                          && context->reserved == 42);
  if (!context->setup_valid) {
    fprintf(stderr,
            "post-process-done worker setup: initialized=%d key-invalid=%d block=%zu capacity=%zu reserved=%zu\n",
            context->worker_theap_initialized_before_return, context->worker_auto_key_invalid,
            context->block_size, context->capacity, context->reserved);
    context->failure_stage = 4;
    goto failed;
  }
  context->worker_returned_naturally = true;
  return NULL;

failed:
  if (block != NULL) mi_free(block);
  if (survivor != NULL) mi_free(survivor);
  context->block = NULL;
  context->survivor = NULL;
  context->theap = NULL;
  context->setup_valid = false;
  return NULL;
}

static void* full_page_worker_main(void* argument) {
  full_page_context_t* const context = (full_page_context_t*)argument;
  mi_theap_t* theap = NULL;
  mi_page_t* page = NULL;
  mi_page_t* pressure_page = NULL;
  size_t bin = 0;

  mi_thread_init();
  theap = _mi_theap_default();
  if (theap == NULL || !mi_theap_is_initialized(theap)) {
    context->failure_stage = 1;
    return NULL;
  }
  context->ordinary_abandoning_options =
      (theap->allow_page_abandon && theap->page_full_retain == 2);
  context->worker_auto_key_invalid = (_mi_heap_default_key == MI_PTHREAD_KEY_INVALID);
  if (!context->ordinary_abandoning_options || !context->worker_auto_key_invalid) {
    context->failure_stage = 2;
    return NULL;
  }

  context->clients[0] = mi_malloc(request_size);
  page = _mi_safe_ptr_page(context->clients[0]);
  if (context->clients[0] == NULL || page == NULL
      || page->block_size <= MI_SMALL_MAX_OBJ_SIZE
      || page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
      || page->theap != theap) {
    context->failure_stage = 3;
    return NULL;
  }
  bin = _mi_bin(page->block_size);
  if (bin >= MI_BIN_FULL || page->reserved == 0 || page->reserved > FULL_PAGE_MAX_CLIENTS) {
    context->failure_stage = 4;
    return NULL;
  }
  context->client_count = 1;
  while (page->used < page->reserved) {
    if (context->client_count == FULL_PAGE_MAX_CLIENTS) {
      context->failure_stage = 5;
      return NULL;
    }
    context->clients[context->client_count] = mi_malloc(request_size);
    if (context->clients[context->client_count] == NULL
        || _mi_safe_ptr_page(context->clients[context->client_count]) != page) {
      context->failure_stage = 6;
      return NULL;
    }
    context->client_count++;
  }
  if (page->capacity != page->reserved || page->used != page->reserved) {
    context->failure_stage = 7;
    return NULL;
  }

  // The next allocation performs source `mi_find_page`'s exhausted-page
  // transition. Under the ordinary option image `mi_page_to_full` calls
  // `_mi_page_abandon`; it must not leave the old page in BIN_FULL.
  context->pressure = mi_malloc(request_size);
  pressure_page = _mi_safe_ptr_page(context->pressure);
  if (context->pressure == NULL || pressure_page == NULL || pressure_page == page) {
    context->failure_stage = 8;
    return NULL;
  }
  context->capacity = page->capacity;
  context->reserved = page->reserved;
  context->used = page->used;
  context->regular_queue_count = theap->pages[bin].count;
  context->full_queue_count = theap->pages[MI_BIN_FULL].count;
  context->pressure_uses_different_page = (pressure_page != page);
  context->page_abandoned = mi_page_is_abandoned(page);
  context->page_mapped_abandoned = mi_page_is_abandoned_mapped(page);
  context->page_owned = mi_page_is_owned(page);
  context->page_full = mi_page_is_full(page);
  context->setup_valid = (context->client_count == context->reserved
                          && context->capacity == context->reserved
                          && context->used == context->reserved
                          && context->regular_queue_count == 1
                          && context->full_queue_count == 0
                          && context->pressure_uses_different_page
                          && context->page_abandoned
                          && !context->page_mapped_abandoned
                          && !context->page_owned
                          && context->page_full);
  if (!context->setup_valid) {
    context->failure_stage = 9;
    return NULL;
  }
  context->worker_returned_naturally = true;
  return NULL;
}

int main(void) {
  worker_context_t context = { 0 };
  pthread_t worker;
  full_page_context_t full_page = { 0 };
  pthread_t full_page_worker;
  mi_theap_t* main_theap = NULL;
  mi_page_t* page = NULL;
  const void* page_start = NULL;
  void* block = NULL;
  void* survivor = NULL;
  bool worker_started = false;
  bool full_page_worker_started = false;
  bool valid = false;
  int stage = 0;

  size_t block_size = 0;
  size_t capacity = 0;
  size_t reserved = 0;
  size_t page_used_after_join = 0;
  size_t page_used_after_first_late_free = 0;
  size_t page_used_after_final_late_free = 0;
  int process_initialized_before_done = 0;
  int auto_key_valid_before_done = 0;
  int cached_empty_after_done = 0;
  int auto_key_invalid_after_done = 0;
  int main_theap_initialized_after_done = 0;
  int worker_theap_initialized_before_return = 0;
  int worker_auto_key_invalid = 0;
  int worker_returned_naturally = 0;
  int join_completed = 0;
  int same_page = 0;
  int page_owner_matches_worker_after_join = 0;
  int worker_theap_initialized_after_join = 0;
  int worker_tld_thread_id_retained_after_join = 0;
  int page_owned_after_join = 0;
  int page_abandoned_after_join = 0;
  int page_mapped_abandoned_after_join = 0;
  int page_thread_free_empty_after_join = 0;
  int survivor_live_after_first_late_free = 0;
  int remote_free_published_after_first = 0;
  int remote_free_published_after_final = 0;
  int page_owner_retained_after_final_late_free = 0;
  int page_abandoned_after_final_late_free = 0;
  int page_mapping_retained_after_final_late_free = 0;
  int full_page_join_completed = 0;
  size_t process_done_purge_page_size = 0;
  int process_done_purge_option_enabled = 0;
  int process_done_purge_needs_recommit = 1;
  int process_done_purge_reset_not_decommit = 0;
  int process_done_purge_mapping_retained = 0;
  int process_done_purge_mapping_released = 0;
  void* process_done_purge_mapping = NULL;

  mi_thread_init();
  main_theap = _mi_theap_default();
  process_initialized_before_done = _mi_process_is_initialized;
  auto_key_valid_before_done = (_mi_heap_default_key != MI_PTHREAD_KEY_INVALID);
  if (!process_initialized_before_done || !auto_key_valid_before_done
      || main_theap == NULL || !mi_theap_is_initialized(main_theap)) goto output;
  process_done_purge_page_size = _mi_os_page_size();
  mi_option_set(mi_option_purge_delay, 0);
  mi_option_set(mi_option_purge_decommits, 1);
  process_done_purge_option_enabled =
      (mi_option_get(mi_option_purge_delay) == 0
       && mi_option_is_enabled(mi_option_purge_decommits));
  if (process_done_purge_page_size == 0 || !process_done_purge_option_enabled) goto output;
  stage = 1;

  mi_process_done();
  cached_empty_after_done = (_mi_theap_cached() == _mi_theap_empty_get());
  auto_key_invalid_after_done = (_mi_heap_default_key == MI_PTHREAD_KEY_INVALID);
  main_theap_initialized_after_done = mi_theap_is_initialized(main_theap);
  if (!cached_empty_after_done || !auto_key_invalid_after_done
      || !main_theap_initialized_after_done) goto output;

  process_done_purge_mapping = mmap(NULL, process_done_purge_page_size,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (process_done_purge_mapping == MAP_FAILED) {
    process_done_purge_mapping = NULL;
    goto output;
  }
  ((volatile unsigned char*)process_done_purge_mapping)[0] = 0x5a;
  capture_process_done_purge_advice = true;
  process_done_purge_needs_recommit = _mi_os_purge_ex(_mi_subproc_main(),
      process_done_purge_mapping, process_done_purge_page_size,
      true, process_done_purge_page_size, NULL, NULL);
  capture_process_done_purge_advice = false;
  process_done_purge_reset_not_decommit =
      (process_done_purge_advice_calls == 1 && process_done_purge_advice != MADV_DONTNEED);
  process_done_purge_mapping_retained =
      (((volatile unsigned char*)process_done_purge_mapping)[0] == 0
       || ((volatile unsigned char*)process_done_purge_mapping)[0] == 0x5a);
  process_done_purge_mapping_released =
      (munmap(process_done_purge_mapping, process_done_purge_page_size) == 0);
  process_done_purge_mapping = NULL;
  if (process_done_purge_needs_recommit || !process_done_purge_reset_not_decommit
      || !process_done_purge_mapping_retained || !process_done_purge_mapping_released) goto output;
  stage = 2;

  if (pthread_create(&worker, NULL, worker_main, &context) != 0) goto output;
  worker_started = true;
  stage = 3;
  if (pthread_join(worker, NULL) != 0) goto output;
  worker_started = false;
  join_completed = 1;
  stage = 4;

  block = context.block;
  survivor = context.survivor;
  if (!context.setup_valid || !context.worker_returned_naturally
      || context.theap == NULL || block == NULL || survivor == NULL || block == survivor) {
    stage = 40 + context.failure_stage;
    goto output;
  }
  page = _mi_safe_ptr_page(block);
  if (page == NULL || _mi_safe_ptr_page(survivor) != page) goto output;
  page_start = mi_page_start(page);
  block_size = page->block_size;
  capacity = page->capacity;
  reserved = page->reserved;
  same_page = (_mi_ptr_page(block) == page && _mi_ptr_page(survivor) == page);
  worker_theap_initialized_before_return = context.worker_theap_initialized_before_return;
  worker_auto_key_invalid = context.worker_auto_key_invalid;
  worker_returned_naturally = context.worker_returned_naturally;
  page_owner_matches_worker_after_join = (page->theap == context.theap);
  page_owned_after_join = mi_page_is_owned(page);
  page_abandoned_after_join = mi_page_is_abandoned(page);
  page_mapped_abandoned_after_join = mi_page_is_abandoned_mapped(page);
  page_thread_free_empty_after_join = (mi_page_thread_free(page) == NULL);
  page_used_after_join = page->used;
  if (block_size != 12288 || capacity != 2 || reserved != 42 || !same_page
      || !worker_theap_initialized_before_return || !worker_auto_key_invalid
      || !worker_returned_naturally || !page_owner_matches_worker_after_join
      || !page_owned_after_join || page_abandoned_after_join || page_mapped_abandoned_after_join
      || !page_thread_free_empty_after_join || page_used_after_join != 2) goto output;
  worker_theap_initialized_after_join = mi_theap_is_initialized(context.theap);
  worker_tld_thread_id_retained_after_join =
      (context.theap->tld != NULL && context.theap->tld->thread_id == context.tld_thread_id);
  if (!worker_theap_initialized_after_join || !worker_tld_thread_id_retained_after_join) goto output;
  stage = 5;

  if (pthread_create(&full_page_worker, NULL, full_page_worker_main, &full_page) != 0) goto output;
  full_page_worker_started = true;
  if (pthread_join(full_page_worker, NULL) != 0) goto output;
  full_page_worker_started = false;
  full_page_join_completed = 1;
  if (!full_page.setup_valid || !full_page.worker_returned_naturally) {
    stage = 50 + full_page.failure_stage;
    goto output;
  }
  stage = 6;

  mi_free(block);
  block = NULL;
  page = _mi_safe_ptr_page(survivor);
  if (page == NULL) goto output;
  survivor_live_after_first_late_free = (_mi_ptr_page(survivor) == page);
  remote_free_published_after_first = (mi_page_thread_free(page) != NULL);
  page_used_after_first_late_free = page->used;
  if (!survivor_live_after_first_late_free || !remote_free_published_after_first
      || page_used_after_first_late_free != 2) goto output;
  stage = 7;

  mi_free(survivor);
  survivor = NULL;
  page = (page_start == NULL ? NULL : _mi_safe_ptr_page(page_start));
  if (page == NULL) goto output;
  remote_free_published_after_final = (mi_page_thread_free(page) != NULL);
  page_used_after_final_late_free = page->used;
  page_owner_retained_after_final_late_free = mi_page_is_owned(page);
  page_abandoned_after_final_late_free = mi_page_is_abandoned(page);
  page_mapping_retained_after_final_late_free =
      (page_start != NULL && _mi_safe_ptr_page(page_start) == page);
  valid = (process_initialized_before_done && auto_key_valid_before_done
           && cached_empty_after_done && auto_key_invalid_after_done
           && main_theap_initialized_after_done && worker_theap_initialized_before_return
           && process_done_purge_option_enabled && !process_done_purge_needs_recommit
           && process_done_purge_reset_not_decommit && process_done_purge_mapping_retained
           && process_done_purge_mapping_released
           && worker_auto_key_invalid && worker_returned_naturally && join_completed
           && full_page_join_completed && full_page.setup_valid
           && full_page.ordinary_abandoning_options && full_page.worker_auto_key_invalid
           && full_page.worker_returned_naturally
           && full_page.client_count == full_page.reserved
           && full_page.capacity == full_page.reserved && full_page.used == full_page.reserved
           && full_page.regular_queue_count == 1 && full_page.full_queue_count == 0
           && full_page.pressure_uses_different_page && full_page.page_abandoned
           && !full_page.page_mapped_abandoned && !full_page.page_owned && full_page.page_full
           && same_page && page_owner_matches_worker_after_join
           && worker_theap_initialized_after_join && worker_tld_thread_id_retained_after_join
           && page_owned_after_join && !page_abandoned_after_join
           && !page_mapped_abandoned_after_join && page_thread_free_empty_after_join
           && page_used_after_join == 2 && survivor_live_after_first_late_free
           && remote_free_published_after_first && page_used_after_first_late_free == 2
           && remote_free_published_after_final && page_used_after_final_late_free == 2
           && page_owner_retained_after_final_late_free
           && !page_abandoned_after_final_late_free && page_mapping_retained_after_final_late_free);

output:
  if (worker_started) (void)pthread_join(worker, NULL);
  if (full_page_worker_started) (void)pthread_join(full_page_worker, NULL);
  if (process_done_purge_mapping != NULL)
    (void)munmap(process_done_purge_mapping, process_done_purge_page_size);
  printf("CRABC_MI_PROCESS_DONE_PTHREAD_KEY_TRACE_BEGIN\n");
#define OUT_N(k,v) printf("trace.process_done_pthread_key.%s=%zu\n", k, (size_t)(v))
#define OUT_B(k,v) printf("trace.process_done_pthread_key.%s=%d\n", k, (v) ? 1 : 0)
  OUT_N("request_size", request_size);
  OUT_N("block_size", block_size);
  OUT_N("capacity", capacity);
  OUT_N("reserved", reserved);
  OUT_B("same_page", same_page);
  OUT_B("process_initialized_before_done", process_initialized_before_done);
  OUT_B("auto_key_valid_before_done", auto_key_valid_before_done);
  OUT_B("cached_empty_after_done", cached_empty_after_done);
  OUT_B("auto_key_invalid_after_done", auto_key_invalid_after_done);
  OUT_B("main_theap_initialized_after_done", main_theap_initialized_after_done);
  OUT_N("process_done_purge_page_size", process_done_purge_page_size);
  OUT_B("process_done_purge_option_enabled", process_done_purge_option_enabled);
  OUT_B("process_done_purge_needs_recommit", process_done_purge_needs_recommit);
  OUT_N("process_done_purge_advice_calls", process_done_purge_advice_calls);
  OUT_B("process_done_purge_reset_not_decommit", process_done_purge_reset_not_decommit);
  OUT_B("process_done_purge_mapping_retained", process_done_purge_mapping_retained);
  OUT_B("process_done_purge_mapping_released", process_done_purge_mapping_released);
  OUT_B("worker_theap_initialized_before_return", worker_theap_initialized_before_return);
  OUT_B("worker_auto_key_invalid", worker_auto_key_invalid);
  OUT_B("worker_returned_naturally", worker_returned_naturally);
  OUT_B("join_completed", join_completed);
  OUT_B("page_owner_matches_worker_after_join", page_owner_matches_worker_after_join);
  OUT_B("worker_theap_initialized_after_join", worker_theap_initialized_after_join);
  OUT_B("worker_tld_thread_id_retained_after_join", worker_tld_thread_id_retained_after_join);
  OUT_B("page_owned_after_join", page_owned_after_join);
  OUT_B("page_abandoned_after_join", page_abandoned_after_join);
  OUT_B("page_mapped_abandoned_after_join", page_mapped_abandoned_after_join);
  OUT_B("page_thread_free_empty_after_join", page_thread_free_empty_after_join);
  OUT_N("page_used_after_join", page_used_after_join);
  OUT_B("survivor_live_after_first_late_free", survivor_live_after_first_late_free);
  OUT_B("remote_free_published_after_first", remote_free_published_after_first);
  OUT_N("page_used_after_first_late_free", page_used_after_first_late_free);
  OUT_B("remote_free_published_after_final", remote_free_published_after_final);
  OUT_N("page_used_after_final_late_free", page_used_after_final_late_free);
  OUT_B("page_owner_retained_after_final_late_free", page_owner_retained_after_final_late_free);
  OUT_B("page_abandoned_after_final_late_free", page_abandoned_after_final_late_free);
  OUT_B("page_mapping_retained_after_final_late_free", page_mapping_retained_after_final_late_free);
  OUT_B("full_page_join_completed", full_page_join_completed);
  OUT_B("full_page_ordinary_abandoning_options", full_page.ordinary_abandoning_options);
  OUT_B("full_page_worker_auto_key_invalid", full_page.worker_auto_key_invalid);
  OUT_B("full_page_worker_returned_naturally", full_page.worker_returned_naturally);
  OUT_N("full_page_client_count", full_page.client_count);
  OUT_N("full_page_capacity", full_page.capacity);
  OUT_N("full_page_reserved", full_page.reserved);
  OUT_N("full_page_used", full_page.used);
  OUT_N("full_page_regular_queue_count", full_page.regular_queue_count);
  OUT_N("full_page_full_queue_count", full_page.full_queue_count);
  OUT_B("full_page_pressure_uses_different_page", full_page.pressure_uses_different_page);
  OUT_B("full_page_abandoned", full_page.page_abandoned);
  OUT_B("full_page_mapped_abandoned", full_page.page_mapped_abandoned);
  OUT_B("full_page_owned", full_page.page_owned);
  OUT_B("full_page_full", full_page.page_full);
  OUT_B("valid", valid);
#undef OUT_B
#undef OUT_N
  printf("CRABC_MI_PROCESS_DONE_PTHREAD_KEY_TRACE_END\n");
  if (!valid) fprintf(stderr, "process-done pthread-key fixture stopped at stage %d\n", stage);
  return valid ? 0 : 1;
}
'''


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exactly_matches(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(observed, dict)
        return set(observed) == set(expected) and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(observed, list)
        return len(observed) == len(expected) and all(
            exactly_matches(actual, wanted) for actual, wanted in zip(observed, expected)
        )
    return observed == expected


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def source_range(contents: bytes, start_line: int, end_line: int) -> bytes:
    lines = contents.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise EvidenceError("process-done pthread-key source anchor is outside its pinned member")
    return b"".join(lines[start_line - 1 : end_line])


def validate_probe_source(probe: str = C_TRACE_PROBE) -> None:
    worker_start = probe.find("static void* worker_main(void* argument) {")
    worker_end = probe.find("\nint main(void) {", worker_start)
    if worker_start < 0 or worker_end < 0:
        raise EvidenceError("process-done pthread-key worker body is missing")
    body = probe[worker_start:worker_end]
    if any(call in body for call in ("mi_thread_done();", "_mi_thread_done(NULL);", "pthread_exit(NULL);")):
        raise EvidenceError("process-done pthread-key worker contains an explicit teardown call")
    joined_owner_guard = "if (block_size != 12288 || capacity != 2 || reserved != 42 || !same_page"
    joined_owner_observation = "worker_theap_initialized_after_join = mi_theap_is_initialized(context.theap);"
    final_page_reacquire = "page = (page_start == NULL ? NULL : _mi_safe_ptr_page(page_start));"
    final_page_observation = "remote_free_published_after_final = (mi_page_thread_free(page) != NULL);"
    if (probe.find(joined_owner_guard) < 0
            or probe.find(joined_owner_observation) < probe.find(joined_owner_guard)):
        raise EvidenceError("process-done pthread-key probe observes the worker owner before its joined-page guard")
    if (probe.find(final_page_reacquire) < 0
            or probe.find(final_page_observation) < probe.find(final_page_reacquire)):
        raise EvidenceError("process-done pthread-key probe observes the final page before reacquiring it")
    required = (
        "extern pthread_key_t _mi_heap_default_key;",
        "mi_process_done();",
        "_mi_os_purge_ex(_mi_subproc_main(),",
        "capture_process_done_purge_advice = true;",
        "process_done_purge_advice != MADV_DONTNEED",
        "_mi_heap_default_key == MI_PTHREAD_KEY_INVALID",
        "context->worker_returned_naturally = true;",
        "pthread_join(worker, NULL)",
        "mi_page_thread_free(page) != NULL",
        "theap->allow_page_abandon && theap->page_full_retain == 2",
        "context->full_queue_count == 0",
        "context->page_abandoned",
        "#if !defined(MI_USE_PTHREADS)",
        "#if !MI_TLS_MODEL_LOCAL",
    )
    if not all(fragment in probe for fragment in required):
        raise EvidenceError("process-done pthread-key probe loses its source boundary")


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = SCHEMA_PATH if path is None else path
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot read x86-64 process-done pthread-key schema") from error
    expected_fields = {
        "c_probe_sha256", "compile_definitions", "format", "profile", "release_flags",
        "release_source_set", "schema", "scope", "source_anchors", "target", "trace", "upstream",
    }
    if not isinstance(schema, dict) or set(schema) != expected_fields:
        raise EvidenceError("process-done pthread-key schema fields drifted")
    if type(schema["format"]) is not int or schema["format"] != 1:
        raise EvidenceError("unsupported process-done pthread-key evidence format")
    if schema["schema"] != "crabc-mimalloc-x86_64-process-done-pthread-key-evidence":
        raise EvidenceError("unsupported process-done pthread-key evidence schema")
    if schema["profile"] != EXPECTED_PROFILE or not exactly_matches(schema["target"], EXPECTED_TARGET):
        raise EvidenceError("process-done pthread-key target/profile drifted")
    if not exactly_matches(schema["upstream"], EXPECTED_UPSTREAM):
        raise EvidenceError("process-done pthread-key upstream drifted")
    if not exactly_matches(schema["scope"], EXPECTED_SCOPE):
        raise EvidenceError("process-done pthread-key scope drifted")
    try:
        pin = run.load_pin()
    except run.HarnessError as error:
        raise EvidenceError("cannot validate pinned process-done pthread-key upstream identity") from error
    if (pin["sha256"] != EXPECTED_ARCHIVE_SHA256
            or pin["archive_root"] != EXPECTED_UPSTREAM["archive_root"]
            or pin["revision"] != EXPECTED_UPSTREAM["revision"]
            or pin["version"] != EXPECTED_UPSTREAM["version"]):
        raise EvidenceError("process-done pthread-key upstream pin drifted")
    if not exactly_matches(schema["release_source_set"], list(run.ORACLE_SOURCES)):
        raise EvidenceError("process-done pthread-key C source set drifted")
    if not exactly_matches(schema["release_flags"], list(run.CONFIGURATION_PROFILES["release"])):
        raise EvidenceError("process-done pthread-key release flags drifted")
    if not exactly_matches(schema["compile_definitions"], list(EXPECTED_COMPILE_DEFINITIONS)):
        raise EvidenceError("process-done pthread-key compile definitions drifted")
    if not exactly_matches(schema["trace"], {"begin": TRACE_BEGIN, "end": TRACE_END, "expected_values": EXPECTED_TRACE_VALUES}):
        raise EvidenceError("process-done pthread-key trace contract drifted")
    validate_probe_source()
    if schema["c_probe_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8")):
        raise EvidenceError("process-done pthread-key C probe hash drifted")
    anchors = schema["source_anchors"]
    if not isinstance(anchors, list) or len(anchors) != len(EXPECTED_SOURCE_ANCHORS):
        raise EvidenceError("process-done pthread-key source anchors drifted")
    observed = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or set(anchor) != {"end_line", "member", "sha256", "start_line"}:
            raise EvidenceError("process-done pthread-key source anchor shape drifted")
        observed.append((anchor.get("member"), anchor.get("start_line"), anchor.get("end_line"), anchor.get("sha256")))
    if tuple(observed) != EXPECTED_SOURCE_ANCHORS:
        raise EvidenceError("process-done pthread-key source anchor contract drifted")
    return schema


def validate_source_anchors(schema: Mapping[str, Any], source: Path) -> list[dict[str, Any]]:
    validated = []
    for anchor in schema["source_anchors"]:
        path = source / str(anchor["member"])
        digest = sha256_bytes(source_range(path.read_bytes(), int(anchor["start_line"]), int(anchor["end_line"]))) if path.is_file() else None
        if digest != anchor["sha256"]:
            raise EvidenceError(f"process-done pthread-key source anchor drifted: {anchor['member']}")
        validated.append(dict(anchor))
    return validated


def parse_trace(output: str) -> dict[str, int]:
    try:
        return run.parse_address_independent_trace(
            output,
            begin=TRACE_BEGIN,
            end=TRACE_END,
            description="pinned C process-done pthread-key trace",
        )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def validate_trace(trace: Mapping[str, int], *, description: str) -> None:
    missing = sorted(set(EXPECTED_TRACE_VALUES) - set(trace))
    unexpected = sorted(set(trace) - set(EXPECTED_TRACE_VALUES))
    non_integer = sorted(key for key, value in trace.items() if type(value) is not int)
    mismatches = sorted(
        key for key, expected in EXPECTED_TRACE_VALUES.items()
        if type(trace.get(key)) is int and trace[key] != expected
    )
    if missing or unexpected or non_integer or mismatches:
        raise EvidenceError(f"{description} violates the fixed {len(EXPECTED_TRACE_VALUES)}-field trace contract")


def normalize_command(command: Sequence[str], temporary: Path, source: Path | None) -> list[str]:
    normalized = []
    temporary_text = str(temporary)
    source_text = str(source) if source is not None else None
    for part in command:
        if source_text is not None and (part == source_text or part.startswith(source_text + "/")):
            normalized.append(NORMALIZED_PINNED_SOURCE + part[len(source_text):])
        elif part == temporary_text or part.startswith(temporary_text + "/"):
            normalized.append(NORMALIZED_EVIDENCE_ROOT + part[len(temporary_text):])
        else:
            normalized.append(part)
    return normalized


def c_trace_command(
    compiler: str, source: Path, probe_source: Path, binary: Path, schema: Mapping[str, Any]
) -> list[str]:
    return [
        compiler, "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        *schema["compile_definitions"], "-I", str(source / "include"), "-I", str(source / "src"),
        *schema["release_flags"], str(probe_source),
        *(str(source / member) for member in schema["release_source_set"]),
        "-pthread", "-o", str(binary),
    ]


def validate_c_command(command: Sequence[str], schema: Mapping[str, Any]) -> None:
    definitions = [part for part in command if part in EXPECTED_COMPILE_DEFINITIONS]
    flags = [part for part in command if part in run.CONFIGURATION_PROFILES["release"]]
    if definitions != list(schema["compile_definitions"]) or flags != list(schema["release_flags"]):
        raise EvidenceError("process-done pthread-key C release command drifted")
    if "-pthread" not in command or "-ftls-model=initial-exec" not in command:
        raise EvidenceError("process-done pthread-key C command lacks pthread/TLS requirements")


def validate_normalized_c_command(command: object, schema: Mapping[str, Any]) -> None:
    if not isinstance(command, list) or not command or Path(command[0]).name != "musl-gcc":
        raise EvidenceError("process-done pthread-key C compiler drifted")
    expected = [
        "-std=c11", "-fPIC", "-ftls-model=initial-exec", *schema["compile_definitions"],
        "-I", f"{NORMALIZED_PINNED_SOURCE}/include", "-I", f"{NORMALIZED_PINNED_SOURCE}/src",
        *schema["release_flags"], f"{NORMALIZED_EVIDENCE_ROOT}/process-done-pthread-key.c",
        *(f"{NORMALIZED_PINNED_SOURCE}/{member}" for member in schema["release_source_set"]),
        "-pthread", "-o", f"{NORMALIZED_EVIDENCE_ROOT}/process-done-pthread-key-c",
    ]
    if command[1:] != expected:
        raise EvidenceError("process-done pthread-key C command drifted")


def build_c_trace(
    compiler: str, readelf: str, source: Path, temporary: Path, schema: Mapping[str, Any]
) -> dict[str, Any]:
    probe_source = temporary / "process-done-pthread-key.c"
    binary = temporary / "process-done-pthread-key-c"
    probe_source.write_text(C_TRACE_PROBE, encoding="utf-8")
    command = c_trace_command(compiler, source, probe_source, binary, schema)
    validate_c_command(command, schema)
    try:
        run.require_success(run.command_record(command, cwd=source), "pinned C process-done pthread-key fixture build")
        header = run.command_record((readelf, "-h", str(binary)), cwd=source)
        run.require_success(header, "pinned C process-done pthread-key ELF identity")
        elf = run.parse_elf_identity(str(header["stdout"]), "x86_64")
        execution = run.command_record((str(binary),), cwd=source)
        if int(execution["status"]) != 0:
            raise EvidenceError(
                "pinned C process-done pthread-key fixture execution failed "
                f"({execution['status']}):\n{execution['stdout']}{execution['stderr']}"
            )
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    trace = parse_trace(str(execution["stdout"]))
    try:
        validate_trace(trace, description="pinned C process-done pthread-key trace")
    except EvidenceError as error:
        raise EvidenceError(f"{error}: {json.dumps(trace, sort_keys=True)}") from error
    return {
        "build_command": normalize_command(command, temporary, source),
        "elf": elf,
        "run_command": [f"{NORMALIZED_EVIDENCE_ROOT}/process-done-pthread-key-c"],
        "source_sha256": sha256_bytes(C_TRACE_PROBE.encode("utf-8")),
        "trace": trace,
    }


def report_from_results(
    schema: Mapping[str, Any],
    provenance: Mapping[str, str],
    archive_sha256: str,
    anchors: Sequence[Mapping[str, Any]],
    c_probe: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "c_probe": dict(c_probe),
        "format": 1,
        "kind": "mimalloc-x86_64-process-done-pthread-key-c-oracle-evidence",
        "profile": schema["profile"],
        "provenance": dict(provenance),
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


def validate_report(report: Mapping[str, Any]) -> None:
    required = {"c_probe", "format", "kind", "profile", "provenance", "scope", "source", "status", "target", "trace", "upstream"}
    if not isinstance(report, dict) or set(report) != required:
        raise EvidenceError("process-done pthread-key report schema drifted")
    if type(report["format"]) is not int or report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("process-done pthread-key report must be a passing format-1 result")
    if report["kind"] != "mimalloc-x86_64-process-done-pthread-key-c-oracle-evidence" or report["profile"] != EXPECTED_PROFILE:
        raise EvidenceError("process-done pthread-key report identity drifted")
    if (not exactly_matches(report["target"], EXPECTED_TARGET)
            or not exactly_matches(report["upstream"], EXPECTED_UPSTREAM)
            or not exactly_matches(report["scope"], EXPECTED_SCOPE)):
        raise EvidenceError("process-done pthread-key report boundary drifted")
    if not any(exactly_matches(report["provenance"], value) for value in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    )):
        raise EvidenceError("process-done pthread-key report lacks native x86-64 provenance")
    schema = load_schema()
    if not exactly_matches(report["trace"], schema["trace"]):
        raise EvidenceError("process-done pthread-key report trace contract drifted")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"archive_sha256", "anchors", "release_flags", "release_source_set"}:
        raise EvidenceError("process-done pthread-key report source drifted")
    if (source["archive_sha256"] != run.load_pin()["sha256"]
            or not exactly_matches(source["anchors"], schema["source_anchors"])
            or not exactly_matches(source["release_flags"], schema["release_flags"])
            or not exactly_matches(source["release_source_set"], schema["release_source_set"])):
        raise EvidenceError("process-done pthread-key report source identity drifted")
    c_probe = report["c_probe"]
    if not isinstance(c_probe, dict) or set(c_probe) != {"build_command", "elf", "run_command", "source_sha256", "trace"}:
        raise EvidenceError("process-done pthread-key C probe record drifted")
    if (not exactly_matches(c_probe["elf"], EXPECTED_C_ELF)
            or c_probe["run_command"] != [f"{NORMALIZED_EVIDENCE_ROOT}/process-done-pthread-key-c"]
            or c_probe["source_sha256"] != sha256_bytes(C_TRACE_PROBE.encode("utf-8"))):
        raise EvidenceError("process-done pthread-key C probe identity drifted")
    validate_normalized_c_command(c_probe["build_command"], schema)
    validate_trace(c_probe["trace"], description="recorded process-done pthread-key trace")


def require_native_x86_64() -> dict[str, str]:
    try:
        return run.require_native_x86_64()
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error


def run_evidence(*, offline: bool, report_path: Path) -> dict[str, Any]:
    provenance = require_native_x86_64()
    schema = load_schema()
    try:
        pin = run.load_pin()
        archive = run.fetch_archive(pin, offline)
    except run.HarnessError as error:
        raise EvidenceError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-process-done-pthread-key-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            source = run.safe_extract(archive, temporary / "source", pin["archive_root"])
            compiler = run.require_tool("musl-gcc")
            readelf = run.require_tool("readelf")
        except run.HarnessError as error:
            raise EvidenceError(str(error)) from error
        anchors = validate_source_anchors(schema, source)
        c_probe = build_c_trace(compiler, readelf, source, temporary, schema)
        report = report_from_results(schema, provenance, sha256_bytes(archive.read_bytes()), anchors, c_probe)
    validate_report(report)
    run.write_json(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    arguments = parser.parse_args()
    try:
        report = run_evidence(offline=arguments.offline, report_path=arguments.report)
    except (EvidenceError, OSError, json.JSONDecodeError) as error:
        print(f"allocator x86-64 process-done pthread-key evidence: FAIL: {error}", file=os.sys.stderr)
        return 1
    print(
        "allocator x86-64 process-done pthread-key evidence: PASS "
        f"({len(report['trace']['expected_values'])} logical values; report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
