/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/*
  Pinned v3.5.0 `mi_page_map_init_once` (src/page-map.c:272-345) when its
  initial top-level commit or its trailing-submap commit fails and the
  `_mi_os_free` cleanup's `munmap` fails too: pinned `mi_os_prim_free` warns
  and leaks the mapping, and initialization fails. Printed in the field order
  of `page_map::tests::emit_m2_page_map_init_cleanup_c_rust_trace`.

  `page-map.c` is included directly so the static once body runs per
  variant, with its `_mi_os_commit` calls lexically counted and failed at a
  chosen ordinal. `munmap` is link-wrapped to fail the first call after that
  commit failure and record the leaked range.
*/
#define _DEFAULT_SOURCE  /* mincore under -std=c11 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>

#include "os.c"

static size_t commit_calls;
static size_t fail_commit_ordinal;
static bool commit_failed;

static bool m2_page_map_commit(mi_subproc_t* subproc, void* addr, size_t size, bool* is_zero) {
  if (++commit_calls == fail_commit_ordinal) {
    commit_failed = true;
    return false;
  }
  return _mi_os_commit(subproc, addr, size, is_zero);
}

int __real_munmap(void* addr, size_t length);
static size_t munmap_after_failure;
static void* leaked_addr;
static size_t leaked_length;

int __wrap_munmap(void* addr, size_t length) {
  if (commit_failed) {
    commit_failed = false;
    munmap_after_failure++;
    leaked_addr = addr;
    leaked_length = length;
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(addr, length);
}

#define _mi_os_commit m2_page_map_commit
#include "page-map.c"
#undef _mi_os_commit

#include "init.c"

static size_t field;
static void emit(size_t value) { printf("m2.page_map.init_cleanup.%zu=%zu\n", field++, value); }

int main(void) {
  _mi_detect_cpu_features();
  _mi_options_init();
  mi_option_set_enabled(mi_option_pagemap_commit, false);
  mi_option_set(mi_option_max_vabits, MI_MAX_VABITS);
  _mi_stats_init();
  _mi_os_init();
  mi_os_mem_config.has_overcommit = false;
  mi_heap_main_init();

  /* 1: the initial top-level commit fails; 2: the trailing submap commit. */
  for (size_t ordinal = 1; ordinal <= 2; ordinal++) {
    commit_calls = 0;
    fail_commit_ordinal = ordinal;
    commit_failed = false;
    munmap_after_failure = 0;
    leaked_addr = NULL;
    const bool initialized = mi_page_map_init_once();
    fail_commit_ordinal = 0;
    unsigned char residency = 0;
    const bool leaked_live = leaked_addr != NULL
        && mincore(leaked_addr, _mi_os_page_size(), &residency) == 0;
    emit(ordinal);
    emit(!initialized);
    emit(commit_calls);
    emit(munmap_after_failure);
    emit(leaked_live);
    if (leaked_addr != NULL && __real_munmap(leaked_addr, leaked_length) != 0) return 2;
  }
  return 0;
}
