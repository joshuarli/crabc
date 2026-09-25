/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/*
  Pinned v3.5.0 main-subprocess VM statistics across a successful startup:
  after `mi_process_init` (which publishes the page map) and after the first
  allocation (which reserves the first arena), printed in the field order of
  `os::tests::emit_m2_startup_statistics_c_rust_trace`.
*/
#include "static.c"
#include <stdio.h>

static size_t field;
static void emit(int64_t value) { printf("m2.startup.statistics.%zu=%lld\n", field++, (long long)value); }

static void emit_statistics(void) {
  const mi_stats_t* const stats = &_mi_subproc_main()->stats;
  emit(stats->reserved.current);
  emit(stats->reserved.total);
  emit(stats->reserved.peak);
  emit(stats->committed.current);
  emit(stats->committed.total);
  emit(stats->committed.peak);
  emit(stats->mmap_calls.total);
  emit(stats->commit_calls.total);
}

int main(void) {
  mi_process_init();
  emit_statistics();
  void* const block = mi_malloc(16);
  if (block == NULL) return 1;
  emit_statistics();
  mi_free(block);
  emit_statistics();
  return 0;
}
