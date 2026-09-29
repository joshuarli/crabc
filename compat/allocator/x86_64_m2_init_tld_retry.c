/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* The direct pinned mi_tld_create failure consumes a ticket; a later request
   receives the next ticket and its one live registration is released. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <mimalloc.h>
#include <mimalloc/atomic.h>
#include <mimalloc/prim.h>
#include <mimalloc/prim-tls.h>
#include <mimalloc/internal.h>

static mi_theap_t detached_meta = mi_init_struct_zero;
static mi_decl_cache_align mi_tld_t retry_storage = mi_init_struct_zero;
static size_t requests;
static size_t releases;
static size_t errors;

static void* retry_meta_zalloc(mi_subproc_t* subproc, size_t size, mi_memid_t* memid) {
  (void)subproc;
  if (size != sizeof(mi_tld_t) || memid == NULL) return NULL;
  requests++;
  if (requests == 1) return NULL;
  *memid = _mi_memid_create_malloc(&retry_storage, sizeof(retry_storage), true);
  return &retry_storage;
}

static void retry_meta_free(mi_subproc_t* subproc, void* pointer, mi_memid_t memid) {
  (void)subproc;
  (void)memid;
  if (pointer == &retry_storage) releases++;
}

static void retry_error_message(int error) {
  if (error == ENOMEM) errors++;
}

#define _mi_meta_zalloc(subproc, size, memid) retry_meta_zalloc(subproc, size, memid)
#define _mi_meta_free(subproc, pointer, memid) retry_meta_free(subproc, pointer, memid)
#define _mi_error_message(error, format, ...) retry_error_message(error)
#include "init.c"
#undef _mi_error_message
#undef _mi_meta_free
#undef _mi_meta_zalloc

static size_t field;
static void emit(size_t value) {
  printf("m2.init.tld_retry.%zu=%zu\n", field++, value);
}

int main(void) {
  mi_subproc_t* subproc = _mi_subproc_main();
  subproc->theap_meta = &detached_meta;
  mi_atomic_store_relaxed(&subproc->thread_total_count, 1);
  mi_atomic_store_relaxed(&subproc->thread_count, 1);

  mi_tld_t* failed = mi_tld_create(subproc);
  const size_t failed_total = mi_atomic_load_relaxed(&subproc->thread_total_count);
  const size_t failed_live = mi_atomic_load_relaxed(&subproc->thread_count);
  mi_tld_t* retried = mi_tld_create(subproc);
  const size_t retry_sequence = retried == NULL ? 0 : retried->thread_seq;
  const size_t retry_total = mi_atomic_load_relaxed(&subproc->thread_total_count);
  const size_t retry_live = mi_atomic_load_relaxed(&subproc->thread_count);
  if (retried != NULL) mi_tld_free(retried);
  const size_t final_live = mi_atomic_load_relaxed(&subproc->thread_count);

  emit(failed == NULL);
  emit(failed_total);
  emit(failed_live);
  emit(retried == &retry_storage);
  emit(retry_sequence);
  emit(retry_total);
  emit(retry_live);
  emit(releases);
  emit(final_live);
  return failed == NULL && failed_total == 2 && failed_live == 1 && errors == 1 &&
      retried == &retry_storage && retry_sequence == 2 && retry_total == 3 &&
      retry_live == 2 && requests == 2 && releases == 1 && final_live == 1 ? 0 : 10;
}
