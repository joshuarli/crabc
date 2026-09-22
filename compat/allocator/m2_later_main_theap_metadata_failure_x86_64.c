#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

#include <mimalloc.h>
#include <mimalloc/atomic.h>
#include <mimalloc/prim.h>
#include <mimalloc/prim-tls.h>
#include <mimalloc/internal.h>

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

static bool m2_recording = false;
static size_t m2_event_count = 0;
static size_t m2_total_event = 0;
static size_t m2_tld_metadata_event = 0;
static size_t m2_live_increment_event = 0;
static size_t m2_theap_failure_event = 0;
static size_t m2_live_decrement_event = 0;
static size_t m2_tld_metadata_free_event = 0;
static size_t m2_result_event = 0;
static mi_subproc_t* m2_subproc = NULL;
static mi_heap_t* m2_heap = NULL;
static mi_theap_t* m2_heap_list_before_worker = NULL;
static mi_decl_cache_align mi_tld_t m2_tld_storage = mi_init_struct_zero;
static bool m2_worker_result_unavailable = false;
static bool m2_worker_roots_empty = false;

static void m2_record(size_t* event) {
  if (m2_recording) *event = ++m2_event_count;
}

static size_t m2_increment_relaxed(_Atomic(size_t)* target) {
  const size_t result = mi_atomic_increment_relaxed(target);
  if (m2_recording && target == &m2_subproc->thread_total_count) {
    m2_record(&m2_total_event);
  }
  else if (m2_recording && target == &m2_subproc->thread_count) {
    m2_record(&m2_live_increment_event);
  }
  return result;
}

static size_t m2_decrement_relaxed(_Atomic(size_t)* target) {
  const size_t result = mi_atomic_decrement_relaxed(target);
  if (m2_recording && target == &m2_subproc->thread_count) {
    m2_record(&m2_live_decrement_event);
  }
  return result;
}

static void* m2_meta_zalloc(mi_subproc_t* subproc, size_t size, mi_memid_t* memid) {
  if (m2_recording && subproc == m2_subproc && size == sizeof(mi_tld_t) && memid != NULL) {
    m2_record(&m2_tld_metadata_event);
    *memid = _mi_memid_create_malloc(&m2_tld_storage, sizeof(m2_tld_storage), true);
    return &m2_tld_storage;
  }
  return _mi_meta_zalloc(subproc, size, memid);
}

static void m2_meta_free(mi_subproc_t* subproc, void* pointer, mi_memid_t memid) {
  if (m2_recording && subproc == m2_subproc && pointer == &m2_tld_storage) {
    (void)memid;
    m2_record(&m2_tld_metadata_free_event);
    return;
  }
  _mi_meta_free(subproc, pointer, memid);
}

static mi_theap_t* m2_theap_alloc(mi_heap_t* heap, mi_tld_t* tld) {
  (void)heap;
  (void)tld;
  m2_record(&m2_theap_failure_event);
  return NULL;
}

#define _mi_meta_zalloc(subproc, size, memid) m2_meta_zalloc(subproc, size, memid)
#define _mi_meta_free(subproc, pointer, memid) m2_meta_free(subproc, pointer, memid)
#define _mi_theap_alloc(heap, tld) m2_theap_alloc(heap, tld)
#undef mi_atomic_increment_relaxed
#define mi_atomic_increment_relaxed(target) m2_increment_relaxed(target)
#undef mi_atomic_decrement_relaxed
#define mi_atomic_decrement_relaxed(target) m2_decrement_relaxed(target)
#include "init.c"
#undef mi_atomic_decrement_relaxed
#undef mi_atomic_increment_relaxed
#undef _mi_theap_alloc
#undef _mi_meta_free
#undef _mi_meta_zalloc

static void* m2_worker(void* ignored) {
  (void)ignored;
  m2_recording = true;
  mi_theap_t* const returned = _mi_thread_init_with_heap(m2_heap);
  m2_result_event = ++m2_event_count;
  m2_recording = false;
  m2_worker_result_unavailable = returned == NULL;
  m2_worker_roots_empty = !mi_theap_is_initialized(_mi_theap_default()) &&
      _mi_thread_local_get(m2_heap->theap) == NULL;
  return NULL;
}

int main(void) {
  if (_mi_thread_init_with_heap(NULL) == NULL) return 10;
  m2_heap = mi_heap_main();
  if (m2_heap == NULL) return 11;
  m2_subproc = m2_heap->subproc;
  if (m2_subproc == NULL) return 11;
  const bool pre_total_one = mi_atomic_load_relaxed(&m2_subproc->thread_total_count) == 1;
  const bool pre_live_one = mi_atomic_load_relaxed(&m2_subproc->thread_count) == 1;
  // This is the source main Heap's initialized static list, which retains
  // `mi_process_theap_meta`. The selected dynamic Theap failure must preserve
  // that exact baseline rather than falsely requiring a one-member Heap list.
  m2_heap_list_before_worker = m2_heap->theaps;
  const bool pre_heap_list_initialized = m2_heap_list_before_worker != NULL;
  pthread_t worker;
  if (pthread_create(&worker, NULL, m2_worker, NULL) != 0) return 12;
  if (pthread_join(worker, NULL) != 0) return 13;

  const bool total_two = mi_atomic_load_relaxed(&m2_subproc->thread_total_count) == 2;
  const bool live_one = mi_atomic_load_relaxed(&m2_subproc->thread_count) == 1;
  const bool no_shared_theap_list_member = m2_heap->theaps == m2_heap_list_before_worker;
  const bool c_order = m2_event_count == 7 && m2_total_event == 1 &&
      m2_tld_metadata_event == 2 && m2_live_increment_event == 3 &&
      m2_theap_failure_event == 4 && m2_live_decrement_event == 5 &&
      m2_tld_metadata_free_event == 6 && m2_result_event == 7;
  const bool relations = pre_total_one && pre_live_one && pre_heap_list_initialized && m2_worker_result_unavailable &&
      total_two && live_one && no_shared_theap_list_member && m2_worker_roots_empty && c_order;
  if (!relations) return 14;

  puts("CRABC_MI_M2_LATER_MAIN_THEAP_METADATA_FAILURE_TRACE_BEGIN");
  U("m2.initialization.later_main_theap_failure.pre.total_thread_count_one", pre_total_one);
  U("m2.initialization.later_main_theap_failure.pre.live_thread_count_one", pre_live_one);
  U("m2.initialization.later_main_theap_failure.post.result_unavailable", m2_worker_result_unavailable);
  U("m2.initialization.later_main_theap_failure.post.total_thread_count_two", total_two);
  U("m2.initialization.later_main_theap_failure.post.live_thread_count_one", live_one);
  U("m2.initialization.later_main_theap_failure.post.no_shared_theap_list_member", no_shared_theap_list_member);
  U("m2.initialization.later_main_theap_failure.post.roots_remain_empty", m2_worker_roots_empty);
  U("m2.initialization.later_main_theap_failure.post.tld_metadata_released_before_root_publication", true);
  puts("CRABC_MI_M2_LATER_MAIN_THEAP_METADATA_FAILURE_TRACE_END");
  return 0;
}
