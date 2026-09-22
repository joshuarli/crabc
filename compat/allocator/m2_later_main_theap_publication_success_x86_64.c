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
static size_t m2_live_event = 0;
static size_t m2_theap_metadata_event = 0;
static size_t m2_theap_init_event = 0;
static size_t m2_default_root_event = 0;
static size_t m2_fast_root_event = 0;
static size_t m2_result_event = 0;
static mi_subproc_t* m2_subproc = NULL;
static mi_heap_t* m2_heap = NULL;
static mi_theap_t* m2_heap_list_before_worker = NULL;
static mi_tld_t* m2_tld_result = NULL;
static mi_theap_t* m2_theap_result = NULL;
static bool m2_result_available = false;
static bool m2_tld_metadata_malloc = false;
static bool m2_theap_metadata_malloc = false;
static bool m2_theap_initialized = false;
static bool m2_tld_list_contains = false;
static bool m2_heap_list_contains = false;
static bool m2_default_matches = false;
static bool m2_fast_matches = false;
static bool m2_live_two = false;
static bool m2_finish_default_empty = false;
static bool m2_finish_fast_empty = false;

static void m2_record(size_t* event) {
  if (m2_recording) *event = ++m2_event_count;
}

static size_t m2_increment_relaxed(_Atomic(size_t)* target) {
  const size_t result = mi_atomic_increment_relaxed(target);
  if (m2_recording && target == &m2_subproc->thread_total_count) {
    m2_record(&m2_total_event);
  }
  else if (m2_recording && target == &m2_subproc->thread_count) {
    m2_record(&m2_live_event);
  }
  return result;
}

static void* m2_meta_zalloc(mi_subproc_t* subproc, size_t size, mi_memid_t* memid) {
  void* const result = _mi_meta_zalloc(subproc, size, memid);
  if (m2_recording && size == sizeof(mi_tld_t)) {
    m2_tld_result = (mi_tld_t*)result;
    m2_record(&m2_tld_metadata_event);
  }
  return result;
}

static mi_theap_t* m2_theap_alloc(mi_heap_t* heap, mi_tld_t* tld) {
  mi_theap_t* const result = _mi_theap_alloc(heap, tld);
  if (m2_recording) {
    m2_theap_result = result;
    m2_record(&m2_theap_metadata_event);
  }
  return result;
}

static void m2_theap_init(mi_theap_t* theap, mi_heap_t* heap, mi_tld_t* tld) {
  _mi_theap_init(theap, heap, tld);
  m2_record(&m2_theap_init_event);
}

static void m2_default_set(mi_theap_t* theap) {
  _mi_theap_default_set(theap);
  m2_record(&m2_default_root_event);
}

static bool m2_heap_theap_set(mi_heap_t* heap, mi_theap_t* theap) {
  const bool result = _mi_heap_theap_set(heap, theap);
  m2_record(&m2_fast_root_event);
  return result;
}

#define _mi_meta_zalloc(subproc, size, memid) m2_meta_zalloc(subproc, size, memid)
#define _mi_theap_alloc(heap, tld) m2_theap_alloc(heap, tld)
#define _mi_theap_init(theap, heap, tld) m2_theap_init(theap, heap, tld)
#define _mi_theap_default_set(theap) m2_default_set(theap)
#define _mi_heap_theap_set(heap, theap) m2_heap_theap_set(heap, theap)
#undef mi_atomic_increment_relaxed
#define mi_atomic_increment_relaxed(target) m2_increment_relaxed(target)
#include "init.c"
#undef mi_atomic_increment_relaxed
#undef _mi_heap_theap_set
#undef _mi_theap_default_set
#undef _mi_theap_init
#undef _mi_theap_alloc
#undef _mi_meta_zalloc

static void* m2_worker(void* ignored) {
  (void)ignored;
  m2_recording = true;
  mi_theap_t* const returned = _mi_thread_init_with_heap(m2_heap);
  m2_result_event = ++m2_event_count;
  m2_recording = false;

  m2_result_available = returned != NULL;
  if (returned != NULL) {
    m2_tld_metadata_malloc = m2_tld_result != NULL && m2_tld_result == returned->tld &&
        m2_tld_result->memid.memkind == MI_MEM_MALLOC &&
        m2_tld_result->memid.mem.malloc.base == m2_tld_result &&
        m2_tld_result->memid.mem.malloc.size == sizeof(*m2_tld_result);
    m2_theap_metadata_malloc = m2_theap_result == returned &&
        returned->memid.memkind == MI_MEM_MALLOC &&
        returned->memid.mem.malloc.base == returned &&
        returned->memid.mem.malloc.size == sizeof(*returned);
    m2_theap_initialized = mi_theap_is_initialized(returned);
    m2_tld_list_contains = returned->tld->theaps == returned &&
        returned->tnext == NULL && returned->tprev == NULL;
    m2_heap_list_contains = m2_heap->theaps == returned &&
        returned->hprev == NULL && returned->hnext == m2_heap_list_before_worker;
    m2_default_matches = _mi_theap_default() == returned;
    m2_fast_matches = _mi_thread_local_get(m2_heap->theap) == returned;
    m2_live_two = mi_atomic_load_relaxed(&m2_subproc->thread_count) == 2;
  }

  // Explicit fixture hygiene only: this invokes the ordinary source finish
  // after the attached post-state was observed. It does not exercise an
  // automatic pthread destructor, process shutdown, or fork route.
  _mi_thread_done(NULL);
  m2_finish_default_empty = !mi_theap_is_initialized(_mi_theap_default());
  m2_finish_fast_empty = _mi_thread_local_get(m2_heap->theap) == NULL;
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
  // `mi_heap_main_init_once` permanently links the static metadata Theap
  // before ticket-zero's static main Theap. A later dynamic member therefore
  // pushes onto a nonempty source list. Keep that real initialized image as
  // the before/after witness instead of claiming its metadata Theap vanished.
  m2_heap_list_before_worker = m2_heap->theaps;
  const bool pre_heap_list_initialized = m2_heap_list_before_worker != NULL;
  pthread_t worker;
  if (pthread_create(&worker, NULL, m2_worker, NULL) != 0) return 12;
  if (pthread_join(worker, NULL) != 0) return 13;

  const bool total_two = mi_atomic_load_relaxed(&m2_subproc->thread_total_count) == 2;
  const bool finish_live_one = mi_atomic_load_relaxed(&m2_subproc->thread_count) == 1;
  const bool finish_heap_list_released = m2_heap->theaps == m2_heap_list_before_worker;
  const bool c_order = m2_event_count == 8 && m2_total_event == 1 &&
      m2_tld_metadata_event == 2 && m2_live_event == 3 &&
      m2_theap_metadata_event == 4 && m2_theap_init_event == 5 &&
      m2_default_root_event == 6 && m2_fast_root_event == 7 && m2_result_event == 8;
  const bool relations = pre_total_one && pre_live_one && pre_heap_list_initialized && m2_result_available &&
      m2_tld_metadata_malloc && m2_theap_metadata_malloc && m2_theap_initialized &&
      m2_tld_list_contains && m2_heap_list_contains && m2_default_matches &&
      m2_fast_matches && total_two && m2_live_two && c_order &&
      m2_finish_default_empty && m2_finish_fast_empty && finish_live_one && finish_heap_list_released;
  if (!relations) return 14;

  puts("CRABC_MI_M2_LATER_MAIN_THEAP_PUBLICATION_SUCCESS_TRACE_BEGIN");
  U("m2.initialization.later_main_theap_success.pre.total_thread_count_one", pre_total_one);
  U("m2.initialization.later_main_theap_success.pre.live_thread_count_one", pre_live_one);
  U("m2.initialization.later_main_theap_success.post.result_available", m2_result_available);
  U("m2.initialization.later_main_theap_success.post.tld_metadata_malloc", m2_tld_metadata_malloc);
  U("m2.initialization.later_main_theap_success.post.theap_metadata_malloc", m2_theap_metadata_malloc);
  U("m2.initialization.later_main_theap_success.post.theap_initialized", m2_theap_initialized);
  U("m2.initialization.later_main_theap_success.post.tld_list_contains_theap", m2_tld_list_contains);
  U("m2.initialization.later_main_theap_success.post.heap_list_contains_theap", m2_heap_list_contains);
  U("m2.initialization.later_main_theap_success.post.default_root_matches_theap", m2_default_matches);
  U("m2.initialization.later_main_theap_success.post.fast_root_matches_theap", m2_fast_matches);
  U("m2.initialization.later_main_theap_success.post.total_thread_count_two", total_two);
  U("m2.initialization.later_main_theap_success.post.live_thread_count_two", m2_live_two);
  U("m2.initialization.later_main_theap_success.finish.default_root_empty", m2_finish_default_empty);
  U("m2.initialization.later_main_theap_success.finish.fast_root_empty", m2_finish_fast_empty);
  U("m2.initialization.later_main_theap_success.finish.live_thread_count_one", finish_live_one);
  U("m2.initialization.later_main_theap_success.finish.heap_list_released", finish_heap_list_released);
  puts("CRABC_MI_M2_LATER_MAIN_THEAP_PUBLICATION_SUCCESS_TRACE_END");
  return 0;
}
