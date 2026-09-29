#define _POSIX_C_SOURCE 200809L

#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this fixture requires native Linux x86-64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif

typedef struct concurrent_init_trace_s {
  atomic_bool begin_contender;
  atomic_bool contender_entered;
  atomic_bool contender_returned;
  bool initialized_at_callback;
  bool reentry_preserves_owner;
  bool contender_waits;
  bool ready_owner_stable;
  bool contender_observed_ready;
  bool contender_no_tld;
  bool counters_preserved;
  bool owner_identity_preserved;
  mi_theap_t* first_default;
  size_t first_total;
  size_t first_live;
  unsigned callback_count;
} concurrent_init_trace_t;

static void* contender_main(void* argument) {
  concurrent_init_trace_t* const trace = (concurrent_init_trace_t*)argument;
  while (!atomic_load_explicit(&trace->begin_contender, memory_order_acquire)) { }
  const bool initially_empty = !mi_theap_is_initialized(_mi_theap_default());
  atomic_store_explicit(&trace->contender_entered, true, memory_order_release);
  mi_process_init();
  trace->contender_no_tld = initially_empty && !mi_theap_is_initialized(_mi_theap_default());
  trace->contender_observed_ready = mi_theap_is_initialized(trace->first_default);
  atomic_store_explicit(&trace->contender_returned, true, memory_order_release);
  return NULL;
}

static void output_callback(const char* message, void* argument) {
  concurrent_init_trace_t* const trace = (concurrent_init_trace_t*)argument;
  if (trace->callback_count != 0 || message == NULL || strstr(message, "failed to reserve") == NULL) return;
  mi_theap_t* const first = _mi_theap_default();
  if (!mi_theap_is_initialized(first)) return;
  trace->callback_count++;
  trace->first_default = first;
  mi_subproc_t* const subprocess = first->tld->subproc;
  trace->first_total = mi_atomic_load_relaxed(&subprocess->thread_total_count);
  trace->first_live = mi_atomic_load_relaxed(&subprocess->thread_count);
  trace->initialized_at_callback = trace->first_total == 1 && trace->first_live == 1;

  // A callback runs on the initializer while its once claim remains held.
  // Recursive entry must return to this callback with the same live Theap.
  mi_process_init();
  trace->reentry_preserves_owner = _mi_theap_default() == first;
  atomic_store_explicit(&trace->begin_contender, true, memory_order_release);
  while (!atomic_load_explicit(&trace->contender_entered, memory_order_acquire)) { }
  const struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000000 };
  nanosleep(&pause, NULL);
  trace->contender_waits = !atomic_load_explicit(&trace->contender_returned, memory_order_acquire);
}

int main(void) {
  concurrent_init_trace_t trace = { 0 };
  pthread_t contender;
  if (pthread_create(&contender, NULL, contender_main, &trace) != 0) return 3;

  // The process constructor is suppressed. This failed small reservation
  // delivers an output callback after source default attachment and before
  // the process once release.
  mi_option_set(mi_option_verbose, 1);
  mi_option_set(mi_option_reserve_os_memory, 1);
  mi_register_output(&output_callback, &trace);
  mi_process_init();
  if (!atomic_load_explicit(&trace.begin_contender, memory_order_acquire)) {
    atomic_store_explicit(&trace.begin_contender, true, memory_order_release);
  }
  if (pthread_join(contender, NULL) != 0) return 4;

  mi_subproc_t* const subprocess = trace.first_default == NULL ? NULL : trace.first_default->tld->subproc;
  trace.ready_owner_stable = trace.first_default != NULL
      && trace.first_default == _mi_theap_default()
      && mi_theap_is_initialized(_mi_theap_default());
  trace.owner_identity_preserved = trace.first_default != NULL;
  trace.counters_preserved = subprocess != NULL
      && trace.first_total == mi_atomic_load_relaxed(&subprocess->thread_total_count)
      && trace.first_live == mi_atomic_load_relaxed(&subprocess->thread_count);

  printf("CRABC_MI_CONCURRENT_INIT_C_TRACE_BEGIN\n");
#define FIELD(name) printf("trace.concurrent_init." #name "=%d\n", trace.name)
  FIELD(initialized_at_callback);
  FIELD(reentry_preserves_owner);
  FIELD(contender_waits);
  FIELD(ready_owner_stable);
  FIELD(contender_observed_ready);
  FIELD(contender_no_tld);
  FIELD(counters_preserved);
  FIELD(owner_identity_preserved);
#undef FIELD
  printf("CRABC_MI_CONCURRENT_INIT_C_TRACE_END\n");
  return trace.callback_count == 1 && trace.initialized_at_callback
      && trace.reentry_preserves_owner && trace.contender_waits
      && trace.ready_owner_stable && trace.contender_observed_ready
      && trace.contender_no_tld && trace.counters_preserved
      && trace.owner_identity_preserved ? 0 : 2;
}
