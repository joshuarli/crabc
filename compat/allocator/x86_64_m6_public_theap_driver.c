#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct worker_input_s {
  mi_theap_t* parent_default;
  bool complete;
  mi_subproc_id_t subprocess;
} worker_input_t;

static size_t collect_calls;
static size_t collect_forced;
static bool collect_default_preserved;
static mi_theap_t* collect_default;

static void collect_callback(bool force, unsigned long long heartbeat, void* argument) {
  (void)heartbeat;
  (void)argument;
  collect_calls++;
  collect_forced += force;
  collect_default_preserved = collect_default_preserved && mi_theap_get_default() == collect_default;
}

static bool all_zero(const unsigned char* block, size_t size) {
  for (size_t index = 0; index < size; index++) {
    if (block[index] != 0) return false;
  }
  return true;
}

typedef struct theap_visit_s {
  mi_heap_t* heap;
  mi_theap_t* default_theap;
  void* marker;
  size_t calls;
  size_t areas;
  size_t blocks;
  size_t found;
  bool ownership;
  bool defaults;
  bool stop;
} theap_visit_t;

static bool theap_visitor(const mi_heap_t* heap, const mi_heap_area_t* area,
                          void* block, size_t size, void* argument) {
  theap_visit_t* trace = argument;
  trace->calls++;
  trace->ownership = trace->ownership && heap == trace->heap && size == area->block_size;
  trace->defaults = trace->defaults && mi_theap_get_default() == trace->default_theap;
  if (block == NULL) trace->areas++;
  else {
    trace->blocks++;
    trace->found += block == trace->marker;
    trace->ownership = trace->ownership && mi_heap_of(block) == trace->heap;
  }
  return !trace->stop;
}

static bool run_case(const char* name, mi_theap_t* parent_default) {
  mi_heap_t* main_heap = mi_heap_main();
  mi_theap_t* base = mi_theap_get_default();
  if (main_heap == NULL || base == NULL) return false;
  printf("%s.base=%d,%d,%d\n", name, mi_heap_theap(main_heap) == base,
         parent_default == NULL || base != parent_default,
         parent_default != NULL && base == parent_default);

  mi_heap_t* heap = mi_heap_new();
  if (heap == NULL) return false;
  mi_theap_t* other = mi_heap_theap(heap);
  if (other == NULL) return false;
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.%s=%d,%d,%d\n", name,
          _mi_theap_heap(base) == main_heap,
          _mi_theap_heap(other) == heap,
          base->tld == other->tld);
#endif
  printf("%s.other=%d,%d,%d\n", name, other != base,
         mi_theap_get_default() == base, mi_heap_theap(heap) == other);

  mi_theap_t* rejected = mi_theap_set_default(NULL);
  printf("%s.reject=%d,%d\n", name, rejected == base,
         mi_theap_get_default() == base);

  void* direct_before = mi_theap_malloc(other, 64);
  if (direct_before == NULL) return false;
  printf("%s.direct_before=%d,%d\n", name,
         mi_heap_of(direct_before) == heap, mi_theap_get_default() == base);

  mi_theap_t* previous = mi_theap_set_default(other);
  printf("%s.switch=%d,%d,%d\n", name, previous == base,
         mi_theap_get_default() == other, mi_heap_theap(main_heap) == base);

  void* switched = mi_malloc(80);
  void* explicit_main = mi_theap_malloc(base, 96);
  void* zero = mi_theap_zalloc(other, 32);
  if (switched == NULL || explicit_main == NULL || zero == NULL) return false;
  printf("%s.allocate=%d,%d,%d,%d\n", name,
         mi_heap_of(switched) == heap, mi_heap_of(explicit_main) == main_heap,
         mi_heap_of(zero) == heap, all_zero((const unsigned char*)zero, 32));
  printf("%s.still_switched=%d,%d\n", name,
         mi_theap_get_default() == other, mi_heap_theap(heap) == other);

  void* count = mi_theap_calloc(other, 7, 13);
  void* small = mi_theap_malloc_small(other, 128);
  void* zero_small = mi_theap_zalloc_small(other, 96);
  void* aligned = mi_theap_malloc_aligned(other, 73, 4096);
  void* zero_aligned = mi_theap_zalloc_aligned(other, 129, 1024 * 1024);
  void* csize = mi_theap_malloc_csize(other, 32);
  void* csize_large = mi_theap_malloc_csize(other, 2048);
  void* zero_csize = mi_theap_zalloc_csize(other, 32);
  void* zero_csize_large = mi_theap_zalloc_csize(other, 2048);
  if (count == NULL || small == NULL || zero_small == NULL || aligned == NULL ||
      zero_aligned == NULL || csize == NULL || csize_large == NULL ||
      zero_csize == NULL || zero_csize_large == NULL) return false;
  printf("%s.variants=%d,%d,%d,%d,%d,%d,%d,%d,%d\n", name,
         mi_heap_of(count) == heap && all_zero(count, 91),
         mi_heap_of(small) == heap,
         mi_heap_of(zero_small) == heap && all_zero(zero_small, 96),
         mi_heap_of(aligned) == heap && (uintptr_t)aligned % 4096 == 0,
         mi_heap_of(zero_aligned) == heap && all_zero(zero_aligned, 129) &&
           (uintptr_t)zero_aligned % (1024 * 1024) == 0,
         mi_heap_of(csize) == heap, mi_heap_of(csize_large) == heap,
         mi_heap_of(zero_csize) == heap && all_zero(zero_csize, 32),
         mi_heap_of(zero_csize_large) == heap);

  errno = 73;
  volatile size_t too_many = SIZE_MAX;
  void* overflow = mi_theap_calloc(other, too_many, 2);
  printf("%s.overflow=%d,%d\n", name, overflow == NULL, errno == 73);
  errno = 0;
  void* invalid = mi_theap_malloc_aligned(other, 33, 3);
  printf("%s.bad_alignment=%d,%d\n", name, invalid == NULL, errno == EINVAL);

  void* main_aligned = mi_theap_zalloc_aligned(base, 79, 4096);
  void* default_aligned = mi_zalloc_aligned(81, 4096);
  if (main_aligned == NULL || default_aligned == NULL) return false;
  printf("%s.aligned_selection=%d,%d,%d,%d\n", name,
         mi_heap_of(main_aligned) == main_heap && all_zero(main_aligned, 79),
         mi_heap_of(default_aligned) == heap && all_zero(default_aligned, 81),
         mi_theap_get_default() == other,
         mi_heap_theap(main_heap) == base);

  void* default_grown = mi_rezalloc_aligned(default_aligned, 8192, 4096);
  if (default_grown == NULL) return false;
  default_aligned = default_grown;
  printf("%s.default_aligned_growth=%d,%d,%d\n", name,
         mi_heap_of(default_aligned) == heap, all_zero(default_aligned, 8192),
         mi_theap_get_default() == other);

  memset(small, 0x6b, 128);
  void* unchanged = mi_theap_realloc(other, small, 96);
  printf("%s.reuse=%d,%d,%d\n", name, unchanged == small,
         mi_heap_of(unchanged) == heap, ((unsigned char*)unchanged)[95] == 0x6b);
  small = unchanged;
  size_t old_usable = mi_usable_size(small);
  memset(small, 0x6b, old_usable);
  void* expanded = mi_theap_rezalloc(other, small, 512);
  if (expanded == NULL) return false;
  printf("%s.expand=%d,%d,%d\n", name,
         mi_heap_of(expanded) == heap, ((unsigned char*)expanded)[old_usable - 1] == 0x6b,
         all_zero((unsigned char*)expanded + old_usable, 512 - old_usable));
  small = expanded;
  errno = 91;
  void* failed = mi_theap_realloc(other, small, SIZE_MAX);
  printf("%s.failed_realloc=%d,%d,%d,%d\n", name, failed == NULL,
         errno == 91, mi_heap_of(small) == heap, ((unsigned char*)small)[0] == 0x6b);
  void* moved = mi_theap_realloc(base, small, 384);
  if (moved == NULL) return false;
  printf("%s.cross_heap=%d,%d,%d,%d\n", name, moved != small,
         mi_heap_of(moved) == main_heap, ((unsigned char*)moved)[0] == 0x6b,
         mi_theap_get_default() == other);
  small = moved;
  void* empty = mi_theap_realloc(other, small, 0);
  if (empty == NULL) return false;
  printf("%s.zero_realloc=%d,%d\n", name,
         mi_heap_of(empty) == heap, ((unsigned char*)empty)[0] == 0);
  small = empty;
  void* null_zero = mi_theap_rezalloc(other, NULL, 49);
  if (null_zero == NULL) return false;
  printf("%s.null_rezalloc=%d,%d\n", name,
         mi_heap_of(null_zero) == heap, all_zero(null_zero, 49));

  mi_theap_guarded_set_sample_rate(other, 1, 123);
  mi_theap_guarded_set_size_bound(other, 32, 1);
  mi_theap_guarded_set_sample_rate(NULL, 1, 0);
  mi_theap_guarded_set_size_bound(NULL, 1, 2);
  printf("%s.guarded=%d\n", name, mi_theap_get_default() == other);
  mi_stats_t statistics;
  mi_stats_init(&statistics);
  bool stats_ok = mi_theap_stats_get(other, &statistics);
  bool header = statistics.size == sizeof(statistics) && statistics.version == MI_STAT_VERSION;
  statistics.size--;
  mi_stats_t before = statistics;
  bool size_refused = !mi_theap_stats_get(other, &statistics) && memcmp(&before, &statistics, sizeof(statistics)) == 0;
  mi_stats_init(&statistics);
  statistics.version++;
  before = statistics;
  bool version_refused = !mi_theap_stats_get(other, &statistics) && memcmp(&before, &statistics, sizeof(statistics)) == 0;
  mi_stats_init(&statistics);
  printf("%s.stats=%d,%d,%d,%d,%d,%d,%d\n", name, stats_ok, header,
         size_refused, version_refused, !mi_theap_stats_get(other, NULL),
         mi_theap_stats_get(base, &statistics), mi_theap_get_default() == other);
  theap_visit_t visited = {heap, other, count, 0, 0, 0, 0, true, true, false};
  bool visit_ok = mi_theap_visit_blocks(other, true, theap_visitor, &visited);
  theap_visit_t areas = {heap, other, count, 0, 0, 0, 0, true, true, false};
  bool area_ok = mi_theap_visit_blocks(other, false, theap_visitor, &areas);
  theap_visit_t stopped = {heap, other, count, 0, 0, 0, 0, true, true, true};
  bool short_circuit = !mi_theap_visit_blocks(other, true, theap_visitor, &stopped);
  printf("%s.visitor=%d,%d,%d,%d,%d,%d,%d,%d\n", name, visit_ok,
         visited.areas > 0 && visited.blocks >= 9 && visited.found == 1,
         visited.ownership, visited.defaults,
         area_ok && areas.areas > 0 && areas.blocks == 0,
         short_circuit && stopped.calls == 1,
         mi_theap_visit_blocks(NULL, true, NULL, NULL), mi_theap_get_default() == other);
  mi_free(count);
  mi_free(small);
  mi_free(zero_small);
  mi_free(aligned);
  mi_free(zero_aligned);
  mi_free(csize);
  mi_free(csize_large);
  mi_free(zero_csize);
  mi_free(zero_csize_large);
  mi_free(main_aligned);
  mi_free(default_aligned);
  mi_free(null_zero);

  mi_free(direct_before);
  mi_free(switched);
  mi_free(explicit_main);
  mi_free(zero);
  collect_calls = 0;
  collect_forced = 0;
  collect_default_preserved = true;
  collect_default = other;
  mi_register_deferred_free(collect_callback, NULL);
  mi_theap_collect(NULL, true);
  mi_theap_collect(other, false);
  mi_theap_collect(other, true);
  mi_theap_collect(base, true);
  mi_collect(true);
  mi_register_deferred_free(NULL, NULL);
  printf("%s.collect=%d,%d,%d,%d\n", name, collect_calls == 4,
         collect_forced == 3, collect_default_preserved, mi_theap_get_default() == other);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.%s.collect_empty=%d\n", name, other->page_count == 0);
#endif
  previous = mi_theap_set_default(base);
  printf("%s.restore=%d,%d\n", name, previous == other,
         mi_theap_get_default() == base);
  void* after = mi_malloc(48);
  if (after == NULL) return false;
  printf("%s.after=%d,%d\n", name, mi_heap_of(after) == main_heap,
         mi_theap_get_default() == base);
  mi_free(after);
  mi_heap_delete(heap);
  printf("%s.done=%d\n", name, mi_theap_get_default() == base);
  return true;
}

static void* worker(void* argument) {
  worker_input_t* input = (worker_input_t*)argument;
  if (input->subprocess._mi_subproc_id != NULL) mi_subproc_add_current_thread(input->subprocess);
  input->complete = run_case(input->subprocess._mi_subproc_id == NULL ? "worker" : "child", input->parent_default);
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_PUBLIC_THEAP_TRACE_BEGIN");
  if (!run_case("main", NULL)) return 4;
  mi_theap_t* main_default = mi_theap_get_default();
  worker_input_t input = { main_default, false, { NULL } };
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &input) != 0) return 2;
  if (pthread_join(thread, NULL) != 0 || !input.complete) return 3;
  printf("main.after_worker=%d\n", mi_theap_get_default() == main_default);
  pid_t child = fork();
  if (child == 0) {
    bool complete = run_case("fork", main_default);
    _exit(complete ? 0 : 5);
  }
  int status = -1;
  bool joined = child > 0 && waitpid(child, &status, 0) == child;
  printf("main.after_fork=%d,%d\n", joined && WIFEXITED(status) && WEXITSTATUS(status) == 0,
         mi_theap_get_default() == main_default);
  mi_subproc_id_t subprocess = mi_subproc_new();
  if (subprocess._mi_subproc_id == NULL) return 6;
  worker_input_t child_input = { NULL, false, subprocess };
  if (pthread_create(&thread, NULL, worker, &child_input) != 0) return 7;
  if (pthread_join(thread, NULL) != 0 || !child_input.complete) return 8;
  mi_subproc_destroy(subprocess);
  printf("main.after_child=%d\n", mi_theap_get_default() == main_default);
  puts("CRABC_MI_M6_PUBLIC_THEAP_TRACE_END");
  return 0;
}
