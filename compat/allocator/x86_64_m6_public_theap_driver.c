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

/* Configuring a live Theap leaves its existing client
   blocks, default selection, and allocation accounting unchanged. Retain
   clients across each setter call so the check covers existing allocations
   as well as requests made after configuration. */
static bool guarded_configuration(const char* name, mi_theap_t* base,
                                   mi_theap_t* selected, mi_heap_t* main_heap,
                                   mi_heap_t* heap) {
  unsigned char* selected_live = mi_theap_malloc(selected, 73);
  unsigned char* base_live = mi_theap_malloc(base, 96);
  if (selected_live == NULL || base_live == NULL) return false;
  memset(selected_live, 0x6b, 73);
  memset(base_live, 0x47, 96);
  size_t selected_usable = mi_usable_size(selected_live);
  size_t base_usable = mi_usable_size(base_live);
  bool roots = true, content = true, usable = true, stats = true;
  bool allocations = true, zero = true, aligned = true, unchanged_errno = true;
  const size_t settings[][4] = {
    {0, 0, 0, 0}, {1, 123, 1, 4096}, {17, 0, 32, 8192},
    {1024, 987, 8192, 65536}, {1, 0, 0, SIZE_MAX},
  };
  mi_theap_t* targets[] = {base, selected, NULL};
  for (size_t setting = 0; setting < sizeof(settings) / sizeof(settings[0]); setting++) {
    for (size_t target = 0; target < sizeof(targets) / sizeof(targets[0]); target++) {
      mi_stats_t before_base, before_selected, after_base, after_selected;
      mi_stats_init(&before_base); mi_stats_init(&before_selected);
      mi_stats_init(&after_base); mi_stats_init(&after_selected);
      stats &= mi_theap_stats_get(base, &before_base) &&
               mi_theap_stats_get(selected, &before_selected);
      errno = 73;
      mi_theap_guarded_set_sample_rate(targets[target], settings[setting][0], settings[setting][1]);
      mi_theap_guarded_set_size_bound(targets[target], settings[setting][2], settings[setting][3]);
      unchanged_errno &= errno == 73;
      roots &= mi_theap_get_default() == selected &&
               mi_heap_theap(main_heap) == base && mi_heap_theap(heap) == selected &&
               mi_heap_of(selected_live) == heap && mi_heap_of(base_live) == main_heap;
      usable &= mi_usable_size(selected_live) == selected_usable &&
                mi_usable_size(base_live) == base_usable;
      for (size_t i = 0; i < 73; i++) content &= selected_live[i] == 0x6b;
      for (size_t i = 0; i < 96; i++) content &= base_live[i] == 0x47;
      stats &= mi_theap_stats_get(base, &after_base) &&
               mi_theap_stats_get(selected, &after_selected) &&
               memcmp(&before_base, &after_base, sizeof(before_base)) == 0 &&
               memcmp(&before_selected, &after_selected, sizeof(before_selected)) == 0;
      unsigned char* direct = mi_theap_zalloc(selected, 257);
      unsigned char* ordinary = mi_zalloc(513);
      unsigned char* explicit_base = mi_theap_zalloc_aligned(base, 79, 128);
      if (direct == NULL || ordinary == NULL || explicit_base == NULL) return false;
      allocations &= mi_heap_of(direct) == heap && mi_heap_of(ordinary) == heap &&
                     mi_heap_of(explicit_base) == main_heap;
      zero &= all_zero(direct, 257) && all_zero(ordinary, 513) && all_zero(explicit_base, 79);
      aligned &= (uintptr_t)explicit_base % 128 == 0;
      mi_free(direct); mi_free(ordinary); mi_free(explicit_base);
    }
  }
  bool defaults = mi_theap_get_default() == selected;
  printf("%s.guarded=%d,%d,%d,%d,%d,%d,%d,%d,%d\n", name,
         roots, content, usable, stats, allocations, zero, aligned, unchanged_errno, defaults);
  mi_free(selected_live); mi_free(base_live);
  return roots && content && usable && stats && allocations && zero && aligned && unchanged_errno && defaults;
}

#if MI_GUARDED
/* Read kernel mapping permissions while each original allocation keeps its
   page live. Guard protection and its discharge are observable without
   accessing bytes outside the public usable extent. */
static bool mapping_permission(uintptr_t address, bool protected) {
  FILE* maps = fopen("/proc/self/maps", "r");
  if (maps == NULL) return false;
  char line[512], permission[5];
  unsigned long start, end;
  bool matched = false;
  while (fgets(line, sizeof(line), maps) != NULL) {
    if (sscanf(line, "%lx-%lx %4s", &start, &end, permission) == 3 &&
        start <= address && address < end) {
      matched = protected ? strncmp(permission, "---", 3) == 0
                          : strncmp(permission, "rw", 2) == 0;
      break;
    }
  }
  fclose(maps);
  return matched;
}

static bool guarded_actual(const char* name, mi_theap_t* base,
                           mi_theap_t* selected, mi_heap_t* main_heap, mi_heap_t* heap) {
  mi_theap_guarded_set_size_bound(base, 0, SIZE_MAX);
  mi_theap_guarded_set_size_bound(selected, 0, SIZE_MAX);
  mi_theap_guarded_set_sample_rate(base, 1, 0);
  mi_theap_guarded_set_sample_rate(selected, 1, 0);
  unsigned char* direct = mi_theap_zalloc(selected, 81);
  unsigned char* ordinary = mi_zalloc(81);
  unsigned char* fixed = mi_theap_zalloc_aligned(base, 79, 128);
  if (direct == NULL || ordinary == NULL || fixed == NULL) return false;
  const size_t usable = mi_usable_size(direct);
  const size_t expected = mi_option_get(mi_option_guarded_precise) != 0 ? 81 : 96;
  uintptr_t old_tail = (uintptr_t)direct + usable;
  bool geometry = usable == expected && mi_usable_size(ordinary) == expected &&
                  mi_usable_size(fixed) == 128 && (uintptr_t)fixed % 128 == 0;
  bool protection = mapping_permission(old_tail, true) &&
                    mapping_permission((uintptr_t)ordinary + mi_usable_size(ordinary), true) &&
                    mapping_permission((uintptr_t)fixed + mi_usable_size(fixed), true);
  bool zero = all_zero(direct, usable) && all_zero(ordinary, mi_usable_size(ordinary)) &&
              all_zero(fixed, mi_usable_size(fixed));
  bool ownership = mi_heap_of(direct) == heap && mi_heap_of(ordinary) == heap &&
                   mi_heap_of(fixed) == main_heap && mi_theap_get_default() == selected;
  memset(direct, 0x6b, usable);
  errno = 0;
  void* refused = mi_theap_realloc(selected, direct, SIZE_MAX);
  bool refusal = refused == NULL && errno == ENOMEM && mi_usable_size(direct) == usable &&
                 mapping_permission(old_tail, true);
  errno = 91;
  refused = mi_theap_realloc_aligned(selected, direct, SIZE_MAX, 64);
  refusal &= refused == NULL && errno == 91 && mi_heap_of(direct) == heap;
  bool retained = true;
  for (size_t i = 0; i < usable; i++) retained &= direct[i] == 0x6b;
  unsigned char* grown = mi_theap_rezalloc(selected, direct, usable + 4097);
  if (grown == NULL) return false;
  bool growth = grown != direct && mi_heap_of(grown) == heap &&
                mi_usable_size(grown) >= usable + 4097;
  for (size_t i = 0; i < usable; i++) growth &= grown[i] == 0x6b;
  bool growth_zero = all_zero(grown + usable, mi_usable_size(grown) - usable);
  bool consumed = mapping_permission(old_tail, false) &&
                  mapping_permission((uintptr_t)grown + mi_usable_size(grown), true);
  uintptr_t grown_tail = (uintptr_t)grown + mi_usable_size(grown);
  mi_free(grown);
  bool discharged = mapping_permission(grown_tail, false);
  mi_free(ordinary); mi_free(fixed);
  mi_theap_guarded_set_sample_rate(base, 0, 0);
  mi_theap_guarded_set_sample_rate(selected, 0, 0);
  printf("%s.guarded_actual=%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", name,
         geometry, protection, zero, ownership, refusal, retained, growth,
         growth_zero, consumed, discharged);
  return geometry && protection && zero && ownership && refusal && retained &&
         growth && growth_zero && consumed && discharged;
}
#endif

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

#ifdef CRABC_PUBLIC_GUARDED_CONFIGURATION_ONLY
  bool guarded = guarded_configuration(name, base, other, main_heap, heap);
#if MI_GUARDED
  guarded &= guarded_actual(name, base, other, main_heap, heap);
#endif
  previous = mi_theap_set_default(base);
  printf("%s.restore=%d,%d\n", name, previous == other, mi_theap_get_default() == base);
  mi_free(direct_before);
  mi_heap_delete(heap);
  printf("%s.done=%d\n", name, mi_theap_get_default() == base);
  return guarded;
#endif

  void* switched = mi_malloc(80);
  void* explicit_main = mi_theap_malloc(base, 96);
  void* zero = mi_theap_zalloc(other, 32);
  if (switched == NULL || explicit_main == NULL || zero == NULL) return false;
  printf("%s.allocate=%d,%d,%d,%d\n", name,
         mi_heap_of(switched) == heap, mi_heap_of(explicit_main) == main_heap,
         mi_heap_of(zero) == heap, all_zero((const unsigned char*)zero, 32));
  printf("%s.still_switched=%d,%d\n", name,
         mi_theap_get_default() == other, mi_heap_theap(heap) == other);

  bool interleaved = true;
  for (size_t cycle = 0; cycle < 4; cycle++) {
    interleaved = interleaved && mi_heap_theap(main_heap) == base;
    void* selected_block = mi_theap_malloc(other, 33);
    interleaved = interleaved && mi_heap_theap(heap) == other;
    void* main_block = mi_theap_malloc(base, 33);
    if (selected_block == NULL || main_block == NULL) return false;
    interleaved = interleaved && mi_heap_of(selected_block) == heap &&
      mi_heap_of(main_block) == main_heap && mi_theap_get_default() == other;
    mi_free(selected_block);
    mi_free(main_block);
  }
  printf("%s.interleaved=%d\n", name, interleaved);

  void* count = mi_theap_calloc(other, 7, 13);
  void* small = mi_theap_malloc_small(other, 128);
  void* zero_small = mi_theap_zalloc_small(other, 96);
  void* aligned = mi_theap_malloc_aligned(other, 73, 4096);
  void* zero_aligned = mi_theap_zalloc_aligned(other, 129, 1024 * 1024);
  void* csize = mi_theap_malloc_csize(other, 32);
  void* csize_large = mi_theap_malloc_csize(other, 2048);
  void* zero_csize = mi_theap_zalloc_csize(other, 32);
  // The pinned constant-size wrapper uses ordinary malloc above its small
  // limit; this large branch has no zero-initialization guarantee.
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

  if (!guarded_configuration(name, base, other, main_heap, heap)) return false;
#if MI_GUARDED
  if (!guarded_actual(name, base, other, main_heap, heap)) return false;
#endif
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
  void* survivor = mi_theap_malloc(other, 57);
  if (survivor == NULL) return false;
  memset(survivor, 0x47, 57);
  mi_heap_delete(heap);
  bool preserved = true;
  for (size_t index = 0; index < 57; index++) {
    preserved = preserved && ((unsigned char*)survivor)[index] == 0x47;
  }
  printf("%s.delete_live=%d,%d,%d\n", name,
         mi_heap_of(survivor) == main_heap, preserved,
         mi_theap_get_default() == base);
  mi_free(survivor);
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
