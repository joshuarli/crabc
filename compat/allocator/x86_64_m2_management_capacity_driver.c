#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"
#ifdef CRABC_SOURCE_AUDIT
#include "mimalloc/internal.h"
#endif

enum { CAPACITY = 160 };
#define MINIMUM_BYTES ((size_t)32 * 1024 * 1024)
#define PARENT_BYTES ((size_t)16 * 1024 * 1024 * 1024)
#ifdef CRABC_SOURCE_AUDIT
_Static_assert(MI_MAX_ARENAS == CAPACITY, "pinned registry capacity");
_Static_assert(MI_ARENA_MAX_SIZE == PARENT_BYTES, "pinned split boundary");
_Static_assert(MI_ARENA_MIN_SIZE == MINIMUM_BYTES, "pinned minimum span");
#endif

static void print_stats(const char* label, const mi_stats_t* stats) {
  printf("%s.header=%zu,%zu\n", label, stats->size, stats->version);
#define MI_STAT_COUNT(name) printf("%s." #name "=%lld,%lld,%lld\n", label, (long long)stats->name.total, (long long)stats->name.peak, (long long)stats->name.current);
#define MI_STAT_COUNTER(name) printf("%s." #name "=%lld\n", label, (long long)stats->name.total);
  MI_STAT_FIELDS()
#undef MI_STAT_COUNT
#undef MI_STAT_COUNTER
  for (size_t i = 0; i < 4; ++i) {
    printf("%s.reserved_count%zu=%lld,%lld,%lld\n", label, i, (long long)stats->_stat_reserved[i].total, (long long)stats->_stat_reserved[i].peak, (long long)stats->_stat_reserved[i].current);
    printf("%s.reserved_counter%zu=%lld\n", label, i, (long long)stats->_stat_counter_reserved[i].total);
  }
  for (size_t i = 0; i <= MI_BIN_HUGE; ++i) {
    printf("%s.malloc_bin%zu=%lld,%lld,%lld\n", label, i, (long long)stats->malloc_bins[i].total, (long long)stats->malloc_bins[i].peak, (long long)stats->malloc_bins[i].current);
    printf("%s.page_bin%zu=%lld,%lld,%lld\n", label, i, (long long)stats->page_bins[i].total, (long long)stats->page_bins[i].peak, (long long)stats->page_bins[i].current);
  }
  for (size_t i = 0; i < MI_CBIN_COUNT; ++i)
    printf("%s.chunk_bin%zu=%lld,%lld,%lld\n", label, i, (long long)stats->chunk_bins[i].total, (long long)stats->chunk_bins[i].peak, (long long)stats->chunk_bins[i].current);
}

typedef struct {
  mi_subproc_id_t child;
  void* small[CAPACITY - 1];
  mi_arena_id_t ids[CAPACITY - 1];
  void* large;
  void* refused;
  size_t alignment;
  bool done;
} caller_t;

static void* reserve(size_t size, size_t alignment) {
  void* raw = mmap(NULL, size + alignment, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  assert(raw != MAP_FAILED);
  uintptr_t base = (uintptr_t)raw;
  uintptr_t aligned = (base + alignment - 1) & ~(uintptr_t)(alignment - 1);
  size_t prefix = aligned - base;
  size_t suffix = alignment - prefix;
  if (prefix) assert(munmap(raw, prefix) == 0);
  if (suffix) assert(munmap((void*)(aligned + size), suffix) == 0);
  return (void*)aligned;
}

static bool mapped(void* area) {
  unsigned char resident;
  return mincore(area, 4096, &resident) == 0;
}

static void observe(caller_t* caller, const char* label) {
  mi_stats_t_decl(stats);
  assert(mi_subproc_stats_get(caller->child, &stats));
  print_stats(label, &stats);
}

static void* worker(void* argument) {
  caller_t* caller = argument;
  assert(mi_subproc_add_current_thread(caller->child));
  observe(caller, "stats.initial");
  size_t accepted = 0;
  for (size_t i = 0; i < CAPACITY - 1; ++i) {
    errno = 0;
    bool ok = mi_manage_os_memory_ex(caller->small[i], MINIMUM_BYTES,
        false, false, true, -1, true, &caller->ids[i]);
    assert(ok && caller->ids[i] != NULL && errno == 0);
    size_t size = 0;
    assert(mi_arena_area(caller->ids[i], &size) == caller->small[i]);
    assert(size == MINIMUM_BYTES);
    accepted++;
  }
  printf("capacity.accepted=%zu\n", accepted);
  observe(caller, "stats.filled");
  mi_arena_id_t parent = NULL;
  errno = 0;
  bool partial = mi_manage_os_memory_ex(caller->large, PARENT_BYTES + MINIMUM_BYTES,
      false, false, true, -1, true, &parent);
  assert(partial && parent != NULL && errno == 0);
  size_t managed = 0;
  assert(mi_arena_area(parent, &managed) == caller->large);
  assert(managed == PARENT_BYTES);
  assert(mi_arena_contains(parent, caller->large));
  assert(mi_arena_contains(parent, (unsigned char*)caller->large + PARENT_BYTES - 1));
  assert(!mi_arena_contains(parent, (unsigned char*)caller->large + PARENT_BYTES));
  assert(mapped((unsigned char*)caller->large + PARENT_BYTES));
  printf("capacity.partial=%d,%d,%zu,1,1,1,1\n", partial, parent != NULL, managed);
#ifdef CRABC_SOURCE_AUDIT
  /* This is a live, quiescent source identity. The external memory ID keeps
     the whole caller mapping even when publication accepts only its prefix. */
  mi_arena_t* arena = (mi_arena_t*)parent;
  mi_subproc_t* subproc = (mi_subproc_t*)caller->child._mi_subproc_id;
  fprintf(stderr, "source.capacity=%d,%d,%d,%d,%d\n",
      subproc->arena_count == CAPACITY, arena->subproc == subproc,
      arena->total_size == PARENT_BYTES, arena->memid.memkind == MI_MEM_EXTERNAL,
      arena->memid.mem.os.base == caller->large &&
          arena->memid.mem.os.size == PARENT_BYTES + MINIMUM_BYTES);
#endif
  observe(caller, "stats.partial");
  mi_arena_id_t rejected = parent;
  errno = 0;
  bool refusal = mi_manage_os_memory_ex(caller->refused, MINIMUM_BYTES,
      false, false, true, -1, true, &rejected);
  assert(!refusal && rejected == NULL && errno == 0 && mapped(caller->refused));
  size_t preserved = 0;
  assert(mi_arena_area(parent, &preserved) == caller->large && preserved == PARENT_BYTES);
  for (size_t i = 0; i < CAPACITY - 1; ++i)
    assert(mi_arena_area(caller->ids[i], NULL) == caller->small[i]);
  printf("capacity.refusal=1,1,1,1,1\n");
  observe(caller, "stats.refused");
  caller->done = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set_enabled(mi_option_show_errors, true);
  mi_option_set(mi_option_arena_reserve, 0);
  assert(mi_arena_min_size() == MINIMUM_BYTES);
  size_t alignment = mi_arena_min_alignment();
  assert(alignment != 0 && (alignment & (alignment - 1)) == 0);
  caller_t caller = {0};
  caller.alignment = alignment;
  for (size_t i = 0; i < CAPACITY - 1; ++i)
    caller.small[i] = reserve(MINIMUM_BYTES, alignment);
  caller.large = reserve(PARENT_BYTES + MINIMUM_BYTES, alignment);
  caller.refused = reserve(MINIMUM_BYTES, alignment);
  caller.child = mi_subproc_new();
  assert(caller.child._mi_subproc_id != NULL);
  puts("CRABC_MI_MANAGEMENT_CAPACITY_BEGIN");
  printf("capacity.geometry=%zu,%zu,%d\n", MINIMUM_BYTES, alignment, CAPACITY);
  pthread_t owner;
  assert(pthread_create(&owner, NULL, worker, &caller) == 0);
  assert(pthread_join(owner, NULL) == 0 && caller.done);
  observe(&caller, "stats.joined");
  mi_subproc_destroy(caller.child);
  size_t live = 0, released = 0;
  for (size_t i = 0; i < CAPACITY - 1; ++i) {
    assert(mapped(caller.small[i])); live++;
    assert(munmap(caller.small[i], MINIMUM_BYTES) == 0); released++;
    errno = 0; assert(!mapped(caller.small[i]) && errno == ENOMEM);
  }
  assert(mapped(caller.large) && mapped((unsigned char*)caller.large + PARENT_BYTES));
  assert(mapped(caller.refused)); live += 2;
  assert(munmap(caller.large, PARENT_BYTES + MINIMUM_BYTES) == 0); released++;
  assert(munmap(caller.refused, MINIMUM_BYTES) == 0); released++;
  errno = 0; assert(!mapped(caller.large) && errno == ENOMEM);
  errno = 0; assert(!mapped(caller.refused) && errno == ENOMEM);
  printf("capacity.terminal=%zu,%zu,1,1\n", live, released);
  puts("CRABC_MI_MANAGEMENT_CAPACITY_END");
  return 0;
}
