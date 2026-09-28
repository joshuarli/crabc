#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#include "bitmap.h"
#endif

#define MIB ((size_t)1024 * 1024)

typedef struct {
  mi_arena_id_t reserved;
  mi_arena_id_t managed;
  void* reserved_area;
  size_t reserved_size;
  void* managed_area;
  size_t managed_size;
  void* reserved_block;
  void* managed_block;
} fixture_t;

static bool in_area(const void* p, const void* area, size_t size) {
  uintptr_t value = (uintptr_t)p;
  uintptr_t first = (uintptr_t)area;
  return p != NULL && area != NULL && value >= first && value - first < size;
}

static void* observer(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  size_t reserved_size = 0;
  size_t managed_size = 0;
  void* reserved = mi_arena_area(fixture->reserved, &reserved_size);
  void* managed = mi_arena_area(fixture->managed, &managed_size);
  printf("arena.worker=%d,%d,%d,%d,%d,%d\n",
         reserved == fixture->reserved_area, reserved_size == fixture->reserved_size,
         managed == fixture->managed_area, managed_size == fixture->managed_size,
         mi_arena_contains(fixture->reserved, fixture->reserved_block),
         mi_arena_contains(fixture->managed, fixture->managed_block));
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_PUBLIC_ARENA_BEGIN");
  fixture_t fixture = {0};
  size_t minimum = mi_arena_min_size();
  size_t alignment = mi_arena_min_alignment();
  size_t maximum_object = mi_arena_max_object_size();
  printf("arena.sizes=%d,%d,%d\n", minimum == 32 * MIB,
         alignment >= minimum && alignment % minimum == 0,
         maximum_object >= minimum && maximum_object <= 1024 * MIB);
  if (minimum == 0 || alignment == 0) return 2;

  errno = 0;
  int reserve = mi_reserve_os_memory_ex(minimum, true, false, true, &fixture.reserved);
  fixture.reserved_area = mi_arena_area(fixture.reserved, &fixture.reserved_size);
  printf("arena.reserve=%d,%d,%d,%d,%d\n", reserve == 0,
         fixture.reserved != NULL, fixture.reserved_area != NULL,
         fixture.reserved_size == minimum, errno == 0);
  if (reserve != 0 || fixture.reserved_area == NULL) return 3;

  void* raw = mmap(NULL, minimum + alignment, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) return 4;
  uintptr_t base = (uintptr_t)raw;
  uintptr_t aligned = (base + alignment - 1) & ~(uintptr_t)(alignment - 1);
  size_t prefix = aligned - base;
  size_t suffix = minimum + alignment - prefix - minimum;
  if (prefix != 0 && munmap(raw, prefix) != 0) return 5;
  if (suffix != 0 && munmap((void*)(aligned + minimum), suffix) != 0) return 6;
  fixture.managed_area = (void*)aligned;
  errno = 0;
  bool managed = mi_manage_os_memory_ex(fixture.managed_area, minimum, true,
                                      false, true, -1, true, &fixture.managed);
  size_t area_size = 0;
  void* managed_area = mi_arena_area(fixture.managed, &area_size);
  fixture.managed_size = area_size;
  printf("arena.manage=%d,%d,%d,%d,%d\n", managed,
         fixture.managed != NULL, managed_area == fixture.managed_area,
         area_size == minimum, errno == 0);
  if (!managed || managed_area != fixture.managed_area) return 7;

  mi_arena_id_t rejected = fixture.managed;
  errno = 0;
  bool short_region = mi_manage_os_memory_ex(fixture.managed_area, minimum - 1,
      true, false, true, -1, true, &rejected);
  printf("arena.manage_reject=%d,%d,%d\n", !short_region, rejected == NULL, errno == 0);
  rejected = fixture.reserved;
  errno = 0;
  int huge_request = mi_reserve_os_memory_ex(SIZE_MAX, true, false, true, &rejected);
  printf("arena.reserve_reject=%d,%d,%d\n", huge_request == ENOMEM,
         rejected == NULL, errno == ENOMEM);

  mi_heap_t* reserved_heap = mi_heap_new_in_arena(fixture.reserved);
  mi_heap_t* managed_heap = mi_heap_new_in_arena(fixture.managed);
  if (reserved_heap == NULL || managed_heap == NULL) return 8;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_theap_t* reserved_theap = mi_heap_theap(reserved_heap);
  mi_theap_t* managed_theap = mi_heap_theap(managed_heap);
  mi_memid_t reserved_theap_memid = reserved_theap->memid;
  mi_memid_t managed_theap_memid = managed_theap->memid;
#endif
  fixture.reserved_block = mi_heap_malloc(reserved_heap, 64);
  fixture.managed_block = mi_heap_malloc(managed_heap, 96);
  if (fixture.reserved_block == NULL || fixture.managed_block == NULL) return 9;
  printf("arena.owned=%d,%d,%d,%d\n",
         in_area(fixture.reserved_block, fixture.reserved_area, fixture.reserved_size),
         in_area(fixture.managed_block, fixture.managed_area, fixture.managed_size),
         mi_arena_contains(fixture.reserved, fixture.reserved_block),
         mi_arena_contains(fixture.managed, fixture.managed_block));
  printf("arena.exclusive=%d,%d,%d,%d\n",
         !mi_arena_contains(fixture.reserved, fixture.managed_block),
         !mi_arena_contains(fixture.managed, fixture.reserved_block),
         !mi_arena_contains(NULL, fixture.reserved_block),
         !mi_arena_contains(fixture.reserved, NULL));
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.arena_owners=%d,%d,%d\n",
          reserved_heap->exclusive_arena == (mi_arena_t*)fixture.reserved,
          managed_heap->exclusive_arena == (mi_arena_t*)fixture.managed,
          ((mi_arena_t*)fixture.managed)->commit_fun == NULL);
#endif

  pthread_t worker;
  if (pthread_create(&worker, NULL, observer, &fixture) != 0) return 10;
  if (pthread_join(worker, NULL) != 0) return 11;
  mi_free(fixture.reserved_block);
  mi_free(fixture.managed_block);
  mi_heap_destroy(reserved_heap);
  mi_heap_destroy(managed_heap);
  (void)mi_heap_theap(mi_heap_main());
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.slices_released=%d,%d\n",
          reserved_theap_memid.memkind == MI_MEM_ARENA &&
              mi_bbitmap_is_setN(reserved_theap_memid.mem.arena.arena->slices_free,
                                 reserved_theap_memid.mem.arena.slice_index,
                                 reserved_theap_memid.mem.arena.slice_count),
          managed_theap_memid.memkind == MI_MEM_ARENA &&
              mi_bbitmap_is_setN(managed_theap_memid.mem.arena.arena->slices_free,
                                 managed_theap_memid.mem.arena.slice_index,
                                 managed_theap_memid.mem.arena.slice_count));
#endif
  printf("arena.areas_retained=%d,%d\n",
         mi_arena_contains(fixture.reserved, fixture.reserved_block),
         mi_arena_contains(fixture.managed, fixture.managed_block));
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_subproc_t* source_subprocess = (mi_subproc_t*)mi_subproc_main()._mi_subproc_id;
  mi_arena_t* source_managed = (mi_arena_t*)fixture.managed;
  bool external_purge_pending = mi_atomic_loadi64_relaxed(&source_managed->purge_expire) != 0;
  int64_t purges_before = source_subprocess->stats.purge_calls.total;
#endif
  mi_collect(true);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.external_forced_purge=%d,%d\n", external_purge_pending,
          source_subprocess->stats.purge_calls.total > purges_before);
#endif
  unsigned char residency = 0;
  printf("arena.external_retained=%d,%d,%d\n",
         mi_arena_area(fixture.managed, NULL) == fixture.managed_area,
         mincore(fixture.managed_area, 4096, &residency) == 0,
         mi_arena_contains(fixture.managed, fixture.managed_area));

  void* reserved_raw = mmap(NULL, minimum + alignment, PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reserved_raw == MAP_FAILED) return 12;
  uintptr_t reserved_base = (uintptr_t)reserved_raw;
  uintptr_t reserved_aligned = (reserved_base + alignment - 1) & ~(uintptr_t)(alignment - 1);
  size_t reserved_prefix = reserved_aligned - reserved_base;
  size_t reserved_suffix = alignment - reserved_prefix;
  if (reserved_prefix != 0 && munmap(reserved_raw, reserved_prefix) != 0) return 13;
  if (reserved_suffix != 0 && munmap((void*)(reserved_aligned + minimum), reserved_suffix) != 0) return 14;
  mi_arena_id_t reserved_external = NULL;
  bool reserved_managed = mi_manage_os_memory_ex((void*)reserved_aligned, minimum,
      false, false, true, -1, true, &reserved_external);
  size_t reserved_area_size = 0;
  void* reserved_area = mi_arena_area(reserved_external, &reserved_area_size);
  printf("arena.reserved_manage=%d,%d,%d,%d\n", reserved_managed,
         reserved_external != NULL, reserved_area == (void*)reserved_aligned,
         reserved_area_size == minimum);
  if (!reserved_managed || reserved_area == NULL) return 15;
  mi_heap_t* reserved_external_heap = mi_heap_new_in_arena(reserved_external);
  if (reserved_external_heap == NULL) return 16;
  mi_theap_t* reserved_external_theap = mi_heap_theap(reserved_external_heap);
  void* reserved_external_block = mi_heap_malloc(reserved_external_heap, 80);
  printf("arena.reserved_selected=%d,%d,%d,%d\n", reserved_external_theap != NULL,
         reserved_external_block != NULL,
         mi_arena_contains(reserved_external, reserved_external_block),
         in_area(reserved_external_block, reserved_area, reserved_area_size));
  if (reserved_external_block == NULL) return 17;
  mi_free(reserved_external_block);
  mi_heap_destroy(reserved_external_heap);
  (void)mi_heap_theap(mi_heap_main());
  mi_collect(true);
  printf("arena.reserved_retained=%d,%d\n",
         mi_arena_contains(reserved_external, reserved_area),
         mincore(reserved_area, 4096, &residency) == 0);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.reserved_external_callback=%d\n",
          ((mi_arena_t*)reserved_external)->commit_fun == NULL);
#endif
  puts("CRABC_MI_M6_PUBLIC_ARENA_END");
  return 0;
}
