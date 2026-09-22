/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Direct pinned v3.5.0 destruction, with real regular OS backing. */
#include "static.c"
#include <stdio.h>
#include <stdlib.h>

static mi_subproc_t subprocess;
static size_t commits;
static size_t purges;
static size_t fail_at;
static size_t free_count;

int __real_munmap(void* address, size_t size);
int __wrap_munmap(void* address, size_t size) {
  if (fail_at != 0 && ++free_count == fail_at) {
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(address, size);
}

static void require(bool ok) { if (!ok) abort(); }

static bool external_transition(bool commit, void* start, size_t size, bool* zero, void* arg) {
  MI_UNUSED(start); MI_UNUSED(size); MI_UNUSED(arg);
  if (commit) commits++; else purges++;
  if (zero != NULL) *zero = false;
  return true;
}

int main(void) {
  mi_process_init();
  mi_arena_id_t id;
  require(mi_reserve_os_memory_ex2(&subprocess, MI_ARENA_MIN_SIZE, true, false, false, &id) == 0);
  require(mi_reserve_os_memory_ex2(&subprocess, MI_ARENA_MIN_SIZE, false, false, false, &id) == 0);
  mi_memid_t external_memid;
  uint8_t* external = _mi_os_alloc_aligned(&subprocess, MI_ARENA_MIN_SIZE,
    MI_ARENA_ALIGNMENT, true, false, &external_memid);
  require(external != NULL);
  external_memid.memkind = MI_MEM_EXTERNAL;
  require(mi_manage_os_memory_ex2(&subprocess, external, MI_ARENA_MIN_SIZE,
    -1, false, external_memid, external_transition, NULL, &id));
  commits = 0; purges = 0;
  const size_t count = mi_arenas_get_count(&subprocess);
  const int64_t reserved = subprocess.stats.reserved.current;
  const int64_t committed = subprocess.stats.committed.current;
  _mi_arenas_unsafe_destroy_all(&subprocess);
  external[MI_ARENA_MIN_SIZE - 1] = 0x5a;
  const int64_t values[] = { (int64_t)count, (int64_t)mi_arenas_get_count(&subprocess),
    reserved - subprocess.stats.reserved.current,
    committed - subprocess.stats.committed.current,
    (int64_t)commits, (int64_t)purges, external[MI_ARENA_MIN_SIZE - 1] == 0x5a };
  for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); i++) {
    printf("m2.arena.destroy.%zu=%lld\n", i, (long long)values[i]);
  }
  require(munmap(external_memid.mem.os.base, external_memid.mem.os.size) == 0);

  /* A failed parent free keeps the child's metadata mapped in the pinned C
     loop. Rust separately checks successful multi-arena destruction without
     reading a child header after its parent owner has been released. */
  const size_t multiple_size = MI_ARENA_MAX_SIZE + MI_ARENA_MIN_SIZE;
  require(mi_reserve_os_memory_ex2(&subprocess, multiple_size, false, false, false, &id) == 0);
  mi_arena_t* parent = _mi_arena_from_id(id);
  mi_memid_t retained = parent->memid;
  fail_at = 1; free_count = 0;
  _mi_arenas_unsafe_destroy_all(&subprocess);
  printf("m2.arena.destroy.7=%zu\n", free_count);
  printf("m2.arena.destroy.8=%zu\n", mi_arenas_get_count(&subprocess));
  unsigned char residency;
  printf("m2.arena.destroy.9=%d\n", mincore(retained.mem.os.base, _mi_os_page_size(), &residency) == 0);
  fail_at = 0;
  require(munmap(retained.mem.os.base, retained.mem.os.size) == 0);

  /* Anonymous backing substitutes only for huge-page provisioning, matching
     Rust's test_registry_allocation. Source huge-free and failure continuation
     execute unchanged; this is not hugetlb or NUMA qualification. */
  const size_t huge_size = 3 * MI_GiB;
  mi_memid_t huge;
  void* huge_base = _mi_os_alloc_aligned(&subprocess, huge_size, MI_GiB, true, false, &huge);
  require(huge_base != NULL);
  huge.memkind = MI_MEM_OS_HUGE;
  huge.is_pinned = true;
  require(mi_manage_os_memory_ex2(&subprocess, huge_base, huge_size, -1, false,
    huge, NULL, NULL, &id));
  fail_at = 2; free_count = 0;
  _mi_arenas_unsafe_destroy_all(&subprocess);
  printf("m2.arena.destroy.10=%zu\n", free_count);
  printf("m2.arena.destroy.11=%zu\n", mi_arenas_get_count(&subprocess));
  printf("m2.arena.destroy.12=%d\n", mincore((uint8_t*)huge_base + MI_GiB, _mi_os_page_size(), &residency) == 0);
  fail_at = 0;
  require(munmap((uint8_t*)huge_base + MI_GiB, MI_GiB) == 0);
  return 0;
}
