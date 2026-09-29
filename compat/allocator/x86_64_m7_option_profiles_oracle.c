/* Run one source environment image through process startup and allocation.
   Controlled overcommit images observe the PageMap's actual mapping and
   protection arguments, then change the environment and descriptor table
   independently to distinguish startup decisions from later reads. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* The controlled input changes only the primitive's overcommit observation.
   Every allocation and protection operation still reaches the real kernel. */
static long option_capability_syscall(long, ...);
static void* option_profile_mmap(void*, size_t, int, int, int, off_t);
static int option_profile_mprotect(void*, size_t, int);
#define syscall option_capability_syscall
#define mmap option_profile_mmap
#define mprotect option_profile_mprotect
#include "static.c"
#undef syscall
#undef mmap
#undef mprotect

static int overcommit_descriptor = -1;
static size_t map_count;
static size_t map_lengths[16];
static int map_protections[16];
static int map_flags[16];
static size_t protect_count;
static uintptr_t protect_addresses[16];
static size_t protect_lengths[16];
static int protect_flags[16];

static long option_capability_syscall(long number, ...) {
  va_list arguments;
  va_start(arguments, number);
  long result;
  if (number == SYS_open) {
    const char* path = va_arg(arguments, const char*);
    const int flags = va_arg(arguments, int);
    const int mode = va_arg(arguments, int);
    result = syscall(number, path, flags, mode);
    if (strcmp(path, "/proc/sys/vm/overcommit_memory") == 0) overcommit_descriptor = (int)result;
  } else if (number == SYS_read) {
    const int descriptor = va_arg(arguments, int);
    void* buffer = va_arg(arguments, void*);
    const size_t count = va_arg(arguments, size_t);
    const char* controlled = getenv("CRABC_MI_OPTION_CAP_OVERCOMMIT");
    if (descriptor == overcommit_descriptor && controlled != NULL) {
      const char* value = strcmp(controlled, "0") == 0 ? "2\n" : "1\n";
      const size_t length = count < 2 ? count : 2;
      memcpy(buffer, value, length);
      result = (long)length;
    } else result = syscall(number, descriptor, buffer, count);
  } else if (number == SYS_close) {
    const int descriptor = va_arg(arguments, int);
    if (descriptor == overcommit_descriptor) overcommit_descriptor = -1;
    result = syscall(number, descriptor);
  } else if (number == SYS_access) {
    const char* path = va_arg(arguments, const char*);
    const int mode = va_arg(arguments, int);
    result = syscall(number, path, mode);
  } else if (number == SYS_getcpu) {
    unsigned* cpu = va_arg(arguments, unsigned*);
    unsigned* node = va_arg(arguments, unsigned*);
    void* cache = va_arg(arguments, void*);
    result = syscall(number, cpu, node, cache);
  } else if (number == SYS_getrandom) {
    void* buffer = va_arg(arguments, void*);
    const size_t count = va_arg(arguments, size_t);
    const int flags = va_arg(arguments, int);
    result = syscall(number, buffer, count, flags);
  } else if (number == SYS_mbind) {
    void* start = va_arg(arguments, void*);
    const size_t length = va_arg(arguments, size_t);
    const unsigned long mode = va_arg(arguments, unsigned long);
    const unsigned long* mask = va_arg(arguments, const unsigned long*);
    const size_t maxnode = va_arg(arguments, size_t);
    const unsigned flags = va_arg(arguments, unsigned);
    result = syscall(number, start, length, mode, mask, maxnode, flags);
  } else abort();
  va_end(arguments);
  return result;
}

static void* option_profile_mmap(void* hint, size_t length, int protection,
                                 int flags, int descriptor, off_t offset) {
  if (map_count < 16) {
    map_lengths[map_count] = length;
    map_protections[map_count] = protection;
    map_flags[map_count] = flags;
  }
  map_count++;
  return mmap(hint, length, protection, flags, descriptor, offset);
}

static int option_profile_mprotect(void* pointer, size_t length, int protection) {
  if (protect_count < 16) {
    protect_addresses[protect_count] = (uintptr_t)pointer;
    protect_lengths[protect_count] = length;
    protect_flags[protect_count] = protection;
  }
  protect_count++;
  return mprotect(pointer, length, protection);
}

static void show_option(const char* stage, mi_option_t option) {
  printf("profile.%s.%s=%ld,%d,%zu\n", stage, mi_options[option].name,
         mi_option_get(option), (int)mi_options[option].init, mi_option_get_size(option));
}

static void show_page_map(const char* stage) {
  const mi_page_map_t* root = _mi_page_map();
  printf("profile.%s.page_map=%zu,%zu,%zu\n", stage, root->reserved_size,
         mi_atomic_load_relaxed(&((mi_page_map_t*)root)->committed_count),
         mi_page_map_count_of_size(root->reserved_size));
}

static void report_commit_decision(void) {
  const mi_page_map_t* root = _mi_page_map();
  printf("profile.control.overcommit=%d\n", _mi_os_has_overcommit() ? 1 : 0);
  show_option("initial", mi_option_max_vabits);
  show_option("initial", mi_option_pagemap_commit);
  show_page_map("initial");
  printf("profile.initial.mapping_count=%zu\n", map_count);
  if (map_count != 1) abort();
  printf("profile.initial.mapping=%zu,%d,%d\n", map_lengths[0], map_protections[0], map_flags[0]);
  printf("profile.initial.commit_calls=%zu\n", protect_count);
  if (protect_count > 16) abort();
  for (size_t index = 0; index < protect_count; index++) {
    printf("profile.initial.protection.%zu=%zu,%zu,%d\n", index,
           protect_addresses[index] - (uintptr_t)root, protect_lengths[index], protect_flags[index]);
  }
  const long initial_commit = mi_option_get(mi_option_pagemap_commit);
  const long initial_bits = mi_option_get(mi_option_max_vabits);
  if (setenv("mimalloc_pagemap_commit", initial_commit == 0 ? "1" : "0", 1) != 0) abort();
  if (setenv("mimalloc_max_vabits", initial_bits == 43 ? "47" : "43", 1) != 0) abort();
  show_option("late_environment", mi_option_pagemap_commit);
  show_option("late_environment", mi_option_max_vabits);
  show_page_map("late_environment");
  printf("profile.late_environment.mapping_count=%zu\n", map_count);
  printf("profile.late_environment.commit_calls=%zu\n", protect_count);
  mi_option_set(mi_option_pagemap_commit, mi_option_get(mi_option_pagemap_commit) == 0 ? 1 : 0);
  mi_option_set(mi_option_max_vabits, mi_option_get(mi_option_max_vabits) == 43 ? 47 : 43);
  show_option("late_set", mi_option_pagemap_commit);
  show_option("late_set", mi_option_max_vabits);
  show_page_map("late_set");
  printf("profile.late_set.mapping_count=%zu\n", map_count);
  printf("profile.late_set.commit_calls=%zu\n", protect_count);
  printf("profile.root_stable=%d\n", root == _mi_page_map() ? 1 : 0);
}

static void report(const char* name, size_t size) {
  void* p = mi_malloc(size);
  printf("profile.%s.null=%d\n", name, p == NULL ? 1 : 0);
  printf("profile.%s.memkind=%d\n", name, p == NULL ? -1 : (int)_mi_ptr_page(p)->memid.memkind);
  printf("profile.%s.slice_pcommitted=%d\n", name, p == NULL ? -1 : (int)_mi_ptr_page(p)->slice_pcommitted);
  mi_free(p);
}

static void report_process(void) {
  const mi_page_map_t* pmap = _mi_page_map();
  const size_t committed = mi_atomic_load_relaxed(&((mi_page_map_t*)pmap)->committed_count);
  printf("profile.page_map=%zu,%d\n", pmap->reserved_size,
         committed == mi_page_map_count_of_size(pmap->reserved_size) ? 1 : 0);
  printf("profile.arena_count=%zu\n", mi_arenas_get_count(_mi_subproc()));
  char line[256];
  const char* thp = "absent";
  static char value[64];
  FILE* status = fopen("/proc/self/status", "r");
  while (status != NULL && fgets(line, sizeof(line), status) != NULL) {
    if (strncmp(line, "THP_enabled:", 12) == 0) {
      const char* v = line + 12;
      while (*v == ' ' || *v == '\t') v++;
      snprintf(value, sizeof(value), "%s", v);
      value[strcspn(value, "\n")] = 0;
      thp = value;
    }
  }
  if (status != NULL) fclose(status);
  printf("profile.thp_enabled=%s\n", thp);
}

/* The arena backing a first small allocation: its size and whether it was
   committed eagerly (the startup `reserve_os_memory` arena, or the first
   `mi_arena_reserve` with `arena_reserve` and `arena_eager_commit`). */
static void report_first_arena(void) {
  void* p = mi_malloc(64);
  mi_page_t* page = (p == NULL ? NULL : _mi_ptr_page(p));
  if (page == NULL || page->memid.memkind != MI_MEM_ARENA) {
    printf("profile.first_arena=none\n");
  } else {
    mi_arena_t* arena = page->memid.mem.arena.arena;
    printf("profile.first_arena=%zu,%d,%d\n", mi_arena_size(arena), arena->memid.initially_committed ? 1 : 0,
           arena->numa_node);
  }
  mi_free(p);
}

int main(void) {
  printf("CRABC_MI_M7_OPTION_PROFILES_TRACE_BEGIN\n");
  if (getenv("CRABC_MI_OPTION_CAP_OVERCOMMIT") != NULL) {
    report_commit_decision();
    printf("CRABC_MI_M7_OPTION_PROFILES_TRACE_END\n");
    return 0;
  }
  report_first_arena();
  report_process();
  report("small", 64);
  report("medium", 200 * 1024);
  report("large", 3 * 1024 * 1024);
  report("huge", 48 * 1024 * 1024);
  printf("CRABC_MI_M7_OPTION_PROFILES_TRACE_END\n");
  return 0;
}
