/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "static.c"

static mi_subproc_t subproc;
static bool selected;
static size_t huge_calls;
static size_t huge_1g_calls;
static size_t huge_2m_calls;
static size_t exact_hints;
static size_t warning_fragments;
static size_t warning_order;
static size_t warning_after_first;
static uintptr_t selected_start;
static int64_t reserved_before;
static int64_t committed_before;

void* __real_mmap(void*, size_t, int, int, int, off_t);
void* __wrap_mmap(void* hint, size_t size, int prot, int flags, int fd, off_t offset) {
  if (selected && (flags & MAP_HUGETLB) != 0) {
    huge_calls++;
    huge_1g_calls += (flags & MAP_HUGE_1GB) == MAP_HUGE_1GB;
    huge_2m_calls += (flags & MAP_HUGE_2MB) == MAP_HUGE_2MB;
    exact_hints += (uintptr_t)hint == selected_start + (huge_calls == 1 ? 0 : MI_GiB)
        && size == MI_GiB && prot == (PROT_READ | PROT_WRITE);
    if (huge_calls == 1) {
      /* The sole selected success is a virtual stand-in for the source
       * primitive's successful mapping; no physical huge page is claimed. */
      return __real_mmap(hint, size, prot,
          MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
    }
    errno = ENOMEM;
    return MAP_FAILED;
  }
  return __real_mmap(hint, size, prot, flags, fd, offset);
}

static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (!selected) return;
  warning_fragments++;
  const char* retry = "unable to allocate huge (1GiB) page, trying large (2MiB) pages instead (errno: 12)\n";
  const char* terminal = "unable to allocate huge OS page (error: 12 (0x0C), address: 0x200040000000, size: 40000000 bytes)\n";
  const bool body = strcmp(message, retry) == 0 || strcmp(message, terminal) == 0;
  if (strcmp(message, retry) == 0) warning_order = warning_order*10 + 1;
  if (strcmp(message, terminal) == 0) warning_order = warning_order*10 + 2;
  if (body) {
    warning_after_first += subproc.stats.reserved.current - reserved_before == MI_GiB
        && subproc.stats.committed.current - committed_before == MI_GiB;
  }
}

static bool live(void* address) {
  unsigned char vector = 0;
  return mincore(address, 4096, &vector) == 0;
}

static void emit(const char* name, long long value) {
  printf("m2.huge_reservation_progress.%s=%lld\n", name, value);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);
  selected_start = ((uintptr_t)32 << 40);
  mi_atomic_store_relaxed(&mi_huge_start, selected_start);
  reserved_before = subproc.stats.reserved.current;
  committed_before = subproc.stats.committed.current;
  const int64_t mmap_before = subproc.stats.mmap_calls.total;
  const int64_t arena_before = subproc.stats.arena_count.total;
  size_t pages = 0, size = 0;
  mi_memid_t huge;
  selected = true;
  void* base = _mi_os_alloc_huge_os_pages(&subproc, 3, -1, 0, &pages, &size, &huge);
  selected = false;
  emit("pages", pages);
  emit("size_gib", size / MI_GiB);
  emit("base_exact", (uintptr_t)base == selected_start);
  emit("memory_huge", huge.memkind == MI_MEM_OS_HUGE);
  emit("memory_pinned", huge.is_pinned);
  emit("memory_committed", huge.initially_committed);
  emit("memory_zero", huge.initially_zero);
  emit("huge_calls", huge_calls);
  emit("huge_1g_calls", huge_1g_calls);
  emit("huge_2m_calls", huge_2m_calls);
  emit("exact_hints", exact_hints);
  emit("warning_fragments", warning_fragments);
  emit("warning_order", warning_order);
  emit("warning_after_first", warning_after_first);
  emit("first_live", live(base));
  emit("second_absent", !live((uint8_t*)base + MI_GiB));
  emit("reserved_after", (subproc.stats.reserved.current - reserved_before) / MI_GiB);
  emit("committed_after", (subproc.stats.committed.current - committed_before) / MI_GiB);
  emit("mmap_after", subproc.stats.mmap_calls.total - mmap_before);
  emit("arena_after", subproc.stats.arena_count.total - arena_before);
  mi_memid_t ordinary;
  void* later = _mi_os_alloc_aligned(&subproc, 4096, 4096, true, false, &ordinary);
  emit("ordinary_live", later != NULL && live(later));
  emit("ordinary_memory", ordinary.memkind == MI_MEM_OS);
  emit("reserved_with_ordinary", subproc.stats.reserved.current - reserved_before == MI_GiB + 4096);
  emit("committed_with_ordinary", subproc.stats.committed.current - committed_before == MI_GiB + 4096);
  _mi_os_free(&subproc, later, 4096, ordinary);
  emit("ordinary_gone", !live(later));
  _mi_os_free(&subproc, base, size, huge);
  emit("huge_gone", !live(base));
  emit("reserved_terminal", subproc.stats.reserved.current - reserved_before);
  emit("committed_terminal", subproc.stats.committed.current - committed_before);
  emit("mmap_terminal", subproc.stats.mmap_calls.total - mmap_before);
  emit("arena_terminal", subproc.stats.arena_count.total - arena_before);
  return 0;
}
