/* A caller-owned regular OS map survives a failed protect and same-range retry. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc/internal.h"

#include "alloc.c"
#include "alloc-aligned.c"
#include "alloc-posix.c"
#include "arena.c"
#include "bitmap.c"
#include "heap.c"
#include "init.c"
#include "libc.c"
#include "options.c"
#include "os.c"
#include "page.c"
#include "page-map.c"
#include "random.c"
#include "stats.c"
#include "subproc.c"
#include "theap.c"
#include "threadlocal.c"
#include "prim/prim.c"
#include "prim/prim-tls.c"

static bool capture_protection;
static bool fail_first_protect;
static unsigned protection_calls;
static void* protection_addresses[3];
static size_t protection_lengths[3];
static int protection_flags[3];
static unsigned selected_warning_count;
static unsigned warning_order;
static int warning_errno;
static bool warning_text_exact;
static uintptr_t warning_address;
static size_t warning_size;
static unsigned warning_protection_calls;
static int64_t warning_commit_calls;
static int64_t warning_committed;
static int64_t warning_reserved;
static int64_t warning_mmap_calls;
static mi_subproc_t* observed_subprocess;
int __real_mprotect(void*, size_t, int);

int __wrap_mprotect(void* address, size_t length, int protection) {
  if (capture_protection) {
    if (protection_calls < 3) {
      protection_addresses[protection_calls] = address;
      protection_lengths[protection_calls] = length;
      protection_flags[protection_calls] = protection;
    }
    protection_calls++;
  }
  if (capture_protection && fail_first_protect && protection == PROT_NONE) {
    fail_first_protect = false;
    errno = ENOMEM;
    return -1;
  }
  return __real_mprotect(address, length, protection);
}

static void capture_warning(const char* message, void* ignored) {
  (void)ignored;
  if (message == NULL || observed_subprocess == NULL) return;
  int category = 0;
  if (strstr(message, "cannot protect OS memory") != NULL) category = 1;
  if (strstr(message, "cannot unprotect OS memory") != NULL) category = 2;
  if (category == 0) return;
  warning_order = warning_order * 10 + (unsigned)category;
  selected_warning_count++;
  const char* error = strstr(message, "error: ");
  const char* address = strstr(message, "address: ");
  const char* size = strstr(message, "size: 0x");
  if (error != NULL) warning_errno = (int)strtol(error + 7, NULL, 10);
  if (address != NULL) warning_address = (uintptr_t)strtoull(address + 9, NULL, 16);
  if (size != NULL) warning_size = (size_t)strtoull(size + 8, NULL, 16);
  char expected[256];
  _mi_snprintf(expected, sizeof(expected),
      "cannot %s OS memory (error: %d (0x%x), address: %p, size: 0x%zx bytes)\n",
      (category == 1 ? "protect" : "unprotect"), warning_errno, warning_errno,
      (void*)warning_address, warning_size);
  warning_text_exact = strcmp(message, expected) == 0;
  warning_protection_calls = protection_calls;
  warning_commit_calls = observed_subprocess->stats.commit_calls.total;
  warning_committed = observed_subprocess->stats.committed.current;
  warning_reserved = observed_subprocess->stats.reserved.current;
  warning_mmap_calls = observed_subprocess->stats.mmap_calls.total;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_subproc_t* const subproc = _mi_subproc_main();
  observed_subprocess = subproc;
  mi_register_output(capture_warning, NULL);
  const int64_t reserved_before = subproc->stats.reserved.current;
  const int64_t committed_before = subproc->stats.committed.current;
  const int64_t commits_before = subproc->stats.commit_calls.total;
  const int64_t mmaps_before = subproc->stats.mmap_calls.total;
  const size_t page = _mi_os_page_size();
  const size_t request_size = 3 * page;
  mi_memid_t memid = _mi_memid_none();
  unsigned char* const base = _mi_os_alloc(subproc, request_size, &memid);
  if (base == NULL) return 2;
  const int64_t reserved_at_map = subproc->stats.reserved.current;
  const int64_t committed_at_map = subproc->stats.committed.current;
  const int64_t commits_at_map = subproc->stats.commit_calls.total;
  const int64_t mmaps_at_map = subproc->stats.mmap_calls.total;
  const size_t request_offset = 19;
  const size_t protect_size = 2 * page + 5;
  base[page] = 0x51;
  fail_first_protect = true;
  capture_protection = true;
  const bool failed_protect = _mi_os_protect(base + request_offset, protect_size);
  const bool writable_after_failure = base[page] == 0x51;
  base[page] = 0x52;
  const bool retry_protect = _mi_os_protect(base + request_offset, protect_size);
  unsigned char residence = 0;
  const bool mapped_while_protected = mincore(base + page, page, &residence) == 0;
  const bool unprotected = _mi_os_unprotect(base + request_offset, protect_size);
  capture_protection = false;
  const bool readable_after_unprotect = base[page] == 0x52;
  base[page] = 0x53;
  const bool writable_after_unprotect = readable_after_unprotect && base[page] == 0x53;
  const int64_t reserved_after_protection = subproc->stats.reserved.current;
  const int64_t committed_after_protection = subproc->stats.committed.current;
  const int64_t commits_after_protection = subproc->stats.commit_calls.total;
  const int64_t mmaps_after_protection = subproc->stats.mmap_calls.total;
  const bool memid_os = memid.memkind == MI_MEM_OS && memid.mem.os.base == base
      && memid.mem.os.size == _mi_os_good_alloc_size(request_size);
  _mi_os_free(subproc, base, request_size, memid);
  const bool unmapped = mincore(base, page, &residence) == -1 && errno == ENOMEM;
  printf("CRABC_M2_PROCESS_OWNED_PROTECT_FAULT_C_TRACE_BEGIN\n");
#define EMIT(name, value) printf(name "=%lld\n", (long long)(value))
  EMIT("allocated", base != NULL);
  EMIT("memid_os", memid_os);
  EMIT("page_size", page);
  EMIT("mapping_size", memid.mem.os.size);
  EMIT("request_offset", request_offset);
  EMIT("request_size", protect_size);
  EMIT("failed_protect", !failed_protect);
  EMIT("writable_after_failure", writable_after_failure);
  EMIT("retry_protect", retry_protect);
  EMIT("mapped_while_protected", mapped_while_protected);
  EMIT("unprotected", unprotected);
  EMIT("writable_after_unprotect", writable_after_unprotect);
  EMIT("protection_calls", protection_calls);
  EMIT("protect1_offset", (uintptr_t)protection_addresses[0] - (uintptr_t)base);
  EMIT("protect1_length", protection_lengths[0]);
  EMIT("protect1_flags", protection_flags[0]);
  EMIT("protect2_offset", (uintptr_t)protection_addresses[1] - (uintptr_t)base);
  EMIT("protect2_length", protection_lengths[1]);
  EMIT("protect2_flags", protection_flags[1]);
  EMIT("unprotect_offset", (uintptr_t)protection_addresses[2] - (uintptr_t)base);
  EMIT("unprotect_length", protection_lengths[2]);
  EMIT("unprotect_flags", protection_flags[2]);
  EMIT("warning_order", warning_order);
  EMIT("warning_count", selected_warning_count);
  EMIT("warning_errno", warning_errno);
  EMIT("warning_text_exact", warning_text_exact);
  EMIT("warning_offset", warning_address - (uintptr_t)base);
  EMIT("warning_size", warning_size);
  EMIT("warning_protection_calls", warning_protection_calls);
  EMIT("reserved_at_map", reserved_at_map - reserved_before);
  EMIT("committed_at_map", committed_at_map - committed_before);
  EMIT("commits_at_map", commits_at_map - commits_before);
  EMIT("mmaps_at_map", mmaps_at_map - mmaps_before);
  EMIT("warning_reserved", warning_reserved - reserved_before);
  EMIT("warning_committed", warning_committed - committed_before);
  EMIT("warning_commit_calls", warning_commit_calls - commits_before);
  EMIT("warning_mmap_calls", warning_mmap_calls - mmaps_before);
  EMIT("reserved_after_protection", reserved_after_protection - reserved_before);
  EMIT("committed_after_protection", committed_after_protection - committed_before);
  EMIT("commits_after_protection", commits_after_protection - commits_before);
  EMIT("mmaps_after_protection", mmaps_after_protection - mmaps_before);
  EMIT("terminal_reserved", subproc->stats.reserved.current - reserved_before);
  EMIT("terminal_committed", subproc->stats.committed.current - committed_before);
  EMIT("terminal_unmapped", unmapped);
#undef EMIT
  printf("CRABC_M2_PROCESS_OWNED_PROTECT_FAULT_C_TRACE_END\n");
  return 0;
}
