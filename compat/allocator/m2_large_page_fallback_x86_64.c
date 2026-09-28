/* A failed huge-page mmap falls through to one process-owned regular mapping.
 * The ordinary source process initializer precedes the private OS caller.
 */
#define _GNU_SOURCE

#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

#include "os.c"
#include "init.c"

static bool capture_advice;
static bool capture_prctl;
static unsigned thp_prctl_count;
static unsigned advice_count;
static void* advised_address;
static size_t advised_length;
static int advised_kind;
static int advised_result;
static bool capture_mmap;
static unsigned mmap_attempt_count;
static void* mmap_attempt_address[4];
static size_t mmap_attempt_length[4];
static int mmap_attempt_protection[4];
static int mmap_attempt_flags[4];
static int mmap_attempt_result[4];
static unsigned huge_failure_count;
static bool capture_release;
static unsigned release_count;
static void* released_address;
static size_t released_length;
static int released_result;

int __real_madvise(void* address, size_t length, int advice);
void* __real_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset);
int __real_munmap(void* address, size_t length);
int __real_prctl(int option, ...);

int __wrap_prctl(int option, unsigned long a0, unsigned long a1,
                 unsigned long a2, unsigned long a3) {
  if (capture_prctl && (option == PR_GET_THP_DISABLE || option == PR_SET_THP_DISABLE)) {
    thp_prctl_count++;
  }
  return __real_prctl(option, a0, a1, a2, a3);
}

int __wrap_madvise(void* address, size_t length, int advice) {
  const int result = __real_madvise(address, length, advice);
  if (capture_advice) {
    advice_count++;
    advised_address = address;
    advised_length = length;
    advised_kind = advice;
    advised_result = result;
  }
  return result;
}

void* __wrap_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset) {
  if (!capture_mmap) return __real_mmap(address, length, protection, flags, fd, offset);
  const unsigned index = mmap_attempt_count++;
  if (index < 4) {
    mmap_attempt_address[index] = address;
    mmap_attempt_length[index] = length;
    mmap_attempt_protection[index] = protection;
    mmap_attempt_flags[index] = flags;
  }
  if ((flags & MAP_HUGETLB) != 0) {
    huge_failure_count++;
    if (index < 4) mmap_attempt_result[index] = -1;
    errno = ENOMEM;
    return MAP_FAILED;
  }
  void* const result = __real_mmap(address, length, protection, flags, fd, offset);
  if (index < 4) mmap_attempt_result[index] = (result == MAP_FAILED ? -1 : 0);
  return result;
}

int __wrap_munmap(void* address, size_t length) {
  const int result = __real_munmap(address, length);
  if (capture_release) {
    release_count++;
    released_address = address;
    released_length = length;
    released_result = result;
  }
  return result;
}

static bool mapping_has_explicit_thp_advice(void* address) {
  FILE* const input = fopen("/proc/self/smaps", "r");
  if (input == NULL) return false;
  char line[512];
  bool selected = false;
  bool advised = false;
  while (fgets(line, sizeof(line), input) != NULL) {
    unsigned long long first = 0;
    unsigned long long end = 0;
    if (sscanf(line, "%llx-%llx", &first, &end) == 2) {
      const uintptr_t target = (uintptr_t)address;
      selected = first <= target && target < end;
    }
    if (selected && strncmp(line, "VmFlags:", 8) == 0) {
      advised = strstr(line, " hg") != NULL;
      break;
    }
  }
  fclose(input);
  return advised;
}

int main(void) {
  if (clearenv() != 0 || setenv("mimalloc_allow_thp", "1", 1) != 0
      || setenv("mimalloc_allow_large_os_pages", "1", 1) != 0) return 1;
  capture_prctl = true;
  mi_process_init();
  capture_prctl = false;
  mi_subproc_t* const subproc = _mi_subproc_main();
  const size_t length = mi_os_mem_config.large_page_size;
  if (subproc == NULL || length == 0) return 2;
  const int64_t mmap_before = subproc->stats.mmap_calls.total;
  const int64_t reserved_before = subproc->stats.reserved.current;
  const int64_t committed_before = subproc->stats.committed.current;
  bool is_large = false;
  bool is_zero = false;
  capture_advice = true;
  capture_mmap = true;
  void* const mapping = mi_os_prim_alloc_at(subproc, NULL, length, length,
      true, true, &is_large, &is_zero);
  capture_mmap = false;
  capture_advice = false;
  if (mapping == NULL) return 3;
  const bool vmflags_hg = mapping_has_explicit_thp_advice(mapping);
  volatile unsigned char* const bytes = mapping;
  bytes[0] = 0x5a;
  const bool mapping_survived = bytes[0] == 0x5a;
  const int64_t mmap_live = subproc->stats.mmap_calls.total - mmap_before;
  const int64_t reserved_live = subproc->stats.reserved.current - reserved_before;
  const int64_t committed_live = subproc->stats.committed.current - committed_before;
  capture_release = true;
  mi_os_prim_free(subproc, mapping, length, length, false);
  capture_release = false;

  puts("CRABC_M2_LARGE_PAGE_FALLBACK_C_TRACE_BEGIN");
  printf("selected_allow_thp_raw=%ld\n", mi_option_get(mi_option_allow_thp));
  printf("selected_allow_large_os_pages_raw=%ld\n", mi_option_get(mi_option_allow_large_os_pages));
  printf("config_has_transparent_huge_pages=%u\n", (unsigned)mi_os_mem_config.has_transparent_huge_pages);
  printf("config_has_overcommit=%u\n", (unsigned)mi_os_mem_config.has_overcommit);
  printf("process_ready=%u\n", (unsigned)_mi_process_is_initialized);
  printf("thp_prctl_count=%u\n", thp_prctl_count);
  printf("mmap_attempt_count=%u\n", mmap_attempt_count);
  printf("huge_failure_count=%u\n", huge_failure_count);
  printf("regular_hint_differs=%u\n", (unsigned)(mmap_attempt_address[0] != mmap_attempt_address[2]));
  for (unsigned index = 0; index < 3; index++) {
    printf("attempt%u_hint_present=%u\n", index, (unsigned)(mmap_attempt_address[index] != NULL));
    printf("attempt%u_length=%zu\n", index, mmap_attempt_length[index]);
    printf("attempt%u_protection=%d\n", index, mmap_attempt_protection[index]);
    printf("attempt%u_flags=%u\n", index, (unsigned)mmap_attempt_flags[index]);
    printf("attempt%u_result=%d\n", index, mmap_attempt_result[index]);
  }
  printf("huge_failure_errno=%d\n", ENOMEM);
  printf("mapping_owned=%u\n", (unsigned)(mapping != NULL && !is_large));
  printf("mapping_aligned_2m=%u\n", (unsigned)(((uintptr_t)mapping % length) == 0));
  printf("mapping_length=%zu\n", length);
  printf("advice_count=%u\n", advice_count);
  printf("advice_address_is_mapping=%u\n", (unsigned)(advised_address == mapping));
  printf("advice_length=%zu\n", advised_length);
  printf("advice_kind=%d\n", advised_kind);
  printf("advice_result=%d\n", advised_result);
  printf("advice_succeeded=%u\n", (unsigned)(advised_result == 0));
  printf("vmflags_hg=%u\n", (unsigned)vmflags_hg);
  printf("mapping_survived=%u\n", (unsigned)mapping_survived);
  printf("mmap_calls_delta=%lld\n", (long long)mmap_live);
  printf("reserved_live_delta=%lld\n", (long long)reserved_live);
  printf("committed_live_delta=%lld\n", (long long)committed_live);
  printf("release_count=%u\n", release_count);
  printf("release_exact_range=%u\n", (unsigned)(released_address == mapping && released_length == length));
  printf("release_result=%d\n", released_result);
  printf("reserved_after_release_delta=%lld\n", (long long)(subproc->stats.reserved.current - reserved_before));
  printf("committed_after_release_delta=%lld\n", (long long)(subproc->stats.committed.current - committed_before));
  puts("CRABC_M2_LARGE_PAGE_FALLBACK_C_TRACE_END");
  return 0;
}
