/* A failed offset-aligned replacement must leave the original allocation
   address, usable extent, and bytes valid until the caller frees it. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "mimalloc.h"

#define MiB ((size_t)1024 * 1024)

int main(void) {
  unsigned char* old = mi_malloc_aligned_at(1000, 4096, 13);
  if (old == NULL) return 10;
  memset(old, 0x71, 1000);
  const size_t old_usable = mi_usable_size(old);
  if (old_usable < 1000 || (((uintptr_t)old + 13) & 4095) != 0) return 11;

  struct rlimit original;
  if (getrlimit(RLIMIT_AS, &original) != 0) return 12;
  FILE* status = fopen("/proc/self/status", "r");
  if (status == NULL) return 13;
  size_t vm_kib = 0;
  char line[256];
  while (fgets(line, sizeof line, status) != NULL) {
    if (strncmp(line, "VmSize:", 7) == 0) vm_kib = (size_t)strtoull(line + 7, NULL, 10);
  }
  fclose(status);
  if (vm_kib == 0) return 14;
  struct rlimit bounded = original;
  bounded.rlim_cur = (rlim_t)(vm_kib * 1024 + 16 * MiB);
  if (setrlimit(RLIMIT_AS, &bounded) != 0) return 15;

  errno = 0;
  void* failed = mi_realloc_aligned_at(old, 2 * 1024 * MiB, 4096, 13);
  const int failed_errno = errno;
  if (failed != NULL) {
    mi_free(failed);
    return 17;
  }
  int bytes_kept = 1;
  for (size_t i = 0; i < 1000; i++) bytes_kept &= old[i] == 0x71;
  const int usable_kept = mi_usable_size(old) == old_usable;
  errno = 0;
  void* reused = mi_realloc_aligned_at(old, old_usable, 4096, 13);
  const int reuse_errno = errno;

  printf("CRABC_MI_M4_OPERATIONS_TRACE_BEGIN\n");
  printf("oom_survival.failed_null=%d\n", failed == NULL);
  printf("oom_survival.failed_errno=%d\n", failed_errno);
  printf("oom_survival.bytes_kept=%d\n", bytes_kept);
  printf("oom_survival.usable_kept=%d\n", usable_kept);
  printf("oom_survival.same_pointer=%d\n", reused == old);
  printf("oom_survival.reuse_errno=%d\n", reuse_errno);
  printf("CRABC_MI_M4_OPERATIONS_TRACE_END\n");
  if (setrlimit(RLIMIT_AS, &original) != 0) return 16;
  if (reused != NULL) mi_free(reused);
  else mi_free(old);
  return failed_errno == ENOMEM && bytes_kept && usable_kept
      && reused == old && reuse_errno == 0 ? 0 : 17;
}
