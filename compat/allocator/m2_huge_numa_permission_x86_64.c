/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* One ordinary-page permission probe for the hardware huge/NUMA job.
 *
 * This deliberately does not use MAP_HUGETLB, reserve a huge page, touch the
 * anonymous byte, modify NUMA policy outside its private mapping, or retry a
 * denial.  It records the one raw flags=0 MPOL_PREFERRED mbind result and
 * immediately unmaps the page.  A nonzero mbind result is a reportable
 * pending permission gate, not evidence that seccomp in general denied it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Linux 5.10's stable mbind ABI value.  This is the same source constant as
 * `crabc-mimalloc/src/os.rs`; the pinned musl image intentionally does not
 * ship Linux UAPI headers. */
enum { MPOL_PREFERRED = 1 };

int main(int argc, char** argv) {
  if (argc != 2) return 64;
  char* end = NULL;
  errno = 0;
  const long node = strtol(argv[1], &end, 10);
  if (errno != 0 || end == argv[1] || *end != '\0' || node < 0 || node >= 63) return 65;
  const long page = sysconf(_SC_PAGESIZE);
  if (page <= 0 || page > INT_MAX) return 66;
  void* mapping = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) return 67;
  const unsigned long mask = 1UL << node;
  errno = 0;
  const long result = syscall(SYS_mbind, mapping, (unsigned long)page,
                              MPOL_PREFERRED, &mask, 8 * sizeof(mask), 0);
  const int mbind_errno = (result == 0 ? 0 : errno);
  const int unmap_result = munmap(mapping, (size_t)page);
  const int unmap_errno = (unmap_result == 0 ? 0 : errno);
  printf("CRABC_MI_HUGE_NUMA_MBIND_PROBE.node=%ld\n", node);
  printf("CRABC_MI_HUGE_NUMA_MBIND_PROBE.page_bytes=%ld\n", page);
  printf("CRABC_MI_HUGE_NUMA_MBIND_PROBE.result=%ld\n", result);
  printf("CRABC_MI_HUGE_NUMA_MBIND_PROBE.errno=%d\n", mbind_errno);
  printf("CRABC_MI_HUGE_NUMA_MBIND_PROBE.unmap_result=%d\n", unmap_result);
  printf("CRABC_MI_HUGE_NUMA_MBIND_PROBE.unmap_errno=%d\n", unmap_errno);
  return (unmap_result == 0 ? 0 : 68);
}
