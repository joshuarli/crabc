/*
 * SPDX-License-Identifier: MIT
 *
 * Harness-side launcher for the integrated startup-plus-first-allocation
 * row.  It is built once with the pinned musl toolchain and is identical
 * for both allocator products; only the program it launches differs.
 *
 *   integrated-startup-launcher batches=B launches=L root=DIR|- PROGRAM ARG...
 *
 * Each batch forks and execs PROGRAM L times in sequence (chrooted into
 * DIR unless DIR is `-`), waits for each, and prints one record in the
 * engine fixture's grammar, then `ok`:
 *
 *   batch ns=<wall ns for L launches> cpu_ns=<children's user+system ns> ops=<L>
 *
 * The launched program's output goes to /dev/null; any nonzero status fails.
 */
#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
  struct timespec value;
  clock_gettime(CLOCK_MONOTONIC, &value);
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static int parse(const char *argument, const char *key, unsigned long *out)
{
  const size_t length = strlen(key);
  char *end = NULL;
  if (strncmp(argument, key, length) != 0 || argument[length] != '=') return -1;
  *out = strtoul(argument + length + 1, &end, 10);
  return end != NULL && *end == '\0' && *out != 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
  unsigned long batches;
  unsigned long launches;
  const char *root;
  int null_fd;
  unsigned long batch;
  if (argc < 5 || parse(argv[1], "batches", &batches) != 0 || parse(argv[2], "launches", &launches) != 0
      || strncmp(argv[3], "root=", 5) != 0) {
    fputs("usage: integrated-startup-launcher batches=B launches=L root=DIR|- PROGRAM ARG...\n", stderr);
    return 64;
  }
  root = argv[3] + 5;
  null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (null_fd < 0) return 65;
  for (batch = 0; batch < batches; batch++) {
    const uint64_t before = now_ns();
    uint64_t cpu = 0;
    unsigned long index;
    for (index = 0; index < launches; index++) {
      struct rusage usage;
      int status = 0;
      const pid_t child = fork();
      if (child == 0) {
        if (dup2(null_fd, 1) < 0 || dup2(null_fd, 2) < 0) _exit(126);
        if (strcmp(root, "-") != 0 && (chroot(root) != 0 || chdir("/") != 0)) _exit(125);
        execv(argv[4], argv + 4);
        _exit(127);
      }
      if (child < 0 || wait4(child, &status, 0, &usage) != child) return 66;
      if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "launched program failed: status %d\n", status);
        return 67;
      }
      cpu += (uint64_t)usage.ru_utime.tv_sec * UINT64_C(1000000000) + (uint64_t)usage.ru_utime.tv_usec * 1000
             + (uint64_t)usage.ru_stime.tv_sec * UINT64_C(1000000000) + (uint64_t)usage.ru_stime.tv_usec * 1000;
    }
    printf("batch ns=%" PRIu64 " cpu_ns=%" PRIu64 " ops=%lu\n", now_ns() - before, cpu == 0 ? 1 : cpu, launches);
  }
  printf("ok\n");
  return fflush(stdout) == 0 ? 0 : 72;
}
