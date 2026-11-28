/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned process start's ambient Linux memory observations: mi_process_init
   reaches _mi_os_init and _mi_prim_mem_init (src/os.c:99-101,
   src/prim/unix/prim.c:250-277) and the TLD's NUMA count
   (src/os.c:862-880, src/prim/unix/prim.c:677-689) on the real host files.
   The link-time wrappers count the libc open/read/close/access/sysinfo
   imports and forward every call unchanged. Printed in the field order of
   runtime_lifecycle::tests::emit_m2_ambient_memory_detection_c_rust_trace. */
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

#include "os.c"

#if !defined(__linux__) || !(defined(__x86_64__) || defined(__aarch64__))
#error this fixture requires native Linux x86-64 or AArch64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif

static bool observing;
static int overcommit_fd = -1;
static int thp_fd = -1;
static size_t overcommit_opens;
static size_t thp_opens;
static size_t other_opens;
static size_t detection_reads;
static size_t detection_closes;
static size_t other_closes;
static size_t node_access_calls;
static size_t other_access_calls;
static size_t sysinfo_calls;

int __real_open(const char* path, int flags, ...);
ssize_t __real_read(int fd, void* buffer, size_t length);
int __real_close(int fd);
int __real_access(const char* path, int mode);
int __real_sysinfo(struct sysinfo* info);

int __wrap_open(const char* path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) != 0) {
    va_list arguments;
    va_start(arguments, flags);
    mode = va_arg(arguments, mode_t);
    va_end(arguments);
  }
  const int fd = __real_open(path, flags, mode);
  if (observing) {
    if (strcmp(path, "/proc/sys/vm/overcommit_memory") == 0 && flags == O_RDONLY) {
      overcommit_opens++;
      overcommit_fd = fd;
    }
    else if (strcmp(path, "/sys/kernel/mm/transparent_hugepage/enabled") == 0 && flags == O_RDONLY) {
      thp_opens++;
      thp_fd = fd;
    }
    else {
      other_opens++;
    }
  }
  return fd;
}

ssize_t __wrap_read(int fd, void* buffer, size_t length) {
  if (observing && ((fd == overcommit_fd && length == 32) || (fd == thp_fd && length == 64))) detection_reads++;
  return __real_read(fd, buffer, length);
}

int __wrap_close(int fd) {
  if (observing) {
    if (fd >= 0 && (fd == overcommit_fd || fd == thp_fd)) {
      detection_closes++;
      if (fd == overcommit_fd) overcommit_fd = -1;
      if (fd == thp_fd) thp_fd = -1;
    }
    else {
      other_closes++;
    }
  }
  return __real_close(fd);
}

int __wrap_access(const char* path, int mode) {
  if (observing) {
    if (strncmp(path, "/sys/devices/system/node/node", 29) == 0 && mode == R_OK) node_access_calls++;
    else other_access_calls++;
  }
  return __real_access(path, mode);
}

int __wrap_sysinfo(struct sysinfo* info) {
  if (observing) sysinfo_calls++;
  return __real_sysinfo(info);
}

static void emit(const char* field, size_t value) {
  printf("m2.ambient_detection.%s=%zu\n", field, value);
}

int main(void) {
  observing = true;
  mi_process_init();
  observing = false;
  const mi_os_mem_config_t* const config = &mi_os_mem_config;
  emit("page_size", config->page_size);
  emit("alloc_granularity", config->alloc_granularity);
  emit("large_page_size", config->large_page_size);
  emit("physical_memory_in_kib", config->physical_memory_in_kib);
  emit("virtual_address_bits", config->virtual_address_bits);
  emit("has_overcommit", config->has_overcommit);
  emit("has_partial_free", config->has_partial_free);
  emit("has_virtual_reserve", config->has_virtual_reserve);
  emit("has_transparent_huge_pages", config->has_transparent_huge_pages);
  emit("numa_node_count", (size_t)_mi_os_numa_node_count());
#if defined(SYS_open)
  emit("route.raw_open_selected", 1);
#else
  emit("route.raw_open_selected", 0);
#endif
  emit("route.overcommit_opens", overcommit_opens);
  emit("route.thp_opens", thp_opens);
  emit("route.other_opens", other_opens);
  emit("route.detection_reads", detection_reads);
  emit("route.detection_closes", detection_closes);
  emit("route.other_closes", other_closes);
  emit("route.node_scan_complete", node_access_calls >= 5 && other_access_calls == 0);
  emit("route.sysinfo_calls", sysinfo_calls);
  return 0;
}
