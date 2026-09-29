/* One empty huge reservation through the pinned startup reservation policy. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "static.c"

static size_t reservation_warnings;
static size_t primitive_warnings;

void* __real_mmap(void*, size_t, int, int, int, off_t);
void* __wrap_mmap(void* address, size_t size, int protection, int flags, int descriptor, off_t offset) {
  if ((flags & MAP_HUGETLB) != 0) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  return __real_mmap(address, size, protection, flags, descriptor, offset);
}

static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (strstr(message, "failed to reserve 1 GiB huge pages") != NULL) reservation_warnings++;
  if (strstr(message, "unable to allocate huge OS page") != NULL) primitive_warnings++;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);
  const int result = mi_reserve_huge_os_pages_at_ex(1, 0, 0, false, NULL);
  if (result != ENOMEM || primitive_warnings != 1) return 2;
  printf("m2.startup_huge_failure.warning_count=%zu\n", reservation_warnings);
  return 0;
}
