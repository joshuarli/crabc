/* Fail the direct PageMap reservation, then its fallback suffix trim.
   The aligned middle must remain usable while the escaped suffix is warned,
   removed from accounting, and left mapped for raw fixture cleanup. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

void* __real_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset);
static bool mmap_failed;
static bool munmap_failed;
static void* failed_suffix;
static size_t failed_suffix_size;

void* __wrap_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset) {
  if (!mmap_failed) {
    mmap_failed = true;
    errno = ENOMEM;
    return MAP_FAILED;
  }
  return __real_mmap(address, length, protection, flags, fd, offset);
}

int __real_munmap(void* address, size_t length);
int __wrap_munmap(void* address, size_t length) {
  if (!munmap_failed) {
    munmap_failed = true;
    failed_suffix = address;
    failed_suffix_size = length;
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(address, length);
}

static char output[2048];
static size_t output_length;

static void capture(const char* message, void* argument) {
  (void)argument;
  const size_t length = strlen(message);
  if (output_length + length < sizeof(output)) {
    memcpy(output + output_length, message, length);
    output_length += length;
  }
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_register_output(&capture, NULL);
  mi_option_enable(mi_option_show_errors);
  mi_process_init();

  char thread_text[40];
  snprintf(thread_text, sizeof(thread_text), "0x%02zX", (size_t)_mi_thread_id());
  const size_t thread_length = strlen(thread_text);
  char suffix_text[40];
  snprintf(suffix_text, sizeof(suffix_text), "0x%08zX", (size_t)failed_suffix);
  const size_t suffix_text_length = strlen(suffix_text);
  printf("m2.page_map.fallback_trim_fault.output=");
  for (size_t i = 0; i < output_length; ) {
    if (i + thread_length <= output_length && memcmp(output + i, thread_text, thread_length) == 0) {
      for (const char* c = "0xTID"; *c != 0; c++) printf("%02x", (unsigned char)*c);
      i += thread_length;
    } else if (i + suffix_text_length <= output_length
        && memcmp(output + i, suffix_text, suffix_text_length) == 0) {
      for (const char* c = "0xSUFFIX"; *c != 0; c++) printf("%02x", (unsigned char)*c);
      i += suffix_text_length;
    } else {
      printf("%02x", (unsigned char)output[i]);
      i++;
    }
  }
  printf("\n");

  mi_subproc_t* const subproc = _mi_subproc_main();
  printf("m2.page_map.fallback_trim_fault.initialized=%d\n", _mi_page_map() != &mi_page_map_empty);
  printf("m2.page_map.fallback_trim_fault.reserved=%lld\n", (long long)subproc->stats.reserved.current);
  printf("m2.page_map.fallback_trim_fault.committed=%lld\n", (long long)subproc->stats.committed.current);
  printf("m2.page_map.fallback_trim_fault.mmap_calls=%lld\n", (long long)subproc->stats.mmap_calls.total);
  printf("m2.page_map.fallback_trim_fault.commit_calls=%lld\n", (long long)subproc->stats.commit_calls.total);
  unsigned char residency = 0;
  const bool suffix_live = failed_suffix != NULL
      && mincore(failed_suffix, (size_t)sysconf(_SC_PAGESIZE), &residency) == 0;
  printf("m2.page_map.fallback_trim_fault.suffix_length=%zu\n", failed_suffix_size);
  printf("m2.page_map.fallback_trim_fault.suffix_live=%d\n", suffix_live);
  void* block = mi_malloc(16);
  printf("m2.page_map.fallback_trim_fault.allocated=%d\n", block != NULL);
  mi_free(block);
  if (failed_suffix != NULL) {
    const int cleaned = __real_munmap(failed_suffix, failed_suffix_size);
    printf("m2.page_map.fallback_trim_fault.raw_cleanup=%d\n", cleaned == 0);
  }
  return 0;
}
