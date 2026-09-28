/* A failed lazy PageMap submap allocation must let registration rollback
   allocate an empty submap. A later registration reuses that same submap. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "static.c"

void* __real_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset);
static bool fail_next_map;
static size_t map_attempts;

void* __wrap_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset) {
  if (fail_next_map) {
    fail_next_map = false;
    map_attempts++;
    errno = ENOMEM;
    return MAP_FAILED;
  }
  map_attempts++;
  return __real_mmap(address, length, protection, flags, fd, offset);
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

static void emit_output(void) {
  char thread_text[40];
  snprintf(thread_text, sizeof(thread_text), "0x%02zX", (size_t)_mi_thread_id());
  const size_t thread_length = strlen(thread_text);
  printf("m2.page_map.lazy_map_rollback.output=");
  for (size_t i = 0; i < output_length; ) {
    if (i + thread_length <= output_length && memcmp(output + i, thread_text, thread_length) == 0) {
      for (const char* c = "0xTID"; *c != 0; c++) printf("%02x", (unsigned char)*c);
      i += thread_length;
    } else {
      printf("%02x", (unsigned char)output[i]);
      i++;
    }
  }
  printf("\n");
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_register_output(&capture, NULL);
  mi_option_enable(mi_option_show_errors);
  mi_process_init();
  mi_page_map_t* const page_map = _mi_page_map();
  if (page_map == NULL || page_map == &mi_page_map_empty || page_map->submaps[1] != NULL) return 2;
  mi_subproc_t* const subproc = _mi_subproc_main();
  const long long reserved_before = (long long)subproc->stats.reserved.current;
  const long long committed_before = (long long)subproc->stats.committed.current;
  const long long mmap_before = (long long)subproc->stats.mmap_calls.total;
  output_length = 0;
  map_attempts = 0;
  fail_next_map = true;

  mi_page_t* const sentinel = (mi_page_t*)&mi_page_empty;
  const bool failed = !mi_page_map_set_range(page_map, sentinel, 1, 0, 1);
  const bool empty_after_failure = page_map->submaps[1] != NULL
      && page_map->submaps[1][0] == NULL;
  const size_t failure_map_attempts = map_attempts;
  const long long reserved_delta = (long long)subproc->stats.reserved.current - reserved_before;
  const long long committed_delta = (long long)subproc->stats.committed.current - committed_before;
  const long long mmap_delta = (long long)subproc->stats.mmap_calls.total - mmap_before;
  emit_output();

  const bool retry = mi_page_map_set_range(page_map, sentinel, 1, 0, 1);
  const bool entry_published = page_map->submaps[1] != NULL
      && page_map->submaps[1][0] == sentinel;
  const bool retry_reused = map_attempts == failure_map_attempts;
  const bool cleared = mi_page_map_set_range(page_map, NULL, 1, 0, 1)
      && page_map->submaps[1][0] == NULL;
  printf("m2.page_map.lazy_map_rollback.failed=%d\n", failed);
  printf("m2.page_map.lazy_map_rollback.empty_after_failure=%d\n", empty_after_failure);
  printf("m2.page_map.lazy_map_rollback.map_attempts=%zu\n", failure_map_attempts);
  printf("m2.page_map.lazy_map_rollback.reserved_delta=%lld\n", reserved_delta);
  printf("m2.page_map.lazy_map_rollback.committed_delta=%lld\n", committed_delta);
  printf("m2.page_map.lazy_map_rollback.mmap_delta=%lld\n", mmap_delta);
  printf("m2.page_map.lazy_map_rollback.retry=%d\n", retry);
  printf("m2.page_map.lazy_map_rollback.entry_published=%d\n", entry_published);
  printf("m2.page_map.lazy_map_rollback.retry_reused=%d\n", retry_reused);
  printf("m2.page_map.lazy_map_rollback.cleared=%d\n", cleared);
  printf("m2.page_map.lazy_map_rollback.root_ready=%d\n", _mi_page_map() == page_map);
  return 0;
}
