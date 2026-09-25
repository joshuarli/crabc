/* Pinned-C half of the M2 PageMap first-map fallback differential.

   Pinned `mi_page_map_init_once` (src/page-map.c:302) maps its top-level
   extent through `_mi_os_alloc_aligned(subproc, extra_reserve_size, 1,
   commit, true)`. When that direct map fails, `mi_os_prim_alloc_aligned`
   (src/os.c:366-420) warns, over-allocates by one page, and trims, so the
   page map still initializes and allocation proceeds.

   Built against the pinned v3.5.0 release sources (`src/static.c`) by
   `m2_page_map_first_map_fallback_x86_64.py` with `mmap` link-wrapped to
   fail its first call, which is the page map's direct map. With
   `show_errors` enabled and a registered output, it prints the joined
   TID-normalized output of `mi_process_init` as hex, the main-subprocess
   VM statistics after it, and whether a first allocation succeeds; the
   Rust test `process_page_map::tests::emit_m2_page_map_first_map_fallback_c_rust_trace`
   prints the same keys. */
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
static bool mmap_failed;

void* __wrap_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset) {
  if (!mmap_failed) {
    mmap_failed = true;
    errno = ENOMEM;
    return MAP_FAILED;
  }
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

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_register_output(&capture, NULL);
  mi_option_enable(mi_option_show_errors);
  mi_process_init();

  char thread_text[40];
  snprintf(thread_text, sizeof(thread_text), "0x%02zX", (size_t)_mi_thread_id());
  const size_t thread_length = strlen(thread_text);
  printf("m2.page_map.first_map_fallback.output=");
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

  mi_subproc_t* const subproc = _mi_subproc_main();
  printf("m2.page_map.first_map_fallback.initialized=%d\n", _mi_page_map() != &mi_page_map_empty);
  printf("m2.page_map.first_map_fallback.reserved=%lld\n", (long long)subproc->stats.reserved.current);
  printf("m2.page_map.first_map_fallback.committed=%lld\n", (long long)subproc->stats.committed.current);
  printf("m2.page_map.first_map_fallback.mmap_calls=%lld\n", (long long)subproc->stats.mmap_calls.total);
  printf("m2.page_map.first_map_fallback.commit_calls=%lld\n", (long long)subproc->stats.commit_calls.total);
  void* block = mi_malloc(16);
  printf("m2.page_map.first_map_fallback.allocated=%d\n", block != NULL);
  mi_free(block);
  return 0;
}
