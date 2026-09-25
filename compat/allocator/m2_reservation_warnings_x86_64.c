/* Pinned-C half of the M2 failed-reservation warning differential.

   Built against the pinned mimalloc v3.5.0 release sources (`src/static.c`)
   with an empty environment by `m2_reservation_warnings_x86_64.py`. With
   `show_errors` enabled and a registered output, it drives the two failed
   `mi_reserve_os_memory_ex2` reservations whose source warnings the port
   must render identically:

   - an unmappable size (`1 << 62`), committed and uncommitted:
     `mi_os_prim_alloc_at` (`src/os.c:319-322`) warns "unable to allocate OS
     memory" for the direct candidate, `mi_os_prim_alloc_aligned` warns its
     over-allocation fallback, and the over-allocation warns again;
   - a 100-byte request, rounded to one slice, which maps but is rejected by
     `mi_manage_os_memory_ex2` (`src/arena.c:1816-1819`) as "not large
     enough".

   Each case prints its return code and its output fragments as hex, with the
   thread's `0x<tid>` replaced by `0xTID`; the Rust test
   `arena::owned::tests::emit_m2_reservation_warnings_c_rust_trace` prints
   the same keys. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "static.c"

#define MAX_MESSAGES 16
#define MAX_MESSAGE_BYTES 256

static size_t message_count;
static char messages[MAX_MESSAGES][MAX_MESSAGE_BYTES];
static char thread_text[40];

static void capture(const char* message, void* argument) {
  (void)argument;
  if (message == NULL || message[0] == 0) return;
  if (message_count < MAX_MESSAGES) snprintf(messages[message_count], MAX_MESSAGE_BYTES, "%s", message);
  message_count++;
}

static void print_case(const char* name, int rc) {
  printf("m2.reservation_warnings.%s.rc=%d\n", name, rc);
  printf("m2.reservation_warnings.%s.messages=", name);
  const size_t thread_length = strlen(thread_text);
  for (size_t index = 0; index < message_count && index < MAX_MESSAGES; index++) {
    if (index != 0) printf(":");
    const char* message = messages[index];
    const size_t length = strlen(message);
    for (size_t i = 0; i < length; ) {
      if (i + thread_length <= length && memcmp(message + i, thread_text, thread_length) == 0) {
        for (const char* c = "0xTID"; *c != 0; c++) printf("%02x", (unsigned char)*c);
        i += thread_length;
      } else {
        printf("%02x", (unsigned char)message[i]);
        i++;
      }
    }
  }
  printf("\n");
  message_count = 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  mi_register_output(&capture, NULL);
  message_count = 0;
  mi_option_enable(mi_option_show_errors);
  snprintf(thread_text, sizeof(thread_text), "0x%02zX", (size_t)_mi_thread_id());

  int rc = mi_reserve_os_memory_ex((size_t)1 << 62, true, false, false, NULL);
  print_case("unmappable_committed", rc);
  rc = mi_reserve_os_memory_ex((size_t)1 << 62, false, true, false, NULL);
  print_case("unmappable_reserved", rc);
  rc = mi_reserve_os_memory(100, true, false);
  print_case("too_small", rc);
  return 0;
}
