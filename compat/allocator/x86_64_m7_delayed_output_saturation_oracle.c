/* Exercise the delayed output cap and terminal custom registration directly
   against the pinned options.c state included by static.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "static.c"

static size_t deliveries;
static size_t lengths[2];
static uint64_t hashes[2];

static void capture(const char* message, void* argument) {
  (void)argument;
  if (deliveries >= 2 || message == NULL) abort();
  const size_t index = deliveries++;
  hashes[index] = UINT64_C(14695981039346656037);
  for (const unsigned char* p = (const unsigned char*)message; *p != 0; p++) {
    lengths[index]++;
    hashes[index] = (hashes[index] ^ *p) * UINT64_C(1099511628211);
  }
}

int main(void) {
  char fragment[901];
  memset(fragment, 'x', sizeof(fragment) - 1);
  fragment[sizeof(fragment) - 1] = 0;

  /* The executable has finished source post-init before main. Restore the
     source's initial private output route for this isolated transition. */
  mi_atomic_store_ptr_release(void, &mi_out_default, NULL);
  mi_atomic_store_ptr_release(void, &mi_out_arg, NULL);
  mi_atomic_store_release(&out_len, (size_t)0);
  out_buf[0] = 0;

  for (size_t i = 0; i < 19; i++) _mi_raw_message("%s", fragment);
  mi_register_output(&capture, NULL);
  _mi_raw_message("%s", "tail\n");
  if (deliveries != 2 || lengths[0] != 16383 || lengths[1] != 5) abort();

  printf("CRABC_MI_M7_DELAYED_OUTPUT_SATURATION_TRACE_BEGIN\n");
  printf("deliveries=%zu\n", deliveries);
  for (size_t i = 0; i < deliveries; i++) {
    printf("delivery.%zu=%zu,%016llx\n", i, lengths[i], (unsigned long long)hashes[i]);
  }
  printf("CRABC_MI_M7_DELAYED_OUTPUT_SATURATION_TRACE_END\n");
  return 0;
}
