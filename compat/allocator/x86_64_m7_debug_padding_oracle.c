/* One fresh process per bounded allocation. The same public driver links
 * against pinned C and the native Rust adapter in separate processes. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mimalloc.h"

static char output[1024];
static size_t output_length;
static int error_code;
static unsigned error_count;

static void capture_output(const char *message, void *argument) {
  (void)argument;
  if (message == NULL) return;
  size_t length = strlen(message);
  if (length >= sizeof(output) - output_length) {
    length = sizeof(output) - output_length - 1;
  }
  memcpy(output + output_length, message, length);
  output_length += length;
  output[output_length] = 0;
}

static void capture_error(int code, void *argument) {
  (void)argument;
  error_code = code;
  error_count++;
}

int main(int argc, char **argv) {
  if (argc != 2 || (strcmp(argv[1], "clean") != 0 && strcmp(argv[1], "corrupt") != 0)) return 2;
  const int corrupt = strcmp(argv[1], "corrupt") == 0;
  mi_register_output(&capture_output, NULL);
  mi_register_error(&capture_error, NULL);
  output_length = 0;
  output[0] = 0;
  printf("CRABC_MI_DEBUG_PADDING_TRACE_BEGIN\n");
  printf("case=%s\n", argv[1]);
  printf("show_errors=%ld\n", mi_option_get(mi_option_show_errors));
  unsigned char *block = (unsigned char *)mi_malloc(17);
  if (block == NULL) return 3;
  printf("usable=%zu\n", mi_usable_size(block));
  unsigned filled = 1;
  for (size_t index = 0; index < 17; index++) {
    if (block[index] != 0xD0) filled = 0;
  }
  printf("debug_uninit_fill=%u\n", filled);
  volatile size_t corrupt_offset = 17;
  if (corrupt) block[corrupt_offset] = 0;
  mi_free(block);
  printf("error_count=%u\n", error_count);
  printf("error_code=%d\n", error_code);
  printf("overflow_diagnostic=%u\n", strstr(output, "buffer overflow in heap block") != NULL);
  printf("offset_17_diagnostic=%u\n", strstr(output, "write after 17 bytes") != NULL);
  printf("CRABC_MI_DEBUG_PADDING_TRACE_END\n");
  return 0;
}
