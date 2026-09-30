/* One fresh process per bounded allocation. The same public driver links
 * against pinned C and the native Rust adapter in separate processes. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "mimalloc.h"

static char output[1024];
static size_t output_length;
static int error_code;
static unsigned error_count;
static void capture_output(const char *message, void *argument);
static void capture_error(int code, void *argument);

static void require_at(int condition, int line) {
  if (!condition) {
    fprintf(stderr, "driver contract failed at line %d\n", line);
    if (output_length) fwrite(output, 1, output_length, stderr);
    abort();
  }
}
#define require(condition) require_at((condition), __LINE__)

struct aligned_case {
  const char *shape;
  const char *operation;
  unsigned char *block;
  size_t request;
  size_t alignment;
  size_t block_size;
  size_t usable;
  unsigned initial;
  unsigned preserved;
  unsigned growth_fill;
};

static unsigned bytes_are(const unsigned char *block, size_t size, unsigned char value) {
  for (size_t i = 0; i < size; i++) if (block[i] != value) return 0;
  return 1;
}

static void allocate_aligned_case(struct aligned_case *test) {
  const int zero = strcmp(test->operation, "calloc") == 0 || strcmp(test->operation, "rezalloc") == 0;
  if (strcmp(test->operation, "record") == 0) {
    test->block = mi_umalloc_aligned(test->request, test->alignment, &test->block_size);
  }
  else if (zero) test->block = mi_calloc_aligned(1, test->request, test->alignment);
  else test->block = mi_malloc_aligned(test->request, test->alignment);
  require(test->block != NULL);
  test->usable = mi_usable_size(test->block);
  require(test->usable >= test->request);
  test->initial = zero ? bytes_are(test->block, test->usable, 0) :
                  bytes_are(test->block, test->request, strcmp(test->shape, "small") == 0 ? 0xD0 : 0);
  test->preserved = test->growth_fill = 1;
  if (strcmp(test->operation, "realloc") == 0 || strcmp(test->operation, "rezalloc") == 0) {
    memset(test->block, 0x5A, test->request);
    size_t old_request = test->request;
    test->request = old_request * 2 + 13;
    test->block = zero ? mi_rezalloc_aligned(test->block, test->request, test->alignment) :
                        mi_realloc_aligned(test->block, test->request, test->alignment);
    require(test->block != NULL);
    test->preserved = bytes_are(test->block, old_request, 0x5A);
    test->growth_fill = bytes_are(test->block + old_request, test->request - old_request,
                                zero || strcmp(test->shape, "small") != 0 ? 0 : 0xD0);
    test->usable = mi_usable_size(test->block);
    require(test->usable >= test->request);
  }
}

static void *owner_allocate(void *argument) { allocate_aligned_case(argument); return NULL; }
static void *remote_free(void *argument) { mi_free(argument); return NULL; }

static int aligned_case(int argc, char **argv) {
  require(argc == 5);
  struct aligned_case test = {0};
  test.shape = argv[2]; test.operation = argv[3];
  test.request = strcmp(test.shape, "small") == 0 || strcmp(test.shape, "os-small") == 0 ? 17 : 589825;
  test.alignment = strcmp(test.shape, "small") == 0 ? 256 :
                   (strcmp(test.shape, "arena") == 0 ? 16 : 1024 * 1024);
  mi_register_output(&capture_output, NULL);
  mi_register_error(&capture_error, NULL);
  mi_option_set(mi_option_arena_reserve, 0);
  mi_option_set(mi_option_purge_delay, -1);
  {
    mi_arena_id_t arena = NULL;
    require(mi_reserve_os_memory_ex(64 * 1024 * 1024, false, false, false, &arena) == 0);
  }
  pthread_t thread;
  if (strcmp(argv[4], "owner-exit") == 0) {
    require(pthread_create(&thread, NULL, owner_allocate, &test) == 0);
    require(pthread_join(thread, NULL) == 0);
  }
  else allocate_aligned_case(&test);
  output_length = 0; output[0] = 0; error_count = 0; error_code = 0;
  printf("CRABC_MI_DEBUG_PADDING_TRACE_BEGIN\n");
  printf("case=%s\nshape=%s\noperation=%s\nroute=%s\n", argv[1], test.shape, test.operation, argv[4]);
  printf("usable=%zu\nrequest=%zu\n", test.usable, test.request);
  printf("aligned=%u\ninitial=%u\npreserved=%u\ngrowth_fill=%u\n",
         (uintptr_t)test.block % test.alignment == 0, test.initial, test.preserved, test.growth_fill);
  if (strcmp(argv[1], "corrupt") == 0) {
    volatile size_t offset = strcmp(test.operation, "record") == 0 ? test.block_size - 8 : test.usable;
    test.block[offset] = 1;
  }
  if (strcmp(argv[4], "remote") == 0) {
    require(pthread_create(&thread, NULL, remote_free, test.block) == 0);
    require(pthread_join(thread, NULL) == 0);
  }
  else mi_free(test.block);
  mi_collect(true);
  printf("error_count=%u\nerror_code=%d\n", error_count, error_code);
  printf("overflow_diagnostic=%u\n", strstr(output, "buffer overflow in heap block") != NULL);
  printf("owned_after_collect=%u\n", mi_check_owned(test.block));
  printf("CRABC_MI_DEBUG_PADDING_TRACE_END\n");
  if (output_length) fwrite(output, 1, output_length, stderr);
  return 0;
}

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
  if (argc == 5) return aligned_case(argc, argv);
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
