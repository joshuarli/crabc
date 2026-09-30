/* Allocation errors and returning controls use only public source APIs.
   Each argument selects a fresh process; diagnostics remain in raw stderr. */
#include <mimalloc.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int errors[8];
static size_t error_count;
static void observe_error(int code, void* argument) {
  if (argument != errors || error_count >= 8) { return; }
  errors[error_count++] = code;
}

int main(int argc, char** argv) {
  if (argc != 2) { return 2; }
  setvbuf(stdout, NULL, _IOLBF, 0);
  void* warm = mi_malloc(64);
  if (warm == NULL) { return 3; }
  mi_free(warm);
  printf("xmalloc.entered=%s\n", argv[1]);
  if (strcmp(argv[1], "oversized") == 0) {
    volatile size_t size = SIZE_MAX;
    (void)mi_malloc(size);
    puts("xmalloc.returned=1");
    return 4;
  }
  if (strcmp(argv[1], "bad-alignment") == 0) {
    volatile size_t alignment = 3;
    (void)mi_malloc_aligned(64, alignment);
    puts("xmalloc.returned=1");
    return 4;
  }
  if (strcmp(argv[1], "count-overflow") == 0) {
    volatile size_t count = SIZE_MAX;
    errno = 123;
    void* p = mi_calloc(count, 2);
    printf("xmalloc.count=%d,%d\n", p == NULL, errno);
    return p == NULL && errno == 123 ? 0 : 5;
  }
  if (strcmp(argv[1], "handler") == 0) {
    volatile size_t size = SIZE_MAX;
    mi_register_error(observe_error, errors);
    errno = 0;
    void* p = mi_malloc(size);
    const int saved_errno = errno;
    mi_register_error(NULL, NULL);
    printf("xmalloc.handler=%d,%d", p == NULL, saved_errno);
    for (size_t i = 0; i < error_count; i++) { printf(",%d", errors[i]); }
    puts("");
    return p == NULL && saved_errno == 0 && error_count != 0 ? 0 : 6;
  }
  if (strcmp(argv[1], "success") == 0) {
    unsigned char* p = mi_calloc(8, 8);
    if (p == NULL) { return 7; }
    for (size_t i = 0; i < 64; i++) { if (p[i] != 0) { return 8; } }
    mi_free(p);
    puts("xmalloc.success=1");
    return 0;
  }
  return 2;
}
