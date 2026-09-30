#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mimalloc.h"

typedef struct { uint32_t words[7]; } item_t;
static int failures;
static void check(const char* name, int value) {
  printf("%s=%d\n", name, value != 0);
  failures += !value;
}
static int zero(const void* p, size_t n) {
  if (!p) return 0;
  const unsigned char* b = p;
  for (size_t i = 0; i < n; ++i) if (b[i]) return 0;
  return 1;
}
static int filled(const void* p, size_t n) {
  if (!p) return 0;
  const unsigned char* b = p;
  for (size_t i = 0; i < n; ++i) if (b[i] != 0x5a) return 0;
  return 1;
}
static mi_heap_t* counted_heap(mi_heap_t* heap, int* calls) { ++*calls; return heap; }
static size_t counted_count(int* calls) { ++*calls; return 3; }

int main(void) {
  mi_heap_t* heap = mi_heap_new();
  check("heap", heap != NULL);
  if (!heap) return 1;
  int calls = 0;
  item_t* p = mi_heap_malloc_tp(item_t, counted_heap(heap, &calls));
  check("malloc.typed", p && mi_heap_of(p) == heap && mi_usable_size(p) >= sizeof(*p) && calls == 1);
  if (p) { memset(p, 0x5a, sizeof(*p)); mi_free(p); }
  p = mi_heap_zalloc_tp(item_t, heap);
  check("zalloc.typed", zero(p, sizeof(*p)) && mi_heap_of(p) == heap);
  mi_free(p);
  p = mi_heap_calloc_tp(item_t, heap, 3);
  check("calloc.typed", zero(p, 3 * sizeof(*p)) && mi_heap_of(p) == heap);
  mi_free(p);
  calls = 0;
  p = mi_heap_mallocn_tp(item_t, heap, counted_count(&calls));
  check("mallocn.typed", p && calls == 1 && mi_heap_of(p) == heap && mi_usable_size(p) >= 3 * sizeof(*p));
  if (!p) return 1;
  memset(p, 0x5a, 3 * sizeof(*p));
  item_t* q = mi_heap_reallocn_tp(item_t, heap, p, 300);
  check("reallocn.grow", filled(q, 3 * sizeof(*p)) && mi_heap_of(q) == heap);
  if (!q) { mi_free(p); return 1; }
  p = q;
  q = mi_heap_reallocn_tp(item_t, heap, p, 2);
  check("reallocn.shrink", filled(q, 2 * sizeof(*p)) && mi_heap_of(q) == heap);
  if (!q) { mi_free(p); return 1; }
  mi_free(q);
  p = mi_heap_calloc_tp(item_t, heap, 3);
  if (!p) return 1;
  const size_t old_usable = mi_usable_size(p);
  memset(p, 0x5a, old_usable);
  q = mi_heap_recalloc_tp(item_t, heap, p, 300);
  /* Recalloc starts zeroing at the previous usable size, not requested size. */
  check("recalloc.grow", filled(q, old_usable) && q &&
        zero((unsigned char*)q + old_usable, 300 * sizeof(*q) - old_usable) && mi_heap_of(q) == heap);
  if (!q) { mi_free(p); return 1; }
  mi_free(q);
  q = mi_heap_reallocn_tp(item_t, heap, NULL, 3);
  check("reallocn.null", q && mi_heap_of(q) == heap);
  mi_free(q);
  q = mi_heap_recalloc_tp(item_t, heap, NULL, 3);
  check("recalloc.null", zero(q, 3 * sizeof(*q)) && mi_heap_of(q) == heap);
  mi_free(q);
  p = mi_heap_malloc_tp(item_t, heap);
  if (!p) return 1;
  q = mi_heap_reallocn_tp(item_t, heap, p, 0);
  check("reallocn.zero", q && mi_heap_of(q) == heap);
  if (!q) { mi_free(p); return 1; }
  mi_free(q);
  p = mi_heap_zalloc_tp(item_t, heap);
  if (!p) return 1;
  q = mi_heap_recalloc_tp(item_t, heap, p, 0);
  check("recalloc.zero", q && mi_heap_of(q) == heap);
  if (!q) { mi_free(p); return 1; }
  mi_free(q);
  for (int i = 0; i < 4; ++i) {
    void* z = i == 0 ? mi_heap_calloc_tp(item_t, heap, 0) :
              i == 1 ? mi_heap_mallocn_tp(item_t, heap, 0) :
              i == 2 ? mi_heap_reallocn_tp(item_t, heap, NULL, 0) :
                       mi_heap_recalloc_tp(item_t, heap, NULL, 0);
    check("zero.count", z && mi_heap_of(z) == heap);
    mi_free(z);
  }
  /* Volatile counts keep real multiply-overflow requests in the caller. */
  volatile size_t overflow = SIZE_MAX / sizeof(item_t) + 1;
  errno = 0;
  q = mi_heap_calloc_tp(item_t, heap, overflow);
  check("calloc.overflow", q == NULL);
  printf("calloc.errno=%d\n", errno);
  errno = 0;
  q = mi_heap_mallocn_tp(item_t, heap, overflow);
  check("mallocn.overflow", q == NULL);
  printf("mallocn.errno=%d\n", errno);
  p = mi_heap_mallocn_tp(item_t, heap, 3);
  if (!p) return 1;
  memset(p, 0x5a, 3 * sizeof(*p));
  errno = 0;
  q = mi_heap_reallocn_tp(item_t, heap, p, overflow);
  check("reallocn.failure_preserves", !q && filled(p, 3 * sizeof(*p)) && mi_heap_of(p) == heap);
  printf("reallocn.errno=%d\n", errno);
  errno = 0;
  q = mi_heap_recalloc_tp(item_t, heap, p, overflow);
  check("recalloc.failure_preserves", !q && filled(p, 3 * sizeof(*p)) && mi_heap_of(p) == heap);
  printf("recalloc.errno=%d\n", errno);
  mi_free(p);
  volatile size_t huge = SIZE_MAX / sizeof(item_t);
  q = mi_heap_mallocn_tp(item_t, heap, huge);
  check("mallocn.refused_size", q == NULL);
  mi_free(q);
  q = mi_heap_calloc_tp(item_t, heap, huge);
  check("calloc.refused_size", q == NULL);
  mi_free(q);
  p = mi_heap_mallocn_tp(item_t, heap, 3);
  if (!p) return 1;
  memset(p, 0x5a, 3 * sizeof(*p));
  q = mi_heap_reallocn_tp(item_t, heap, p, huge);
  check("reallocn.refused_preserves", !q && filled(p, 3 * sizeof(*p)) && mi_heap_of(p) == heap);
  q = mi_heap_recalloc_tp(item_t, heap, p, huge);
  check("recalloc.refused_preserves", !q && filled(p, 3 * sizeof(*p)) && mi_heap_of(p) == heap);
  mi_free(p);
  mi_heap_destroy(heap);
  mi_heap_t* main_heap = mi_heap_main();
  p = mi_heap_calloc_tp(item_t, main_heap, 3);
  mi_heap_delete(main_heap);
  mi_heap_destroy(main_heap);
  check("main.refuses_release", zero(p, 3 * sizeof(*p)) && mi_heap_of(p) == main_heap);
  mi_free(p);
  mi_heap_delete(NULL);
  mi_heap_destroy(NULL);
  check("null.release", 1);
  fflush(stdout);
  /* Avoid unrelated process-exit policy in this caller-owned API boundary. */
  _exit(failures ? 1 : 0);
}
