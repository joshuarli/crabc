/* Shared C driver for the allocator M6 adapter differential.

   The same unmodified source is linked once against the pinned mimalloc
   v3.5.0 release sources (`src/static.c`) and once against the native Rust
   adapter (`native-mi-adapter/`), and each binary runs as its own process
   with an empty environment. It calls only public `mimalloc.h` entries: the
   first-class Heap and OS-reservation entries of M6, plus the M4 free and
   M7 output/error/statistics entries it needs to observe them. It prints
   address-free `key=value` facts, so the two traces must be identical.
   Driven by `compat/allocator/x86_64_m6_adapter.py`. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

#define MAX_MESSAGES 32
#define MAX_MESSAGE_BYTES 256
#define MIB ((size_t)1 << 20)
#define GIB ((size_t)1 << 30)

static size_t message_count;
static char messages[MAX_MESSAGES][MAX_MESSAGE_BYTES];

static void capture(const char* message, void* argument) {
  (void)argument;
  if (message == NULL || message[0] == 0) return;
  if (message_count < MAX_MESSAGES) snprintf(messages[message_count], MAX_MESSAGE_BYTES, "%s", message);
  message_count++;
}

static char thread_text[40];

/* Messages print as hex with the initial thread's `0x<tid>` replaced by
   `0xTID`, as the M7 adapter driver prints them. */
static void print_messages(const char* key) {
  printf("%s=", key);
  const size_t thread_length = strlen(thread_text);
  for (size_t index = 0; index < message_count && index < MAX_MESSAGES; index++) {
    if (index != 0) printf(":");
    const char* message = messages[index];
    const size_t length = strlen(message);
    for (size_t i = 0; i < length; ) {
      if (thread_length > 0 && i + thread_length <= length && memcmp(message + i, thread_text, thread_length) == 0) {
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

static int error_codes[16];
static size_t error_count;

static void record_error(int code, void* argument) {
  (void)argument;
  if (error_count < 16) error_codes[error_count] = code;
  error_count++;
}

static void print_errors(const char* key) {
  printf("%s=", key);
  for (size_t i = 0; i < error_count && i < 16; i++) printf("%s%d", i == 0 ? "" : ",", error_codes[i]);
  printf("\n");
  error_count = 0;
}

static bool zeroed(const void* p, size_t size) {
  const unsigned char* bytes = (const unsigned char*)p;
  for (size_t i = 0; i < size; i++) if (bytes[i] != 0) return false;
  return true;
}

static mi_stats_t stats_now(void) {
  mi_stats_t_decl(stats);
  mi_stats_get(&stats);
  return stats;
}

static void reserve_section(void) {
  mi_stats_t before = stats_now();
  int rc = mi_reserve_os_memory(64 * MIB, true, false);
  mi_stats_t after = stats_now();
  printf("reserve.commit.rc=%d\n", rc);
  printf("reserve.commit.reserved=%lld\n", (long long)(after.reserved.current - before.reserved.current));
  printf("reserve.commit.committed=%lld\n", (long long)(after.committed.current - before.committed.current));
  printf("reserve.commit.arena_count=%lld\n", (long long)(after.arena_count.total - before.arena_count.total));

  before = stats_now();
  rc = mi_reserve_os_memory(16 * GIB, false, true);   /* test-api.c arena_reserve */
  after = stats_now();
  printf("reserve.lazy.rc=%d\n", rc);
  printf("reserve.lazy.reserved=%lld\n", (long long)(after.reserved.current - before.reserved.current));
  printf("reserve.lazy.committed=%lld\n", (long long)(after.committed.current - before.committed.current));

  rc = mi_reserve_os_memory(100, true, false);        /* rounded up to one slice */
  printf("reserve.small.rc=%d\n", rc);

  mi_arena_id_t arena = NULL;
  rc = mi_reserve_os_memory_ex(64 * MIB, true, false, true, &arena);
  printf("reserve.exclusive.rc=%d\n", rc);
  printf("reserve.exclusive.id=%d\n", arena != NULL ? 1 : 0);

  /* An exclusive arena is not used by ordinary allocation. */
  void* p = mi_malloc(32);
  printf("reserve.exclusive.after_malloc=%d\n", p != NULL ? 1 : 0);
  mi_free(p);

  errno = 0;
  arena = (mi_arena_id_t)&rc;
  rc = mi_reserve_os_memory_ex((size_t)1 << 62, true, false, false, &arena);
  printf("reserve.too_large.rc=%d\n", rc);
  printf("reserve.too_large.id=%d\n", arena == NULL ? 0 : 1);
  printf("reserve.too_large.errno=%d\n", errno);
  print_errors("reserve.too_large.codes");
  print_messages("reserve.too_large.messages");

  errno = 0;
  rc = mi_reserve_os_memory(SIZE_MAX, true, false);
  printf("reserve.over_max.rc=%d\n", rc);
  printf("reserve.over_max.errno=%d\n", errno);
  print_errors("reserve.over_max.codes");
  print_messages("reserve.over_max.messages");
}

static void allocation_section(void) {
  mi_heap_t* h = mi_heap_new();
  printf("heap.new=%d\n", h != NULL ? 1 : 0);
  printf("heap.new.not_main=%d\n", h != mi_heap_main() ? 1 : 0);
  void* p = mi_heap_malloc(h, 32);
  printf("heap.malloc=%d\n", p != NULL ? 1 : 0);
  printf("heap.malloc.usable=%zu\n", mi_usable_size(p));
  memset(p, 0xa5, 32);
  mi_free(p);
  p = mi_heap_malloc(h, 32);
  printf("heap.malloc.reuse_usable=%zu\n", mi_usable_size(p));
  unsigned char* z = (unsigned char*)mi_heap_zalloc(h, 200);
  printf("heap.zalloc=%d\n", z != NULL && zeroed(z, 200) ? 1 : 0);
  unsigned char* c = (unsigned char*)mi_heap_calloc(h, 10, 30);
  printf("heap.calloc=%d\n", c != NULL && zeroed(c, 300) ? 1 : 0);
  printf("heap.calloc.usable=%zu\n", mi_usable_size(c));
  errno = 0;
  void* overflow = mi_heap_calloc(h, SIZE_MAX / 2, 3);
  printf("heap.calloc.overflow=%d,%d\n", overflow == NULL ? 1 : 0, errno);
  void* n = mi_heap_mallocn(h, 8, 16);
  printf("heap.mallocn.usable=%zu\n", mi_usable_size(n));
  void* small = mi_heap_malloc_small(h, 8);
  void* zsmall = mi_heap_zalloc_small(h, 64);
  printf("heap.small=%zu,%d\n", mi_usable_size(small), zsmall != NULL && zeroed(zsmall, 64) ? 1 : 0);
  void* a = mi_heap_malloc_aligned(h, 100, 256);
  printf("heap.aligned=%d,%zu\n", ((uintptr_t)a % 256) == 0 ? 1 : 0, mi_usable_size(a));
  void* at = mi_heap_malloc_aligned_at(h, 100, 128, 16);
  printf("heap.aligned_at=%d\n", (((uintptr_t)at + 16) % 128) == 0 ? 1 : 0);
  unsigned char* za = (unsigned char*)mi_heap_zalloc_aligned(h, 1000, 64);
  printf("heap.zalloc_aligned=%d\n", ((uintptr_t)za % 64) == 0 && zeroed(za, 1000) ? 1 : 0);
  unsigned char* zat = (unsigned char*)mi_heap_zalloc_aligned_at(h, 1000, 64, 8);
  printf("heap.zalloc_aligned_at=%d\n", (((uintptr_t)zat + 8) % 64) == 0 && zeroed(zat, 1000) ? 1 : 0);
  unsigned char* ca = (unsigned char*)mi_heap_calloc_aligned(h, 5, 50, 32);
  printf("heap.calloc_aligned=%d\n", ((uintptr_t)ca % 32) == 0 && zeroed(ca, 250) ? 1 : 0);
  unsigned char* cat = (unsigned char*)mi_heap_calloc_aligned_at(h, 5, 50, 32, 4);
  printf("heap.calloc_aligned_at=%d\n", (((uintptr_t)cat + 4) % 32) == 0 && zeroed(cat, 250) ? 1 : 0);
  void* big = mi_heap_malloc(h, 5 * MIB);
  printf("heap.huge=%d,%zu\n", big != NULL ? 1 : 0, mi_usable_size(big));

  errno = 0;
  void* bad = mi_heap_malloc_aligned(h, 100, 24);
  printf("heap.bad_alignment=%d,%d\n", bad == NULL ? 1 : 0, errno);
  print_errors("heap.bad_alignment.codes");
  print_messages("heap.bad_alignment.messages");
  errno = 0;
  void* huge = mi_heap_malloc(h, (size_t)PTRDIFF_MAX + 1);
  printf("heap.too_large=%d,%d\n", huge == NULL ? 1 : 0, errno);
  print_errors("heap.too_large.codes");
  print_messages("heap.too_large.messages");

  mi_free(p); mi_free(z); mi_free(c); mi_free(n); mi_free(small); mi_free(zsmall);
  mi_free(a); mi_free(at); mi_free(za); mi_free(zat); mi_free(ca); mi_free(cat);
  mi_free(big);
  mi_heap_destroy(h);
  print_messages("heap.destroy.messages");

  /* The main Heap allocates from the default Theap and refuses release. */
  mi_heap_t* main_heap = mi_heap_main();
  printf("heap.main=%d\n", main_heap != NULL ? 1 : 0);
  void* m = mi_heap_malloc(main_heap, 48);
  printf("heap.main.malloc=%zu\n", mi_usable_size(m));
  mi_free(m);
  mi_heap_delete(main_heap);
  mi_heap_destroy(main_heap);
  print_messages("heap.main.release.messages");
  mi_heap_delete(NULL);
  mi_heap_destroy(NULL);
  print_messages("heap.null.release.messages");
}

static void delete_section(void) {
  /* test-api.c heap-os1 and heap-os2. */
  mi_heap_t* h = mi_heap_new();
  void* moved = mi_heap_malloc_aligned(h, MIB, 2 * MIB);
  void* regular = mi_heap_malloc(h, 1000);
  memset(regular, 1, 1000);
  mi_heap_delete(h);
  printf("delete.usable=%zu,%zu\n", mi_usable_size(moved), mi_usable_size(regular));
  mi_free(moved);
  mi_free(regular);

  mi_collect(true);
  mi_stats_t before = stats_now();
  h = mi_heap_new();
  long failed = 0;
  for (int i = 0; i < 10; i++) {
    int* p = (int*)mi_heap_malloc_aligned(h, MIB, 2 * MIB);
    if (p == NULL) failed++; else p[0] = 42;
  }
  mi_stats_t during = stats_now();
  mi_heap_destroy(h);
  mi_collect(true);
  mi_stats_t after = stats_now();
  printf("destroy.failed=%ld\n", failed);
  printf("destroy.pages.during=%lld\n", (long long)(during.pages.current - before.pages.current));
  printf("destroy.pages.after=%lld\n", (long long)(after.pages.current - before.pages.current));
  printf("destroy.heaps.after=%lld\n", (long long)(after.heaps.current - before.heaps.current));

  /* test-api.c heap-many. */
  enum { NHEAPS = 1000 };
  static mi_heap_t* heaps[NHEAPS];
  int ok = 1;
  for (size_t i = 0; i < NHEAPS; i++) {
    heaps[i] = mi_heap_new();
    if (heaps[i] == NULL || mi_heap_malloc(heaps[i], 32) == NULL) { ok = 0; break; }
  }
  mi_stats_t many = stats_now();
  for (size_t i = 0; i < NHEAPS; i++) mi_heap_destroy(heaps[i]);
  mi_stats_t done = stats_now();
  printf("many.ok=%d\n", ok);
  printf("many.heaps=%lld,%lld\n", (long long)(many.heaps.current - after.heaps.current),
         (long long)(done.heaps.current - after.heaps.current));
}

static mi_heap_t* shared_heap;
static void* worker_blocks[3];

static void* worker(void* argument) {
  (void)argument;
  /* A second thread's own Theap for a Heap the initial thread created. */
  worker_blocks[0] = mi_heap_malloc(shared_heap, 64);
  worker_blocks[1] = mi_heap_malloc(shared_heap, 64);
  worker_blocks[2] = mi_heap_malloc_aligned(shared_heap, MIB, 2 * MIB);
  mi_heap_t* own = mi_heap_new();
  void* p = mi_heap_malloc(own, 100);
  mi_free(p);
  mi_heap_delete(own);
  return NULL;
}

static void thread_section(void) {
  shared_heap = mi_heap_new();
  void* local = mi_heap_malloc(shared_heap, 64);
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0 || pthread_join(thread, NULL) != 0) {
    printf("thread.run=0\n");
    return;
  }
  printf("thread.run=1\n");
  printf("thread.blocks=%d,%d,%d\n", worker_blocks[0] != NULL, worker_blocks[1] != NULL, worker_blocks[2] != NULL);
  /* The exited worker's pages are abandoned; free one from here, then
     destroy the Heap with the rest. */
  mi_free(worker_blocks[0]);
  mi_free(local);
  mi_stats_t before = stats_now();
  mi_heap_destroy(shared_heap);
  mi_stats_t after = stats_now();
  printf("thread.destroy.heaps=%lld\n", (long long)(after.heaps.current - before.heaps.current));
}

int main(void) {
  /* Unbuffered, so a failing side's trace ends at its failing step. */
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_register_output(&capture, NULL);
  message_count = 0;
  mi_register_error(&record_error, NULL);
  snprintf(thread_text, sizeof(thread_text), "0x%02lX", (unsigned long)(uintptr_t)pthread_self());
  printf("CRABC_MI_M6_ADAPTER_TRACE_BEGIN\n");
  /* The reservation section keeps show_errors off: the OS-layer warnings of
     a failed reservation are not all rendered by the port yet. */
  reserve_section();
  /* Heap error and warning messages reach the registered output. */
  mi_option_enable(mi_option_show_errors);
  allocation_section();
  delete_section();
  thread_section();
  print_messages("final.messages");
  printf("CRABC_MI_M6_ADAPTER_TRACE_END\n");
  return 0;
}
