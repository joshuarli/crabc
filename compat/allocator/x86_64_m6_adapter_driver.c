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
#include <sched.h>
#include <unistd.h>

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


static char deferred[64];
static size_t deferred_count;

static void record_deferred(bool force, unsigned long long heartbeat, void* argument) {
  (void)heartbeat; (void)argument;
  if (deferred_count < sizeof(deferred) - 1) deferred[deferred_count++] = force ? '1' : '0';
}

static bool filled(const unsigned char* p, size_t size, unsigned char value) {
  for (size_t i = 0; i < size; i++) if (p[i] != value) return false;
  return true;
}

static void realloc_section(void) {
  mi_heap_t* h = mi_heap_new();
  unsigned char* p = (unsigned char*)mi_heap_malloc(h, 100);
  memset(p, 0x11, 100);
  unsigned char* q = (unsigned char*)mi_heap_realloc(h, p, 80);
  printf("realloc.heap.shrink=%d,%d\n", q == p ? 1 : 0, filled(q, 80, 0x11) ? 1 : 0);
  /* Through the default Theap the block's Heap differs: no reuse. */
  unsigned char* r = (unsigned char*)mi_realloc(q, 80);
  printf("realloc.default.same_size=%d,%d\n", r == q ? 1 : 0, filled(r, 80, 0x11) ? 1 : 0);
  /* A main-Heap block reallocated through the Heap moves into it. */
  unsigned char* m = (unsigned char*)mi_malloc(100);
  memset(m, 0x22, 100);
  unsigned char* moved = (unsigned char*)mi_heap_realloc(h, m, 90);
  printf("realloc.heap.foreign=%d,%d\n", moved == m ? 1 : 0, filled(moved, 90, 0x22) ? 1 : 0);
  unsigned char* grown = (unsigned char*)mi_heap_realloc(h, moved, 5000);
  printf("realloc.heap.grow=%d,%zu\n", filled(grown, 90, 0x22) ? 1 : 0, mi_usable_size(grown));
  unsigned char* z = (unsigned char*)mi_heap_rezalloc(h, NULL, 40);
  memset(z, 0x33, 40);
  z = (unsigned char*)mi_heap_rezalloc(h, z, 400);
  printf("realloc.heap.rezalloc=%d,%d\n", filled(z, 32, 0x33) ? 1 : 0, zeroed(z + 40, 360) ? 1 : 0);
  unsigned char* c = (unsigned char*)mi_heap_recalloc(h, NULL, 10, 10);
  c = (unsigned char*)mi_heap_recalloc(h, c, 30, 10);
  printf("realloc.heap.recalloc=%d,%zu\n", zeroed(c, 300) ? 1 : 0, mi_usable_size(c));
  errno = 0;
  void* overflow = mi_heap_recalloc(h, c, SIZE_MAX / 2, 3);
  printf("realloc.heap.recalloc_overflow=%d,%d\n", overflow == NULL ? 1 : 0, errno);
  void* n = mi_heap_reallocn(h, NULL, 4, 16);
  n = mi_heap_reallocn(h, n, 8, 16);
  printf("realloc.heap.reallocn=%zu\n", mi_usable_size(n));
  void* f = mi_heap_malloc(h, 64);
  void* failed = mi_heap_reallocf(h, f, (size_t)PTRDIFF_MAX + 1);
  printf("realloc.heap.reallocf_fail=%d\n", failed == NULL ? 1 : 0);
  print_errors("realloc.heap.reallocf_fail.codes");
  print_messages("realloc.heap.reallocf_fail.messages");
  void* a = mi_heap_malloc_aligned(h, 200, 64);
  void* a2 = mi_heap_realloc_aligned(h, a, 150, 64);
  printf("realloc.heap.aligned_fit=%d\n", a2 == a ? 1 : 0);
  unsigned char* a3 = (unsigned char*)mi_heap_realloc_aligned_at(h, a2, 150, 256, 16);
  printf("realloc.heap.aligned_at=%d\n", (((uintptr_t)a3 + 16) % 256) == 0 ? 1 : 0);
  /* The whole usable extent is copied, then the rest is zeroed. */
  const size_t size3 = mi_usable_size(a3);
  memset(a3, 0x44, size3);
  unsigned char* a4 = (unsigned char*)mi_heap_rezalloc_aligned(h, a3, 3000, 128);
  printf("realloc.heap.rezalloc_aligned=%d,%d,%d\n", ((uintptr_t)a4 % 128) == 0 ? 1 : 0,
         filled(a4, size3, 0x44) ? 1 : 0, zeroed(a4 + size3, 3000 - size3) ? 1 : 0);
  unsigned char* a5 = (unsigned char*)mi_heap_rezalloc_aligned_at(h, a4, 4000, 128, 8);
  printf("realloc.heap.rezalloc_aligned_at=%d,%d\n", (((uintptr_t)a5 + 8) % 128) == 0 ? 1 : 0,
         zeroed(a5 + 3000, 1000) ? 1 : 0);
  unsigned char* a6 = (unsigned char*)mi_heap_recalloc_aligned(h, NULL, 20, 20, 32);
  unsigned char* a7 = (unsigned char*)mi_heap_recalloc_aligned_at(h, NULL, 20, 20, 32, 4);
  printf("realloc.heap.recalloc_aligned=%d,%d\n", ((uintptr_t)a6 % 32) == 0 && zeroed(a6, 400) ? 1 : 0,
         (((uintptr_t)a7 + 4) % 32) == 0 && zeroed(a7, 400) ? 1 : 0);
  errno = 0;
  void* bad = mi_heap_realloc_aligned_at(h, a6, 100, 24, 0);
  printf("realloc.heap.bad_alignment=%d,%d\n", bad == NULL ? 1 : 0, errno);
  print_errors("realloc.heap.bad_alignment.codes");
  print_messages("realloc.heap.bad_alignment.messages");
  void* main_block = mi_heap_realloc(mi_heap_main(), NULL, 70);
  main_block = mi_heap_realloc(mi_heap_main(), main_block, 60);
  printf("realloc.main=%zu\n", mi_usable_size(main_block));

  char* s = mi_heap_strdup(h, "first-class heap");
  char* t = mi_heap_strndup(h, "first-class heap", 5);
  printf("strings.dup=%d,%d,%d\n", strcmp(s, "first-class heap") == 0 ? 1 : 0, strcmp(t, "first") == 0 ? 1 : 0,
         mi_heap_strdup(h, NULL) == NULL ? 1 : 0);
  char* rp = mi_heap_realpath(h, "/", NULL);
  printf("strings.realpath=%s\n", rp == NULL ? "(null)" : rp);
  void* nw = mi_heap_alloc_new(h, 72);
  void* nn = mi_heap_alloc_new_n(h, 4, 24);
  printf("new.heap=%zu,%zu\n", mi_usable_size(nw), mi_usable_size(nn));

  mi_free(r); mi_free(grown); mi_free(z); mi_free(c); mi_free(n); mi_free(a5); mi_free(a6); mi_free(a7);
  mi_free(main_block); mi_free(s); mi_free(t); mi_free(rp); mi_free(nw); mi_free(nn);

  /* mi_heap_collect: the deferred-free callback, then page collection. */
  enum { COUNT = 200 };
  static void* blocks[COUNT];
  mi_stats_t d0 = stats_now();
  for (int i = 0; i < COUNT; i++) blocks[i] = mi_heap_malloc(h, 1000);
  mi_stats_t d1 = stats_now();
  for (int i = 0; i < COUNT; i++) mi_free(blocks[i]);
  mi_stats_t d2 = stats_now();
  printf("collect.setup.pages=%lld,%lld,%lld\n", (long long)(d1.pages.current - d0.pages.current),
         (long long)(d2.pages.current - d0.pages.current), (long long)d2.pages_abandoned.current);
  mi_register_deferred_free(&record_deferred, NULL);
  mi_stats_t before = stats_now();
  mi_heap_collect(h, false);
  mi_stats_t normal = stats_now();
  mi_heap_collect(h, true);
  mi_stats_t forced = stats_now();
  mi_heap_collect(mi_heap_main(), true);
  mi_register_deferred_free(NULL, NULL);
  deferred[deferred_count] = 0;
  printf("collect.deferred=%s\n", deferred);
  printf("collect.pages=%lld,%lld\n", (long long)(normal.pages.current - before.pages.current),
         (long long)(forced.pages.current - before.pages.current));
  mi_heap_destroy(h);

  /* Even a reusable block from another Heap resolves this Heap's Theap
     before the aligned realloc kernel decides to return the same pointer. */
  mi_heap_t* empty_heap = mi_heap_new();
  unsigned char* foreign = (unsigned char*)mi_malloc_aligned(64, 64);
  memset(foreign, 0x5a, 64);
  mi_stats_t empty_before = stats_now();
  unsigned char* foreign_reused = (unsigned char*)mi_heap_realloc_aligned(empty_heap, foreign, 56, 64);
  mi_stats_t empty_after = stats_now();
  printf("realloc.heap.foreign_aligned_theap=%d,%lld,%d\n", foreign_reused == foreign,
         (long long)(empty_after.theaps.current - empty_before.theaps.current),
         filled(foreign_reused, 56, 0x5a));
  mi_free(foreign_reused);
  mi_heap_destroy(empty_heap);

  /* The public wrapper resolves the Heap's Theap before the count-overflow
     check, and the failed request leaves the foreign block owned by caller. */
  mi_heap_t* overflow_heap = mi_heap_new();
  unsigned char* protected = (unsigned char*)mi_malloc(64);
  memset(protected, 0x6b, 64);
  mi_stats_t overflow_before = stats_now();
  void* overflow_result = mi_heap_recalloc(overflow_heap, protected, SIZE_MAX / 2, 3);
  mi_stats_t overflow_after = stats_now();
  printf("realloc.heap.overflow_theap=%d,%lld,%d\n", overflow_result == NULL,
         (long long)(overflow_after.theaps.current - overflow_before.theaps.current),
         filled(protected, 64, 0x6b));
  mi_free(protected);
  mi_heap_destroy(overflow_heap);
}

static mi_heap_t* shared_heap;
static void* worker_blocks[3];
static void* initial_block;
static int worker_realloc_in_place;

static void* worker(void* argument) {
  (void)argument;
  /* A second thread's own Theap for a Heap the initial thread created. */
  worker_blocks[0] = mi_heap_malloc(shared_heap, 64);
  worker_blocks[1] = mi_heap_malloc(shared_heap, 64);
  worker_blocks[2] = mi_heap_malloc_aligned(shared_heap, MIB, 2 * MIB);
  /* A block of the same Heap on the initial thread's Theap is reused. */
  void* reused = mi_heap_realloc(shared_heap, initial_block, 56);
  worker_realloc_in_place = (reused == initial_block);
  mi_heap_t* own = mi_heap_new();
  void* p = mi_heap_malloc(own, 100);
  mi_free(p);
  mi_heap_delete(own);
  return NULL;
}

static void thread_section(void) {
  shared_heap = mi_heap_new();
  void* local = mi_heap_malloc(shared_heap, 64);
  initial_block = mi_heap_malloc(shared_heap, 64);
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0 || pthread_join(thread, NULL) != 0) {
    printf("thread.run=0\n");
    return;
  }
  printf("thread.run=1\n");
  printf("thread.blocks=%d,%d,%d\n", worker_blocks[0] != NULL, worker_blocks[1] != NULL, worker_blocks[2] != NULL);
  printf("thread.realloc_in_place=%d\n", worker_realloc_in_place);
  mi_free(initial_block);
  /* The exited worker's pages are abandoned; free one from here, then
     destroy the Heap with the rest. */
  mi_free(worker_blocks[0]);
  mi_free(local);
  mi_stats_t before = stats_now();
  mi_heap_destroy(shared_heap);
  mi_stats_t after = stats_now();
  printf("thread.destroy.heaps=%lld\n", (long long)(after.heaps.current - before.heaps.current));
}


static int visit_count;
static int visit_limit;

static bool count_heap(mi_heap_t* heap, void* argument) {
  (void)heap;
  visit_count++;
  if (argument != NULL) *(int*)argument += 1;
  return visit_limit == 0 || visit_count < visit_limit;
}

static int visit(mi_subproc_id_t subproc, int limit, bool* result) {
  visit_count = 0;
  visit_limit = limit;
  int counted = 0;
  bool ok = mi_subproc_visit_heaps(subproc, &count_heap, &counted);
  if (result != NULL) *result = ok;
  return counted;
}

static mi_subproc_id_t child;
static int child_facts[12];

static void* child_worker(void* argument) {
  (void)argument;
  mi_subproc_add_current_thread(child);
  child_facts[0] = mi_subproc_current()._mi_subproc_id == child._mi_subproc_id;
  child_facts[1] = mi_heap_main() != NULL;
  void* p = mi_malloc(100);
  child_facts[2] = p != NULL;
  mi_free(p);
  mi_heap_t* h = mi_heap_new();
  child_facts[3] = h != NULL && h != mi_heap_main();
  void* q = mi_heap_malloc(h, 64);
  child_facts[4] = q != NULL;
  bool ok;
  child_facts[5] = visit(child, 0, &ok);
  child_facts[6] = ok;
  child_facts[7] = visit(child, 1, &ok);
  child_facts[8] = ok;
  /* A second add to the same child changes nothing. */
  mi_subproc_add_current_thread(child);
  child_facts[9] = mi_subproc_current()._mi_subproc_id == child._mi_subproc_id;
  mi_free(q);
  mi_heap_delete(h);
  child_facts[10] = visit(child, 0, NULL);
  return NULL;
}

static void subproc_section(void) {
  mi_subproc_id_t main_id = mi_subproc_main();
  printf("subproc.main=%d,%d\n", main_id._mi_subproc_id != NULL ? 1 : 0,
         mi_subproc_current()._mi_subproc_id == main_id._mi_subproc_id ? 1 : 0);
  mi_heap_t* h = mi_heap_new();
  bool ok;
  int all = visit(main_id, 0, &ok);
  printf("subproc.main.visit=%d,%d\n", all, ok ? 1 : 0);
  int first = visit(main_id, 1, &ok);
  printf("subproc.main.visit_stop=%d,%d\n", first, ok ? 1 : 0);
  mi_heap_delete(h);
  printf("subproc.main.visit_after=%d\n", visit(main_id, 0, NULL));
  /* The initial thread is already initialized in the main subprocess. */
  mi_subproc_add_current_thread(main_id);
  print_messages("subproc.add_main.messages");
  mi_subproc_destroy(main_id);
  printf("subproc.main.destroy_ignored=%d\n", mi_subproc_current()._mi_subproc_id == main_id._mi_subproc_id ? 1 : 0);

  mi_stats_t before = stats_now();
  child = mi_subproc_new();
  printf("subproc.new=%d,%d\n", child._mi_subproc_id != NULL ? 1 : 0,
         child._mi_subproc_id != main_id._mi_subproc_id ? 1 : 0);
  printf("subproc.child.visit=%d\n", visit(child, 0, NULL));
  /* Adding the already-initialized initial thread warns with an address. */
  mi_subproc_add_current_thread(child);
  /* Mask the other subprocess's address in the warning body. */
  for (size_t i = 0; i < message_count && i < MAX_MESSAGES; i++) {
    char* at = strstr(messages[i], "(at 0x");
    if (at != NULL) {
      char* end = strchr(at, ')');
      if (end != NULL) memmove(at + 4, end, strlen(end) + 1);
    }
  }
  print_messages("subproc.add_other.messages");
  pthread_t thread;
  if (pthread_create(&thread, NULL, child_worker, NULL) != 0 || pthread_join(thread, NULL) != 0) {
    printf("subproc.child.run=0\n");
    return;
  }
  printf("subproc.child.run=1\n");
  printf("subproc.child.facts=");
  for (int i = 0; i < 11; i++) printf("%s%d", i == 0 ? "" : ",", child_facts[i]);
  printf("\n");
  mi_subproc_destroy(child);
  mi_stats_t after = stats_now();
  printf("subproc.child.destroyed.threads=%lld\n", (long long)(after.threads.total - before.threads.total));
  printf("subproc.child.destroyed.heaps=%lld\n", (long long)(after.heaps.current - before.heaps.current));
  print_messages("subproc.messages");
}


/* A child destroyed under a thread that still belongs to it. Source
   destroys the child's Heaps, Theaps, pages, and arenas under the thread;
   the thread makes no allocator call afterwards and never exits before the
   process does (its thread-done would reach released child memory). */
static mi_subproc_id_t doomed;
static volatile int doomed_ready;

static void* doomed_worker(void* argument) {
  (void)argument;
  mi_subproc_add_current_thread(doomed);
  void* p = mi_malloc(200);
  memset(p, 0x55, 200);
  mi_heap_t* h = mi_heap_new();
  void* q = mi_heap_malloc(h, 64);
  memset(q, 0x66, 64);
  __atomic_store_n(&doomed_ready, 1, __ATOMIC_RELEASE);
  for (;;) pause();
  return NULL;
}

static void subproc_destroy_live_section(void) {
  doomed = mi_subproc_new();
  pthread_t thread;
  if (pthread_create(&thread, NULL, doomed_worker, NULL) != 0) {
    printf("subproc.live.run=0\n");
    return;
  }
  while (!__atomic_load_n(&doomed_ready, __ATOMIC_ACQUIRE)) sched_yield();
  printf("subproc.live.visit=%d\n", visit(doomed, 0, NULL));
  mi_stats_t before = stats_now();
  mi_subproc_destroy(doomed);
  mi_stats_t after = stats_now();
  printf("subproc.live.destroyed.threads=%lld,%lld\n", (long long)(after.threads.total - before.threads.total),
         (long long)(after.threads.current - before.threads.current));
  printf("subproc.live.destroyed.heaps=%lld,%lld\n", (long long)(after.heaps.total - before.heaps.total),
         (long long)(after.heaps.current - before.heaps.current));
  printf("subproc.live.destroyed.theaps=%lld,%lld\n", (long long)(after.theaps.total - before.theaps.total),
         (long long)(after.theaps.current - before.theaps.current));
  printf("subproc.live.current=%d\n", mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id ? 1 : 0);
  void* p = mi_malloc(64);
  printf("subproc.live.main_malloc=%d\n", p != NULL ? 1 : 0);
  mi_free(p);
  print_messages("subproc.live.messages");
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
  realloc_section();
  delete_section();
  thread_section();
  subproc_section();
  subproc_destroy_live_section();
  print_messages("final.messages");
  printf("CRABC_MI_M6_ADAPTER_TRACE_END\n");
  return 0;
}
