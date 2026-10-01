#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct fixture_s {
  mi_heap_t* heap;
  uintptr_t live;
  uintptr_t freed;
  size_t usable;
  size_t os_page_size;
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  unsigned areas;
  unsigned blocks;
  unsigned used;
  unsigned live_area;
  unsigned live_block;
  unsigned freed_area;
  unsigned freed_block;
  unsigned order;
  unsigned stop;
  size_t full_block_size;
  size_t client_offset;
  size_t block_size;
} visit_t;

static bool in_area(uintptr_t pointer, const mi_heap_area_t* area) {
  uintptr_t start = (uintptr_t)area->blocks;
  return pointer >= start && pointer - start < area->committed;
}

static bool observe(const mi_heap_t* heap, const mi_heap_area_t* area,
                    void* block, size_t block_size, void* argument) {
  visit_t* visit = (visit_t*)argument;
  if (heap != visit->fixture->heap || block_size != area->block_size) abort();
  #if MI_GUARDED
  // A guarded client is an interior pointer; traversal reports the retained
  // canonical slot, whose final OS page remains protected after owner exit.
  if (!in_area(visit->fixture->live, area)) abort();
  uintptr_t tag;
  memcpy(&tag, area->blocks, sizeof(tag));
  size_t offset = visit->fixture->live - (uintptr_t)area->blocks;
  if (tag != UINTPTR_MAX || offset < sizeof(uintptr_t) || area->used != 1 ||
      area->full_block_size < offset + visit->fixture->os_page_size ||
      area->full_block_size - offset - visit->fixture->os_page_size != visit->fixture->usable ||
      *(const unsigned char*)visit->fixture->live != 0x5a ||
      *((const unsigned char*)visit->fixture->live + 1024 * 1024) != 0x5a) abort();
  visit->full_block_size = area->full_block_size;
  visit->client_offset = offset;
  visit->block_size = block_size;
  #endif
  if (block == NULL) {
    visit->areas++;
    visit->used += (unsigned)area->used;
    visit->live_area += in_area(visit->fixture->live, area);
    visit->freed_area += in_area(visit->fixture->freed, area);
    visit->order = visit->order * 10 + 1;
    return visit->stop != 1;
  }
  visit->blocks++;
  #if MI_GUARDED
  if (block != area->blocks) abort();
  visit->live_block += visit->fixture->live >= (uintptr_t)block &&
      visit->fixture->live - (uintptr_t)block < block_size;
  visit->freed_block += visit->fixture->freed >= (uintptr_t)block &&
      visit->fixture->freed - (uintptr_t)block < block_size;
  #else
  visit->live_block += (uintptr_t)block == visit->fixture->live;
  visit->freed_block += (uintptr_t)block == visit->fixture->freed;
  #endif
  visit->order = visit->order * 10 + 2;
  return visit->stop != 2;
}

static void print_visit(const char* name, const fixture_t* fixture,
                        bool abandoned, bool visit_blocks, unsigned stop) {
  visit_t visit = { 0 };
  visit.fixture = fixture;
  visit.stop = stop;
  bool complete = abandoned
    ? mi_heap_visit_abandoned_blocks(fixture->heap, visit_blocks, observe, &visit)
    : mi_heap_visit_blocks(fixture->heap, visit_blocks, observe, &visit);
  printf("os.%s=%d,%u,%u,%u,%u,%u,%u,%u,%u\n", name, complete,
         visit.areas, visit.blocks, visit.used, visit.live_area,
         visit.live_block, visit.freed_area, visit.freed_block, visit.order);
  #if MI_GUARDED
  printf("os.%s.guard=1,%zu,%zu,%zu,%zu,%zu\n", name, fixture->usable,
         visit.full_block_size, visit.client_offset, visit.block_size, fixture->os_page_size);
  #endif
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  fixture->heap = mi_heap_new();
  if (fixture->heap == NULL) return NULL;
  #if MI_GUARDED
  mi_theap_t* theap = mi_heap_theap(fixture->heap);
  if (theap == NULL) return NULL;
  mi_theap_guarded_set_sample_rate(theap, 1, 1);
  mi_theap_guarded_set_size_bound(theap, 0, SIZE_MAX);
  void* live = mi_heap_malloc(fixture->heap, 1024 * 1024 + 1);
  void* freed = mi_heap_malloc(fixture->heap, 1024 * 1024 + 1);
  #else
  void* live = mi_heap_malloc_aligned(fixture->heap, 10 * 1024 + 1, 128 * 1024);
  void* freed = mi_heap_malloc_aligned(fixture->heap, 10 * 1024 + 1, 128 * 1024);
  #endif
  if (live == NULL || freed == NULL) return NULL;
  fixture->live = (uintptr_t)live;
  fixture->freed = (uintptr_t)freed;
  #if MI_GUARDED
  fixture->usable = mi_usable_size(live);
  memset(live, 0x5a, 1024 * 1024 + 1);
  #endif
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.os=%d,%d\n",
          mi_memid_is_os(_mi_ptr_page(live)->memid),
          mi_memid_is_os(_mi_ptr_page(freed)->memid));
#endif
  mi_free(freed);
  fixture->ready = true;
  return NULL;
}

#if MI_GUARDED
static bool guarded_tail_is_protected(const fixture_t* fixture) {
  pid_t child = fork();
  if (child < 0) return false;
  if (child == 0) {
    *(volatile unsigned char*)(fixture->live + fixture->usable) = 1;
    _exit(99);
  }
  int status;
  pid_t waited;
  do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  return waited == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV;
}
#endif

int main(void) {
  #if MI_GUARDED
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  #endif
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_ABANDONED_OS_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { 0 };
  #if MI_GUARDED
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) return 4;
  fixture.os_page_size = (size_t)page_size;
  #endif
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &fixture) != 0) return 2;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 3;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_page_t* page = _mi_ptr_page((void*)fixture.live);
  fprintf(stderr, "source.transfer=%d,%d,%d\n",
          mi_page_is_abandoned(page), mi_page_heap(page) == fixture.heap,
          fixture.heap->os_abandoned_pages == page);
#endif
  #if MI_GUARDED
  if (fixture.usable < 1024 * 1024 + 1 || !guarded_tail_is_protected(&fixture)) return 5;
  #endif
  print_visit("areas", &fixture, true, false, 0);
  print_visit("blocks", &fixture, true, true, 0);
  print_visit("stop_area", &fixture, true, true, 1);
  print_visit("stop_block", &fixture, true, true, 2);
  print_visit("ordinary", &fixture, false, true, 0);
  #if MI_GUARDED
  if (!guarded_tail_is_protected(&fixture)) return 6;
  puts("os.protected=1,1");
  #endif
  puts("CRABC_MI_M6_ABANDONED_OS_VISITOR_TRACE_END");
  return 0;
}
