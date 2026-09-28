/* Select between two expandable pages after an option change. */
#ifdef CRABC_PINNED_C
#include "static.c"
#else
#include "mimalloc.h"
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Medium pages occupy one 512 KiB source page span on the selected target. */
#define PAGE_SPAN (512u * 1024u)

static void require(int condition) {
  if (!condition) abort();
}

static uintptr_t page_key(const void* block) {
  return (uintptr_t)block & ~((uintptr_t)PAGE_SPAN - 1);
}

static int filled_with(const unsigned char* block, unsigned char byte) {
  for (size_t index = 0; index < 8192; index++) {
    if (block[index] != byte) return 0;
  }
  return 1;
}

int main(int argc, char** argv) {
  require(argc == 2);
  const long limit = strtol(argv[1], NULL, 10);
  require(limit == 0 || limit == 4);

  unsigned char* first = mi_malloc(8192);
  require(first != NULL);
  memset(first, 0xa1, 8192);

  mi_heap_t* heap = mi_heap_new();
  require(heap != NULL);
  unsigned char* transferred_free = mi_heap_malloc(heap, 8192);
  unsigned char* transferred_live = mi_heap_malloc(heap, 8192);
  require(transferred_free != NULL && transferred_live != NULL);
  memset(transferred_live, 0xb2, 8192);
  require(page_key(first) != page_key(transferred_live));
  mi_heap_delete(heap);

  /* Reclaim the transferred page into the main queue without consuming its
     newly freed block. The first page remains expandable with no immediate
     block, while the second is expandable and has one immediate block. */
  mi_option_set(mi_option_page_reclaim_on_free, 1);
  mi_free(transferred_free);

#ifdef CRABC_PINNED_C
  mi_page_t* first_page = _mi_ptr_page(first);
  mi_page_t* second_page = _mi_ptr_page(transferred_live);
  mi_page_queue_t* queue = mi_page_queue(_mi_theap_default(), 8192);
  require(queue->count == 2 && queue->first == first_page && first_page->next == second_page);
  require(first_page->capacity < first_page->reserved && first_page->free == NULL && first_page->used == 1);
  require(second_page->capacity < second_page->reserved && second_page->free != NULL && second_page->used == 1);
  const size_t source_first_capacity = first_page->capacity;
  const size_t source_first_reserved = first_page->reserved;
  const size_t source_second_capacity = second_page->capacity;
  const size_t source_second_reserved = second_page->reserved;
#endif

  mi_option_set(mi_option_page_max_candidates, limit);
  unsigned char* selected = mi_malloc(8192);
  require(selected != NULL);
  const int chose_first = page_key(selected) == page_key(first);
  const int chose_transferred = page_key(selected) == page_key(transferred_live);
  require(chose_first != chose_transferred);

  printf("CRABC_MI_M7_PAGE_MAX_CANDIDATES_TRACE_BEGIN\n");
  printf("case.limit=%ld\n", limit);
  printf("case.distinct_pages=1\n");
  printf("case.selected=%s\n", chose_first ? "first" : "transferred");
  printf("case.first_data=%d\n", filled_with(first, 0xa1));
  printf("case.transferred_data=%d\n", filled_with(transferred_live, 0xb2));
  printf("case.usable=%zu\n", mi_usable_size(selected));
#ifdef CRABC_PINNED_C
  printf("source.queue=2,%zu,%zu,1,%zu,%zu,1,1\n",
      source_first_capacity, source_first_reserved,
      source_second_capacity, source_second_reserved);
#endif
  printf("CRABC_MI_M7_PAGE_MAX_CANDIDATES_TRACE_END\n");

  mi_free(selected);
  mi_free(transferred_live);
  mi_free(first);
  return 0;
}
