/* SPDX-License-Identifier: MIT
 *
 * A source-built queue-helper differential for pinned mimalloc v3.5.0.
 * Compile this file with the pinned include/src directories. Its direct
 * inclusion of page-queue.c keeps the actual source transitions under test.
 */
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/atomic.h"
#include <stdio.h>
#include <stdlib.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this queue fixture requires native Linux/x86-64
#endif

#define MI_IN_PAGE_C
#include "page-queue.c"

static mi_page_t empty_page;
mi_page_t* _mi_page_empty_get(void) { return &empty_page; }

static char name_of(const mi_page_t* page, const mi_page_t* first,
                    const mi_page_t* middle, const mi_page_t* last) {
  if (page == first) return 'A';
  if (page == middle) return 'B';
  if (page == last) return 'C';
  abort();
}

static void show(const char* step, const mi_theap_t* theap,
                 const mi_page_queue_t* regular, const mi_page_queue_t* full,
                 const mi_page_t* first, const mi_page_t* middle, const mi_page_t* last) {
  printf("M3Q %s regular=", step);
  size_t count = 0;
  const mi_page_t* previous = NULL;
  for (const mi_page_t* page = regular->first; page != NULL; page = page->next) {
    if (page->prev != previous || ++count > 3 || mi_page_is_in_full(page)) abort();
    putchar(name_of(page, first, middle, last));
    previous = page;
  }
  if (count != regular->count || previous != regular->last) abort();
  printf(" full=");
  count = 0;
  previous = NULL;
  for (const mi_page_t* page = full->first; page != NULL; page = page->next) {
    if (page->prev != previous || ++count > 3 || !mi_page_is_in_full(page)) abort();
    putchar(name_of(page, first, middle, last));
    previous = page;
  }
  if (count != full->count || previous != full->last) abort();
  printf(" bytes=%zu pages=%zu\n", theap->pages_full_size, theap->page_count);
}

int main(void) {
  mi_theap_t theap = {0};
  mi_page_queue_t* regular = &theap.pages[4];
  mi_page_queue_t* full = &theap.pages[MI_BIN_FULL];
  regular->block_size = 32;
  full->block_size = MI_LARGE_MAX_OBJ_SIZE + 2 * sizeof(uintptr_t);
  mi_page_t first = {0}, middle = {0}, last = {0};
  mi_page_t* pages[] = {&first, &middle, &last};
  const size_t capacities[] = {4, 6, 8};
  for (size_t i = 0; i < 3; i++) {
    pages[i]->theap = &theap;
    pages[i]->block_size = 32;
    pages[i]->capacity = (uint16_t)capacities[i];
    pages[i]->reserved = (uint16_t)capacities[i];
  }

  mi_page_queue_push_at_end(&theap, regular, &first);
  mi_page_queue_push_at_end(&theap, regular, &middle);
  mi_page_queue_push_at_end(&theap, regular, &last);
  show("start", &theap, regular, full, &first, &middle, &last);
  mi_page_queue_enqueue_from(full, regular, &first);
  show("first-full", &theap, regular, full, &first, &middle, &last);
  mi_page_queue_enqueue_from(full, regular, &middle);
  show("middle-full", &theap, regular, full, &first, &middle, &last);
  mi_page_queue_move_to_front(&theap, full, &middle);
  show("full-front", &theap, regular, full, &first, &middle, &last);
  mi_page_queue_enqueue_from_ex(regular, full, false, &middle);
  show("second-position", &theap, regular, full, &first, &middle, &last);
  mi_page_queue_enqueue_from_full(regular, full, &first);
  show("full-return", &theap, regular, full, &first, &middle, &last);
  return 0;
}
