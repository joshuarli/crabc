/* SPDX-License-Identifier: MIT
 * Source-built page-queue head retirement and reuse trace for mimalloc v3.5.0.
 */
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/atomic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this fixture requires native Linux/x86-64
#endif

#define MI_IN_PAGE_C
#include "page-queue.c"

static mi_page_t empty_page;
mi_page_t* _mi_page_empty_get(void) { return &empty_page; }

static char name_of(const mi_page_t* page, const mi_page_t* const pages[3]) {
  if (page == pages[0]) return 'A';
  if (page == pages[1]) return 'B';
  if (page == pages[2]) return 'C';
  abort();
}

static void queue_names(const mi_page_queue_t* queue, const mi_page_t* const pages[3],
                        char output[4]) {
  size_t count = 0;
  const mi_page_t* previous = NULL;
  for (const mi_page_t* page = queue->first; page != NULL; page = page->next) {
    if (count >= 3 || page->prev != previous) abort();
    output[count++] = name_of(page, pages);
    previous = page;
  }
  if (count != queue->count || previous != queue->last) abort();
  output[count] = 0;
}

static void show(const char* step, const mi_theap_t* theap,
                 const mi_page_t* const pages[3]) {
  char regular[4], full[4], flags[4];
  queue_names(&theap->pages[4], pages, regular);
  queue_names(&theap->pages[MI_BIN_FULL], pages, full);
  size_t bytes = 0;
  for (size_t i = 0; i < 3; i++) {
    const mi_page_t* page = pages[i];
    if (page->theap != theap) abort();
    const char name = name_of(page, pages);
    const bool in_regular = (strchr(regular, name) != NULL);
    const bool in_full = (strchr(full, name) != NULL);
    if (in_regular && in_full) abort();
    if (!in_regular && !in_full && (page->prev != NULL || page->next != NULL)) abort();
    if (mi_page_is_in_full(page) != in_full) abort();
    if (in_full) bytes += page->capacity * page->block_size;
    flags[i] = in_full ? 'F' : (in_regular ? 'R' : 'D');
  }
  flags[3] = 0;
  if (theap->pages_full_size != bytes) abort();
  const mi_page_t* direct = theap->pages_free_direct[3];
  if (direct != theap->pages_free_direct[4]) abort();
  const char direct_name = direct == &empty_page ? '-' : name_of(direct, pages);
  if (direct != (theap->pages[4].first == NULL ? &empty_page : theap->pages[4].first)) abort();
  if (theap->page_count != strlen(regular) + strlen(full)) abort();
  printf("M3R %s regular=%s full=%s direct=%c state=%s bytes=%zu pages=%zu\n",
         step, regular, full, direct_name, flags, bytes, theap->page_count);
}

int main(void) {
  mi_theap_t theap = {0};
  mi_page_queue_t* regular = &theap.pages[4];
  mi_page_queue_t* full = &theap.pages[MI_BIN_FULL];
  regular->block_size = 32;
  full->block_size = MI_LARGE_MAX_OBJ_SIZE + 2 * sizeof(uintptr_t);
  mi_page_t a = {0}, b = {0}, c = {0};
  mi_page_t* pages[3] = {&a, &b, &c};
  const mi_page_t* const names[3] = {&a, &b, &c};
  const uint16_t capacities[3] = {4, 6, 8};
  for (size_t i = 0; i < 3; i++) {
    pages[i]->theap = &theap;
    pages[i]->block_size = 32;
    pages[i]->capacity = capacities[i];
    pages[i]->reserved = capacities[i];
    mi_page_queue_push_at_end(&theap, regular, pages[i]);
  }
  show("start", &theap, names);
  mi_page_queue_remove(regular, &a);
  show("retire-head", &theap, names);
  mi_page_queue_push_at_end(&theap, regular, &a);
  show("reuse-tail", &theap, names);
  mi_page_queue_move_to_front(&theap, regular, &c);
  show("move-head", &theap, names);
  mi_page_queue_enqueue_from(full, regular, &c);
  show("full-head", &theap, names);
  mi_page_queue_enqueue_from(full, regular, &b);
  show("full-next", &theap, names);
  mi_page_queue_remove(regular, &a);
  show("retire-last-regular", &theap, names);
  mi_page_queue_enqueue_from_full(regular, full, &c);
  show("reuse-from-full", &theap, names);
  mi_page_queue_remove(full, &b);
  show("retire-full", &theap, names);
  mi_page_queue_remove(regular, &c);
  show("retire-final", &theap, names);
  return 0;
}
