/* SPDX-License-Identifier: MIT
 * Source-built page-queue head retirement and reuse trace for mimalloc v3.5.0.
 */
#define _GNU_SOURCE
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/atomic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this fixture requires native Linux/x86-64
#endif

#include "static.c"

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
  const char direct_name = direct == _mi_page_empty_get() ? '-' : name_of(direct, pages);
  if (direct != (theap->pages[4].first == NULL ? _mi_page_empty_get() : theap->pages[4].first)) abort();
  if (theap->page_count != strlen(regular) + strlen(full)) abort();
  printf("M3R %s regular=%s full=%s direct=%c state=%s bytes=%zu pages=%zu\n",
         step, regular, full, direct_name, flags, bytes, theap->page_count);
}

static void retirement_sequence(void) {
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
}

static void show_bin(size_t bin, uint64_t seed, size_t step, const char* action,
                     char changed, const mi_theap_t* theap,
                     const mi_page_t* const pages[3], const mi_page_t* sentinel,
                     size_t sentinel_bin, bool sentinel_live) {
  const mi_page_queue_t* regular = &theap->pages[bin];
  const mi_page_queue_t* full = &theap->pages[MI_BIN_FULL];
  char regular_names[4], full_names[4], flags[4], direct[MI_PAGES_DIRECT + 1];
  queue_names(regular, pages, regular_names);
  queue_names(full, pages, full_names);
  size_t bytes = 0;
  for (size_t i = 0; i < 3; i++) {
    const char name = name_of(pages[i], pages);
    const bool in_regular = strchr(regular_names, name) != NULL;
    const bool in_full = strchr(full_names, name) != NULL;
    if (pages[i]->theap != theap || (in_regular && in_full)) abort();
    if (mi_page_is_in_full(pages[i]) != in_full) abort();
    if (!in_regular && !in_full && (pages[i]->prev != NULL || pages[i]->next != NULL)) abort();
    flags[i] = in_full ? 'F' : (in_regular ? 'R' : 'D');
    if (in_full) bytes += pages[i]->capacity * pages[i]->block_size;
  }
  flags[3] = 0;
  for (size_t i = 0; i < MI_PAGES_DIRECT; i++) {
    const size_t direct_bin = mi_bin(i * sizeof(uintptr_t));
    const mi_page_t* expected = _mi_page_empty_get();
    if (direct_bin == bin && regular->block_size <= MI_SMALL_SIZE_MAX && regular->first != NULL) expected = regular->first;
    if (direct_bin == sentinel_bin && sentinel_live) expected = sentinel;
    if (theap->pages_free_direct[i] != expected) abort();
    direct[i] = expected == _mi_page_empty_get() ? '-' :
                  (expected == sentinel ? 'S' : name_of(expected, pages));
  }
  direct[MI_PAGES_DIRECT] = 0;
  if (theap->pages_full_size != bytes ||
      theap->page_count != regular->count + full->count + sentinel_live) abort();
  printf("M3B bin=%zu size=%zu seed=%llu step=%zu action=%s page=%c regular=%s full=%s direct=%s state=%s bytes=%zu pages=%zu sentinel=%u\n",
         bin, regular->block_size, (unsigned long long)seed, step, action, changed,
         regular_names, full_names, direct, flags, bytes, theap->page_count, sentinel_live);
}

static void bin_transition_matrix(void) {
  const uint64_t seeds[] = {UINT64_C(0x4d3342494e), UINT64_C(0x9e3779b97f4a7c15)};
  for (size_t bin = 1; bin <= MI_BIN_HUGE; bin++) {
    const size_t size = _mi_theap_empty.pages[bin].block_size;
    if (mi_bin(size) != bin) continue;
    const size_t sentinel_bin = bin == 1 ? 2 : 1;
    for (size_t s = 0; s < sizeof(seeds)/sizeof(seeds[0]); s++) {
      mi_theap_t theap = _mi_theap_empty;
      mi_page_t a = {0}, b = {0}, c = {0}, sentinel = {0};
      mi_page_t* pages[3] = {&a, &b, &c};
      const mi_page_t* const names[3] = {&a, &b, &c};
      mi_page_queue_t* regular = &theap.pages[bin];
      mi_page_queue_t* full = &theap.pages[MI_BIN_FULL];
      for (size_t i = 0; i < 3; i++) {
        pages[i]->theap = &theap;
        pages[i]->block_size = size;
        pages[i]->capacity = pages[i]->reserved = (uint16_t)(bin == MI_BIN_HUGE ? 1 : 4 + 2*i);
      }
      sentinel.theap = &theap;
      sentinel.block_size = theap.pages[sentinel_bin].block_size;
      sentinel.capacity = sentinel.reserved = 1;
      mi_page_queue_push_at_end(&theap, &theap.pages[sentinel_bin], &sentinel);
      unsigned states[3] = {0, 0, 0};
      uint64_t random = seeds[s];
      show_bin(bin, seeds[s], 0, "init", '-', &theap, names, &sentinel, sentinel_bin, true);
      size_t step;
      for (step = 1; step <= 128; step++) {
        random = random * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
        const size_t index = (random >> 32) % 3;
        const unsigned op = (unsigned)((random >> 16) % 6);
        mi_page_t* selected = pages[index];
        const char* action;
        if (states[index] == 0) {
          if (op % 2 == 0) {
            mi_page_queue_push(&theap, regular, selected);
            action = "push-head";
          } else {
            mi_page_queue_push_at_end(&theap, regular, selected);
            action = "push-tail";
          }
          states[index] = 1;
        } else {
          mi_page_queue_t* from = states[index] == 1 ? regular : full;
          mi_page_queue_t* to = states[index] == 1 ? full : regular;
          if (op == 0) {
            mi_page_queue_remove(from, selected);
            states[index] = 0;
            action = "remove";
          } else if (op == 1) {
            mi_page_queue_move_to_front(&theap, from, selected);
            action = "front";
          } else {
            if (op == 2 && states[index] == 2) {
              mi_page_queue_enqueue_from_full(to, from, selected);
              action = "return-tail";
            } else {
              mi_page_queue_enqueue_from_ex(to, from, op % 2 == 0, selected);
              action = op % 2 == 0 ? "transfer-tail" : "transfer-second";
            }
            states[index] = 3 - states[index];
          }
        }
        show_bin(bin, seeds[s], step, action, 'A' + index, &theap, names, &sentinel, sentinel_bin, true);
      }
      for (size_t i = 0; i < 3; i++) {
        if (states[i] != 0) {
          mi_page_queue_remove(states[i] == 1 ? regular : full, pages[i]);
          show_bin(bin, seeds[s], step++, "remove", 'A' + i, &theap, names, &sentinel, sentinel_bin, true);
        }
      }
      mi_page_queue_remove(&theap.pages[sentinel_bin], &sentinel);
      show_bin(bin, seeds[s], step, "release-sentinel", 'S', &theap, names, &sentinel, sentinel_bin, false);
    }
  }
}

static void print_blocks(const mi_page_t* page, const mi_block_t* block) {
  size_t count = 0;
  while (block != NULL) {
    const uintptr_t offset = (uintptr_t)block - (uintptr_t)mi_page_start(page);
    if (++count > page->capacity || offset % page->block_size != 0 ||
        offset / page->block_size >= page->capacity) abort();
    if (count > 1) putchar(',');
    printf("%zu", (size_t)(offset / page->block_size));
    block = mi_block_next(page, block);
  }
  if (count == 0) putchar('-');
}

static void show_free(const char* stage, const mi_page_t* page) {
  printf("M3F size=%zu stage=%s capacity=%u reserved=%u used=%zu zero=%u free=",
         page->block_size, stage, page->capacity, page->reserved, (size_t)page->used,
         page->free_is_zero);
  print_blocks(page, page->free);
  printf(" local=");
  print_blocks(page, page->local_free);
  putchar('\n');
}

static mi_block_t* pop_checked(mi_theap_t* theap, mi_page_t* page, bool zero) {
  if (page->free == NULL) abort();
  mi_block_t* block = mi_page_malloc_zero(theap, page, page->block_size, zero, NULL);
  if (block->next != 0) abort();
  if (zero) {
    const uint8_t* bytes = (const uint8_t*)block;
    for (size_t i = 0; i < page->block_size; i++) if (bytes[i] != 0) abort();
  }
  return block;
}

static void free_list_matrix(void) {
  for (size_t bin = 1; bin < MI_BIN_HUGE; bin++) {
    const size_t size = _mi_theap_empty.pages[bin].block_size;
    if (mi_bin(size) != bin) continue;
    const size_t first_extend = size >= MI_MAX_EXTEND_SIZE ? 1 : MI_MAX_EXTEND_SIZE / size;
    const uint16_t reserved = (uint16_t)(first_extend + 3);
    const size_t offset = _mi_align_up(sizeof(mi_page_t), MI_MAX_ALIGN_SIZE);
    mi_page_t* page = calloc(1, offset + reserved * size);
    mi_block_t** allocated = calloc(reserved, sizeof(*allocated));
    if (page == NULL || allocated == NULL) abort();
    mi_theap_t theap = _mi_theap_empty;
    page->block_size = size;
    page->page_offset = offset;
    page->reserved = reserved;
    page->free_is_zero = true;
    page->theap = &theap;
    show_free("fresh", page);
    size_t count = 0;
    while (count < reserved) {
      if (page->free == NULL) {
        if (!mi_page_extend_free(&theap, page)) abort();
        show_free("extend", page);
      }
      allocated[count++] = pop_checked(&theap, page, true);
    }
    show_free("allocated", page);
    for (size_t i = 0; i < 2; i++) {
      memset(allocated[i], 0xa5, size);
      mi_free_block_local(page, allocated[i], false, false, false);
    }
    show_free("local-two", page);
    _mi_page_free_collect(page, false);
    show_free("transfer", page);
    if (pop_checked(&theap, page, true) != allocated[1]) abort();
    memset(allocated[1], 0xa5, size);
    mi_free_block_local(page, allocated[1], false, false, false);
    show_free("both-lists", page);
    _mi_page_free_collect(page, false);
    show_free("false-force", page);
    if (!mi_page_free_quick_collect(page)) abort();
    show_free("quick-preserve", page);
    _mi_page_free_collect(page, true);
    show_free("force-append", page);
    if (pop_checked(&theap, page, true) != allocated[1] ||
        pop_checked(&theap, page, true) != allocated[0]) abort();
    show_free("reallocated", page);
    for (size_t i = 0; i + 1 < reserved; i++) {
      memset(allocated[i], 0xa5, size);
      mi_free_block_local(page, allocated[i], false, false, false);
    }
    show_free("local-many", page);
    if (!mi_page_free_quick_collect(page)) abort();
    show_free("quick-transfer", page);
    for (size_t i = reserved - 1; i > 0; i--) {
      if (pop_checked(&theap, page, true) != allocated[i - 1]) abort();
    }
    if (!mi_page_extend_free(&theap, page)) abort();
    _mi_page_free_collect(page, true);
    if (mi_page_free_quick_collect(page)) abort();
    show_free("exhausted", page);
    free(allocated);
    free(page);
  }
}

int main(void) {
  retirement_sequence();
  bin_transition_matrix();
  free_list_matrix();
  return 0;
}
