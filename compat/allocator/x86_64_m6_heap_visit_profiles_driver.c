#include <mimalloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CLIENTS 96

static size_t os_page_size;

typedef struct client_s {
  unsigned char* pointer;
  size_t requested;
  size_t usable;
  bool live;
  bool guarded;
} client_t;

typedef struct population_s {
  mi_heap_t* heap;
  client_t clients[MAX_CLIENTS];
  size_t count;
  bool ready;
} population_t;

typedef struct capture_s {
  population_t* population;
  mi_heap_t* heap;
  bool strict;
  bool valid;
  bool area_selected;
  bool seen[MAX_CLIENTS];
  size_t stop;
  size_t calls;
  size_t areas;
  size_t blocks;
  size_t found;
  size_t guarded;
  size_t used;
  size_t full;
  size_t empty;
  size_t reserved;
  size_t committed;
  size_t payload;
  size_t stride;
  size_t last_block;
  size_t geometry[MAX_CLIENTS][7];
} capture_t;

static bool inside(uintptr_t pointer, uintptr_t start, size_t length) {
  return pointer >= start && pointer - start < length;
}

/* Traversal is synchronous and quiescent. The callback only copies geometry
   and reads retained client bytes; it never allocates, frees, collects, or
   changes Heap ownership. Aligned clients can be interior to the raw slot
   reported by the source visitor, so identify their containing slot. */
static bool observe(const mi_heap_t* heap, const mi_heap_area_t* area,
                    void* block, size_t block_size, void* argument) {
  capture_t* capture = argument;
  population_t* population = capture->population;
  capture->valid &= heap == capture->heap && area != NULL &&
      area->full_block_size >= area->block_size && area->block_size > 0 &&
      block_size == area->block_size && area->reserved >= area->committed &&
      area->committed % area->full_block_size == 0 &&
      area->used <= area->committed / area->full_block_size;
  if (block == NULL) {
    bool selected = capture->strict;
    for (size_t i = 0; i < population->count; i++) {
      selected |= inside((uintptr_t)population->clients[i].pointer,
                         (uintptr_t)area->blocks, area->committed);
    }
    capture->area_selected = selected;
    capture->last_block = 0;
    if (!selected) return true;
    capture->calls++; capture->areas++;
    capture->used += area->used;
    capture->full += area->used > 1 && area->used == area->committed / area->full_block_size;
    capture->empty += area->used == 0;
    capture->reserved += area->reserved;
    capture->committed += area->committed;
    capture->payload += area->block_size;
    capture->stride += area->full_block_size;
  } else {
    if (!capture->area_selected) return true;
    capture->calls++; capture->blocks++;
    uintptr_t address = (uintptr_t)block;
    capture->valid &= inside(address, (uintptr_t)area->blocks, area->committed) &&
        (address - (uintptr_t)area->blocks) % area->full_block_size == 0 &&
        (capture->last_block == 0 || address > capture->last_block);
    capture->last_block = address;
    size_t matches = 0;
    for (size_t i = 0; i < population->count; i++) {
      client_t* client = &population->clients[i];
      if (!inside((uintptr_t)client->pointer, address, block_size)) continue;
      matches++;
      capture->valid &= client->live && !capture->seen[i];
      if (!client->live) continue;
      capture->seen[i] = true; capture->found++;
      size_t offset = (uintptr_t)client->pointer - address;
      size_t geometry[] = {offset, area->block_size, area->full_block_size,
          area->reserved, area->committed, area->used, client->usable};
      memcpy(capture->geometry[i], geometry, sizeof(geometry));
      capture->valid &= client->requested <= block_size - offset &&
          client->usable <= block_size - offset;
      if (client->guarded) {
        uintptr_t tag;
        memcpy(&tag, block, sizeof(tag));
        capture->guarded++;
        capture->valid &= tag == UINTPTR_MAX && offset >= sizeof(uintptr_t) &&
            area->full_block_size >= offset + os_page_size &&
            client->usable == area->full_block_size - offset - os_page_size;
      }
      for (size_t j = 0; j < client->requested; j++) {
        capture->valid &= client->pointer[j] == (unsigned char)(i + 1);
      }
    }
    if (capture->strict) capture->valid &= matches == 1;
  }
  return capture->stop == 0 || capture->calls < capture->stop;
}

static bool add(population_t* population, size_t size, size_t alignment) {
  if (population->count == MAX_CLIENTS) return false;
  size_t index = population->count;
  unsigned char* block = alignment == 0
      ? mi_heap_malloc(population->heap, size)
      : mi_heap_malloc_aligned(population->heap, size, alignment);
  if (block == NULL) return false;
  size_t usable = mi_usable_size(block);
  if (usable < size || mi_heap_of(block) != population->heap ||
      (alignment != 0 && (uintptr_t)block % alignment != 0)) return false;
  memset(block, (unsigned char)(index + 1), size);
  population->clients[index] = (client_t){block, size, usable, true,
      MI_GUARDED && (alignment == 0 || alignment == 4096)};
  population->count++;
  return true;
}

static bool populate(population_t* population) {
  #if MI_GUARDED
  mi_theap_t* theap = mi_heap_theap(population->heap);
  if (theap == NULL) return false;
  mi_theap_guarded_set_sample_rate(theap, 1, 1);
  mi_theap_guarded_set_size_bound(theap, 0, SIZE_MAX);
  #endif
  const size_t groups[][2] = {{73, 5}, {91, 3}, {8192, 32}, {32769, 18}, {200000, 3}};
  for (size_t group = 0; group < sizeof(groups) / sizeof(groups[0]); group++) {
    for (size_t i = 0; i < groups[group][1]; i++) {
      if (!add(population, groups[group][0], 0)) return false;
    }
  }
  if (!add(population, 1000, 4096) || !add(population, 10241, 131072) ||
      !add(population, 1048576, 0)) return false;
  population->ready = true;
  return true;
}

static bool visit(const char* name, population_t* population, mi_heap_t* heap,
                  mi_theap_t* theap, int alias, bool blocks, size_t stop,
                  bool strict, bool all_live, bool require_full) {
  capture_t capture = {.population = population, .heap = heap, .strict = strict, .valid = true, .stop = stop};
  bool complete = alias == 0 ? mi_heap_visit_blocks(heap, blocks, observe, &capture)
      : alias == 1 ? mi_heap_visit_abandoned_blocks(heap, blocks, observe, &capture)
      : alias == 2 ? mi_theap_visit_blocks(theap, blocks, observe, &capture)
      : mi_heap_visit_blocks(NULL, blocks, observe, &capture);
  size_t live = 0, guarded = 0;
  for (size_t i = 0; i < population->count; i++) {
    live += population->clients[i].live;
    guarded += population->clients[i].live && population->clients[i].guarded;
  }
  bool expected = capture.valid && (stop == 0 ? complete : !complete && capture.calls == stop);
  if (blocks && all_live && stop == 0) expected &= capture.found == live && capture.guarded == guarded;
  if (!blocks) expected &= capture.blocks == 0;
  if (require_full) expected &= capture.full > 0;
  // Secure free-list shuffling changes the first visited client. The callback
  // validates that client's bytes and geometry; stopping exposes cardinality,
  // while complete visits below retain every client's geometry and identity.
  if (stop != 0) {
    printf("%s=%d,%d,%zu,%zu,%zu,%zu\n", name, complete, expected,
           capture.calls, capture.areas, capture.blocks, capture.found);
    return expected;
  }
  uint64_t identities[2] = {0, 0};
  for (size_t i = 0; i < population->count; i++) {
    if (capture.seen[i]) identities[i / 64] |= UINT64_C(1) << (i % 64);
  }
  printf("%s=%d,%d,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%016llx,%016llx\n", name,
         complete, expected, capture.areas, capture.blocks, capture.found, capture.used,
         capture.full, capture.empty, capture.reserved, capture.committed, capture.payload, capture.stride,
         (unsigned long long)identities[0], (unsigned long long)identities[1]);
  for (size_t i = 0; i < population->count; i++) {
    if (!capture.seen[i]) continue;
    printf("%s.client%zu=%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu\n", name, i,
           population->clients[i].requested, capture.geometry[i][0], capture.geometry[i][1],
           capture.geometry[i][2], capture.geometry[i][3], capture.geometry[i][4],
           capture.geometry[i][5], capture.geometry[i][6]);
  }
  #if MI_GUARDED
  printf("%s.guarded=%zu\n", name, capture.guarded);
  #endif
  return expected;
}

static void* remote_free(void* argument) {
  population_t* population = argument;
  for (size_t i = 0; i < population->count; i++) {
    if (i % 3 == 1 && population->clients[i].live) mi_free(population->clients[i].pointer);
  }
  return NULL;
}

static void drain(population_t* population) {
  for (size_t i = 0; i < population->count; i++) {
    if (population->clients[i].live) {
      mi_free(population->clients[i].pointer);
      population->clients[i].live = false;
    }
  }
}

static void* owner(void* argument) {
  population_t* population = argument;
  return populate(population) ? (void*)1 : NULL;
}

int main(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) return 8;
  os_page_size = (size_t)page_size;
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_HEAP_VISIT_PROFILES_BEGIN");
  mi_theap_t* initial = mi_theap_get_default();
  population_t population = {.heap = mi_heap_new()};
  if (population.heap == NULL) return 2;
  mi_theap_t* theap = mi_heap_theap(population.heap);
  bool passed = visit("empty.heap", &population, population.heap, theap, 0, true, 0, true, true, false) &&
      visit("empty.theap", &population, population.heap, theap, 2, true, 0, true, true, false) &&
      visit("empty.abandoned", &population, population.heap, theap, 1, true, 0, true, true, false);
  if (!populate(&population)) return 3;
  passed &= visit("populated.heap", &population, population.heap, theap, 0, true, 0, true, true, true);
  // Theap queues and abandoned-bin selection cover their own source page
  // sets. Record exact client identities for those subsets; the ordinary
  // Heap traversal separately proves the complete retained population.
  passed &= visit("populated.theap", &population, population.heap, theap, 2, true, 0, true, false, false);
  passed &= visit("populated.areas", &population, population.heap, theap, 0, false, 0, true, false, true);
  passed &= visit("populated.stop_area", &population, population.heap, theap, 0, false, 1, true, false, false);
  passed &= visit("populated.stop_block", &population, population.heap, theap, 0, true, 2, true, false, false);
  passed &= visit("populated.theap_stop", &population, population.heap, theap, 2, true, 2, true, false, false);
  pthread_t thread;
  if (pthread_create(&thread, NULL, remote_free, &population) != 0 || pthread_join(thread, NULL) != 0) return 4;
  for (size_t i = 0; i < population.count; i++) if (i % 3 == 1) population.clients[i].live = false;
  mi_heap_collect(population.heap, true);
  passed &= visit("remote.heap", &population, population.heap, theap, 0, true, 0, true, true, false);
  passed &= visit("remote.theap", &population, population.heap, theap, 2, true, 0, true, false, false);
  drain(&population);
  passed &= visit("zero.heap", &population, population.heap, theap, 0, true, 0, true, true, false);
  mi_heap_collect(population.heap, true);
  passed &= visit("drained.heap", &population, population.heap, theap, 0, true, 0, true, true, false);
  mi_heap_destroy(population.heap);

  population_t released = {.heap = mi_heap_new()};
  if (released.heap == NULL) return 5;
  void* result = NULL;
  if (pthread_create(&thread, NULL, owner, &released) != 0 ||
      pthread_join(thread, &result) != 0 || result != (void*)1 || !released.ready) return 6;
  // Joining the owner excludes allocation and remote publication while its
  // abandoned clients are observed. No exited Theap handle is retained.
  passed &= visit("exited.heap", &released, released.heap, NULL, 0, true, 0, true, true, true);
  passed &= visit("exited.abandoned", &released, released.heap, NULL, 1, true, 0, true, false, false);
  passed &= visit("exited.stop_area", &released, released.heap, NULL, 1, false, 1, true, false, false);
  passed &= visit("exited.stop_block", &released, released.heap, NULL, 1, true, 2, true, false, false);
  mi_heap_delete(released.heap);
  // Delete transfers live pages to the main Heap. Only that live destination
  // is queried; unrelated main-Heap metadata pages are outside this capture.
  mi_heap_t* main_heap = mi_heap_main();
  passed &= visit("deleted.heap", &released, main_heap, NULL, 0, true, 0, false, true, true);
  passed &= visit("deleted.abandoned", &released, main_heap, NULL, 1, true, 0, false, false, false);
  passed &= visit("deleted.default", &released, main_heap, NULL, 3, true, 0, false, true, true);
  drain(&released); mi_heap_collect(main_heap, true);
  passed &= visit("deleted.drained", &released, main_heap, NULL, 0, true, 0, false, true, false);
  printf("default.retained=%d\n", mi_theap_get_default() == initial);
  puts("CRABC_MI_HEAP_VISIT_PROFILES_END");
  return passed && mi_theap_get_default() == initial ? 0 : 7;
}
