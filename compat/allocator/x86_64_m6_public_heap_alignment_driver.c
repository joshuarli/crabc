#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mimalloc.h"

/* Debug pointer validation requires word-aligned clients for usable-size,
   reallocation, and free. Preserve nonzero offsets within that condition;
   release also covers byte-granular aligned-at outputs. */
static size_t client_offset(size_t offset) {
#if MI_DEBUG
  return (offset + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
#else
  return offset;
#endif
}

#if MI_DEBUG
#define COUNT_OVERFLOW_ERRNO ENOMEM
#else
#define COUNT_OVERFLOW_ERRNO 0
#endif

static bool all_zero(const unsigned char* bytes, size_t size) {
  if (bytes == NULL) return false;
  for (size_t i = 0; i < size; i++) {
    if (bytes[i] != 0) return false;
  }
  return true;
}

typedef struct {
  mi_heap_t* heap;
  mi_theap_t* main_theap;
  bool complete;
} worker_state_t;

static void* worker_allocate(void* argument) {
  worker_state_t* state = (worker_state_t*)argument;
  errno = 0;
  unsigned char* block = (unsigned char*)mi_heap_zalloc_aligned_at(
      state->heap, 1000, 256, client_offset(31));
  mi_theap_t* theap = mi_heap_theap(state->heap);
  printf("alignment.worker=%d,%d,%d,%d,%d,%d\n",
      block != NULL, block != NULL && (((uintptr_t)block + client_offset(31)) % 256) == 0,
      all_zero(block, 1000), block != NULL && mi_heap_of(block) == state->heap,
      theap != NULL && theap != state->main_theap, errno == 0);
  state->complete = block != NULL && theap != NULL && theap != state->main_theap;
  if (block != NULL) mi_free(block);
  return NULL;
}

static bool success_case(mi_heap_t* heap, size_t size, size_t alignment,
                         size_t offset, size_t index) {
  errno = 0;
  unsigned char* block = (unsigned char*)mi_heap_zalloc_aligned_at(
      heap, size, alignment, offset);
  bool present = block != NULL;
  bool aligned = present && (((uintptr_t)block + offset) % alignment) == 0;
  bool zero = all_zero(block, size);
  bool owner = present && mi_heap_of(block) == heap && mi_heap_contains(heap, block);
  bool usable = present && mi_usable_size(block) >= size;
  bool unchanged = errno == 0;
  printf("alignment.case%zu=%d,%d,%d,%d,%d,%d\n", index,
         present, aligned, zero, owner, usable, unchanged);
  if (present) {
    memset(block, 0xa5, size);
    mi_free(block);
  }
  return present && aligned && zero && owner && usable && unchanged;
}

static void failure_case(mi_heap_t* heap, size_t size, size_t alignment,
                         size_t offset, size_t index) {
  errno = 0;
  void* block = mi_heap_zalloc_aligned_at(heap, size, alignment, offset);
  printf("alignment.failure%zu=%d,%d\n", index, block == NULL, errno);
  if (block != NULL) mi_free(block);
}


typedef void (*new_handler_t)(void);
static size_t new_calls;
static void count_new_handler(void) { new_calls++; }
/* Supply the C++ new-handler input through the pinned weak C boundary. */
new_handler_t _ZSt15get_new_handlerv(void) { return count_new_handler; }

static const char* allocation_names[] = {
  "mi_heap_malloc", "mi_heap_zalloc", "mi_heap_calloc", "mi_heap_mallocn",
  "mi_heap_malloc_small", "mi_heap_zalloc_small", "mi_heap_malloc_aligned",
  "mi_heap_malloc_aligned_at", "mi_heap_zalloc_aligned", "mi_heap_zalloc_aligned_at",
  "mi_heap_calloc_aligned", "mi_heap_calloc_aligned_at", "mi_heap_alloc_new", "mi_heap_alloc_new_n"
};
static const char* replacement_names[] = {
  "mi_heap_realloc", "mi_heap_reallocn", "mi_heap_rezalloc", "mi_heap_recalloc",
  "mi_heap_realloc_aligned", "mi_heap_realloc_aligned_at", "mi_heap_rezalloc_aligned",
  "mi_heap_rezalloc_aligned_at", "mi_heap_recalloc_aligned", "mi_heap_recalloc_aligned_at"
};
static unsigned char* allocation_entry(mi_heap_t* heap, size_t entry, size_t count, size_t size) {
  switch (entry) {
    case 0: return mi_heap_malloc(heap, size);
    case 1: return mi_heap_zalloc(heap, size);
    case 2: return mi_heap_calloc(heap, count, size);
    case 3: return mi_heap_mallocn(heap, count, size);
    case 4: return mi_heap_malloc_small(heap, size);
    case 5: return mi_heap_zalloc_small(heap, size);
    case 6: return mi_heap_malloc_aligned(heap, size, 128);
    case 7: return mi_heap_malloc_aligned_at(heap, size, 128, client_offset(7));
    case 8: return mi_heap_zalloc_aligned(heap, size, 128);
    case 9: return mi_heap_zalloc_aligned_at(heap, size, 128, client_offset(7));
    case 10: return mi_heap_calloc_aligned(heap, count, size, 128);
    case 11: return mi_heap_calloc_aligned_at(heap, count, size, 128, client_offset(7));
    case 12: return mi_heap_alloc_new(heap, size);
    case 13: return mi_heap_alloc_new_n(heap, count, size);
  }
  return NULL;
}
static unsigned char* replacement_entry(mi_heap_t* heap, size_t entry,
                                         unsigned char* old, size_t count, size_t size) {
  switch (entry) {
    case 0: return mi_heap_realloc(heap, old, size);
    case 1: return mi_heap_reallocn(heap, old, count, size);
    case 2: return mi_heap_rezalloc(heap, old, size);
    case 3: return mi_heap_recalloc(heap, old, count, size);
    case 4: return mi_heap_realloc_aligned(heap, old, size, 128);
    case 5: return mi_heap_realloc_aligned_at(heap, old, size, 128, client_offset(7));
    case 6: return mi_heap_rezalloc_aligned(heap, old, size, 128);
    case 7: return mi_heap_rezalloc_aligned_at(heap, old, size, 128, client_offset(7));
    case 8: return mi_heap_recalloc_aligned(heap, old, count, size, 128);
    case 9: return mi_heap_recalloc_aligned_at(heap, old, count, size, 128, client_offset(7));
  }
  return NULL;
}
static bool payload(const unsigned char* pointer, size_t size, unsigned char value) {
  if (pointer == NULL) return false;
  for (size_t i = 0; i < size; i++) if (pointer[i] != value) return false;
  return true;
}
static bool allocation_refusals(mi_heap_t* sentinel_heap, unsigned char* sentinel) {
  mi_heap_t* empty = mi_heap_new();
  if (empty == NULL || mi_heap_theap(empty) == NULL) return false;
  unsigned char* originals[11];
  for (size_t i = 0; i < 11; i++) {
    originals[i] = mi_heap_malloc(sentinel_heap, 73);
    if (originals[i] == NULL) return false;
    memset(originals[i], 0x6b, 73);
  }
  bool previous_os = mi_option_is_enabled(mi_option_disallow_os_alloc);
  bool previous_arena = mi_option_is_enabled(mi_option_disallow_arena_alloc);
  mi_option_set_enabled(mi_option_disallow_os_alloc, true);
  mi_option_set_enabled(mi_option_disallow_arena_alloc, true);
  bool passed = true;
  for (size_t entry = 0; entry < sizeof(allocation_names)/sizeof(allocation_names[0]); entry++) {
    errno = 0;
    size_t calls_before = new_calls;
    unsigned char* refused = allocation_entry(empty, entry, 1, 73);
    int observed_errno = errno;
    bool intact = payload(sentinel, 73, 0xa5) && mi_heap_of(sentinel) == sentinel_heap;
    printf("entry.%s.refusal=%d,%d,%d\n", allocation_names[entry], refused == NULL, observed_errno, intact);
    passed &= refused == NULL && observed_errno == ENOMEM && intact;
    if (entry >= 12) {
      printf("entry.%s.refusal_handler=%zu\n", allocation_names[entry], new_calls - calls_before);
      passed &= new_calls - calls_before == 4;
    }
    if (refused != NULL) mi_free(refused);
  }
  for (size_t entry = 0; entry < 10; entry++) {
    errno = 0;
    unsigned char* refused = replacement_entry(empty, entry, originals[entry], 1, 16 * 1024 * 1024);
    int observed_errno = errno;
    bool intact = payload(originals[entry], 73, 0x6b) && mi_heap_of(originals[entry]) == sentinel_heap;
    printf("entry.%s.refusal=%d,%d,%d\n", replacement_names[entry], refused == NULL, observed_errno, intact);
    passed &= refused == NULL && observed_errno == ENOMEM && intact;
    mi_free(refused == NULL ? originals[entry] : refused);
  }
  const char* string_names[] = { "mi_heap_strdup", "mi_heap_strndup", "mi_heap_realpath" };
  for (size_t entry = 0; entry < 3; entry++) {
    errno = 0;
    char* refused = entry == 0 ? mi_heap_strdup(empty, "heap-content") :
        entry == 1 ? mi_heap_strndup(empty, "heap-content", 4) : mi_heap_realpath(empty, "/", NULL);
    int observed_errno = errno;
    bool intact = payload(sentinel, 73, 0xa5) && mi_heap_of(sentinel) == sentinel_heap;
    printf("entry.%s.refusal=%d,%d,%d\n", string_names[entry], refused == NULL, observed_errno, intact);
    passed &= refused == NULL && observed_errno == ENOMEM && intact;
    mi_free(refused);
  }
  errno = 0;
  unsigned char* consumed = mi_heap_reallocf(empty, originals[10], 16 * 1024 * 1024);
  int consumed_errno = errno;
  /* reallocf releases its input on failure. Observe only the live neighbor. */
  bool neighbor = payload(sentinel, 73, 0xa5) && mi_heap_of(sentinel) == sentinel_heap;
  printf("entry.mi_heap_reallocf.refusal=%d,%d,%d\n", consumed == NULL, consumed_errno, neighbor);
  passed &= consumed == NULL && consumed_errno == ENOMEM && neighbor;
  mi_free(consumed);
  mi_option_set_enabled(mi_option_disallow_os_alloc, previous_os);
  mi_option_set_enabled(mi_option_disallow_arena_alloc, previous_arena);
  mi_heap_destroy(empty);
  return passed;
}

/* Keep every exported Heap entry in one content/ownership transaction.
   Small-entry requests remain within their documented size precondition. */
static bool allocation_contract(void) {
  mi_heap_t* growth_heap = mi_heap_new();
  if (growth_heap == NULL) return false;
  bool growth = true;
  for (size_t i = 0; i < 28; i++) {
    unsigned char* block = mi_heap_malloc(growth_heap, 8192);
    growth &= block != NULL;
    if (block != NULL) memset(block, 0x5a, 8192);
  }
  mi_heap_destroy(growth_heap);
  printf("contract.growth=%d\n", growth);
  if (!growth) return false;
  mi_heap_t* heap = mi_heap_new();
  if (heap == NULL) return false;
  unsigned char* live[28];
  size_t sizes[28];
  bool allocations = true;
  for (size_t i = 0; i < 14; i++) {
    errno = 37;
    live[i] = allocation_entry(heap, i, 1, 73);
    bool errno_preserved = errno == 37;
    sizes[i] = 73;
    bool zero = i == 1 || i == 2 || i == 5 || (i >= 8 && i <= 11);
    bool owner = live[i] != NULL && mi_heap_of(live[i]) == heap;
    bool initialized = !zero || all_zero(live[i], 73);
    bool aligned = i < 6 || i > 11 || (live[i] != NULL &&
        (((uintptr_t)live[i] + ((i & 1) ? client_offset(7) : 0)) % 128) == 0);
    printf("entry.%s.normal=%d,%d,%d,%d,%d\n", allocation_names[i], live[i] != NULL, owner, initialized, aligned, errno_preserved);
    allocations &= owner && errno_preserved;
    if (zero) allocations &= all_zero(live[i], 73);
    if (i >= 6 && i <= 11) {
      allocations &= live[i] != NULL &&
          (((uintptr_t)live[i] + ((i & 1) ? client_offset(7) : 0)) % 128) == 0;
    }
    if (live[i] != NULL) memset(live[i], 0xa5, 73);
  }
  printf("contract.allocations=%d\n", allocations);
  bool refusals = allocation_refusals(heap, live[0]);
  bool overflows = true;
  for (size_t entry = 0; entry < sizeof(allocation_names)/sizeof(allocation_names[0]); entry++) {
    if (entry == 4 || entry == 5) {
      printf("entry.%s.overflow=source-small-size-precondition\n", allocation_names[entry]);
      continue;
    }
    bool counted = entry == 2 || entry == 3 || entry == 10 || entry == 11 || entry == 13;
    errno = 0;
    unsigned char* failed = allocation_entry(heap, entry, counted ? SIZE_MAX : 1, counted ? 2 : SIZE_MAX);
    int observed_errno = errno;
    bool intact = payload(live[0], 73, 0xa5) && mi_heap_of(live[0]) == heap;
    printf("entry.%s.overflow=%d,%d,%d\n", allocation_names[entry], failed == NULL, observed_errno, intact);
    overflows &= failed == NULL && intact;
    if (failed != NULL) mi_free(failed);
  }

  bool strings = true;
  char* text = mi_heap_strdup(heap, "heap-content");
  char* limited = mi_heap_strndup(heap, "heap-content", 4);
  char* path = mi_heap_realpath(heap, "/", NULL);
  strings &= text != NULL && strcmp(text, "heap-content") == 0 && mi_heap_of(text) == heap;
  strings &= limited != NULL && strcmp(limited, "heap") == 0 && mi_heap_of(limited) == heap;
  strings &= path != NULL && strcmp(path, "/") == 0 && mi_heap_of(path) == heap;
  strings &= mi_heap_strdup(heap, NULL) == NULL;
  strings &= mi_heap_strndup(heap, NULL, 4) == NULL;
  strings &= mi_heap_realpath(heap, "/crabc-heap-contract-absent/path", NULL) == NULL;
  printf("entry.mi_heap_strdup.normal=%d,%d,%d\n", text != NULL, text != NULL && mi_heap_of(text) == heap,
         text != NULL && strcmp(text, "heap-content") == 0);
  printf("entry.mi_heap_strndup.normal=%d,%d,%d\n", limited != NULL, limited != NULL && mi_heap_of(limited) == heap,
         limited != NULL && strcmp(limited, "heap") == 0);
  printf("entry.mi_heap_realpath.normal=%d,%d,%d\n", path != NULL, path != NULL && mi_heap_of(path) == heap,
         path != NULL && strcmp(path, "/") == 0);
  printf("entry.mi_heap_strdup.null=%d\n", mi_heap_strdup(heap, NULL) == NULL);
  printf("entry.mi_heap_strndup.null=%d\n", mi_heap_strndup(heap, NULL, 4) == NULL);
  live[14] = (unsigned char*)text; sizes[14] = 13;
  live[15] = (unsigned char*)limited; sizes[15] = 5;
  live[16] = (unsigned char*)path; sizes[16] = 2;
  for (size_t i = 14; i < 17; i++) {
    if (live[i] != NULL) memset(live[i], 0xa5, sizes[i]);
  }
  printf("contract.strings=%d\n", strings);

  bool failures = true;
  errno = 0; failures &= mi_heap_malloc(heap, SIZE_MAX) == NULL && errno == ENOMEM;
  errno = 0; failures &= mi_heap_zalloc(heap, SIZE_MAX) == NULL && errno == ENOMEM;
  /* Count overflow diagnoses ENOMEM only when debug diagnostics are enabled. */
  errno = 0; failures &= mi_heap_mallocn(heap, SIZE_MAX, 2) == NULL && errno == COUNT_OVERFLOW_ERRNO;
  errno = 0; failures &= mi_heap_calloc(heap, SIZE_MAX, 2) == NULL && errno == COUNT_OVERFLOW_ERRNO;
  errno = 0; failures &= mi_heap_calloc_aligned(heap, SIZE_MAX, 2, 128) == NULL && errno == COUNT_OVERFLOW_ERRNO;
  errno = 0; failures &= mi_heap_calloc_aligned_at(heap, SIZE_MAX, 2, 128, client_offset(7)) == NULL && errno == COUNT_OVERFLOW_ERRNO;
  errno = 0; failures &= mi_heap_malloc_aligned(heap, 73, 24) == NULL && errno == EINVAL;
  errno = 0; failures &= mi_heap_malloc_aligned_at(heap, 73, 24, 7) == NULL && errno == EINVAL;
  errno = 0; failures &= mi_heap_zalloc_aligned(heap, 73, 24) == NULL && errno == EINVAL;
  errno = 0; failures &= mi_heap_zalloc_aligned_at(heap, 73, 24, 7) == NULL && errno == EINVAL;
  size_t before_new = new_calls;
  errno = 0; failures &= mi_heap_alloc_new(heap, SIZE_MAX) == NULL && errno == ENOMEM;
  errno = 0; failures &= mi_heap_alloc_new_n(heap, SIZE_MAX, 2) == NULL && errno == COUNT_OVERFLOW_ERRNO;
  failures &= new_calls == before_new + 2;
  printf("contract.failures=%d\n", failures);

  bool replacements = true;
  for (size_t kind = 0; kind < 10; kind++) {
    unsigned char* old = mi_heap_zalloc(heap, 73);
    if (old == NULL) return false;
    memset(old, 0x6b, 73);
    bool counted = kind == 1 || kind == 3 || kind == 8 || kind == 9;
    if (counted) {
      errno = 0;
      unsigned char* failed = replacement_entry(heap, kind, old, SIZE_MAX, 2);
      int observed_errno = errno;
      bool intact = payload(old, 73, 0x6b) && mi_heap_of(old) == heap;
      printf("entry.%s.count_overflow=%d,%d,%d\n", replacement_names[kind], failed == NULL, observed_errno, intact);
      replacements &= failed == NULL && observed_errno == COUNT_OVERFLOW_ERRNO && intact;
    }
    unsigned char* result = NULL;
    bool zero = kind == 2 || kind == 3 || kind >= 6;
    for (size_t stage = 0; stage < 2; stage++) {
      size_t size = stage == 0 ? SIZE_MAX : 4096;
      errno = 0;
      result = replacement_entry(heap, kind, old, 1, size);
      if (stage == 0) {
        printf("entry.%s.overflow=%d,%d,%d\n", replacement_names[kind], result == NULL, errno, payload(old, 73, 0x6b));
        replacements &= result == NULL && errno != 0;
        for (size_t j = 0; j < 73; j++) replacements &= old[j] == 0x6b;
      } else {
        replacements &= result != NULL && mi_heap_of(result) == heap;
        if (result != NULL) {
          for (size_t j = 0; j < 73; j++) replacements &= result[j] == 0x6b;
          if (zero) replacements &= all_zero(result + 73, size - 73);
          if (kind >= 4) replacements &=
              (((uintptr_t)result + ((kind & 1) ? client_offset(7) : 0)) % 128) == 0;
        }
        printf("entry.%s.normal=%d,%d,%d,%d\n", replacement_names[kind], result != NULL,
               result != NULL && mi_heap_of(result) == heap, payload(result, 73, 0x6b),
               !zero || (result != NULL && all_zero(result + 73, size - 73)));
        live[17 + kind] = result; sizes[17 + kind] = 4096;
        if (result != NULL) memset(result, 0xa5, 4096);
      }
    }
  }
  unsigned char* consumed = mi_heap_malloc(heap, 73);
  if (consumed == NULL) return false;
  errno = 0;
  unsigned char* reallocf_failed = mi_heap_reallocf(heap, consumed, SIZE_MAX);
  int reallocf_errno = errno;
  replacements &= reallocf_failed == NULL && reallocf_errno == ENOMEM;
  printf("entry.mi_heap_reallocf.overflow=%d,%d,%d\n", reallocf_failed == NULL, reallocf_errno,
         payload(live[0], 73, 0xa5) && mi_heap_of(live[0]) == heap);
  unsigned char* reallocf_source = mi_heap_malloc(heap, 73);
  if (reallocf_source == NULL) return false;
  memset(reallocf_source, 0xa5, 73);
  live[27] = mi_heap_reallocf(heap, reallocf_source, 4096); sizes[27] = 4096;
  replacements &= live[27] != NULL && mi_heap_of(live[27]) == heap;
  if (live[27] != NULL) {
    for (size_t j = 0; j < 73; j++) replacements &= live[27][j] == 0xa5;
    memset(live[27], 0xa5, 4096);
  }
  printf("entry.mi_heap_reallocf.normal=%d,%d,%d\n", live[27] != NULL,
         live[27] != NULL && mi_heap_of(live[27]) == heap, payload(live[27], 4096, 0xa5));
  /* reallocf consumed its argument; it is never accessed again. */
  printf("contract.replacements=%d\n", replacements);

  mi_heap_delete(heap);
  mi_heap_t* destination = mi_heap_new();
  if (destination == NULL) return false;
  bool lifetime = true;
  for (size_t i = 0; i < 28; i++) {
    if (live[i] == NULL) { lifetime = false; continue; }
    bool before = mi_usable_size(live[i]) >= sizes[i];
    for (size_t j = 0; j < sizes[i]; j++) before &= live[i][j] == 0xa5;
    unsigned char* replacement = mi_heap_realloc(destination, live[i], 8192);
    bool owner = replacement != NULL && mi_heap_of(replacement) == destination;
    bool copied = replacement != NULL;
    if (replacement != NULL) {
      for (size_t j = 0; j < sizes[i]; j++) copied &= replacement[j] == 0xa5;
      /* The destination owns every replacement until its destroy below. */
    } else {
      mi_free(live[i]);
    }
    const char* entry = i < 14 ? allocation_names[i] : i < 17 ?
        (const char*[]){ "mi_heap_strdup", "mi_heap_strndup", "mi_heap_realpath" }[i - 14] :
        i < 27 ? replacement_names[i - 17] : "mi_heap_reallocf";
    printf("entry.%s.lifetime=%d,%d,%d\n", entry, before, owner, copied);
    lifetime &= before && owner && copied;
    if (!before || !owner || !copied) {
      fprintf(stderr, "heap contract lifetime item %zu: before=%d owner=%d copied=%d\n",
              i, before, owner, copied);
    }
  }
  unsigned char* terminal = mi_heap_zalloc(destination, 4096);
  lifetime &= all_zero(terminal, 4096);
  mi_heap_destroy(destination);
  /* Destroy consumes the remaining block; no stale client is observed. */
  void* after = mi_malloc(73);
  lifetime &= after != NULL;
  mi_free(after);
  printf("contract.lifetime=%d\n", lifetime);
  return growth && allocations && refusals && overflows && strings && failures && replacements && lifetime;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set_enabled(mi_option_show_errors, true);
  mi_option_set(mi_option_arena_reserve, 0);
  puts("CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_BEGIN");
#ifdef CRABC_MI_HEAP_ALLOCATION_CONTRACT_ONLY
  /* The transaction retains all clients across delete, then transfers their
     content into a live destination Heap before that Heap is destroyed. */
  bool contract_only = allocation_contract();
  puts("CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_END");
  _exit(contract_only ? 0 : 6);
#endif
  mi_heap_t* heap = mi_heap_new();
  mi_theap_t* main_theap = heap == NULL ? NULL : mi_heap_theap(heap);
  printf("alignment.heap=%d,%d\n", heap != NULL, main_theap != NULL);
  if (heap == NULL || main_theap == NULL) return 2;
  unsigned char* dirty = (unsigned char*)mi_heap_malloc(heap, 73);
  if (dirty == NULL) return 3;
  memset(dirty, 0xa5, 73);
  mi_free(dirty);
  bool cases = true;
  cases &= success_case(heap, 24, 8, 0, 0);
  cases &= success_case(heap, 73, 128, client_offset(7), 1);
  cases &= success_case(heap, 7, 64, client_offset(19), 2);
  cases &= success_case(heap, 1024, 4096, client_offset(1), 3);
  cases &= success_case(heap, 8192, 65536, client_offset(13), 4);
  cases &= success_case(heap, 4096, 1024 * 1024, 0, 5);
  failure_case(heap, 64, 24, 0, 0);
  failure_case(heap, 64, 0, 0, 1);
  failure_case(heap, SIZE_MAX, 64, 0, 2);
  failure_case(heap, 64, 1024 * 1024, 1, 3);
  worker_state_t worker_state = {heap, main_theap, false};
  pthread_t worker;
  if (pthread_create(&worker, NULL, worker_allocate, &worker_state) != 0) return 4;
  if (pthread_join(worker, NULL) != 0) return 5;
  unsigned char* live = (unsigned char*)mi_heap_zalloc_aligned_at(heap, 73, 128, client_offset(7));
  bool live_owned = live != NULL && mi_heap_of(live) == heap && all_zero(live, 73);
  printf("alignment.before_delete=%d,%d\n", live_owned, worker_state.complete);
  mi_heap_delete(heap);
  bool retained_owner = live != NULL && mi_heap_of(live) == heap;
  bool main_owner = live != NULL && mi_heap_of(live) == mi_heap_main();
  bool remained = live != NULL && live[0] == 0 && live[72] == 0;
  printf("alignment.after_delete=%d,%d,%d\n", retained_owner,
         main_owner, remained);
  if (live != NULL) mi_free(live);
  puts("alignment.freed_after_delete=1");
  mi_heap_t* destroyed = mi_heap_new();
  printf("alignment.second_heap=%d\n", destroyed != NULL);
  unsigned char* terminal = destroyed == NULL ? NULL :
      (unsigned char*)mi_heap_zalloc_aligned_at(destroyed, 81, 128, client_offset(11));
  bool terminal_owned = terminal != NULL && mi_heap_of(terminal) == destroyed &&
      all_zero(terminal, 81);
  printf("alignment.second_block=%d\n", terminal_owned);
  if (destroyed != NULL) mi_heap_destroy(destroyed);
  puts("alignment.second_destroyed=1");
  void* after = mi_malloc(64);
  printf("alignment.destroy=%d,%d\n", terminal_owned, after != NULL);
  if (after != NULL) mi_free(after);
  bool contract = allocation_contract();
  puts("CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_END");
  _exit(cases && worker_state.complete && live_owned && remained &&
        terminal_owned && after != NULL && contract ? 0 : 6);
}
