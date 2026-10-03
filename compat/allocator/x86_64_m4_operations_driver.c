/* Shared C driver for public allocator operations.

   The same unmodified source is linked twice: once against the pinned
   mimalloc v3.5.0 release sources (`src/static.c`) and once against the
   native Rust adapter, and each binary runs as its own process. Every line it
   prints is an address-free `key=value` fact, so the two traces must be
   identical:

   - an allocation prints `id` (its logical allocation number), `reuse` (the
     id of the most recent earlier allocation at the same address, or `-`),
     its usable size, its address alignment as trailing zero bits capped at
     16, and its 64 KiB slice within the 256 MiB arena alignment; `null`
     otherwise;
   - `errno` is cleared before, and printed after, every call whose source
     path can set it;
   - contents are compared against byte patterns the driver wrote.

   Only the public `mimalloc.h` declarations are used. The one argument
   selects a scenario, each run in a fresh process: `operations`,
   `page-kinds`, `collection`, `oom`, `threads`, `aligned-preservation`, or a process-terminating
   `abort:<name>` that the runner observes through the exit status. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Walloc-size-larger-than="
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/resource.h>
#include <unistd.h>
#include <wchar.h>

#include "mimalloc.h"
#if defined(CRABC_MI_M4_SOURCE_CANARY) || defined(CRABC_MI_M4_SOURCE_FRESH_PAGE_ORDER)
#include "mimalloc/internal.h"
#endif

#ifdef CRABC_MI_M4_SOURCE_FRESH_PAGE_ORDER
#if MI_DEBUG < 3 || MI_GUARDED != 0
#error "Fresh-page observation requires the ordinary source path and its expensive zero assertion"
#endif
/* Only the selected source build includes this translation unit. The link
 * closure omits its ordinary page.c member so every definition stays singular.
 * The inline predicate is already defined above; interposition here observes
 * the actual page initializer's call and preserves its bytes and result. */
static bool fresh_page_zero_observe(const void* start, size_t size);
#define mi_mem_is_zero(start, size) fresh_page_zero_observe(start, size)
#include "page.c"
#undef mi_mem_is_zero

static bool fresh_page_armed;
static mi_page_t* fresh_page;
static size_t fresh_page_register_calls;
static size_t fresh_page_zero_calls;
static bool fresh_page_register_succeeded;
static bool fresh_page_primary_before_register;
static size_t fresh_page_aliases_before_register;
static bool fresh_page_aliases_match_before_register;
static bool fresh_page_counted;
static bool fresh_page_bin_counted;
static bool fresh_page_zero_after_registration;
static bool fresh_page_zero_after_statistics;
static bool fresh_page_zero_before_free_list;
static bool fresh_page_zero_before_queue;
static bool fresh_page_zero_result;

bool __real__mi_page_map_register(mi_page_t* page);
void __real___mi_stat_increase(mi_stat_count_t* stat, size_t amount);

bool __wrap__mi_page_map_register(mi_page_t* page) {
  const bool selected = fresh_page_armed && page->memid.memkind == MI_MEM_OS
      && mi_page_theap(page) == _mi_theap_default()
      && page->block_size >= 64 * 1024 && page->block_size <= 128 * 1024;
  if (selected) {
    fresh_page = page;
    fresh_page_register_calls++;
    fresh_page_primary_before_register =
        mi_atomic_load_ptr_acquire(mi_page_t, &page->self) == page;
    size_t area_size;
    uint8_t* const area = mi_page_area(page, &area_size);
    fresh_page_aliases_match_before_register = true;
    for (size_t offset = 0; offset < area_size; offset += MI_ARENA_SLICE_SIZE) {
      mi_page_t* const alias = _mi_aligned_ptr_page0(area + offset);
      if (alias != page) {
        fresh_page_aliases_before_register++;
        fresh_page_aliases_match_before_register =
            fresh_page_aliases_match_before_register
            && mi_atomic_load_ptr_acquire(mi_page_t, &alias->self) == page;
      }
    }
  }
  const bool result = __real__mi_page_map_register(page);
  if (selected) { fresh_page_register_succeeded = result; }
  return result;
}

void __wrap___mi_stat_increase(mi_stat_count_t* stat, size_t amount) {
  __real___mi_stat_increase(stat, amount);
  if (fresh_page != NULL && fresh_page_armed) {
    mi_theap_t* const theap = mi_page_theap(fresh_page);
    if (stat == &theap->stats.pages) {
      fresh_page_counted = amount == 1 && stat->current > 0;
    }
    if (stat == &theap->stats.page_bins[_mi_page_stats_bin(fresh_page)]) {
      fresh_page_bin_counted = amount == 1 && stat->current > 0;
    }
  }
}

static bool fresh_page_zero_observe(const void* start, size_t size) {
  /* This calls the original inline byte predicate. In particular, the earlier
   * backing-memory check in arena.c remains outside this translation unit. */
  const bool result = mi_mem_is_zero(start, size);
  if (fresh_page_armed && fresh_page != NULL
      && start == mi_page_start(fresh_page) && fresh_page->capacity == 0) {
    fresh_page_zero_calls++;
    fresh_page_zero_after_registration = fresh_page_register_succeeded
        && _mi_checked_ptr_page(start) == fresh_page
        && _mi_checked_ptr_page((const uint8_t*)start + size - 1) == fresh_page;
    fresh_page_zero_after_statistics = fresh_page_counted && fresh_page_bin_counted;
    fresh_page_zero_before_free_list = fresh_page->free == NULL
        && fresh_page->local_free == NULL && fresh_page->used == 0;
    mi_page_queue_t* const queue = mi_page_queue(mi_page_theap(fresh_page), fresh_page->block_size);
    fresh_page_zero_before_queue = queue->first != fresh_page
        && queue->last != fresh_page && fresh_page->next == NULL && fresh_page->prev == NULL;
    fresh_page_zero_result = result;
  }
  return result;
}
#endif

#define TRACE_BEGIN "CRABC_MI_M4_OPERATIONS_TRACE_BEGIN"
#define TRACE_END "CRABC_MI_M4_OPERATIONS_TRACE_END"
#define MAX_IDS 8192
#define KiB ((size_t)1024)
#define MiB (KiB * KiB)

static uintptr_t id_address[MAX_IDS];
static int id_count;
static bool valid_domain;

/* The source debug word-alignment check rejects valid offset clients. In
   this explicitly selected source-oracle mode, bypass only that check;
   guarded allocation itself is disabled by the compiler profile. */
static void set_live_client_precise(bool enabled) {
#if defined(CRABC_MI_M4_SOURCE_CANARY) && MI_DEBUG >= 1 && MI_GUARDED == 0
  if (valid_domain) { enabled = true; }
#endif
  mi_option_set_enabled(mi_option_guarded_precise, enabled);
}


static void line(const char* key, const char* format, ...) __attribute__((format(printf, 2, 3)));
static void line(const char* key, const char* format, ...) {
  va_list arguments;
  va_start(arguments, format);
  printf("%s=", key);
  vprintf(format, arguments);
  printf("\n");
  va_end(arguments);
}

static unsigned alignment_bits(const void* p) {
  uintptr_t address = (uintptr_t)p;
  unsigned bits = 0;
  while (bits < 16 && (address & ((uintptr_t)1 << bits)) == 0) { bits++; }
  return bits;
}

/* Records one allocation result under `key`. The logical id and reuse
   relation replace the raw address. */
static int note(const char* key, const void* p) {
  if (p == NULL) {
    line(key, "null");
    return -1;
  }
  int reuse = -1;
  for (int i = id_count - 1; i >= 0; i--) {
    if (id_address[i] == (uintptr_t)p) { reuse = i; break; }
  }
  const int id = id_count;
  if (id_count < MAX_IDS) { id_address[id_count++] = (uintptr_t)p; }
  char reuse_text[16];
  if (reuse < 0) { snprintf(reuse_text, sizeof reuse_text, "-"); }
  else { snprintf(reuse_text, sizeof reuse_text, "%d", reuse); }
  /* Arenas and OS-aligned singletons are MI_PAGE_META_ALIGNMENT (256 MiB)
     aligned, so the 64 KiB slice within that alignment is layout, not a raw
     address. */
  const unsigned slice = (unsigned)(((uintptr_t)p & ((uintptr_t)256 * MiB - 1)) >> 16);
  line(key, "id:%d,reuse:%s,usable:%zu,align:%u,slice:%u", id, reuse_text, mi_usable_size(p), alignment_bits(p), slice);
  return id;
}

/* Ordinary class allocations use the public good-size extent. Singleton
   blocks also apply the OS allocation rounding, which is coarser than the
   page-size rounding returned by mi_good_size above the large class range.
   This is a request-derived bound, independent of either observed client. */
static size_t allocation_capacity_upper(size_t size) {
  const size_t good = mi_good_size(size);
  if (good <= 512 * KiB) { return good; }
  const size_t alignment = good < 2 * MiB ? 64 * KiB
      : good < 8 * MiB ? 256 * KiB
      : good < 32 * MiB ? MiB : 4 * MiB;
  if (good >= SIZE_MAX - alignment) { return good; }
  return (good + alignment - 1) & ~(alignment - 1);
}

/* Aligned allocation can select an already aligned free block or allocate
   max(size,16)+alignment-1 bytes and adjust within that block. Record the
   request and its capacity bound, without equating random block placement.
   `distinct` checks concurrently live clients where the caller has them. */
static void note_request(const char* key, const void* p, size_t size,
                         size_t alignment, size_t offset, bool distinct) {
  note(key, p);
  if (!valid_domain) { return; }
  char contract_key[128];
  snprintf(contract_key, sizeof contract_key, "%s.contract", key);
  const size_t oversize = (size < 16 ? 16 : size) + alignment - 1;
  line(contract_key, "requested:%zu,alignment:%zu,offset:%zu,upper:%zu,success:%d,aligned:%d,distinct:%d",
       size, alignment, offset, allocation_capacity_upper(oversize), p != NULL,
       p != NULL && (((uintptr_t)p + offset) & (alignment - 1)) == 0, distinct);
}

static void note_errno(const char* key) {
  char name[128];
  snprintf(name, sizeof name, "%s.errno", key);
  line(name, "%d", errno);
}

static void fill(void* p, size_t size, unsigned char seed) {
  unsigned char* bytes = (unsigned char*)p;
  for (size_t i = 0; i < size; i++) { bytes[i] = (unsigned char)(seed + i * 7); }
}

static bool has_fill(const void* p, size_t size, unsigned char seed) {
  const unsigned char* bytes = (const unsigned char*)p;
  for (size_t i = 0; i < size; i++) {
    if (bytes[i] != (unsigned char)(seed + i * 7)) { return false; }
  }
  return true;
}

static bool is_zero(const void* p, size_t size) {
  const unsigned char* bytes = (const unsigned char*)p;
  for (size_t i = 0; i < size; i++) {
    if (bytes[i] != 0) { return false; }
  }
  return true;
}

/* Private clients check the requested extent, retaining the raw allocation
   observation. Never write the extent if the allocator reports it too small. */
static void note_client_request(const char* key, void* p, size_t size,
                                size_t alignment, size_t offset, bool zero) {
  if (!valid_domain) { note(key, p); return; }
  note_request(key, p, size, alignment, offset, true);
  char payload_key[128];
  snprintf(payload_key, sizeof payload_key, "%s.payload", key);
  bool correct = p != NULL && mi_usable_size(p) >= size;
  if (correct && zero) { correct = is_zero(p, size); }
  if (correct && !zero) { fill(p, size, 0x47); correct = has_fill(p, size, 0x47); }
  line(payload_key, "%d", correct);
}

static void note_plain_request(const char* key, void* p, size_t size, bool zero) {
  note_client_request(key, p, size, size <= 8 ? 8 : 16, 0, zero);
  if (valid_domain) {
    char context[128];
    snprintf(context, sizeof context, "%s.natural", key);
    line(context, "%zu", allocation_capacity_upper(size));
  }
}

static void note_text_request(const char* key, const void* p, const void* expected, size_t size) {
  if (!valid_domain) { note(key, p); return; }
  note_request(key, p, size, size <= 8 ? 8 : 16, 0, true);
  char payload_key[128];
  snprintf(payload_key, sizeof payload_key, "%s.payload", key);
  line(payload_key, "%d", p != NULL && mi_usable_size(p) >= size && memcmp(p, expected, size) == 0);
}

/* These clients use the default heap. Ordinary realloc delegates through a
   word alignment and keeps the floor-half extent; aligned realloc keeps the
   ceil-half extent only when the old pointer meets the requested alignment. */
static void note_realloc_request(const char* key, void* p, uintptr_t old,
                                 size_t old_size, size_t size, size_t alignment,
                                 size_t offset, size_t keep, unsigned char seed,
                                 bool zero, bool dynamic) {
  if (!valid_domain) { note(key, p); return; }
  int old_id = -1;
  for (int i = id_count - 1; i >= 0; i--) {
    if (id_address[i] == old) { old_id = i; break; }
  }
  note(key, p);
  const size_t half = alignment <= sizeof(uintptr_t) && offset == 0
      ? old_size / 2 : old_size - old_size / 2;
  const bool reuse = old != 0 && size > 0 && size <= old_size && size >= half
      && ((old + offset) & (alignment - 1)) == 0;
  size_t upper = allocation_capacity_upper((size < 16 ? 16 : size) + alignment - 1);
  if (reuse && upper < old_size) { upper = old_size; }
  char context[128];
  snprintf(context, sizeof context, "%s.contract", key);
  line(context, "requested:%zu,alignment:%zu,offset:%zu,upper:%zu,success:%d,aligned:%d,distinct:1",
       size, alignment, offset, upper, p != NULL,
       p != NULL && (((uintptr_t)p + offset) & (alignment - 1)) == 0);
  snprintf(context, sizeof context, "%s.realloc", key);
  const size_t copy = size < old_size ? size : old_size;
  line(context, "old:%zu,old_id:%d,dynamic:%d,identity:%d,payload:%d,zero:%d",
       old_size, old_id, dynamic, p != NULL && (((uintptr_t)p == old) == reuse),
       p != NULL && mi_usable_size(p) >= keep && has_fill(p, keep, seed),
       !zero || reuse || (p != NULL && mi_usable_size(p) >= copy
           && is_zero((char*)p + copy, mi_usable_size(p) - copy)));
}

static void key_name(char* out, size_t out_size, const char* prefix, size_t a, size_t b) {
  snprintf(out, out_size, "%s.%zu.%zu", prefix, a, b);
}

/* Request sizes at every small/medium/large class edge and the huge
   (singleton) range. */
static const size_t class_sizes[] = {
  0, 1, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 40, 48, 56, 63, 64, 65, 80, 96, 112, 127, 128, 129,
  160, 192, 224, 255, 256, 257, 320, 384, 448, 511, 512, 513, 640, 768, 896, 1023, 1024, 1025,
  1280, 2048, 2049, 4095, 4096, 4097, 8192, 10239, 10240, 10241, 16384, 32768, 65535, 65536,
  65537, 86016, 86017, 131072, 262144, 524287, 524288, 524289, 1048576, 2097152, 4194304,
  4194305, 8388608, 16777216, 67108872,
};
#define CLASS_SIZE_COUNT (sizeof class_sizes / sizeof class_sizes[0])

static void section_allocation(void) {
  char key[96];
  void* blocks[CLASS_SIZE_COUNT];
  for (size_t i = 0; i < CLASS_SIZE_COUNT; i++) {
    key_name(key, sizeof key, "malloc", i, class_sizes[i]);
    errno = 0;
    blocks[i] = mi_malloc(class_sizes[i]);
    bool distinct = true;
    if (valid_domain) {
      for (size_t j = 0; j < i; j++) { distinct &= blocks[i] != blocks[j]; }
    }
    note_request(key, blocks[i], class_sizes[i], class_sizes[i] <= 8 ? 8 : 16, 0, distinct);
    if (valid_domain) {
      char context[128]; snprintf(context, sizeof context, "%s.natural", key);
      line(context, "%zu", allocation_capacity_upper(class_sizes[i]));
    }
    if (blocks[i] != NULL) { fill(blocks[i], mi_usable_size(blocks[i]), (unsigned char)i); }
  }
  for (size_t i = 0; i < CLASS_SIZE_COUNT; i++) {
    key_name(key, sizeof key, "malloc.keep", i, class_sizes[i]);
    line(key, "%d", blocks[i] != NULL && has_fill(blocks[i], mi_usable_size(blocks[i]), (unsigned char)i));
    mi_free(blocks[i]);
  }
  /* A freed block's garbage must not leak through zeroing entries. */
  for (size_t i = 0; i < CLASS_SIZE_COUNT; i++) {
    key_name(key, sizeof key, "zalloc", i, class_sizes[i]);
    void* p = mi_zalloc(class_sizes[i]);
    note_request(key, p, class_sizes[i], class_sizes[i] <= 8 ? 8 : 16, 0, true);
    if (valid_domain) {
      char context[128]; snprintf(context, sizeof context, "%s.natural", key);
      line(context, "%zu", allocation_capacity_upper(class_sizes[i]));
    }
    key_name(key, sizeof key, "zalloc.zero", i, class_sizes[i]);
    line(key, "%d", p != NULL && is_zero(p, mi_usable_size(p)));
    if (p != NULL) { fill(p, mi_usable_size(p), 0x5a); }
    mi_free(p);
    key_name(key, sizeof key, "calloc", i, class_sizes[i]);
    p = mi_calloc(1, class_sizes[i]);
    note_request(key, p, class_sizes[i], class_sizes[i] <= 8 ? 8 : 16, 0, true);
    if (valid_domain) {
      char context[128]; snprintf(context, sizeof context, "%s.natural", key);
      line(context, "%zu", allocation_capacity_upper(class_sizes[i]));
    }
    key_name(key, sizeof key, "calloc.zero", i, class_sizes[i]);
    line(key, "%d", p != NULL && is_zero(p, mi_usable_size(p)));
    mi_free(p);
  }
  errno = 0;
  note("calloc.overflow", mi_calloc(SIZE_MAX / 2, 3));
  note_errno("calloc.overflow");
  errno = 0;
  note("mallocn.overflow", mi_mallocn(SIZE_MAX / 4, 8));
  note_errno("mallocn.overflow");
  void* p = mi_calloc(0, 1000);
  note_plain_request("calloc.zero_count", p, 0, true);
  mi_free(p);
  p = mi_mallocn(3, 40);
  note_plain_request("mallocn.3x40", p, 120, false);
  mi_free(p);
  errno = 0;
  note("malloc.too_large", mi_malloc((size_t)PTRDIFF_MAX + 1));
  note_errno("malloc.too_large");
  errno = 0;
  note("zalloc.too_large", mi_zalloc(SIZE_MAX));
  note_errno("zalloc.too_large");
  for (size_t size = 0; size <= MI_SMALL_SIZE_MAX; size += 120) {
    key_name(key, sizeof key, "malloc_small", size, 0);
    p = mi_malloc_small(size);
    note_plain_request(key, p, size, false);
    mi_free(p);
    key_name(key, sizeof key, "zalloc_small", size, 0);
    p = mi_zalloc_small(size);
    note_plain_request(key, p, size, true);
    key_name(key, sizeof key, "zalloc_small.zero", size, 0);
    line(key, "%d", p != NULL && is_zero(p, mi_usable_size(p)));
    mi_free(p);
  }
  static const size_t u_sizes[] = { 0, 1, 100, 1024, 5000, 70000, 600000, 5 * MiB };
  for (size_t i = 0; i < sizeof u_sizes / sizeof u_sizes[0]; i++) {
    size_t block_size = 12345;
    key_name(key, sizeof key, "umalloc", i, u_sizes[i]);
    p = mi_umalloc(u_sizes[i], &block_size);
    note_plain_request(key, p, u_sizes[i], false);
    key_name(key, sizeof key, "umalloc.block", i, u_sizes[i]);
    line(key, "%zu", block_size);
    size_t freed = 777;
    mi_ufree(p, &freed);
    key_name(key, sizeof key, "ufree.block", i, u_sizes[i]);
    line(key, "%zu", freed);
    block_size = 12345;
    key_name(key, sizeof key, "ucalloc", i, u_sizes[i]);
    p = mi_ucalloc(2, u_sizes[i] / 2, &block_size);
    note_plain_request(key, p, 2 * (u_sizes[i] / 2), true);
    key_name(key, sizeof key, "ucalloc.block", i, u_sizes[i]);
    line(key, "%zu,%d", block_size, p != NULL && is_zero(p, mi_usable_size(p)));
    mi_free(p);
    if (u_sizes[i] <= MI_SMALL_SIZE_MAX) {
      block_size = 12345;
      key_name(key, sizeof key, "umalloc_small", i, u_sizes[i]);
      p = mi_umalloc_small(u_sizes[i], &block_size);
      note_plain_request(key, p, u_sizes[i], false);
      key_name(key, sizeof key, "umalloc_small.block", i, u_sizes[i]);
      line(key, "%zu", block_size);
      mi_free(p);
      block_size = 12345;
      key_name(key, sizeof key, "uzalloc_small", i, u_sizes[i]);
      p = mi_uzalloc_small(u_sizes[i], &block_size);
      note_plain_request(key, p, u_sizes[i], true);
      key_name(key, sizeof key, "uzalloc_small.block", i, u_sizes[i]);
      line(key, "%zu,%d", block_size, p != NULL && is_zero(p, mi_usable_size(p)));
      mi_free(p);
    }
  }
  size_t freed = 777;
  mi_ufree(NULL, &freed);
  line("ufree.null", "%zu", freed);
  p = mi_new(100);
  note_plain_request("new.100", p, 100, false);
  mi_free(p);
  p = mi_new_n(10, 10);
  note_plain_request("new_n.10x10", p, 100, false);
  mi_free(p);
  errno = 0;
  note("new_nothrow.too_large", mi_new_nothrow(SIZE_MAX / 2));
  note_errno("new_nothrow.too_large");
  p = mi_new_nothrow(64);
  note_plain_request("new_nothrow.64", p, 64, false);
  mi_free(p);
}

static void section_good_size(void) {
  char key[96];
  for (size_t i = 0; i < CLASS_SIZE_COUNT; i++) {
    key_name(key, sizeof key, "good_size", i, class_sizes[i]);
    line(key, "%zu,%zu", mi_good_size(class_sizes[i]), mi_malloc_good_size(class_sizes[i]));
  }
  line("good_size.max", "%zu", mi_good_size((size_t)PTRDIFF_MAX));
  line("good_size.above_max", "%zu", mi_good_size((size_t)PTRDIFF_MAX + 1));
  line("good_size.size_max", "%zu", mi_good_size(SIZE_MAX));
}

static void section_free(void) {
  mi_free(NULL);
  line("free.null", "1");
  line("cfree.null", "%d", mi_cfree(NULL));
  int on_stack = 0;
  if (!valid_domain) {
    line("cfree.invalid_low", "%d", mi_cfree((void*)(uintptr_t)0x0000000003990080));
    line("cfree.stack", "%d", mi_cfree(&on_stack));
  }
  void* p = mi_malloc(48);
  note_plain_request("cfree.block", p, 48, false);
  line("cfree.valid", "%d", mi_cfree(p));
  p = mi_malloc(48);
  note_plain_request("cfree.block.again", p, 48, false);
  mi_free_size(p, 48);
  p = mi_malloc_small(64);
  note_plain_request("free_small.block", p, 64, false);
  mi_free_small(p);
  p = mi_malloc_aligned(100, 64);
  note_client_request("free_aligned.block", p, 100, 64, 0, false);
  mi_free_aligned(p, 64);
  p = mi_malloc_aligned(100, 64);
  note_client_request("free_size_aligned.block", p, 100, 64, 0, false);
  mi_free_size_aligned(p, 100, 64);
  line("usable_size.null", "%zu", mi_usable_size(NULL));
  if (!valid_domain) { line("check_owned.stack", "%d", mi_check_owned(&on_stack)); }
  line("check_owned.null", "%d", mi_check_owned(NULL));
  p = mi_malloc(200);
  line("check_owned.block", "%d", mi_check_owned(p));
  line("check_owned.interior", "%d", mi_check_owned((char*)p + 100));
  mi_free(p);
  line("is_redirected", "%d", mi_is_redirected());
}

static void section_realloc(void) {
  char key[96];
  errno = 0;
  void* p = mi_realloc(NULL, 4);
  note_plain_request("realloc.null", p, 4, false);
  note_errno("realloc.null");
  mi_free(p);
  p = mi_realloc(NULL, 0);
  note_plain_request("realloc.null_zero", p, 0, false);
  line("realloc.null_zero.byte", "%d", p == NULL ? -1 : ((unsigned char*)p)[0]);
  mi_free(p);
  p = mi_malloc(4);
  note_plain_request("realloc.sized_zero.source", p, 4, false);
  fill(p, 4, 9);
  const uintptr_t old_zero = (uintptr_t)p;
  const size_t old_zero_size = valid_domain ? mi_usable_size(p) : 0;
  p = mi_realloc(p, 0);
  note_realloc_request("realloc.sized_zero", p, old_zero, old_zero_size, 0, 8, 0, 0, 9, false, false);
  line("realloc.sized_zero.byte", "%d", p == NULL ? -1 : ((unsigned char*)p)[0]);
  mi_free(p);
  static const size_t sources[] = { 1, 24, 100, 1000, 5000, 20000, 100000, 600000, 5 * MiB };
  for (size_t s = 0; s < sizeof sources / sizeof sources[0]; s++) {
    void* source = mi_malloc(sources[s]);
    key_name(key, sizeof key, "realloc.source", s, sources[s]);
    note_plain_request(key, source, sources[s], false);
    const size_t usable = mi_usable_size(source);
    size_t initialized = 0;
    const size_t targets[] = { usable, usable / 2 + usable % 2, usable / 2, usable / 2 - (usable > 1), usable + 1, usable * 3 };
    for (size_t t = 0; t < sizeof targets / sizeof targets[0]; t++) {
      const size_t current = mi_usable_size(source);
      initialized = current;
      fill(source, current, (unsigned char)(s * 16 + t));
      const size_t keep = targets[t] < current ? targets[t] : current;
      errno = 0;
      const uintptr_t old = (uintptr_t)source;
      void* q = mi_realloc(source, targets[t]);
      key_name(key, sizeof key, "realloc", s, t);
      note_realloc_request(key, q, old, current, targets[t], 8, 0, keep,
                           (unsigned char)(s * 16 + t), false, true);
      key_name(key, sizeof key, "realloc.kept", s, t);
      line(key, "%d", q != NULL && has_fill(q, keep, (unsigned char)(s * 16 + t)));
      if (q != NULL) { source = q; }
    }
    /* Pinned-C `mi_urealloc` reports the pre and post page block sizes. */
    size_t pre = 1, post = 1;
    const uintptr_t old_urealloc = (uintptr_t)source;
    const size_t old_usable = valid_domain ? mi_usable_size(source) : 0;
    void* q = mi_urealloc(source, sources[s] * 2 + 1, &pre, &post);
    key_name(key, sizeof key, "urealloc", s, sources[s]);
    const size_t kept = initialized < sources[s] * 2 + 1 ? initialized : sources[s] * 2 + 1;
    note_realloc_request(key, q, old_urealloc, old_usable, sources[s] * 2 + 1, 8, 0, kept,
                         (unsigned char)(s * 16 + 5), false, false);
    key_name(key, sizeof key, "urealloc.sizes", s, sources[s]);
    line(key, "%zu,%zu", pre, post);
    if (q != NULL) { source = q; }
    const size_t grow = mi_usable_size(source);
    fill(source, grow, 0x33);
    const uintptr_t old_rezalloc = (uintptr_t)source;
    q = mi_rezalloc(source, grow * 2 + 17);
    key_name(key, sizeof key, "rezalloc", s, sources[s]);
    note_realloc_request(key, q, old_rezalloc, grow, grow * 2 + 17, 8, 0, grow, 0x33, true, true);
    key_name(key, sizeof key, "rezalloc.content", s, sources[s]);
    line(key, "%d,%d", q != NULL && has_fill(q, grow, 0x33),
         q != NULL && is_zero((char*)q + grow, mi_usable_size(q) - grow));
    if (q != NULL) { source = q; }
    const size_t before = mi_usable_size(source);
    key_name(key, sizeof key, "expand.fit", s, sources[s]);
    line(key, "%d", mi_expand(source, before) == source);
    key_name(key, sizeof key, "expand.shrink", s, sources[s]);
    line(key, "%d", mi_expand(source, 1) == source);
    errno = 0;
    key_name(key, sizeof key, "expand.grow", s, sources[s]);
    line(key, "%d", mi_expand(source, before + 1) == NULL);
    note_errno(key);
    errno = 0;
    key_name(key, sizeof key, "_expand.grow", s, sources[s]);
    line(key, "%d", mi__expand(source, before + 1) == NULL);
    note_errno(key);
    mi_free(source);
  }
  line("expand.null", "%d", mi_expand(NULL, 10) == NULL);
  size_t pre = 1, post = 1;
  p = mi_urealloc(NULL, 50, &pre, &post);
  note_plain_request("urealloc.null", p, 50, false);
  line("urealloc.null.sizes", "%zu,%zu", pre, post);
  mi_free(p);

  p = mi_malloc(64);
  if (valid_domain) { note_plain_request("reallocn.source", p, 64, false); }
  fill(p, 64, 1);
  errno = 0;
  void* q = mi_realloc(p, (size_t)PTRDIFF_MAX + 1);
  note("realloc.too_large", q);
  note_errno("realloc.too_large");
  line("realloc.too_large.kept", "%d", has_fill(p, 64, 1));
  errno = 0;
  q = mi_reallocn(p, SIZE_MAX / 2, 4);
  note("reallocn.overflow", q);
  note_errno("reallocn.overflow");
  line("reallocn.overflow.kept", "%d", has_fill(p, 64, 1));
  uintptr_t old_client = (uintptr_t)p;
  size_t old_client_size = valid_domain ? mi_usable_size(p) : 0;
  q = mi_reallocn(p, 10, 20);
  note_realloc_request("reallocn.10x20", q, old_client, old_client_size, 200, 8, 0, 64, 1, false, false);
  line("reallocn.10x20.kept", "%d", q != NULL && has_fill(q, 64, 1));
  p = q;
  errno = 0;
  q = mi_reallocf(p, (size_t)PTRDIFF_MAX + 1);
  note("reallocf.too_large", q);
  note_errno("reallocf.too_large");
  /* The source freed `p`; a same-size request reuses its block. */
  note_plain_request("reallocf.reuse_probe", mi_malloc(200), 200, false);
  p = mi_reallocf(NULL, 30);
  note_plain_request("reallocf.null", p, 30, false);
  mi_free(p);

  errno = 0;
  p = mi_reallocarray(NULL, 0, 16);
  note_plain_request("reallocarray.null_zero", p, 0, false);
  note_errno("reallocarray.null_zero");
  errno = 0;
  q = mi_reallocarray(p, SIZE_MAX / 2, 3);
  note("reallocarray.overflow", q);
  note_errno("reallocarray.overflow");
  errno = 0;
  q = mi_reallocarray(p, (size_t)PTRDIFF_MAX / 2 + 1, 2);
  note("reallocarray.too_large", q);
  note_errno("reallocarray.too_large");
  old_client = (uintptr_t)p;
  old_client_size = valid_domain ? mi_usable_size(p) : 0;
  q = mi_reallocarray(p, 7, 9);
  note_realloc_request("reallocarray.7x9", q, old_client, old_client_size, 63, 8, 0, 0, 0, false, false);
  p = q;
  if (!valid_domain) {
    errno = 0;
    line("reallocarr.null_pointer", "%d", mi_reallocarr(NULL, 1, 1));
    note_errno("reallocarr.null_pointer");
    errno = 0;
    line("reallocarr.zero_size", "%d", mi_reallocarr(&p, 1, 0));
    note_errno("reallocarr.zero_size");
  }
  errno = 0;
  line("reallocarr.overflow", "%d", mi_reallocarr(&p, SIZE_MAX / 2, 3));
  note_errno("reallocarr.overflow");
  errno = 0;
  line("reallocarr.too_large", "%d", mi_reallocarr(&p, (size_t)PTRDIFF_MAX / 2 + 1, 2));
  note_errno("reallocarr.too_large");
  if (valid_domain) { fill(p, mi_usable_size(p), 0x58); }
  old_client = (uintptr_t)p;
  old_client_size = valid_domain ? mi_usable_size(p) : 0;
  line("reallocarr.grow", "%d", mi_reallocarr(&p, 20, 20));
  note_realloc_request("reallocarr.grow.block", p, old_client, old_client_size, 400, 8, 0, old_client_size, 0x58, false, false);
  const int zero_count = mi_reallocarr(&p, 0, 8);
  line("reallocarr.zero_count", "%d,%d", zero_count, p == NULL);
  void* none = NULL;
  line("reallocarr.from_null", "%d", mi_reallocarr(&none, 3, 5));
  note_plain_request("reallocarr.from_null.block", none, 15, false);
  mi_free(none);

  p = mi_recalloc(NULL, 5, 7);
  note_plain_request("recalloc.null", p, 35, true);
  line("recalloc.null.zero", "%d", p != NULL && is_zero(p, mi_usable_size(p)));
  fill(p, 35, 3);
  old_client = (uintptr_t)p;
  old_client_size = valid_domain ? mi_usable_size(p) : 0;
  q = mi_recalloc(p, 50, 7);
  note_realloc_request("recalloc.grow", q, old_client, old_client_size, 350, 8, 0, 35, 3, true, false);
  line("recalloc.grow.content", "%d,%d", q != NULL && has_fill(q, 35, 3),
       q != NULL && is_zero((char*)q + 40, mi_usable_size(q) - 40));
  if (q != NULL) { p = q; }
  errno = 0;
  q = mi_recalloc(p, SIZE_MAX / 2, 5);
  note("recalloc.overflow", q);
  note_errno("recalloc.overflow");
  mi_free(p);
  p = mi_rezalloc(NULL, 90);
  note_plain_request("rezalloc.null", p, 90, true);
  line("rezalloc.null.zero", "%d", p != NULL && is_zero(p, mi_usable_size(p)));
  mi_free(p);
  p = mi_malloc(40);
  if (valid_domain) { note_plain_request("new_realloc.source", p, 40, false); fill(p, 40, 0x58); }
  old_client = (uintptr_t)p;
  old_client_size = valid_domain ? mi_usable_size(p) : 0;
  q = mi_new_realloc(p, 400);
  note_realloc_request("new_realloc", q, old_client, old_client_size, 400, 8, 0, 40, 0x58, false, false);
  old_client = (uintptr_t)q;
  old_client_size = valid_domain ? mi_usable_size(q) : 0;
  q = mi_new_reallocn(q, 30, 30);
  note_realloc_request("new_reallocn", q, old_client, old_client_size, 900, 8, 0, 40, 0x58, false, false);
  mi_free(q);
  /* issue #1304: the source's zero-to-64 KiB realloc ladder */
  void* shared = NULL;
  bool ladder_identity = true;
  for (int iteration = 0; iteration < 4; iteration++) {
    for (int i = 0; i < 1024; i++) {
      const size_t request = (size_t)i * 64;
      if (!valid_domain) { shared = mi_realloc(shared, request); continue; }
      const uintptr_t previous = (uintptr_t)shared;
      const size_t extent = mi_usable_size(shared);
      shared = mi_realloc(shared, request);
      if (valid_domain) {
        const bool reuse = previous != 0 && request > 0 && request <= extent && request >= extent / 2;
        ladder_identity &= shared != NULL && (((uintptr_t)shared == previous) == reuse);
      }
    }
  }
  note_plain_request("realloc.ladder", shared, 1023 * 64, false);
  if (valid_domain) { line("realloc.ladder.identity", "%d", ladder_identity); }
  mi_free(shared);
}

static void section_aligned(void) {
  char key[96];
  static const size_t sizes[] = { 0, 1, 8, 48, 100, 512, 4097, 70000, 1 * MiB, 5 * MiB };
  for (size_t shift = 0; shift <= 27; shift++) {
    const size_t alignment = (size_t)1 << shift;
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
      if (alignment > 64 * KiB && sizes[s] > 1 * MiB) { continue; }
      key_name(key, sizeof key, "malloc_aligned", shift, s);
      errno = 0;
      void* p = mi_malloc_aligned(sizes[s], alignment);
      note_request(key, p, sizes[s], alignment, 0, true);
      key_name(key, sizeof key, "malloc_aligned.ok", shift, s);
      line(key, "%d,%d", p != NULL && ((uintptr_t)p % alignment) == 0, errno);
      if (p != NULL) { fill(p, sizes[s], 0x44); }
      key_name(key, sizeof key, "zalloc_aligned", shift, s);
      void* z = mi_zalloc_aligned(sizes[s], alignment);
      note_request(key, z, sizes[s], alignment, 0, z != p);
      key_name(key, sizeof key, "zalloc_aligned.ok", shift, s);
      line(key, "%d,%d", z != NULL && ((uintptr_t)z % alignment) == 0,
           z != NULL && is_zero(z, mi_usable_size(z)));
      mi_free(z);
      mi_free(p);
    }
  }
  static const size_t offsets[] = { 0, 1, 7, 8, 16, 100, 4096 };
  for (size_t shift = 3; shift <= 17; shift += 2) {
    const size_t alignment = (size_t)1 << shift;
    for (size_t o = 0; o < sizeof offsets / sizeof offsets[0]; o++) {
      if (valid_domain && alignment > 64 * KiB && offsets[o] != 0) { continue; }
      key_name(key, sizeof key, "malloc_aligned_at", shift, o);
      errno = 0;
      void* p = mi_malloc_aligned_at(50, alignment, offsets[o]);
      note_request(key, p, 50, alignment, offsets[o], true);
      key_name(key, sizeof key, "malloc_aligned_at.ok", shift, o);
      line(key, "%d,%d", p != NULL && (((uintptr_t)p + offsets[o]) % alignment) == 0, errno);
      key_name(key, sizeof key, "zalloc_aligned_at", shift, o);
      void* z = mi_zalloc_aligned_at(3000, alignment, offsets[o]);
      note_request(key, z, 3000, alignment, offsets[o], z != p);
      key_name(key, sizeof key, "zalloc_aligned_at.ok", shift, o);
      line(key, "%d", z != NULL && (((uintptr_t)z + offsets[o]) % alignment) == 0 && is_zero(z, mi_usable_size(z)));
      key_name(key, sizeof key, "calloc_aligned_at", shift, o);
      void* c = mi_calloc_aligned_at(3, 70, alignment, offsets[o]);
      note_request(key, c, 210, alignment, offsets[o], c != p && c != z);
      if (valid_domain) {
        key_name(key, sizeof key, "calloc_aligned_at.zero", shift, o);
        line(key, "%d", c != NULL && is_zero(c, mi_usable_size(c)));
      }
      mi_free(c);
      mi_free(z);
      mi_free(p);
    }
  }
  if (!valid_domain) {
  errno = 0;
  note("malloc_aligned.bad_alignment", mi_malloc_aligned(32, 3));
  note_errno("malloc_aligned.bad_alignment");
  errno = 0;
  note("malloc_aligned.zero_alignment", mi_malloc_aligned(32, 0));
  note_errno("malloc_aligned.zero_alignment");
  }
  errno = 0;
  note("malloc_aligned.too_large", mi_malloc_aligned((size_t)PTRDIFF_MAX, 64));
  note_errno("malloc_aligned.too_large");
  if (!valid_domain) {
  errno = 0;
  note("malloc_aligned_at.huge_offset", mi_malloc_aligned_at(100, 1 * MiB, 8));
  note_errno("malloc_aligned_at.huge_offset");
  }
  errno = 0;
  note("malloc_aligned.meta_alignment", mi_malloc_aligned(100, 256 * MiB));
  note_errno("malloc_aligned.meta_alignment");
  errno = 0;
  note("calloc_aligned.overflow", mi_calloc_aligned(SIZE_MAX / 2, 3, 64));
  note_errno("calloc_aligned.overflow");
  void* p = mi_calloc_aligned(10, 10, 128);
  note_client_request("calloc_aligned.10x10", p, 100, 128, 0, true);
  line("calloc_aligned.10x10.zero", "%d", p != NULL && is_zero(p, 100));
  mi_free(p);
  size_t block_size = 1;
  p = mi_umalloc_aligned(100, 256, &block_size);
  note_client_request("umalloc_aligned", p, 100, 256, 0, false);
  line("umalloc_aligned.block", "%zu", block_size);
  mi_free(p);
  block_size = 1;
  p = mi_uzalloc_aligned(3000, 4096, &block_size);
  note_client_request("uzalloc_aligned", p, 3000, 4096, 0, true);
  line("uzalloc_aligned.block", "%zu,%d", block_size, p != NULL && is_zero(p, 3000));
  mi_free(p);

  /* Aligned reallocation: reuse at the ceil-half boundary, replacement,
     copy, and tail zeroing. */
  static const size_t realign[] = { 8, 16, 64, 4096, 64 * KiB, 1 * MiB };
  for (size_t a = 0; a < sizeof realign / sizeof realign[0]; a++) {
    const size_t alignment = realign[a];
    void* source = mi_malloc_aligned(300, alignment);
    key_name(key, sizeof key, "realloc_aligned.source", a, alignment);
    note_client_request(key, source, 300, alignment, 0, false);
    const size_t usable = mi_usable_size(source);
    const size_t targets[] = { usable, usable - usable / 2, usable - usable / 2 - 1, usable + 1, 5000 };
    for (size_t t = 0; t < sizeof targets / sizeof targets[0]; t++) {
      const size_t current = mi_usable_size(source) < 300 ? mi_usable_size(source) : 300;
      fill(source, current, (unsigned char)(a + t));
      const size_t keep = targets[t] < current ? targets[t] : current;
      const uintptr_t old = (uintptr_t)source;
      const size_t old_size = valid_domain ? mi_usable_size(source) : 0;
      void* q = mi_realloc_aligned(source, targets[t], alignment);
      key_name(key, sizeof key, "realloc_aligned", a, t);
      note_realloc_request(key, q, old, old_size, targets[t], alignment, 0, keep,
                           (unsigned char)(a + t), false, true);
      key_name(key, sizeof key, "realloc_aligned.ok", a, t);
      line(key, "%d,%d", q != NULL && ((uintptr_t)q % alignment) == 0,
           q != NULL && has_fill(q, keep, (unsigned char)(a + t)));
      if (q != NULL) { source = q; }
    }
    const size_t grow = mi_usable_size(source);
    fill(source, grow, 0x21);
    const uintptr_t old_rezalloc = (uintptr_t)source;
    void* q = mi_rezalloc_aligned(source, grow * 2 + 3, alignment);
    key_name(key, sizeof key, "rezalloc_aligned", a, alignment);
    note_realloc_request(key, q, old_rezalloc, grow, grow * 2 + 3, alignment, 0, grow, 0x21, true, true);
    key_name(key, sizeof key, "rezalloc_aligned.content", a, alignment);
    line(key, "%d,%d", q != NULL && has_fill(q, grow, 0x21),
         q != NULL && is_zero((char*)q + grow, mi_usable_size(q) - grow));
    if (q != NULL) { source = q; }
    uintptr_t old_recalloc = (uintptr_t)source;
    size_t old_size = valid_domain ? mi_usable_size(source) : 0;
    q = mi_recalloc_aligned(source, 3, grow * 2, alignment);
    key_name(key, sizeof key, "recalloc_aligned", a, alignment);
    note_realloc_request(key, q, old_recalloc, old_size, grow * 6, alignment, 0, grow, 0x21, true, true);
    if (q != NULL) { source = q; }
    old_recalloc = (uintptr_t)source;
    old_size = valid_domain ? mi_usable_size(source) : 0;
    q = mi_aligned_recalloc(source, 2, grow * 4, alignment);
    key_name(key, sizeof key, "aligned_recalloc", a, alignment);
    note_realloc_request(key, q, old_recalloc, old_size, grow * 8, alignment, 0, grow, 0x21, true, true);
    if (q != NULL) { source = q; }
    mi_free(source);
  }
  for (size_t o = 0; o < sizeof offsets / sizeof offsets[0]; o++) {
    void* source = mi_malloc_aligned_at(90, 256, offsets[o]);
    key_name(key, sizeof key, "realloc_aligned_at.source", o, offsets[o]);
    note_client_request(key, source, 90, 256, offsets[o], false);
    fill(source, 90, 0x61);
    uintptr_t old = (uintptr_t)source;
    size_t old_size = valid_domain ? mi_usable_size(source) : 0;
    void* q = mi_realloc_aligned_at(source, 900, 256, offsets[o]);
    key_name(key, sizeof key, "realloc_aligned_at", o, offsets[o]);
    note_realloc_request(key, q, old, old_size, 900, 256, offsets[o], 90, 0x61, false, false);
    key_name(key, sizeof key, "realloc_aligned_at.ok", o, offsets[o]);
    line(key, "%d,%d", q != NULL && (((uintptr_t)q + offsets[o]) % 256) == 0, q != NULL && has_fill(q, 90, 0x61));
    old = (uintptr_t)q;
    old_size = valid_domain ? mi_usable_size(q) : 0;
    q = mi_rezalloc_aligned_at(q, 1900, 256, offsets[o]);
    key_name(key, sizeof key, "rezalloc_aligned_at", o, offsets[o]);
    note_realloc_request(key, q, old, old_size, 1900, 256, offsets[o], 90, 0x61, true, false);
    key_name(key, sizeof key, "rezalloc_aligned_at.ok", o, offsets[o]);
    /* A replacement preserves the whole old usable extent, including bytes
       beyond the earlier request. Only its newly added capacity is zeroed;
       padding modes make the old usable extent equal that earlier request. */
    const size_t zero_start = valid_domain ? old_size : 900;
    const size_t zero_end = valid_domain && q != NULL ? mi_usable_size(q) : 1900;
    line(key, "%d,%d", q != NULL && has_fill(q, 90, 0x61),
         q != NULL && zero_end >= zero_start
           && is_zero((char*)q + zero_start, zero_end - zero_start));
    old = (uintptr_t)q;
    old_size = valid_domain ? mi_usable_size(q) : 0;
    q = mi_recalloc_aligned_at(q, 4, 700, 256, offsets[o]);
    key_name(key, sizeof key, "recalloc_aligned_at", o, offsets[o]);
    note_realloc_request(key, q, old, old_size, 2800, 256, offsets[o], 90, 0x61, true, false);
    old = (uintptr_t)q;
    old_size = valid_domain ? mi_usable_size(q) : 0;
    q = mi_aligned_offset_recalloc(q, 5, 700, 256, offsets[o]);
    key_name(key, sizeof key, "aligned_offset_recalloc", o, offsets[o]);
    note_realloc_request(key, q, old, old_size, 3500, 256, offsets[o], 90, 0x61, true, false);
    mi_free(q);
  }
  p = mi_malloc_aligned(100, 64);
  if (valid_domain) { note_client_request("realloc_aligned.word_source", p, 100, 64, 0, false); }
  fill(p, 100, 5);
  errno = 0;
  void* q = mi_realloc_aligned(p, (size_t)PTRDIFF_MAX, 64);
  note("realloc_aligned.too_large", q);
  note_errno("realloc_aligned.too_large");
  line("realloc_aligned.too_large.kept", "%d", has_fill(p, 100, 5));
  if (!valid_domain) {
    errno = 0;
    q = mi_realloc_aligned(p, 200, 24);
    note("realloc_aligned.bad_alignment", q);
    note_errno("realloc_aligned.bad_alignment");
  }
  /* An alignment of at most one word is ordinary realloc, which consumes p. */
  errno = 0;
  const uintptr_t word_old = (uintptr_t)p;
  const size_t word_old_size = valid_domain ? mi_usable_size(p) : 0;
  q = mi_realloc_aligned(p, 200, 3);
  note_realloc_request("realloc_aligned.word_alignment", q, word_old, word_old_size, 200, 8, 0, 100, 5, false, false);
  note_errno("realloc_aligned.word_alignment");
  mi_free(q == NULL ? p : q);
  p = mi_realloc_aligned(NULL, 0, 8);
  note_plain_request("realloc_aligned.null_zero", p, 0, false);
  line("realloc_aligned.null_zero.byte", "%d", p == NULL ? -1 : ((unsigned char*)p)[0]);
  mi_free(p);

  /* alloc-posix.c entries */
  static const size_t posix_alignments[] = { 0, 1, 3, 4, 8, 16, 24, 64, 4096, 1 * MiB };
  static const size_t posix_sizes[] = { 0, 32, 5000, SIZE_MAX };
  for (size_t a = 0; a < sizeof posix_alignments / sizeof posix_alignments[0]; a++) {
    for (size_t s = 0; s < sizeof posix_sizes / sizeof posix_sizes[0]; s++) {
      if (valid_domain && (posix_alignments[a] < sizeof(void*)
          || (posix_alignments[a] & (posix_alignments[a] - 1)) != 0
          || posix_sizes[s] % posix_alignments[a] != 0)) { continue; }
      void* out = &out;
      errno = 0;
      const int result = mi_posix_memalign(&out, posix_alignments[a], posix_sizes[s]);
      key_name(key, sizeof key, "posix_memalign", a, s);
      line(key, "%d,%d,%d", result, out == (void*)&out, errno);
      if (result == 0 && out != (void*)&out) {
        key_name(key, sizeof key, "posix_memalign.block", a, s);
        note_client_request(key, out, posix_sizes[s], posix_alignments[a], 0, false);
        mi_free(out);
      }
      errno = 0;
      p = mi_memalign(posix_alignments[a], posix_sizes[s]);
      key_name(key, sizeof key, "memalign", a, s);
      note_client_request(key, p, posix_sizes[s], posix_alignments[a], 0, false);
      note_errno(key);
      mi_free(p);
      errno = 0;
      p = mi_aligned_alloc(posix_alignments[a], posix_sizes[s]);
      key_name(key, sizeof key, "aligned_alloc", a, s);
      note_client_request(key, p, posix_sizes[s], posix_alignments[a], 0, false);
      note_errno(key);
      mi_free(p);
    }
  }
  if (!valid_domain) { line("posix_memalign.null_out", "%d", mi_posix_memalign(NULL, 16, 16)); }
  static const size_t page_sizes[] = { 0, 1, 4095, 4096, 4097, 100000 };
  for (size_t s = 0; s < sizeof page_sizes / sizeof page_sizes[0]; s++) {
    key_name(key, sizeof key, "valloc", s, page_sizes[s]);
    p = mi_valloc(page_sizes[s]);
    note_client_request(key, p, page_sizes[s], 4096, 0, false);
    mi_free(p);
    key_name(key, sizeof key, "pvalloc", s, page_sizes[s]);
    p = mi_pvalloc(page_sizes[s]);
    note_client_request(key, p, ((page_sizes[s] + 4095) & ~(size_t)4095), 4096, 0, false);
    mi_free(p);
  }
  errno = 0;
  note("pvalloc.overflow", mi_pvalloc(SIZE_MAX - 100));
  note_errno("pvalloc.overflow");
  p = mi_new_aligned(100, 128);
  note_client_request("new_aligned", p, 100, 128, 0, false);
  mi_free(p);
  errno = 0;
  note("new_aligned_nothrow.too_large", mi_new_aligned_nothrow(SIZE_MAX / 2, 64));
  note_errno("new_aligned_nothrow.too_large");
  /* test-api.c zero_aligned_first, here on the initial thread */
  p = mi_malloc_aligned(0, 16);
  note_client_request("malloc_aligned.zero16", p, 0, 16, 0, false);
  mi_free(p);
  /* test-api.c mimalloc-aligned13: every small size and alignment */
  int bad = 0;
  for (size_t size = 1; size <= MI_SMALL_SIZE_MAX * 2; size++) {
    for (size_t alignment = 1; alignment <= size; alignment *= 2) {
      void* ps[10];
      for (int i = 0; i < 10; i++) {
        ps[i] = mi_malloc_aligned(size, alignment);
        if (ps[i] == NULL || ((uintptr_t)ps[i] % alignment) != 0) { bad++; }
      }
      for (int i = 0; i < 10; i++) { mi_free(ps[i]); }
    }
  }
  line("aligned13.bad", "%d", bad);
}

/* Exercise the distinct aligned-at validation and word-sized aligned-realloc
   delegation while observing the original block after rejected replacements. */
static void section_aligned_preservation(void) {
  const size_t alignment = 64;
  const size_t offset = 7;
  unsigned char* p = (unsigned char*)mi_malloc_aligned_at(73, alignment, offset);
  line("aligned_preservation.source", "%d", p != NULL &&
       (((uintptr_t)p + offset) & (alignment - 1)) == 0);
  if (p == NULL) { return; }
  const size_t usable = mi_usable_size(p);
  line("aligned_preservation.usable", "%zu", usable);
  fill(p, usable, 0x43);

  errno = 0;
  void* failed = mi_realloc_aligned_at(p, SIZE_MAX, alignment, offset);
  line("aligned_preservation.oversize", "%d,%d,%d,%d", failed == NULL, errno,
       mi_usable_size(p) == usable, has_fill(p, usable, 0x43));
  if (!valid_domain) {
    errno = 0;
    failed = mi_realloc_aligned_at(p, 150, 3, offset);
    line("aligned_preservation.bad_offset_alignment", "%d,%d,%d,%d", failed == NULL, errno,
         mi_usable_size(p) == usable, has_fill(p, usable, 0x43));
  }

  const size_t half = usable - usable / 2;
  void* reused = mi_realloc_aligned_at(p, half, alignment, offset);
  line("aligned_preservation.reuse", "%d,%d", reused == p,
       reused != NULL && has_fill(reused, half, 0x43));
  if (reused == NULL) { mi_free(p); return; }
  void* replacement = mi_realloc_aligned_at(reused, half - 1, alignment, offset);
  line("aligned_preservation.replace", "%d,%d,%d", replacement != NULL && replacement != reused,
       replacement != NULL && (((uintptr_t)replacement + offset) & (alignment - 1)) == 0,
       replacement != NULL && has_fill(replacement, half - 1, 0x43));
  mi_free(replacement == NULL ? reused : replacement);

  p = (unsigned char*)mi_malloc(40);
  line("aligned_preservation.word_source", "%d", p != NULL);
  if (p == NULL) { return; }
  fill(p, 40, 0x59);
  errno = 0;
  void* q = mi_realloc_aligned(p, 200, 3);
  line("aligned_preservation.word_delegate", "%d,%d,%d", q != NULL, errno,
       q != NULL && has_fill(q, 40, 0x59));
  mi_free(q == NULL ? p : q);
}

/* Observe public allocation contracts without depending on page placement or
   free-list encoding. The same calls apply to statistics and padding modes. */
struct allocation_error_counts {
  size_t overflow;
  size_t memory;
  size_t invalid;
};

static void count_allocation_errors(int error, void* argument) {
  struct allocation_error_counts* counts = (struct allocation_error_counts*)argument;
  if (error == EOVERFLOW) { counts->overflow++; }
  if (error == ENOMEM) { counts->memory++; }
  if (error == EINVAL) { counts->invalid++; }
}

struct allocation_oom_output {
  size_t count;
  size_t size;
};

static void capture_allocation_oom(const char* message, void* argument) {
  struct allocation_oom_output* output = (struct allocation_oom_output*)argument;
  const char* body = strstr(message, "unable to allocate memory (");
  size_t size;
  if (body != NULL && sscanf(body, "unable to allocate memory (%zu bytes)", &size) == 1) {
    output->count++;
    output->size = size;
  }
}

static void unregister_allocation_error(int error, void* argument) {
  count_allocation_errors(error, argument);
  mi_register_error(NULL, NULL);
}

static void note_heap_aligned_failure(const char* key, mi_heap_t* heap, bool direct) {
  const long previous_show = mi_option_get(mi_option_show_errors);
  const long previous_max = mi_option_get(mi_option_max_errors);
  mi_option_set(mi_option_max_errors, LONG_MAX);
  mi_option_set_enabled(mi_option_show_errors, true);
  struct allocation_oom_output output = { 0, SIZE_MAX };
  struct allocation_error_counts counts = { 0 };
  mi_register_output(capture_allocation_oom, &output);
  output = (struct allocation_oom_output){ 0, SIZE_MAX };
  mi_register_error(count_allocation_errors, &counts);
  void* p = direct
    ? mi_theap_malloc_aligned(mi_heap_theap(heap), (size_t)PTRDIFF_MAX - 16, 16)
    : mi_heap_malloc_aligned_at(heap, (size_t)PTRDIFF_MAX - 8, 8, 1);
  line(key, "%d,%zu,%zu,%zu,%zu,%zu", p == NULL, output.count, output.size,
       counts.overflow, counts.memory, counts.invalid);
  mi_register_error(NULL, NULL);
  mi_register_output(NULL, NULL);
  mi_option_set(mi_option_show_errors, previous_show);
  mi_option_set(mi_option_max_errors, previous_max);
}

static bool source_client_error;

static void note_interior_api_modes(mi_heap_t* heap, size_t h) {
  void* p;
  void* q;
  char key[128];
  struct allocation_error_counts counts;
  const long previous_precise = mi_option_get(mi_option_guarded_precise);
  set_live_client_precise(false);
  p = mi_heap_zalloc_aligned_at(heap, 64, 8, 7);
  fill(p, 64, 0x39);
  size_t pre = SIZE_MAX, post = SIZE_MAX;
  counts = (struct allocation_error_counts){ 0 };
  mi_register_error(count_allocation_errors, &counts);
  q = mi_urealloc(p, 129, &pre, &post);
  key_name(key, sizeof key, "api_modes.urealloc_interior", h, 0);
  line(key, "%d,%zu,%zu,%zu,%d", q == NULL, pre, post, counts.invalid,
       q == NULL ? has_fill(p, 64, 0x39) : has_fill(q, 64, 0x39));
  source_client_error |= counts.invalid != 0;
  mi_register_error(NULL, NULL);
  mi_option_set_enabled(mi_option_guarded_precise, true);
  mi_free(q == NULL ? p : q);
  set_live_client_precise(false);
  p = mi_heap_zalloc_aligned_at(heap, 64, 8, 7);
  fill(p, 64, 0x39);
  counts = (struct allocation_error_counts){ 0 };
  mi_register_error(count_allocation_errors, &counts);
  q = mi_heap_rezalloc(heap, p, 129);
  key_name(key, sizeof key, "api_modes.heap_ordinary_interior", h, 0);
  line(key, "%d,%zu,%d", q == NULL, counts.invalid,
       q == NULL ? has_fill(p, 64, 0x39) : has_fill(q, 64, 0x39));
  source_client_error |= counts.invalid != 0;
  mi_register_error(NULL, NULL);
  mi_option_set_enabled(mi_option_guarded_precise, true);
  mi_free(q == NULL ? p : q);
  set_live_client_precise(false);
  p = mi_heap_zalloc_aligned_at(heap, 64, 8, 7);
  counts = (struct allocation_error_counts){ 0 };
  mi_register_error(count_allocation_errors, &counts);
  q = mi_heap_rezalloc_aligned_at(heap, p, 0, 8, 7);
  key_name(key, sizeof key, "api_modes.heap_aligned_zero_interior", h, 0);
  line(key, "%d,%zu,%d", q == p, counts.invalid, q != NULL);
  const bool old_retained = q != NULL && q != p && counts.invalid > 0;
  source_client_error |= counts.invalid != 0;
  mi_register_error(NULL, NULL);
  mi_option_set_enabled(mi_option_guarded_precise, true);
  mi_free(q == NULL ? p : q);
  if (old_retained) { mi_free(p); }
  mi_option_set(mi_option_guarded_precise, previous_precise);
}

static void section_api_modes(void) {
  static const size_t sizes[] = { 0, 1, 7, 8, 9, 17, 33, 64, 129, 1024, 1025, 4096, 65537, 524288, 524289 };
  static const size_t alignments[] = { 1, 8, 16, 64, 4096, 131072 };
  const size_t limit_requests[] = {
    (size_t)PTRDIFF_MAX - 8, (size_t)PTRDIFF_MAX - 7,
    (size_t)PTRDIFF_MAX - 1, (size_t)PTRDIFF_MAX, (size_t)PTRDIFF_MAX + 1,
  };
  char key[96];
  mi_heap_t* main_heap = mi_heap_main();
  mi_heap_t* auxiliary_heap = mi_heap_new();
  mi_theap_t* previous = mi_theap_set_default(mi_heap_theap(auxiliary_heap));
  mi_heap_t* heaps[] = { main_heap, auxiliary_heap };
  for (size_t h = 0; h < sizeof heaps / sizeof heaps[0]; h++) {
    void* p = mi_heap_malloc(heaps[h], 33);
    const size_t usable = mi_usable_size(p);
    key_name(key, sizeof key, "api_modes.heap_target", h, 0);
    line(key, "%d,%d", p != NULL, p != NULL && mi_heap_of(p) == heaps[h]);
    if (p == NULL) { continue; }
    fill(p, usable, 0x69);
    for (size_t kind = 0; kind < 8; kind++) {
      errno = 0;
      void* failed = NULL;
      switch (kind) {
        case 0: failed = mi_heap_calloc(heaps[h], SIZE_MAX, 2); break;
        case 1: failed = mi_heap_mallocn(heaps[h], SIZE_MAX, 2); break;
        case 2: failed = mi_heap_calloc_aligned(heaps[h], SIZE_MAX, 2, 64); break;
        case 3: failed = mi_heap_calloc_aligned_at(heaps[h], SIZE_MAX, 2, 64, 7); break;
        case 4: failed = mi_heap_reallocn(heaps[h], p, SIZE_MAX, 2); break;
        case 5: failed = mi_heap_recalloc(heaps[h], p, SIZE_MAX, 2); break;
        case 6: failed = mi_heap_recalloc_aligned(heaps[h], p, SIZE_MAX, 2, 64); break;
        case 7: failed = mi_heap_recalloc_aligned_at(heaps[h], p, SIZE_MAX, 2, 64, 7); break;
      }
      key_name(key, sizeof key, "api_modes.heap_count_failure", h, kind);
      line(key, "%d,%d,%d,%d", failed == NULL, errno,
           mi_usable_size(p) == usable, has_fill(p, usable, 0x69));
    }
    void* q = mi_heap_rezalloc(heaps[h], p, usable + 17);
    key_name(key, sizeof key, "api_modes.heap_realloc_target", h, 0);
    line(key, "%d,%d,%d,%d", q != NULL, q != NULL && mi_heap_of(q) == heaps[h],
         q != NULL && has_fill(q, usable, 0x69),
         q != NULL && mi_usable_size(q) >= usable
           && is_zero((char*)q + usable, mi_usable_size(q) - usable));
    mi_free(q == NULL ? p : q);
    p = mi_heap_zalloc_aligned_at(heaps[h], 33, 64, 0);
    key_name(key, sizeof key, "api_modes.heap_aligned_target", h, 0);
    line(key, "%d,%d,%d", p != NULL, p != NULL && mi_heap_of(p) == heaps[h],
         p != NULL && is_zero(p, mi_usable_size(p)));
    q = mi_heap_rezalloc_aligned_at(heaps[h], p, 160, 64, 0);
    key_name(key, sizeof key, "api_modes.heap_aligned_realloc_target", h, 0);
    line(key, "%d,%d,%d", q != NULL, q != NULL && mi_heap_of(q) == heaps[h],
         q != NULL && is_zero(q, mi_usable_size(q)));
    mi_free(q == NULL ? p : q);
    struct allocation_error_counts counts = { 0 };
    mi_register_error(unregister_allocation_error, &counts);
    errno = 0;
    p = mi_heap_malloc_aligned_at(heaps[h], 16, 3, 0);
    key_name(key, sizeof key, "api_modes.heap_alignment_dispatch", h, 0);
    line(key, "%d,%d,%zu,%zu,%zu", p == NULL, errno,
         counts.overflow, counts.memory, counts.invalid);
    mi_register_error(NULL, NULL);
    counts = (struct allocation_error_counts){ 0 };
    mi_register_error(unregister_allocation_error, &counts);
    errno = 0;
    p = mi_heap_calloc(heaps[h], SIZE_MAX, 2);
    key_name(key, sizeof key, "api_modes.heap_count_dispatch", h, 0);
    line(key, "%d,%d,%zu,%zu,%zu", p == NULL, errno,
         counts.overflow, counts.memory, counts.invalid);
    mi_register_error(NULL, NULL);
    key_name(key, sizeof key, "api_modes.heap_aligned_oom", h, 0);
    note_heap_aligned_failure(key, heaps[h], false);
    key_name(key, sizeof key, "api_modes.theap_aligned_oom", h, 0);
    note_heap_aligned_failure(key, heaps[h], true);
    for (size_t r = 0; r < sizeof limit_requests / sizeof limit_requests[0]; r++) {
      counts = (struct allocation_error_counts){ 0 };
      mi_register_error(count_allocation_errors, &counts);
      p = mi_heap_malloc(heaps[h], limit_requests[r]);
      snprintf(key, sizeof key, "api_modes.heap_limit_ordinary.%zu.%zu", h, r);
      line(key, "%d,%zu,%zu,%zu", p == NULL, counts.overflow, counts.memory, counts.invalid);
      counts = (struct allocation_error_counts){ 0 };
      p = mi_heap_malloc_aligned_at(heaps[h], limit_requests[r], 8, 1);
      snprintf(key, sizeof key, "api_modes.heap_limit_aligned.%zu.%zu", h, r);
      line(key, "%d,%zu,%zu,%zu", p == NULL, counts.overflow, counts.memory, counts.invalid);
      mi_register_error(NULL, NULL);
    }
    note_interior_api_modes(heaps[h], h);
  }
  mi_theap_set_default(previous);
  mi_heap_delete(auxiliary_heap);
  for (size_t r = 0; r < sizeof limit_requests / sizeof limit_requests[0]; r++) {
    struct allocation_error_counts counts = { 0 };
    mi_register_error(count_allocation_errors, &counts);
    void* p = mi_malloc(limit_requests[r]);
    key_name(key, sizeof key, "api_modes.limit_ordinary", r, 0);
    line(key, "%d,%zu,%zu,%zu", p == NULL, counts.overflow, counts.memory, counts.invalid);
    counts = (struct allocation_error_counts){ 0 };
    p = mi_malloc_aligned_at(limit_requests[r], 8, 1);
    key_name(key, sizeof key, "api_modes.limit_aligned", r, 0);
    line(key, "%d,%zu,%zu,%zu", p == NULL, counts.overflow, counts.memory, counts.invalid);
    mi_register_error(NULL, NULL);
  }
  for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
    void* p = mi_calloc(1, sizes[s]);
    const size_t usable = mi_usable_size(p);
    key_name(key, sizeof key, "api_modes.calloc", s, 0);
    line(key, "%d,%zu,%d,%zu", p != NULL, usable, p != NULL && is_zero(p, usable), mi_good_size(sizes[s]));
    if (p == NULL) { continue; }
    fill(p, usable, 0x37);
    errno = 23;
    void* failed = mi_recalloc(p, SIZE_MAX, 2);
    key_name(key, sizeof key, "api_modes.count_failure", s, 0);
    line(key, "%d,%d,%d,%d", failed == NULL, errno, mi_usable_size(p) == usable, has_fill(p, usable, 0x37));
    errno = 0;
    failed = mi_realloc(p, SIZE_MAX);
    key_name(key, sizeof key, "api_modes.size_failure", s, 0);
    line(key, "%d,%d,%d,%d", failed == NULL, errno, mi_usable_size(p) == usable, has_fill(p, usable, 0x37));
    void* expanded = mi_expand(p, usable);
    key_name(key, sizeof key, "api_modes.expand", s, 0);
    line(key, "%d", expanded == p);
    void* q = mi_rezalloc(p, usable + 17);
    key_name(key, sizeof key, "api_modes.rezalloc", s, 0);
    line(key, "%d,%zu,%d,%d", q != NULL, mi_usable_size(q),
         q != NULL && has_fill(q, usable, 0x37),
         q != NULL && mi_usable_size(q) >= usable
           && is_zero((char*)q + usable, mi_usable_size(q) - usable));
    mi_free(q == NULL ? p : q);
    p = mi_malloc(sizes[s]);
    q = mi_realloc(p, 0);
    key_name(key, sizeof key, "api_modes.zero_replace", s, 0);
    line(key, "%d,%d,%d", q != NULL, q != p, q != NULL && ((unsigned char*)q)[0] == 0);
    mi_free(q == NULL ? p : q);
  }
  for (size_t a = 0; a < sizeof alignments / sizeof alignments[0]; a++) {
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
      for (size_t offset = 0; offset <= 7; offset += 7) {
        if (alignments[a] > 65536 && offset != 0) { continue; }
        void* p = mi_zalloc_aligned_at(sizes[s], alignments[a], offset);
        const size_t usable = mi_usable_size(p);
        snprintf(key, sizeof key, "api_modes.aligned.%zu.%zu.%zu", a, s, offset);
        line(key, "%d,%zu,%d,%d", p != NULL, usable,
             p != NULL && (((uintptr_t)p + offset) & (alignments[a] - 1)) == 0,
             p != NULL && is_zero(p, usable));
        if (p == NULL) { continue; }
        fill(p, usable, 0x51);
        errno = 29;
        void* failed = mi_recalloc_aligned_at(p, SIZE_MAX, 2, alignments[a], offset);
        snprintf(key, sizeof key, "api_modes.aligned_failure.%zu.%zu.%zu", a, s, offset);
        line(key, "%d,%d,%d,%d", failed == NULL, errno,
             mi_usable_size(p) == usable, has_fill(p, usable, 0x51));
        errno = 0;
        failed = mi_realloc_aligned_at(p, SIZE_MAX, alignments[a], offset);
        snprintf(key, sizeof key, "api_modes.aligned_size_failure.%zu.%zu.%zu", a, s, offset);
        line(key, "%d,%d,%d,%d", failed == NULL, errno,
             mi_usable_size(p) == usable, has_fill(p, usable, 0x51));
        void* q = mi_rezalloc_aligned_at(p, usable + 17, alignments[a], offset);
        snprintf(key, sizeof key, "api_modes.aligned_grow.%zu.%zu.%zu", a, s, offset);
        const size_t grown = mi_usable_size(q);
        line(key, "%d,%zu,%d,%d", q != NULL, grown,
             q != NULL && has_fill(q, usable, 0x51),
             q != NULL && grown >= usable && is_zero((char*)q + usable, grown - usable));
        if (q == NULL) { mi_free(p); continue; }
        const size_t half = (alignments[a] <= sizeof(void*) && offset == 0)
                            ? grown / 2 : grown - grown / 2;
        void* reused = mi_realloc_aligned_at(q, half, alignments[a], offset);
        snprintf(key, sizeof key, "api_modes.aligned_half.%zu.%zu.%zu", a, s, offset);
        line(key, "%d,%d", reused == q, reused != NULL && has_fill(reused, usable < half ? usable : half, 0x51));
        if (offset == 0) {
          mi_free_size_aligned(reused == NULL ? q : reused, half, alignments[a]);
        } else {
          mi_free(reused == NULL ? q : reused);
        }
      }
    }
  }
}

#ifdef CRABC_MI_M4_SOURCE_CANARY
static void section_padding_canary(void) {
  const uintptr_t keys[2] = { UINT64_C(0x123456789ABCDE0D), UINT64_C(0xFEDCBA9876543210) };
  const uintptr_t blocks[] = { 0, 0x1000, 0x1010, 0x1FF0 };
  for (size_t i = 0; i < sizeof blocks / sizeof blocks[0]; i++) {
    char key[64];
    snprintf(key, sizeof key, "padding.canary.%zu", i);
    line(key, "%u", mi_ptr_encode_canary((void*)(uintptr_t)0x1000, (void*)blocks[i], keys));
  }
}
#endif

static void section_conveniences(void) {
  char* s = mi_strdup("mimalloc");
  note_text_request("strdup", s, "mimalloc", 9);
  line("strdup.text", "%s", s == NULL ? "(null)" : s);
  mi_free(s);
  if (!valid_domain) { line("strdup.null", "%d", mi_strdup(NULL) == NULL); }
  s = mi_strndup("mimalloc", 3);
  note_text_request("strndup.short", s, "mim", 4);
  line("strndup.short.text", "%s", s == NULL ? "(null)" : s);
  mi_free(s);
  s = mi_strndup("abc", 100);
  note_text_request("strndup.long", s, "abc", 4);
  line("strndup.long.text", "%s", s == NULL ? "(null)" : s);
  mi_free(s);
  if (!valid_domain) { line("strndup.null", "%d", mi_strndup(NULL, 4) == NULL); }
  unsigned char* m = mi_mbsdup((const unsigned char*)"bytes");
  note_text_request("mbsdup", m, "bytes", 6);
  line("mbsdup.text", "%s", m == NULL ? "(null)" : (const char*)m);
  mi_free(m);
  wchar_t* w = mi_wcsdup(L"wide");
  note_text_request("wcsdup", w, L"wide", 5 * sizeof(wchar_t));
  line("wcsdup.equal", "%d", w != NULL && wcscmp(w, L"wide") == 0);
  mi_free(w);
  if (!valid_domain) { line("wcsdup.null", "%d", mi_wcsdup(NULL) == NULL); }
  setenv("CRABC_M4_DUPENV", "value-1", 1);
  char* buffer = (char*)&buffer;
  size_t size = 99;
  int result = mi_dupenv_s(&buffer, &size, "CRABC_M4_DUPENV");
  line("dupenv_s.present", "%d,%zu,%s", result, size, buffer == NULL ? "(null)" : buffer);
  note_text_request("dupenv_s.present.block", buffer, "value-1", 8);
  mi_free(buffer);
  size = 99;
  buffer = (char*)&buffer;
  result = mi_dupenv_s(&buffer, &size, "CRABC_M4_DUPENV_ABSENT");
  line("dupenv_s.absent", "%d,%zu,%d", result, size, buffer == NULL);
  size = 99;
  if (!valid_domain) {
  result = mi_dupenv_s(NULL, &size, "PATH");
  line("dupenv_s.null_buffer", "%d,%zu", result, size);
  line("dupenv_s.null_name", "%d", mi_dupenv_s(&buffer, NULL, NULL));
  }
  wchar_t* wide_buffer = (wchar_t*)&wide_buffer;
  size = 99;
  result = mi_wdupenv_s(&wide_buffer, &size, L"PATH");
  line("wdupenv_s", "%d,%zu,%d", result, size, wide_buffer == NULL);
  char expected[PATH_MAX];
  const bool resolved = realpath(".", expected) != NULL;
  errno = 0;
  s = mi_realpath(".", NULL);
  note_text_request("realpath.allocated", s, expected, valid_domain && resolved ? strlen(expected) + 1 : 0);
  line("realpath.allocated.equal", "%d,%d", resolved, s != NULL && strcmp(s, expected) == 0);
  note_errno("realpath.allocated");
  mi_free(s);
  char given[PATH_MAX];
  s = mi_realpath(".", given);
  line("realpath.given", "%d", s == given && strcmp(given, expected) == 0);
  errno = 0;
  s = mi_realpath("/crabc-m4-absent/none", NULL);
  line("realpath.absent", "%d", s == NULL);
  note_errno("realpath.absent");
}

/* Offset aligned clients can have an odd usable extent even when their
   canonical block size is word aligned. Exercise both sides of the aligned
   ceil-half reuse boundary and compare every byte after each replacement. */
static void section_offset_rezalloc_boundaries(void) {
  static const size_t sizes[] = { 33, 70000, 600000 };
  static const size_t alignments[] = { 256, 4096 };
  static const size_t offsets[] = { 1, 7 };
  char key[96];
  char base[80];
  for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
    for (size_t a = 0; a < sizeof alignments / sizeof alignments[0]; a++) {
      for (size_t o = 0; o < sizeof offsets / sizeof offsets[0]; o++) {
        snprintf(base, sizeof base, "offset_rezalloc.%zu.%zu.%zu", s, a, o);
        void* p = mi_malloc_aligned_at(sizes[s], alignments[a], offsets[o]);
        if (p == NULL) {
          snprintf(key, sizeof key, "%s.initial", base);
          line(key, "initial_null");
          continue;
        }
        const size_t initial_usable = mi_usable_size(p);
        const bool initial_aligned = (((uintptr_t)p + offsets[o]) & (alignments[a] - 1)) == 0;
        fill(p, initial_usable, 0x36);
        void* grown = mi_rezalloc_aligned_at(p, initial_usable + 17, alignments[a], offsets[o]);
        snprintf(key, sizeof key, "%s.grow", base);
        line(key, "grow:%d,copy:%d,tail:%d,odd:%d,old_usable:%zu,new_usable:%zu",
             grown != NULL && grown != p,
             grown != NULL && has_fill(grown, initial_usable, 0x36),
             grown != NULL && is_zero((char*)grown + initial_usable,
                                      mi_usable_size(grown) - initial_usable),
             (int)(initial_usable & 1), initial_usable,
             grown == NULL ? 0 : mi_usable_size(grown));
        if (grown == NULL) { mi_free(p); continue; }
        const size_t grown_usable = mi_usable_size(grown);
        const bool grown_aligned = (((uintptr_t)grown + offsets[o]) & (alignments[a] - 1)) == 0;
        const size_t reuse_size = grown_usable - grown_usable / 2;
        fill(grown, grown_usable, 0x59);
        void* reused = mi_rezalloc_aligned_at(grown, reuse_size, alignments[a], offsets[o]);
        snprintf(key, sizeof key, "%s.reuse", base);
        line(key, "reuse:%d,copy:%d",
             reused == grown,
             reused != NULL && has_fill(reused, grown_usable, 0x59));
        if (reused == NULL) { mi_free(grown); continue; }
        const size_t replacement_size = reuse_size - 1;
        void* replaced = mi_rezalloc_aligned_at(reused, replacement_size,
                                               alignments[a], offsets[o]);
        snprintf(key, sizeof key, "%s.replace", base);
        line(key, "replace:%d,copy:%d,tail:%d,aligned:%d,new_usable:%zu",
             replaced != NULL && replaced != reused,
             replaced != NULL && has_fill(replaced, replacement_size, 0x59),
             replaced != NULL && is_zero((char*)replaced + replacement_size,
                                         mi_usable_size(replaced) - replacement_size),
             replaced != NULL &&
               (((uintptr_t)replaced + offsets[o]) & (alignments[a] - 1)) == 0,
             replaced == NULL ? 0 : mi_usable_size(replaced));
        if (valid_domain) {
          snprintf(key, sizeof key, "%s.basis", base);
          line(key, "requested:%zu,alignment:%zu,offset:%zu,initial:%zu,initial_upper:%zu,grown:%zu,grown_upper:%zu,replacement:%zu,replacement_upper:%zu,initial_aligned:%d,grown_aligned:%d",
               sizes[s], alignments[a], offsets[o], initial_usable,
               allocation_capacity_upper((sizes[s] < 16 ? 16 : sizes[s]) + alignments[a] - 1),
               grown_usable, allocation_capacity_upper(initial_usable + 17 + alignments[a] - 1),
               replaced == NULL ? 0 : mi_usable_size(replaced),
               allocation_capacity_upper((replacement_size < 16 ? 16 : replacement_size) + alignments[a] - 1),
               initial_aligned, grown_aligned);
        }
        mi_free(replaced == NULL ? reused : replaced);
      }
    }
  }
}

/* Every page kind at its class edges: enough blocks to fill two pages of
   the kind (a full page leaves its queue and is abandoned), then frees in an
   interleaved order and a second allocation round that shows which blocks,
   pages, and slices each allocator reuses. */
static void section_page_kinds(void) {
  char key[96];
  static const size_t sizes[] = {
    1024, 1025, 10240, 10241, 65536, 86016, 86017, 262144, 524288, 524289, 4194304, 4194305, 9 * MiB,
  };
  static void* blocks[301];
  for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
    const size_t block_size = mi_good_size(sizes[s]);
    const size_t page_size = block_size <= 10240 ? 64 * KiB : block_size <= 86016 ? 512 * KiB
                           : block_size <= 512 * KiB ? 4 * MiB : block_size;
    size_t count = 2 * (page_size / block_size) + 1;
    if (count > 301) { count = 301; }
    for (size_t round = 0; round < 2; round++) {
      for (size_t i = 0; i < count; i++) {
        blocks[i] = mi_malloc(sizes[s]);
        snprintf(key, sizeof key, "page_kinds.%zu.%zu.%zu", s, round, i);
        note(key, blocks[i]);
        if (blocks[i] != NULL) { fill(blocks[i], sizes[s] < 64 ? sizes[s] : 64, (unsigned char)i); }
      }
      for (size_t parity = 0; parity < 2; parity++) {
        for (size_t i = parity; i < count; i += 2) { mi_free(blocks[i]); }
      }
    }
  }
}

/* Threads bound to the allocator by their first call, joined before the
   next step so the interleaving is deterministic. */
typedef struct thread_step_s {
  void* inherited[2];   /* blocks the initial thread passed in */
  void* produced[3];    /* blocks the worker allocated and returned */
  void* reallocated;    /* the worker's realloc of inherited[0] */
  int first_aligned_ok;
} thread_step_t;

static void* thread_worker(void* argument) {
  thread_step_t* step = (thread_step_t*)argument;
  step->produced[0] = mi_malloc(48);
  step->produced[1] = mi_malloc(5000);
  step->produced[2] = mi_malloc(700000);
  if (step->produced[0] != NULL) { fill(step->produced[0], 48, 0x51); }
  /* An initial-thread block: same-Heap realloc reuses it in place. */
  step->reallocated = mi_realloc(step->inherited[0], mi_usable_size(step->inherited[0]));
  /* A remote free of the initial thread's huge block. */
  mi_free(step->inherited[1]);
  return NULL;
}

static void* thread_first_aligned(void* argument) {
  thread_step_t* step = (thread_step_t*)argument;
  /* test-api.c `zero_aligned_first`: the thread's first allocator call. */
  void* p = mi_malloc_aligned(0, 16);
  int ok = (p != NULL && ((uintptr_t)p % 16) == 0);
  mi_free(p);
  p = mi_zalloc_aligned(0, 32);
  ok = ok && (p != NULL && ((uintptr_t)p % 32) == 0);
  mi_free(p);
  step->first_aligned_ok = ok;
  return NULL;
}

static void section_threads(void) {
  thread_step_t step = { { mi_malloc(100), mi_malloc(600000) }, { NULL, NULL, NULL }, NULL, 0 };
  note("threads.inherited.0", step.inherited[0]);
  note("threads.inherited.1", step.inherited[1]);
  pthread_t thread;
  line("threads.create", "%d", pthread_create(&thread, NULL, &thread_worker, &step) == 0 && pthread_join(thread, NULL) == 0);
  line("threads.realloc_in_place", "%d", step.reallocated == step.inherited[0]);
  note("threads.produced.0", step.produced[0]);
  note("threads.produced.1", step.produced[1]);
  note("threads.produced.2", step.produced[2]);
  /* The worker has exited: its pages are abandoned, yet share the Heap. */
  void* q = mi_realloc(step.produced[0], 40);
  line("threads.post_exit_realloc_in_place", "%d,%d", q == step.produced[0], q != NULL && has_fill(q, 40, 0x51));
  mi_free(q);
  mi_free(step.produced[1]);
  mi_free(step.produced[2]);
  note("threads.after_post_exit_free", mi_malloc(5000));
  note("threads.huge_after_remote_free", mi_malloc(600000));
  mi_free(step.reallocated);
  thread_step_t first = { { NULL, NULL }, { NULL, NULL, NULL }, NULL, 0 };
  const int ran = pthread_create(&thread, NULL, &thread_first_aligned, &first) == 0 && pthread_join(thread, NULL) == 0;
  line("threads.first_aligned", "%d,%d", ran, first.first_aligned_ok);
  note("threads.after_first_aligned", mi_malloc(100));
}

/* Collection makes freed pages observable through later reuse. */
static void section_collection(void) {
  char key[96];
  static const size_t sizes[] = { 48, 3000, 30000, 200000 };
  for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
    for (int force = 0; force <= 2; force++) {
      void* blocks[64];
      for (int i = 0; i < 64; i++) { blocks[i] = mi_malloc(sizes[s]); }
      key_name(key, sizeof key, "collect.first", s, (size_t)force);
      note(key, blocks[0]);
      for (int i = 0; i < 64; i++) { mi_free(blocks[i]); }
      if (force < 2) { mi_collect(force == 1); }
      /* A different size class probes whether the emptied pages returned. */
      void* probe = mi_malloc(sizes[s] + sizes[s] / 2 + 8);
      key_name(key, sizeof key, "collect.probe", s, (size_t)force);
      note(key, probe);
      void* same = mi_malloc(sizes[s]);
      key_name(key, sizeof key, "collect.same", s, (size_t)force);
      note(key, same);
      mi_free(same);
      mi_free(probe);
    }
  }
  mi_collect(true);
  note("collect.after_force", mi_malloc(100));
}

/* Last: bound the address space so every OS-backed request is refused. */
static void section_oom(void) {
  struct rlimit limit;
  if (getrlimit(RLIMIT_AS, &limit) != 0) { line("oom.getrlimit", "failed"); return; }
  void* keep = mi_malloc(100);
  fill(keep, 100, 0x71);
  void* big = mi_malloc(3 * MiB);
  fill(big, 3 * MiB, 0x72);
  void* aligned = mi_malloc_aligned(1000, 4096);
  fill(aligned, 1000, 0x73);
  FILE* status = fopen("/proc/self/status", "r");
  size_t vm_kib = 0;
  char text[256];
  while (status != NULL && fgets(text, sizeof text, status) != NULL) {
    if (strncmp(text, "VmSize:", 7) == 0) { vm_kib = (size_t)strtoull(text + 7, NULL, 10); }
  }
  if (status != NULL) { fclose(status); }
  struct rlimit bounded = limit;
  bounded.rlim_cur = (rlim_t)(vm_kib * KiB + 16 * MiB);
  line("oom.setrlimit", "%d", setrlimit(RLIMIT_AS, &bounded) == 0);
  static const size_t requests[] = { 2 * 1024 * MiB, 4 * 1024 * MiB };
  for (size_t r = 0; r < sizeof requests / sizeof requests[0]; r++) {
    char key[96];
    errno = 0;
    key_name(key, sizeof key, "oom.malloc", r, 0);
    note(key, mi_malloc(requests[r]));
    note_errno(key);
    errno = 0;
    key_name(key, sizeof key, "oom.calloc", r, 0);
    note(key, mi_calloc(requests[r] / 8, 8));
    note_errno(key);
    errno = 0;
    key_name(key, sizeof key, "oom.malloc_aligned", r, 0);
    note(key, mi_malloc_aligned(requests[r], 1 * MiB));
    note_errno(key);
    errno = 0;
    key_name(key, sizeof key, "oom.realloc", r, 0);
    note(key, mi_realloc(keep, requests[r]));
    note_errno(key);
    key_name(key, sizeof key, "oom.realloc.kept", r, 0);
    line(key, "%d", has_fill(keep, 100, 0x71));
    errno = 0;
    key_name(key, sizeof key, "oom.realloc_big", r, 0);
    note(key, mi_realloc(big, requests[r]));
    note_errno(key);
    key_name(key, sizeof key, "oom.realloc_big.kept", r, 0);
    line(key, "%d", has_fill(big, 3 * MiB, 0x72));
    errno = 0;
    key_name(key, sizeof key, "oom.realloc_aligned", r, 0);
    note(key, mi_realloc_aligned(aligned, requests[r], 4096));
    note_errno(key);
    key_name(key, sizeof key, "oom.realloc_aligned.kept", r, 0);
    line(key, "%d", has_fill(aligned, 1000, 0x73));
    void* out = &out;
    errno = 0;
    key_name(key, sizeof key, "oom.posix_memalign", r, 0);
    const int code = mi_posix_memalign(&out, 64, requests[r]);
    line(key, "%d,%d,%d", code, out == (void*)&out, errno);
  }
  /* The allocator stays usable for requests its existing pages serve. */
  void* small = mi_malloc(100);
  note("oom.small_after", small);
  mi_free(small);
  errno = 0;
  void* freed_on_failure = mi_malloc(200);
  note("oom.reallocf.source", freed_on_failure);
  note("oom.reallocf", mi_reallocf(freed_on_failure, 2 * 1024 * MiB));
  note_errno("oom.reallocf");
  note("oom.reallocf.reuse_probe", mi_malloc(200));
  setrlimit(RLIMIT_AS, &limit);
  note("oom.after_restore", mi_malloc(64 * MiB));
  mi_free(keep);
  mi_free(big);
  mi_free(aligned);
}

static int run_abort_scenario(const char* name) {
  if (strcmp(name, "new_n_overflow") == 0) { (void)mi_new_n(SIZE_MAX / 2, 4); }
  else if (strcmp(name, "new_too_large") == 0) { (void)mi_new(SIZE_MAX / 2); }
  else if (strcmp(name, "new_aligned_too_large") == 0) { (void)mi_new_aligned(SIZE_MAX / 2, 64); }
  else if (strcmp(name, "new_realloc_too_large") == 0) { (void)mi_new_realloc(mi_malloc(8), SIZE_MAX / 2); }
  else if (strcmp(name, "new_reallocn_overflow") == 0) { (void)mi_new_reallocn(mi_malloc(8), SIZE_MAX / 2, 4); }
  else { return 2; }
  printf("returned\n");
  return 0;
}

/* A valid offset client is retained throughout each source diagnostic. The
   temporary option override is used only to release a still-owned client
   after observing the original debug validation condition. */
static int run_source_client_control(const char* name) {
  printf("%s\n", TRACE_BEGIN);
  set_live_client_precise(false);
  if (strcmp(name, "interior-api-modes") == 0) {
    mi_heap_t* main_heap = mi_heap_main();
    mi_heap_t* auxiliary = mi_heap_new();
    if (auxiliary == NULL) { return 3; }
    mi_theap_t* previous = mi_theap_set_default(mi_heap_theap(auxiliary));
    note_interior_api_modes(main_heap, 0);
    note_interior_api_modes(auxiliary, 1);
    mi_theap_set_default(previous);
    mi_heap_delete(auxiliary);
  }
  else if (strcmp(name, "usable-free-73") == 0 || strcmp(name, "usable-free-1000") == 0) {
    const bool large = strcmp(name, "usable-free-1000") == 0;
    const size_t size = large ? 1000 : 73;
    const size_t alignment = large ? 4096 : 64;
    const size_t offset = large ? 13 : 7;
    unsigned char* p = mi_malloc_aligned_at(size, alignment, offset);
    if (p == NULL) { return 3; }
    fill(p, size, 0x71);
    line("control.input", "%zu,%zu,%zu", size, alignment, offset);
    line("control.client", "%d,%d", (((uintptr_t)p + offset) & (alignment - 1)) == 0,
         has_fill(p, size, 0x71));
    struct allocation_error_counts counts = { 0 };
    mi_register_error(count_allocation_errors, &counts);
    errno = 0;
    const size_t usable = mi_usable_size(p);
    const int usable_error = errno;
    line("control.usable", "%zu,%d,%zu", usable, usable_error, counts.invalid);
    errno = 0;
    mi_free(p);
    const int free_error = errno;
    line("control.free", "%d,%zu", free_error, counts.invalid);
    mi_register_error(NULL, NULL);
    source_client_error = counts.invalid != 0;
#if defined(CRABC_MI_M4_SOURCE_CANARY) && MI_DEBUG >= 1 && MI_GUARDED == 0
    if (source_client_error) {
      /* The rejected free left the exact original client owned and live. */
      mi_option_set_enabled(mi_option_guarded_precise, true);
      mi_free(p);
    }
#endif
  }
  else { return 2; }
  printf("%s\n", TRACE_END);
  return source_client_error ? 1 : 0;
}

/* These calls deliberately violate source assertion preconditions. Keeping
   each in a fresh process exposes both the exact debug assertion and the
   returning error path without interrupting live-client observations. */
static int run_precondition_control(const char* name) {
  printf("%s\n", TRACE_BEGIN);
  if (strcmp(name, "reallocarr-null") == 0) {
    line("control.input", "null,1,1");
    errno = 0;
    const int result = mi_reallocarr(NULL, 1, 1);
    const int error = errno;
    line("control.outcome", "%d,%d", result, error);
  }
  else if (strcmp(name, "reallocarr-zero-size") == 0) {
    unsigned char* p = mi_reallocarray(NULL, 7, 9);
    if (p == NULL) { return 3; }
    fill(p, 63, 0x39);
    unsigned char* const original = p;
    line("control.input", "63,1,0");
    errno = 0;
    const int result = mi_reallocarr(&p, 1, 0);
    const int error = errno;
    const bool retained = p == original && has_fill(p, 63, 0x39);
    line("control.outcome", "%d,%d,%d", result, error, retained);
    mi_free(p);
  }
  else if (strcmp(name, "aligned-invalid") == 0) {
    unsigned char* p = mi_malloc_aligned(100, 64);
    if (p == NULL) { return 3; }
    fill(p, 100, 5);
    void* q = mi_realloc_aligned(p, (size_t)PTRDIFF_MAX, 64);
    if (q != NULL) { mi_free(q); return 4; }
    line("control.input", "100,64;200,24");
    errno = 0;
    q = mi_realloc_aligned(p, 200, 24);
    const int error = errno;
    const bool retained = q == NULL && has_fill(p, 100, 5);
    line("control.outcome", "%d,%d,%d", q == NULL, error, retained);
    mi_free(q == NULL ? p : q);
  }
  else if (strcmp(name, "aligned-at-invalid") == 0) {
    unsigned char* p = mi_malloc_aligned_at(73, 64, 7);
    if (p == NULL) { return 3; }
    fill(p, 73, 0x43);
    line("control.input", "73,64,7;150,3,7");
    errno = 0;
    void* q = mi_realloc_aligned_at(p, 150, 3, 7);
    const int error = errno;
    const bool retained = q == NULL && has_fill(p, 73, 0x43);
    line("control.outcome", "%d,%d,%d", q == NULL, error, retained);
    /* The returning control still owns the original live client. */
    mi_option_set_enabled(mi_option_guarded_precise, true);
    mi_free(q == NULL ? p : q);
  }
  else { return 2; }
  printf("%s\n", TRACE_END);
  return 0;
}

#ifdef CRABC_MI_M4_SOURCE_FRESH_PAGE_ORDER
static int run_fresh_page_order(void) {
  mi_option_set(mi_option_arena_reserve, 0);
  mi_option_set(mi_option_page_commit_on_demand, 0);
  mi_option_set_enabled(mi_option_allow_large_os_pages, false);
  mi_option_set_enabled(mi_option_allow_thp, false);
  mi_process_init();
  fresh_page_armed = true;
  void* const allocation = mi_calloc(1, 64 * KiB);
  fresh_page_armed = false;
  const bool fresh_os_page = allocation != NULL && fresh_page != NULL
      && fresh_page->memid.memkind == MI_MEM_OS
      && _mi_checked_ptr_page(allocation) == fresh_page;
  const bool source_assertion_observed = fresh_page_zero_calls == 1;
  const bool published_free_list = fresh_os_page && fresh_page->capacity > 0
      && fresh_page->used == 1;
  const bool published_queue = fresh_os_page
      && mi_page_queue(mi_page_theap(fresh_page), fresh_page->block_size)->first == fresh_page;
  const bool client_zero = allocation != NULL && is_zero(allocation, 64 * KiB);
  puts("CRABC_MI_SOURCE_FRESH_PAGE_ORDER_TRACE_BEGIN");
  line("fresh_os_page", "%d", fresh_os_page);
  line("registration_calls", "%zu", fresh_page_register_calls);
  line("primary_before_registration", "%d", fresh_page_primary_before_register);
  line("alias_count_before_registration", "%zu", fresh_page_aliases_before_register);
  line("aliases_before_registration", "%d", fresh_page_aliases_match_before_register);
  line("source_zero_calls", "%zu", fresh_page_zero_calls);
  line("zero_after_registration", "%d", fresh_page_zero_after_registration);
  line("zero_after_statistics", "%d", fresh_page_zero_after_statistics);
  line("zero_before_free_list", "%d", fresh_page_zero_before_free_list);
  line("zero_before_queue", "%d", fresh_page_zero_before_queue);
  line("source_zero_result", "%d", fresh_page_zero_result);
  line("published_free_list", "%d", published_free_list);
  line("published_queue", "%d", published_queue);
  line("client_zero", "%d", client_zero);
  puts("CRABC_MI_SOURCE_FRESH_PAGE_ORDER_TRACE_END");
  mi_free(allocation);
  return fresh_os_page && fresh_page_register_calls == 1
      && fresh_page_primary_before_register && fresh_page_aliases_before_register > 0
      && fresh_page_aliases_match_before_register && source_assertion_observed
      && fresh_page_zero_after_registration && fresh_page_zero_after_statistics
      && fresh_page_zero_before_free_list && fresh_page_zero_before_queue
      && fresh_page_zero_result && published_free_list && published_queue && client_zero ? 0 : 3;
}
#endif

int main(int argc, char** argv) {
#ifdef CRABC_MI_M4_SOURCE_FRESH_PAGE_ORDER
  if (argc == 2 && strcmp(argv[1], "source-fresh-page-order") == 0) {
    return run_fresh_page_order();
  }
#endif
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc != 2 && argc != 3) { return 2; }
  valid_domain = argc == 3 && strcmp(argv[2], "--valid-domain") == 0;
  if (argc == 3 && !valid_domain) { return 2; }
  if (valid_domain) {
    set_live_client_precise(false);
    fprintf(stderr, "valid-domain guarded_precise=%ld\n", mi_option_get(mi_option_guarded_precise));
    /* A nonzero public sampling seed selects the same first guarded request
       in both independent processes. Keep the configured sampling rate and
       all guards; default entropy otherwise selects unrelated countdowns. */
    const long guarded_rate = mi_option_get_clamp(mi_option_guarded_sample_rate, 0, LONG_MAX);
    const size_t guarded_seed = 1;
    if (guarded_rate > 0) {
      mi_theap_guarded_set_sample_rate(mi_theap_get_default(), (size_t)guarded_rate, guarded_seed);
    }
    fprintf(stderr, "valid-domain guarded_sample_rate=%ld,guarded_sample_seed=%zu\n",
            guarded_rate, guarded_seed);
  }
  const char* scenario = argv[1];
  if (valid_domain && (strncmp(scenario, "source-client:", 14) == 0
      || strncmp(scenario, "precondition:", 13) == 0
      || strncmp(scenario, "abort:", 6) == 0)) { return 2; }
  if (strncmp(scenario, "source-client:", 14) == 0) { return run_source_client_control(scenario + 14); }
  if (strncmp(scenario, "precondition:", 13) == 0) { return run_precondition_control(scenario + 13); }
  if (strncmp(scenario, "abort:", 6) == 0) { return run_abort_scenario(scenario + 6); }
  void (*sections[8])(void) = { NULL };
  if (strcmp(scenario, "operations") == 0) {
    sections[0] = section_allocation;
    sections[1] = section_good_size;
    sections[2] = section_free;
    sections[3] = section_realloc;
    sections[4] = section_aligned;
    sections[5] = section_conveniences;
    sections[6] = section_offset_rezalloc_boundaries;
  }
  else if (strcmp(scenario, "page-kinds") == 0) { sections[0] = section_page_kinds; }
  else if (strcmp(scenario, "collection") == 0) { sections[0] = section_collection; }
  else if (strcmp(scenario, "oom") == 0) { sections[0] = section_oom; }
  else if (strcmp(scenario, "threads") == 0) { sections[0] = section_threads; }
  else if (strcmp(scenario, "aligned-preservation") == 0) { sections[0] = section_aligned_preservation; }
  else if (strcmp(scenario, "api-modes") == 0) { sections[0] = section_api_modes; }
#ifdef CRABC_MI_M4_SOURCE_CANARY
  else if (strcmp(scenario, "padding-canary") == 0) { sections[0] = section_padding_canary; }
#endif
  else { return 2; }
  printf("%s\n", TRACE_BEGIN);
  for (int i = 0; i < 8 && sections[i] != NULL; i++) { sections[i](); }
  printf("%s\n", TRACE_END);
  return 0;
}
