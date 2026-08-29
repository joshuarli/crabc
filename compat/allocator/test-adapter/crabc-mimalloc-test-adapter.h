/*
 * SPDX-License-Identifier: MIT
 *
 * Test-only, prefixed C ABI for differential evidence against pinned mimalloc
 * v3.5.0. This header never installs into crabc's public include directory and
 * the linked library deliberately exports no malloc, free, or mi_* symbol.
 *
 * One creating thread owns the process-global adapter context. Calls from any
 * other thread, concurrent calls, pointers from another allocator, stale
 * pointers, and use after a successful shutdown are outside this test ABI.
 */
#ifndef CRABC_MIMALLOC_TEST_ADAPTER_H
#define CRABC_MIMALLOC_TEST_ADAPTER_H

#include <stddef.h>

/*
 * When the selected existing libc fixture is compiled with
 * `-DCRABC_TEST_ADAPTER_REMAP_STDLIB`, include its allocation declarations
 * before the macro remap. That makes an `-include` of this header safe: later
 * standard allocation headers are guarded and cannot have their declarations
 * rewritten.
 */
#if defined(CRABC_TEST_ADAPTER_REMAP_STDLIB)
#include <stdlib.h>
#include <malloc.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

int crabc_test_init(void);
int crabc_test_shutdown(void);

void *crabc_test_malloc(size_t size);
void *crabc_test_zalloc(size_t size);
void *crabc_test_calloc(size_t count, size_t size);
void crabc_test_free(void *p);
void *crabc_test_realloc(void *p, size_t size);
void *crabc_test_reallocarray(void *p, size_t count, size_t size);
size_t crabc_test_usable_size(const void *p);

void *crabc_test_malloc_aligned(size_t size, size_t alignment);
void *crabc_test_zalloc_aligned(size_t size, size_t alignment);
void *crabc_test_calloc_aligned(size_t count, size_t size, size_t alignment);
void *crabc_test_malloc_aligned_at(size_t size, size_t alignment, size_t offset);
void *crabc_test_realloc_aligned(void *p, size_t size, size_t alignment);
void *crabc_test_rezalloc_aligned(void *p, size_t size, size_t alignment);
int crabc_test_posix_memalign(void **out, size_t alignment, size_t size);

#ifdef __cplusplus
}
#endif

/*
 * This narrow source mapping lets a selected upstream API test exercise the
 * adapter without implying that crabc exports mimalloc's public ABI. Keep the
 * mappings limited to the functions declared above; missing mi_* functions
 * are deliberately compilation failures until their engine slice exists.
 */
#define mi_malloc(size) crabc_test_malloc((size))
#define mi_zalloc(size) crabc_test_zalloc((size))
#define mi_calloc(count, size) crabc_test_calloc((count), (size))
#define mi_free(p) crabc_test_free((p))
#define mi_realloc(p, size) crabc_test_realloc((p), (size))
#define mi_reallocarray(p, count, size) \
  crabc_test_reallocarray((p), (count), (size))
#define mi_usable_size(p) crabc_test_usable_size((p))

#define mi_malloc_aligned(size, alignment) \
  crabc_test_malloc_aligned((size), (alignment))
#define mi_zalloc_aligned(size, alignment) \
  crabc_test_zalloc_aligned((size), (alignment))
#define mi_calloc_aligned(count, size, alignment) \
  crabc_test_calloc_aligned((count), (size), (alignment))
#define mi_malloc_aligned_at(size, alignment, offset) \
  crabc_test_malloc_aligned_at((size), (alignment), (offset))
#define mi_realloc_aligned(p, size, alignment) \
  crabc_test_realloc_aligned((p), (size), (alignment))
#define mi_rezalloc_aligned(p, size, alignment) \
  crabc_test_rezalloc_aligned((p), (size), (alignment))
#define mi_posix_memalign(out, alignment, size) \
  crabc_test_posix_memalign((out), (alignment), (size))

/* The pinned source permits non-multiple sizes here. */
#define mi_aligned_alloc(alignment, size) \
  crabc_test_malloc_aligned((size), (alignment))
#define mi_memalign(alignment, size) \
  crabc_test_malloc_aligned((size), (alignment))

/*
 * This is strictly an opt-in source rewrite for `tests/fixtures/allocator_test.c`.
 * It does not add unprefixed ELF exports and must never be enabled while
 * building crabc's normal libc fixtures. The harness owns the surrounding C
 * wrapper that calls `crabc_test_init` before the fixture and
 * `crabc_test_shutdown` after it returns.
 */
#if defined(CRABC_TEST_ADAPTER_REMAP_STDLIB)
/*
 * This adapter-only fixture boundary requires the pinned Linux 64-bit musl
 * `max_align_t` alignment of 16 bytes for every allocation size. The
 * source-faithful mimalloc entry points above keep their natural small-bin
 * alignment; these private inline shims select the engine's aligned
 * operations only for the existing libc fixture. They add no ELF symbols and
 * do not claim a public crabc-libc allocator ABI.
 */
enum { CRABC_TEST_LIBC_MALLOC_ALIGNMENT = 16 };

/*
 * The Rust adapter's `usize` parameters and the fixture's standard C
 * allocation declarations are valid only for the explicit Linux/AArch64 and
 * Linux/x86-64 64-bit profiles. The checked-in C wrapper verifies those
 * width and alignment facts at its C11 source-remap boundary, so a foreign C
 * ABI cannot silently exercise this private evidence adapter.
 */

static inline void *crabc_test_libc_malloc(size_t size)
{
  return crabc_test_malloc_aligned(size, CRABC_TEST_LIBC_MALLOC_ALIGNMENT);
}

static inline void *crabc_test_libc_calloc(size_t count, size_t size)
{
  return crabc_test_calloc_aligned(count, size, CRABC_TEST_LIBC_MALLOC_ALIGNMENT);
}

static inline void *crabc_test_libc_realloc(void *p, size_t size)
{
  return crabc_test_realloc_aligned(p, size, CRABC_TEST_LIBC_MALLOC_ALIGNMENT);
}

static inline void *crabc_test_libc_reallocarray(void *p, size_t count, size_t size)
{
  if (size != 0 && count > (size_t)-1 / size)
    return crabc_test_reallocarray(p, count, size);
  return crabc_test_realloc_aligned(
      p, count * size, CRABC_TEST_LIBC_MALLOC_ALIGNMENT);
}

#define malloc(size) crabc_test_libc_malloc((size))
#define calloc(count, size) crabc_test_libc_calloc((count), (size))
#define free(p) crabc_test_free((p))
#define realloc(p, size) crabc_test_libc_realloc((p), (size))
#define reallocarray(p, count, size) \
  crabc_test_libc_reallocarray((p), (count), (size))
#define malloc_usable_size(p) crabc_test_usable_size((p))
#define aligned_alloc(alignment, size) crabc_test_malloc_aligned((size), (alignment))
#define posix_memalign(out, alignment, size) \
  crabc_test_posix_memalign((out), (alignment), (size))
#endif

#endif
