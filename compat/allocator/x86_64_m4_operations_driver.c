/* Shared C driver for the allocator M4 operations differential.

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
   `page-kinds`, `collection`, `oom`, `threads`, or a process-terminating
   `abort:<name>` that the runner observes through the exit status. Driven by
   `compat/allocator/x86_64_m4_gate.py --operations-differential`. */
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

#define TRACE_BEGIN "CRABC_MI_M4_OPERATIONS_TRACE_BEGIN"
#define TRACE_END "CRABC_MI_M4_OPERATIONS_TRACE_END"
#define MAX_IDS 8192
#define KiB ((size_t)1024)
#define MiB (KiB * KiB)

static uintptr_t id_address[MAX_IDS];
static int id_count;

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
    note(key, blocks[i]);
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
    note(key, p);
    key_name(key, sizeof key, "zalloc.zero", i, class_sizes[i]);
    line(key, "%d", p != NULL && is_zero(p, mi_usable_size(p)));
    if (p != NULL) { fill(p, mi_usable_size(p), 0x5a); }
    mi_free(p);
    key_name(key, sizeof key, "calloc", i, class_sizes[i]);
    p = mi_calloc(1, class_sizes[i]);
    note(key, p);
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
  note("calloc.zero_count", p);
  mi_free(p);
  p = mi_mallocn(3, 40);
  note("mallocn.3x40", p);
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
    note(key, p);
    mi_free(p);
    key_name(key, sizeof key, "zalloc_small", size, 0);
    p = mi_zalloc_small(size);
    note(key, p);
    key_name(key, sizeof key, "zalloc_small.zero", size, 0);
    line(key, "%d", p != NULL && is_zero(p, mi_usable_size(p)));
    mi_free(p);
  }
  static const size_t u_sizes[] = { 0, 1, 100, 1024, 5000, 70000, 600000, 5 * MiB };
  for (size_t i = 0; i < sizeof u_sizes / sizeof u_sizes[0]; i++) {
    size_t block_size = 12345;
    key_name(key, sizeof key, "umalloc", i, u_sizes[i]);
    p = mi_umalloc(u_sizes[i], &block_size);
    note(key, p);
    key_name(key, sizeof key, "umalloc.block", i, u_sizes[i]);
    line(key, "%zu", block_size);
    size_t freed = 777;
    mi_ufree(p, &freed);
    key_name(key, sizeof key, "ufree.block", i, u_sizes[i]);
    line(key, "%zu", freed);
    block_size = 12345;
    key_name(key, sizeof key, "ucalloc", i, u_sizes[i]);
    p = mi_ucalloc(2, u_sizes[i] / 2, &block_size);
    note(key, p);
    key_name(key, sizeof key, "ucalloc.block", i, u_sizes[i]);
    line(key, "%zu,%d", block_size, p != NULL && is_zero(p, mi_usable_size(p)));
    mi_free(p);
    if (u_sizes[i] <= MI_SMALL_SIZE_MAX) {
      block_size = 12345;
      key_name(key, sizeof key, "umalloc_small", i, u_sizes[i]);
      p = mi_umalloc_small(u_sizes[i], &block_size);
      note(key, p);
      key_name(key, sizeof key, "umalloc_small.block", i, u_sizes[i]);
      line(key, "%zu", block_size);
      mi_free(p);
      block_size = 12345;
      key_name(key, sizeof key, "uzalloc_small", i, u_sizes[i]);
      p = mi_uzalloc_small(u_sizes[i], &block_size);
      note(key, p);
      key_name(key, sizeof key, "uzalloc_small.block", i, u_sizes[i]);
      line(key, "%zu,%d", block_size, p != NULL && is_zero(p, mi_usable_size(p)));
      mi_free(p);
    }
  }
  size_t freed = 777;
  mi_ufree(NULL, &freed);
  line("ufree.null", "%zu", freed);
  p = mi_new(100);
  note("new.100", p);
  mi_free(p);
  p = mi_new_n(10, 10);
  note("new_n.10x10", p);
  mi_free(p);
  errno = 0;
  note("new_nothrow.too_large", mi_new_nothrow(SIZE_MAX / 2));
  note_errno("new_nothrow.too_large");
  p = mi_new_nothrow(64);
  note("new_nothrow.64", p);
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
  line("cfree.invalid_low", "%d", mi_cfree((void*)(uintptr_t)0x0000000003990080));
  int on_stack = 0;
  line("cfree.stack", "%d", mi_cfree(&on_stack));
  void* p = mi_malloc(48);
  note("cfree.block", p);
  line("cfree.valid", "%d", mi_cfree(p));
  p = mi_malloc(48);
  note("cfree.block.again", p);
  mi_free_size(p, 48);
  p = mi_malloc_small(64);
  note("free_small.block", p);
  mi_free_small(p);
  p = mi_malloc_aligned(100, 64);
  note("free_aligned.block", p);
  mi_free_aligned(p, 64);
  p = mi_malloc_aligned(100, 64);
  note("free_size_aligned.block", p);
  mi_free_size_aligned(p, 100, 64);
  line("usable_size.null", "%zu", mi_usable_size(NULL));
  line("check_owned.stack", "%d", mi_check_owned(&on_stack));
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
  note("realloc.null", p);
  note_errno("realloc.null");
  mi_free(p);
  p = mi_realloc(NULL, 0);
  note("realloc.null_zero", p);
  line("realloc.null_zero.byte", "%d", p == NULL ? -1 : ((unsigned char*)p)[0]);
  mi_free(p);
  p = mi_malloc(4);
  note("realloc.sized_zero.source", p);
  fill(p, 4, 9);
  p = mi_realloc(p, 0);
  note("realloc.sized_zero", p);
  line("realloc.sized_zero.byte", "%d", p == NULL ? -1 : ((unsigned char*)p)[0]);
  mi_free(p);
  static const size_t sources[] = { 1, 24, 100, 1000, 5000, 20000, 100000, 600000, 5 * MiB };
  for (size_t s = 0; s < sizeof sources / sizeof sources[0]; s++) {
    void* source = mi_malloc(sources[s]);
    key_name(key, sizeof key, "realloc.source", s, sources[s]);
    note(key, source);
    const size_t usable = mi_usable_size(source);
    const size_t targets[] = { usable, usable / 2 + usable % 2, usable / 2, usable / 2 - (usable > 1), usable + 1, usable * 3 };
    for (size_t t = 0; t < sizeof targets / sizeof targets[0]; t++) {
      const size_t current = mi_usable_size(source);
      fill(source, current, (unsigned char)(s * 16 + t));
      const size_t keep = targets[t] < current ? targets[t] : current;
      errno = 0;
      void* q = mi_realloc(source, targets[t]);
      key_name(key, sizeof key, "realloc", s, t);
      note(key, q);
      key_name(key, sizeof key, "realloc.kept", s, t);
      line(key, "%d", q != NULL && has_fill(q, keep, (unsigned char)(s * 16 + t)));
      if (q != NULL) { source = q; }
    }
    /* Pinned-C `mi_urealloc` reports the pre and post page block sizes. */
    size_t pre = 1, post = 1;
    void* q = mi_urealloc(source, sources[s] * 2 + 1, &pre, &post);
    key_name(key, sizeof key, "urealloc", s, sources[s]);
    note(key, q);
    key_name(key, sizeof key, "urealloc.sizes", s, sources[s]);
    line(key, "%zu,%zu", pre, post);
    if (q != NULL) { source = q; }
    const size_t grow = mi_usable_size(source);
    fill(source, grow, 0x33);
    q = mi_rezalloc(source, grow * 2 + 17);
    key_name(key, sizeof key, "rezalloc", s, sources[s]);
    note(key, q);
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
  note("urealloc.null", p);
  line("urealloc.null.sizes", "%zu,%zu", pre, post);
  mi_free(p);

  p = mi_malloc(64);
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
  q = mi_reallocn(p, 10, 20);
  note("reallocn.10x20", q);
  line("reallocn.10x20.kept", "%d", q != NULL && has_fill(q, 64, 1));
  p = q;
  errno = 0;
  q = mi_reallocf(p, (size_t)PTRDIFF_MAX + 1);
  note("reallocf.too_large", q);
  note_errno("reallocf.too_large");
  /* The source freed `p`; a same-size request reuses its block. */
  note("reallocf.reuse_probe", mi_malloc(200));
  p = mi_reallocf(NULL, 30);
  note("reallocf.null", p);
  mi_free(p);

  errno = 0;
  p = mi_reallocarray(NULL, 0, 16);
  note("reallocarray.null_zero", p);
  note_errno("reallocarray.null_zero");
  errno = 0;
  q = mi_reallocarray(p, SIZE_MAX / 2, 3);
  note("reallocarray.overflow", q);
  note_errno("reallocarray.overflow");
  errno = 0;
  q = mi_reallocarray(p, (size_t)PTRDIFF_MAX / 2 + 1, 2);
  note("reallocarray.too_large", q);
  note_errno("reallocarray.too_large");
  q = mi_reallocarray(p, 7, 9);
  note("reallocarray.7x9", q);
  p = q;
  errno = 0;
  line("reallocarr.null_pointer", "%d", mi_reallocarr(NULL, 1, 1));
  note_errno("reallocarr.null_pointer");
  errno = 0;
  line("reallocarr.zero_size", "%d", mi_reallocarr(&p, 1, 0));
  note_errno("reallocarr.zero_size");
  errno = 0;
  line("reallocarr.overflow", "%d", mi_reallocarr(&p, SIZE_MAX / 2, 3));
  note_errno("reallocarr.overflow");
  errno = 0;
  line("reallocarr.too_large", "%d", mi_reallocarr(&p, (size_t)PTRDIFF_MAX / 2 + 1, 2));
  note_errno("reallocarr.too_large");
  line("reallocarr.grow", "%d", mi_reallocarr(&p, 20, 20));
  note("reallocarr.grow.block", p);
  const int zero_count = mi_reallocarr(&p, 0, 8);
  line("reallocarr.zero_count", "%d,%d", zero_count, p == NULL);
  void* none = NULL;
  line("reallocarr.from_null", "%d", mi_reallocarr(&none, 3, 5));
  note("reallocarr.from_null.block", none);
  mi_free(none);

  p = mi_recalloc(NULL, 5, 7);
  note("recalloc.null", p);
  line("recalloc.null.zero", "%d", p != NULL && is_zero(p, mi_usable_size(p)));
  fill(p, 35, 3);
  q = mi_recalloc(p, 50, 7);
  note("recalloc.grow", q);
  line("recalloc.grow.content", "%d,%d", q != NULL && has_fill(q, 35, 3),
       q != NULL && is_zero((char*)q + 40, mi_usable_size(q) - 40));
  if (q != NULL) { p = q; }
  errno = 0;
  q = mi_recalloc(p, SIZE_MAX / 2, 5);
  note("recalloc.overflow", q);
  note_errno("recalloc.overflow");
  mi_free(p);
  p = mi_rezalloc(NULL, 90);
  note("rezalloc.null", p);
  line("rezalloc.null.zero", "%d", p != NULL && is_zero(p, mi_usable_size(p)));
  mi_free(p);
  p = mi_malloc(40);
  q = mi_new_realloc(p, 400);
  note("new_realloc", q);
  q = mi_new_reallocn(q, 30, 30);
  note("new_reallocn", q);
  mi_free(q);
  /* issue #1304: the source's zero-to-64 KiB realloc ladder */
  void* shared = NULL;
  for (int iteration = 0; iteration < 4; iteration++) {
    for (int i = 0; i < 1024; i++) { shared = mi_realloc(shared, (size_t)i * 64); }
  }
  note("realloc.ladder", shared);
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
      note(key, p);
      key_name(key, sizeof key, "malloc_aligned.ok", shift, s);
      line(key, "%d,%d", p != NULL && ((uintptr_t)p % alignment) == 0, errno);
      if (p != NULL) { fill(p, sizes[s], 0x44); }
      key_name(key, sizeof key, "zalloc_aligned", shift, s);
      void* z = mi_zalloc_aligned(sizes[s], alignment);
      note(key, z);
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
      key_name(key, sizeof key, "malloc_aligned_at", shift, o);
      errno = 0;
      void* p = mi_malloc_aligned_at(50, alignment, offsets[o]);
      note(key, p);
      key_name(key, sizeof key, "malloc_aligned_at.ok", shift, o);
      line(key, "%d,%d", p != NULL && (((uintptr_t)p + offsets[o]) % alignment) == 0, errno);
      key_name(key, sizeof key, "zalloc_aligned_at", shift, o);
      void* z = mi_zalloc_aligned_at(3000, alignment, offsets[o]);
      note(key, z);
      key_name(key, sizeof key, "zalloc_aligned_at.ok", shift, o);
      line(key, "%d", z != NULL && (((uintptr_t)z + offsets[o]) % alignment) == 0 && is_zero(z, mi_usable_size(z)));
      key_name(key, sizeof key, "calloc_aligned_at", shift, o);
      void* c = mi_calloc_aligned_at(3, 70, alignment, offsets[o]);
      note(key, c);
      mi_free(c);
      mi_free(z);
      mi_free(p);
    }
  }
  errno = 0;
  note("malloc_aligned.bad_alignment", mi_malloc_aligned(32, 3));
  note_errno("malloc_aligned.bad_alignment");
  errno = 0;
  note("malloc_aligned.zero_alignment", mi_malloc_aligned(32, 0));
  note_errno("malloc_aligned.zero_alignment");
  errno = 0;
  note("malloc_aligned.too_large", mi_malloc_aligned((size_t)PTRDIFF_MAX, 64));
  note_errno("malloc_aligned.too_large");
  errno = 0;
  note("malloc_aligned_at.huge_offset", mi_malloc_aligned_at(100, 1 * MiB, 8));
  note_errno("malloc_aligned_at.huge_offset");
  errno = 0;
  note("malloc_aligned.meta_alignment", mi_malloc_aligned(100, 256 * MiB));
  note_errno("malloc_aligned.meta_alignment");
  errno = 0;
  note("calloc_aligned.overflow", mi_calloc_aligned(SIZE_MAX / 2, 3, 64));
  note_errno("calloc_aligned.overflow");
  void* p = mi_calloc_aligned(10, 10, 128);
  note("calloc_aligned.10x10", p);
  line("calloc_aligned.10x10.zero", "%d", p != NULL && is_zero(p, 100));
  mi_free(p);
  size_t block_size = 1;
  p = mi_umalloc_aligned(100, 256, &block_size);
  note("umalloc_aligned", p);
  line("umalloc_aligned.block", "%zu", block_size);
  mi_free(p);
  block_size = 1;
  p = mi_uzalloc_aligned(3000, 4096, &block_size);
  note("uzalloc_aligned", p);
  line("uzalloc_aligned.block", "%zu,%d", block_size, p != NULL && is_zero(p, 3000));
  mi_free(p);

  /* Aligned reallocation: reuse at the ceil-half boundary, replacement,
     copy, and tail zeroing. */
  static const size_t realign[] = { 8, 16, 64, 4096, 64 * KiB, 1 * MiB };
  for (size_t a = 0; a < sizeof realign / sizeof realign[0]; a++) {
    const size_t alignment = realign[a];
    void* source = mi_malloc_aligned(300, alignment);
    key_name(key, sizeof key, "realloc_aligned.source", a, alignment);
    note(key, source);
    const size_t usable = mi_usable_size(source);
    const size_t targets[] = { usable, usable - usable / 2, usable - usable / 2 - 1, usable + 1, 5000 };
    for (size_t t = 0; t < sizeof targets / sizeof targets[0]; t++) {
      const size_t current = mi_usable_size(source) < 300 ? mi_usable_size(source) : 300;
      fill(source, current, (unsigned char)(a + t));
      const size_t keep = targets[t] < current ? targets[t] : current;
      void* q = mi_realloc_aligned(source, targets[t], alignment);
      key_name(key, sizeof key, "realloc_aligned", a, t);
      note(key, q);
      key_name(key, sizeof key, "realloc_aligned.ok", a, t);
      line(key, "%d,%d", q != NULL && ((uintptr_t)q % alignment) == 0,
           q != NULL && has_fill(q, keep, (unsigned char)(a + t)));
      if (q != NULL) { source = q; }
    }
    const size_t grow = mi_usable_size(source);
    fill(source, grow, 0x21);
    void* q = mi_rezalloc_aligned(source, grow * 2 + 3, alignment);
    key_name(key, sizeof key, "rezalloc_aligned", a, alignment);
    note(key, q);
    key_name(key, sizeof key, "rezalloc_aligned.content", a, alignment);
    line(key, "%d,%d", q != NULL && has_fill(q, grow, 0x21),
         q != NULL && is_zero((char*)q + grow, mi_usable_size(q) - grow));
    if (q != NULL) { source = q; }
    q = mi_recalloc_aligned(source, 3, grow * 2, alignment);
    key_name(key, sizeof key, "recalloc_aligned", a, alignment);
    note(key, q);
    if (q != NULL) { source = q; }
    q = mi_aligned_recalloc(source, 2, grow * 4, alignment);
    key_name(key, sizeof key, "aligned_recalloc", a, alignment);
    note(key, q);
    if (q != NULL) { source = q; }
    mi_free(source);
  }
  for (size_t o = 0; o < sizeof offsets / sizeof offsets[0]; o++) {
    void* source = mi_malloc_aligned_at(90, 256, offsets[o]);
    key_name(key, sizeof key, "realloc_aligned_at.source", o, offsets[o]);
    note(key, source);
    fill(source, 90, 0x61);
    void* q = mi_realloc_aligned_at(source, 900, 256, offsets[o]);
    key_name(key, sizeof key, "realloc_aligned_at", o, offsets[o]);
    note(key, q);
    key_name(key, sizeof key, "realloc_aligned_at.ok", o, offsets[o]);
    line(key, "%d,%d", q != NULL && (((uintptr_t)q + offsets[o]) % 256) == 0, q != NULL && has_fill(q, 90, 0x61));
    q = mi_rezalloc_aligned_at(q, 1900, 256, offsets[o]);
    key_name(key, sizeof key, "rezalloc_aligned_at", o, offsets[o]);
    note(key, q);
    key_name(key, sizeof key, "rezalloc_aligned_at.ok", o, offsets[o]);
    line(key, "%d,%d", q != NULL && has_fill(q, 90, 0x61), q != NULL && is_zero((char*)q + 900, 1000));
    q = mi_recalloc_aligned_at(q, 4, 700, 256, offsets[o]);
    key_name(key, sizeof key, "recalloc_aligned_at", o, offsets[o]);
    note(key, q);
    q = mi_aligned_offset_recalloc(q, 5, 700, 256, offsets[o]);
    key_name(key, sizeof key, "aligned_offset_recalloc", o, offsets[o]);
    note(key, q);
    mi_free(q);
  }
  p = mi_malloc_aligned(100, 64);
  fill(p, 100, 5);
  errno = 0;
  void* q = mi_realloc_aligned(p, (size_t)PTRDIFF_MAX, 64);
  note("realloc_aligned.too_large", q);
  note_errno("realloc_aligned.too_large");
  line("realloc_aligned.too_large.kept", "%d", has_fill(p, 100, 5));
  errno = 0;
  q = mi_realloc_aligned(p, 200, 24);
  note("realloc_aligned.bad_alignment", q);
  note_errno("realloc_aligned.bad_alignment");
  /* An alignment of at most one word is ordinary realloc, which consumes p. */
  errno = 0;
  q = mi_realloc_aligned(p, 200, 3);
  note("realloc_aligned.word_alignment", q);
  note_errno("realloc_aligned.word_alignment");
  mi_free(q == NULL ? p : q);
  p = mi_realloc_aligned(NULL, 0, 8);
  note("realloc_aligned.null_zero", p);
  line("realloc_aligned.null_zero.byte", "%d", p == NULL ? -1 : ((unsigned char*)p)[0]);
  mi_free(p);

  /* alloc-posix.c entries */
  static const size_t posix_alignments[] = { 0, 1, 3, 4, 8, 16, 24, 64, 4096, 1 * MiB };
  static const size_t posix_sizes[] = { 0, 32, 5000, SIZE_MAX };
  for (size_t a = 0; a < sizeof posix_alignments / sizeof posix_alignments[0]; a++) {
    for (size_t s = 0; s < sizeof posix_sizes / sizeof posix_sizes[0]; s++) {
      void* out = &out;
      errno = 0;
      const int result = mi_posix_memalign(&out, posix_alignments[a], posix_sizes[s]);
      key_name(key, sizeof key, "posix_memalign", a, s);
      line(key, "%d,%d,%d", result, out == (void*)&out, errno);
      if (result == 0 && out != (void*)&out) {
        key_name(key, sizeof key, "posix_memalign.block", a, s);
        note(key, out);
        mi_free(out);
      }
      errno = 0;
      p = mi_memalign(posix_alignments[a], posix_sizes[s]);
      key_name(key, sizeof key, "memalign", a, s);
      note(key, p);
      note_errno(key);
      mi_free(p);
      errno = 0;
      p = mi_aligned_alloc(posix_alignments[a], posix_sizes[s]);
      key_name(key, sizeof key, "aligned_alloc", a, s);
      note(key, p);
      note_errno(key);
      mi_free(p);
    }
  }
  line("posix_memalign.null_out", "%d", mi_posix_memalign(NULL, 16, 16));
  static const size_t page_sizes[] = { 0, 1, 4095, 4096, 4097, 100000 };
  for (size_t s = 0; s < sizeof page_sizes / sizeof page_sizes[0]; s++) {
    key_name(key, sizeof key, "valloc", s, page_sizes[s]);
    p = mi_valloc(page_sizes[s]);
    note(key, p);
    mi_free(p);
    key_name(key, sizeof key, "pvalloc", s, page_sizes[s]);
    p = mi_pvalloc(page_sizes[s]);
    note(key, p);
    mi_free(p);
  }
  errno = 0;
  note("pvalloc.overflow", mi_pvalloc(SIZE_MAX - 100));
  note_errno("pvalloc.overflow");
  p = mi_new_aligned(100, 128);
  note("new_aligned", p);
  mi_free(p);
  errno = 0;
  note("new_aligned_nothrow.too_large", mi_new_aligned_nothrow(SIZE_MAX / 2, 64));
  note_errno("new_aligned_nothrow.too_large");
  /* test-api.c zero_aligned_first, here on the initial thread */
  p = mi_malloc_aligned(0, 16);
  note("malloc_aligned.zero16", p);
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

static void section_conveniences(void) {
  char* s = mi_strdup("mimalloc");
  note("strdup", s);
  line("strdup.text", "%s", s == NULL ? "(null)" : s);
  mi_free(s);
  line("strdup.null", "%d", mi_strdup(NULL) == NULL);
  s = mi_strndup("mimalloc", 3);
  note("strndup.short", s);
  line("strndup.short.text", "%s", s == NULL ? "(null)" : s);
  mi_free(s);
  s = mi_strndup("abc", 100);
  note("strndup.long", s);
  line("strndup.long.text", "%s", s == NULL ? "(null)" : s);
  mi_free(s);
  line("strndup.null", "%d", mi_strndup(NULL, 4) == NULL);
  unsigned char* m = mi_mbsdup((const unsigned char*)"bytes");
  note("mbsdup", m);
  line("mbsdup.text", "%s", m == NULL ? "(null)" : (const char*)m);
  mi_free(m);
  wchar_t* w = mi_wcsdup(L"wide");
  note("wcsdup", w);
  line("wcsdup.equal", "%d", w != NULL && wcscmp(w, L"wide") == 0);
  mi_free(w);
  line("wcsdup.null", "%d", mi_wcsdup(NULL) == NULL);
  setenv("CRABC_M4_DUPENV", "value-1", 1);
  char* buffer = (char*)&buffer;
  size_t size = 99;
  int result = mi_dupenv_s(&buffer, &size, "CRABC_M4_DUPENV");
  line("dupenv_s.present", "%d,%zu,%s", result, size, buffer == NULL ? "(null)" : buffer);
  note("dupenv_s.present.block", buffer);
  mi_free(buffer);
  size = 99;
  buffer = (char*)&buffer;
  result = mi_dupenv_s(&buffer, &size, "CRABC_M4_DUPENV_ABSENT");
  line("dupenv_s.absent", "%d,%zu,%d", result, size, buffer == NULL);
  size = 99;
  result = mi_dupenv_s(NULL, &size, "PATH");
  line("dupenv_s.null_buffer", "%d,%zu", result, size);
  line("dupenv_s.null_name", "%d", mi_dupenv_s(&buffer, NULL, NULL));
  wchar_t* wide_buffer = (wchar_t*)&wide_buffer;
  size = 99;
  result = mi_wdupenv_s(&wide_buffer, &size, L"PATH");
  line("wdupenv_s", "%d,%zu,%d", result, size, wide_buffer == NULL);
  char expected[PATH_MAX];
  const bool resolved = realpath(".", expected) != NULL;
  errno = 0;
  s = mi_realpath(".", NULL);
  note("realpath.allocated", s);
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

int main(int argc, char** argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc != 2) { return 2; }
  const char* scenario = argv[1];
  if (strncmp(scenario, "abort:", 6) == 0) { return run_abort_scenario(scenario + 6); }
  void (*sections[8])(void) = { NULL };
  if (strcmp(scenario, "operations") == 0) {
    sections[0] = section_allocation;
    sections[1] = section_good_size;
    sections[2] = section_free;
    sections[3] = section_realloc;
    sections[4] = section_aligned;
    sections[5] = section_conveniences;
  }
  else if (strcmp(scenario, "page-kinds") == 0) { sections[0] = section_page_kinds; }
  else if (strcmp(scenario, "collection") == 0) { sections[0] = section_collection; }
  else if (strcmp(scenario, "oom") == 0) { sections[0] = section_oom; }
  else if (strcmp(scenario, "threads") == 0) { sections[0] = section_threads; }
  else { return 2; }
  printf("%s\n", TRACE_BEGIN);
  for (int i = 0; i < 8 && sections[i] != NULL; i++) { sections[i](); }
  printf("%s\n", TRACE_END);
  return 0;
}
