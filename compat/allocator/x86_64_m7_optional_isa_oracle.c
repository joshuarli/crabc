/* Pinned bitmap selection and allocation probe. The selected source is
 * compiled directly, so the preprocessor and machine code choose the path. */
#include "static.c"
#include <stdio.h>
#include <string.h>

static void state(const char *name, mi_bchunk_t *chunk) {
  printf("%s.clear=%d\n", name, mi_bchunk_all_are_clear_relaxed(chunk));
  printf("%s.set=%d\n", name, mi_bchunk_all_are_set_relaxed(chunk));
  for (size_t field = 0; field < MI_BCHUNK_FIELDS; field++) {
    printf("%s.field%zu=%zu\n", name, field,
           (size_t)mi_atomic_load_relaxed(&chunk->bfields[field]));
  }
}

int main(void) {
  _Alignas(64) mi_bchunk_t chunk;
  memset(&chunk, 0, sizeof(chunk));
  puts("CRABC_MI_M7_OPTIONAL_ISA_TRACE_BEGIN");
  printf("bitmap.bits=%d\n", MI_BCHUNK_BITS);
#if defined(__AVX2__)
  puts("bitmap.arch=avx2");
#else
  puts("bitmap.arch=scalar");
#endif
#if MI_OPT_SIMD && defined(__AVX2__) && (MI_BCHUNK_BITS == 512)
  puts("bitmap.path=avx2");
#else
  puts("bitmap.path=scalar");
#endif
  state("empty", &chunk);
  mi_atomic_store_relaxed(&chunk.bfields[0], 1);
  mi_atomic_store_relaxed(&chunk.bfields[4], 1);
  mi_atomic_store_relaxed(&chunk.bfields[7], 1);
  size_t index = SIZE_MAX;
  printf("one.first=%zu\n", mi_bchunk_try_find_and_clear(&chunk, &index) ? index : SIZE_MAX);
  index = SIZE_MAX;
  printf("one.second=%zu\n", mi_bchunk_try_find_and_clear(&chunk, &index) ? index : SIZE_MAX);
  index = SIZE_MAX;
  printf("one.third=%zu\n", mi_bchunk_try_find_and_clear(&chunk, &index) ? index : SIZE_MAX);
  state("one_drained", &chunk);
  for (size_t field = 0; field < MI_BCHUNK_FIELDS; field++) {
    mi_atomic_store_relaxed(&chunk.bfields[field], 0);
  }
  mi_atomic_store_relaxed(&chunk.bfields[1], (mi_bfield_t)0xff << 16);
  mi_atomic_store_relaxed(&chunk.bfields[6], (mi_bfield_t)0xff << 48);
  bool temporary = false;
  index = SIZE_MAX;
  printf("byte.first=%zu\n", mi_bchunk_try_find_and_clear8(&chunk, &index, &temporary) ? index : SIZE_MAX);
  index = SIZE_MAX;
  printf("byte.second=%zu\n", mi_bchunk_try_find_and_clear8(&chunk, &index, &temporary) ? index : SIZE_MAX);
  printf("byte.temporary=%d\n", temporary);
  state("byte_drained", &chunk);
  for (size_t field = 0; field < MI_BCHUNK_FIELDS; field++) {
    mi_atomic_store_relaxed(&chunk.bfields[field], ~(mi_bfield_t)0);
  }
  state("full", &chunk);
  /* A binned bitmap claim is the allocator's page-bin path through the
   * same one-bit and full-byte selectors. */
  _Alignas(64) unsigned char storage[4096];
  mi_subproc_t subproc;
  memset(storage, 0, sizeof(storage));
  memset(&subproc, 0, sizeof(subproc));
  mi_bbitmap_t *bitmap = (mi_bbitmap_t *)storage;
  mi_bbitmap_init(&subproc, bitmap, 512, true);
  mi_bbitmap_setN(bitmap, 0, 512);
  printf("bin.one=%zu\n", mi_bbitmap_try_find_and_clearN(bitmap, 0, 1, &index) ? index : SIZE_MAX);
  printf("bin.byte=%zu\n", mi_bbitmap_try_find_and_clearN(bitmap, 0, 8, &index) ? index : SIZE_MAX);
  puts("CRABC_MI_M7_OPTIONAL_ISA_TRACE_END");
  return 0;
}
