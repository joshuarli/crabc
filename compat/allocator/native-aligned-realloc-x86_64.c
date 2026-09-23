/* SPDX-License-Identifier: MIT
 * Source behavior: pinned mimalloc v3.5.0 src/alloc-aligned.c:347-388.
 * This focused C oracle is paired with
 * crabc-mimalloc/tests/native_aligned_reallocate.rs. */
#include "mimalloc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  void *null_zero = mi_realloc_aligned(NULL, 0, sizeof(void *));
  if (null_zero == NULL || ((unsigned char *)null_zero)[0] != 0) return 9;
  mi_free(null_zero);

  const size_t alignment = 128;
  void *original = mi_malloc_aligned(33, alignment);
  if (original == NULL || ((uintptr_t)original & (alignment - 1)) != 0) return 1;
  const size_t usable = mi_usable_size(original);
  if (usable < 33) return 2;
  memset(original, 0x79, usable);

  const size_t half = usable - usable / 2;
  void *reused = mi_realloc_aligned(original, half, alignment);
  if (reused != original) return 3;
  if (mi_realloc_aligned(reused, SIZE_MAX, alignment) != NULL) return 4;
  if (mi_usable_size(reused) != usable || ((unsigned char *)reused)[0] != 0x79) return 5;

  const size_t replacement_size = half - 1;
  void *replacement = mi_realloc_aligned(reused, replacement_size, alignment);
  if (replacement == NULL || replacement == reused) return 6;
  if (((uintptr_t)replacement & (alignment - 1)) != 0) return 7;
  for (size_t i = 0; i < replacement_size; i++) {
    if (((unsigned char *)replacement)[i] != 0x79) return 8;
  }
  mi_free(replacement);
  puts("aligned_realloc:null_zero=1,reuse=1,oom_preserved=1,replaced=1,aligned=1,copy=1");
  return 0;
}
