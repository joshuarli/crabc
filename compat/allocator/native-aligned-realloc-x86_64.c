/* SPDX-License-Identifier: MIT
 * Source behavior: pinned mimalloc v3.5.0 src/alloc-aligned.c:347-388.
 * This focused C oracle is paired with
 * crabc-mimalloc/tests/native_aligned_reallocate.rs. */
#include "mimalloc.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Offset alignment permits a non-word-aligned exact live client. Every call
 * below uses that client under single-threaded lifetime exclusion. */
static int valid_offset_client(void) {
  unsigned char *p = mi_zalloc_aligned_at(81, 128, 11);
  int zero = p != NULL, aligned = p != NULL && ((uintptr_t)p + 11) % 128 == 0;
  if (p != NULL) {
    for (size_t i = 0; i < 81; ++i) zero &= p[i] == 0;
    memset(p, 0x63, 81);
  }
  printf("request=81\nalignment=128\noffset=11\nallocated=%d\nzero=%d\naligned=%d\n", p != NULL, zero, aligned);
  if (p == NULL) return 2;
  errno = 0;
  size_t usable = mi_usable_size(p);
  int usable_errno = errno;
  errno = 0;
  unsigned char *r = mi_realloc_aligned_at(p, 257, 128, 11);
  int realloc_errno = errno;
  int copied = r != NULL, realloc_aligned = r != NULL && ((uintptr_t)r + 11) % 128 == 0;
  if (r != NULL) for (size_t i = 0; i < 81; ++i) copied &= r[i] == 0x63;
  errno = 0;
  mi_free(r != NULL ? r : p);
  int free_errno = errno;
  printf("usable=%zu\nusable_errno=%d\nreallocated=%d\nrealloc_aligned=%d\ncopied=%d\nrealloc_errno=%d\nfree_returned=1\nfree_errno=%d\n",
         usable, usable_errno, r != NULL, realloc_aligned, copied, realloc_errno, free_errno);
  return !(zero && aligned && usable >= 81 && usable_errno == 0 &&
           r != NULL && realloc_aligned && copied && realloc_errno == 0 && free_errno == 0);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--valid-offset-client") == 0) return valid_offset_client();
  if (argc != 1) return 64;
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

  void *zeroed = mi_malloc_aligned(33, 16);
  if (zeroed == NULL) return 10;
  const size_t old_usable = mi_usable_size(zeroed);
  memset(zeroed, 0x5a, old_usable);
  if (mi_rezalloc(zeroed, SIZE_MAX) != NULL || ((unsigned char *)zeroed)[0] != 0x5a) return 11;
  void *grown = mi_rezalloc(zeroed, old_usable + 17);
  if (grown == NULL) return 12;
  const size_t grown_usable = mi_usable_size(grown);
  for (size_t i = 0; i < old_usable; i++) {
    if (((unsigned char *)grown)[i] != 0x5a) return 13;
  }
  for (size_t i = old_usable; i < grown_usable; i++) {
    if (((unsigned char *)grown)[i] != 0) return 14;
  }
  void *zero_size = mi_rezalloc(grown, 0);
  if (zero_size == NULL) return 15;
  const size_t zero_size_usable = mi_usable_size(zero_size);
  for (size_t i = 0; i < zero_size_usable; i++) {
    if (((unsigned char *)zero_size)[i] != 0) return 16;
  }
  mi_free(zero_size);

  void *aligned_zeroed = mi_malloc_aligned(33, alignment);
  if (aligned_zeroed == NULL) return 17;
  const size_t aligned_old_usable = mi_usable_size(aligned_zeroed);
  memset(aligned_zeroed, 0x6b, aligned_old_usable);
  void *aligned_grown = mi_rezalloc_aligned(aligned_zeroed, aligned_old_usable + 17, alignment);
  if (aligned_grown == NULL || ((uintptr_t)aligned_grown & (alignment - 1)) != 0) return 18;
  const size_t aligned_new_usable = mi_usable_size(aligned_grown);
  for (size_t i = 0; i < aligned_old_usable; i++) {
    if (((unsigned char *)aligned_grown)[i] != 0x6b) return 19;
  }
  for (size_t i = aligned_old_usable; i < aligned_new_usable; i++) {
    if (((unsigned char *)aligned_grown)[i] != 0) return 20;
  }
  mi_free(aligned_grown);
  puts("zeroed_realloc:ordinary_oom=1,ordinary_copy=1,ordinary_tail=1,ordinary_zero=1,aligned_copy=1,aligned_tail=1");
  return 0;
}
