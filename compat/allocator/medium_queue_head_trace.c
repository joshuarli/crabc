/* SPDX-License-Identifier: MIT
 *
 * One source-shared C ABI trace for a fresh regular medium page and repeated
 * allocations from its queue head. The allocator backend is linked separately.
 */
#include "perf-x86_64/engine-api.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum { BLOCK_SIZE = 32768, BLOCK_COUNT = 16 };

static void fail(const char *message)
{
  fprintf(stderr, "medium queue trace: %s\n", message);
  exit(2);
}

int main(void)
{
  void *blocks[BLOCK_COUNT];
  if (crabc_allocator_engine_process_init() != 0) fail("process init");
  for (unsigned phase = 0; phase < 2; phase++) {
    const char *name = (phase == 0 ? "fresh" : "repeat");
    for (unsigned index = 0; index < BLOCK_COUNT; index++) {
      void *block = crabc_allocator_engine_malloc(BLOCK_SIZE);
      if (block == NULL) fail("malloc");
      const size_t usable = crabc_allocator_engine_usable_size(block);
      const unsigned remainder = (unsigned)((uintptr_t)block & 15U);
      if (usable < BLOCK_SIZE || remainder != 0) fail("size or C alignment");
      for (unsigned earlier = 0; earlier < index; earlier++) {
        if (blocks[earlier] == block) fail("duplicate live block");
      }
      ((unsigned char *)block)[0] = (unsigned char)(index + 1);
      ((unsigned char *)block)[BLOCK_SIZE - 1] = (unsigned char)(phase + 11);
      blocks[index] = block;
      printf("alloc %s %u usable=%zu align=%u\n", name, index, usable, remainder);
    }
    void *retired = blocks[0];
    crabc_allocator_engine_free(retired);
    void *replacement = crabc_allocator_engine_malloc(BLOCK_SIZE);
    if (replacement == NULL) fail("replacement malloc");
    const size_t replacement_usable = crabc_allocator_engine_usable_size(replacement);
    const unsigned replacement_remainder = (unsigned)((uintptr_t)replacement & 15U);
    if (replacement_usable < BLOCK_SIZE || replacement_remainder != 0) fail("replacement size or alignment");
    for (unsigned earlier = 1; earlier < BLOCK_COUNT; earlier++) {
      if (blocks[earlier] == replacement) fail("duplicate replacement block");
    }
    ((unsigned char *)replacement)[0] = 1;
    ((unsigned char *)replacement)[BLOCK_SIZE - 1] = (unsigned char)(phase + 11);
    blocks[0] = replacement;
    printf("replace %s reused=%u usable=%zu align=%u\n", name,
           (unsigned)(replacement == retired), replacement_usable, replacement_remainder);
    void *spill = crabc_allocator_engine_malloc(BLOCK_SIZE);
    if (spill == NULL) fail("next-page malloc");
    const size_t spill_usable = crabc_allocator_engine_usable_size(spill);
    const unsigned spill_remainder = (unsigned)((uintptr_t)spill & 15U);
    if (spill_usable < BLOCK_SIZE || spill_remainder != 0) fail("next-page size or alignment");
    for (unsigned earlier = 0; earlier < BLOCK_COUNT; earlier++) {
      if (blocks[earlier] == spill) fail("duplicate next-page block");
    }
    ((unsigned char *)spill)[0] = 73;
    ((unsigned char *)spill)[BLOCK_SIZE - 1] = 91;
    if (((unsigned char *)spill)[0] != 73 || ((unsigned char *)spill)[BLOCK_SIZE - 1] != 91) {
      fail("next-page block contents");
    }
    printf("spill %s usable=%zu align=%u\n", name, spill_usable, spill_remainder);
    crabc_allocator_engine_free(spill);
    for (unsigned index = 0; index < BLOCK_COUNT; index++) {
      const unsigned char *block = blocks[index];
      if (block[0] != (unsigned char)(index + 1)
          || block[BLOCK_SIZE - 1] != (unsigned char)(phase + 11)) {
        fail("live block contents");
      }
    }
    for (unsigned index = BLOCK_COUNT; index != 0; index--) {
      crabc_allocator_engine_free(blocks[index - 1]);
    }
    printf("drain %s count=%u\n", name, BLOCK_COUNT);
  }
  return 0;
}
