#define _GNU_SOURCE 1
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "static.c"

#if MI_SECURE < 3
#error secure free-list fixture requires an encoded profile
#endif

#if !MI_FREE_IS_CHECKED
#error secure free-list fixture requires checked-free configuration
#endif

#if MI_PAGE_KEY_COUNT != 2
#error secure free-list fixture requires two page keys
#endif

#define BLOCK_SIZE 32
#define RESERVED 65
#define PAGE_KEY ((uintptr_t)0x1020304050607081ULL)
#define PAGE_KEY2 ((uintptr_t)0x8899aabbccddeeffULL)
#define RANDOM_HIGH ((uint32_t)0x11223344U)
#define RANDOM_LOW ((uint32_t)0x55667788U)

typedef struct secure_page_fixture_s {
  mi_page_t page;
  _Alignas(16) uint8_t blocks[BLOCK_SIZE * RESERVED];
} secure_page_fixture_t;

static void initialize_fixture(secure_page_fixture_t* fixture, mi_theap_t* theap) {
  memset(fixture, 0, sizeof(*fixture));
  memset(theap, 0, sizeof(*theap));
  fixture->page.block_size = BLOCK_SIZE;
  fixture->page.page_offset = offsetof(secure_page_fixture_t, blocks);
  fixture->page.reserved = RESERVED;
  fixture->page.slice_pcommitted = 0;
  fixture->page.keys[0] = PAGE_KEY;
  fixture->page.keys[1] = PAGE_KEY2;
  theap->random.input[0] = 0x61707865U;
  for (size_t i = 0; i < 16; i++) {
    theap->random.output[i] = ((i & 1) == 0 ? RANDOM_HIGH : RANDOM_LOW);
  }
  theap->random.output_available = 16;
}

static int corrupt_link(void) {
  secure_page_fixture_t fixture;
  mi_theap_t theap;
  initialize_fixture(&fixture, &theap);
  if (!mi_page_extend_free(&theap, &fixture.page)) return 2;
  mi_block_t* const head = fixture.page.free;
  mi_block_t* const outside = (mi_block_t*)(fixture.blocks + sizeof(fixture.blocks));
  mi_block_set_next(&fixture.page, head, outside);
  (void)mi_block_next(&fixture.page, head);
  return 3;
}

int main(int argc, char** argv) {
  if (argc == 2 && strcmp(argv[1], "corrupt") == 0) return corrupt_link();
  if (argc != 1) return 1;

  secure_page_fixture_t fixture;
  mi_theap_t theap;
  initialize_fixture(&fixture, &theap);
  const int random_before = theap.random.output_available;
  if (!mi_page_extend_free(&theap, &fixture.page)) return 2;
  const int random_words = random_before - theap.random.output_available;
  if (random_words != 2 || fixture.page.capacity != RESERVED) return 3;

  size_t count = 0;
  bool seen[RESERVED] = { false };
  bool encoded_head_link = false;
  bool tail_is_null = false;
  mi_block_t* block = fixture.page.free;
  if (block == NULL) return 4;

  printf("CRABC_MI_M7_SECURE_FREE_LIST_TRACE_BEGIN\n");
  printf("profile.secure_level=%d\n", MI_SECURE);
  printf("profile.free_is_checked=%d\n", MI_FREE_IS_CHECKED);
  printf("extension.capacity=%u\n", (unsigned)fixture.page.capacity);
  printf("extension.used=%zu\n", (size_t)fixture.page.used);
  printf("extension.random_draws=%d\n", random_words / 2);
  printf("extension.free_offsets=");
  while (block != NULL && count < RESERVED) {
    const ptrdiff_t byte_offset = (const uint8_t*)block - fixture.blocks;
    if (byte_offset < 0 || byte_offset % BLOCK_SIZE != 0) return 5;
    const size_t index = (size_t)byte_offset / BLOCK_SIZE;
    if (index >= RESERVED || seen[index]) return 6;
    seen[index] = true;
    if (count != 0) putchar(',');
    printf("%zu", index);
    mi_block_t* const next = mi_block_next(&fixture.page, block);
    if (count == 0) encoded_head_link = ((uintptr_t)block->next != (uintptr_t)next);
    if (next == NULL) tail_is_null = true;
    block = next;
    count++;
  }
  putchar('\n');
  if (count != RESERVED || !tail_is_null || !encoded_head_link) return 7;
  for (size_t i = 0; i < RESERVED; i++) {
    if (!seen[i]) return 8;
  }
  printf("extension.encoded_head_link=%d\n", encoded_head_link ? 1 : 0);
  printf("extension.tail_is_null=%d\n", tail_is_null ? 1 : 0);
  printf("CRABC_MI_M7_SECURE_FREE_LIST_TRACE_END\n");
  return 0;
}
