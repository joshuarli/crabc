#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "mimalloc.h"

static uintptr_t base;
static size_t arena_size;
static bool armed;
static size_t metadata_calls, metadata_bytes, prefix_calls, prefix_bytes;
static uintptr_t refused_prefix;
static size_t refused_bytes;
static bool same_prefix;

static bool commit_memory(bool commit, void* start, size_t size, bool* zero, void* arg) {
  (void)arg;
  if (!commit) abort();
  uintptr_t address = (uintptr_t)start;
  if (address < base || size > arena_size || address - base > arena_size - size) abort();
  if (armed && zero == NULL) {
    metadata_calls++;
    metadata_bytes = size;
  }
  if (armed && zero != NULL) {
    prefix_calls++;
    prefix_bytes = size;
    if (prefix_calls == 1) {
      refused_prefix = address;
      refused_bytes = size;
      return false;
    }
    same_prefix = address == refused_prefix;
  }
  if (mprotect(start, size, PROT_READ | PROT_WRITE) != 0) abort();
  if (zero != NULL) *zero = true;
  return true;
}

int main(void) {
  mi_process_init();
  arena_size = mi_arena_min_size();
  size_t alignment = mi_arena_min_alignment();
  void* mapping = mmap(NULL, arena_size + alignment, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) abort();
  base = ((uintptr_t)mapping + alignment - 1) & ~(alignment - 1);
  mi_arena_id_t arena;
  if (!mi_manage_memory((void*)base, arena_size, false, false, true, -1, false,
                        commit_memory, NULL, &arena)) abort();
  armed = true;
  unsigned char* block = mi_malloc(100000);
  armed = false;
  if (block == NULL) abort();
  memset(block, 0x5a, 100000);
  bool bytes = true;
  for (size_t i = 0; i < 100000; i++) bytes = bytes && block[i] == 0x5a;
  puts("CRABC_COLD_ARENA_PREFIX_RETRY_BEGIN");
  printf("metadata.calls=%zu\nmetadata.bytes=%zu\nprefix.calls=%zu\nprefix.bytes=%zu\n",
         metadata_calls, metadata_bytes, prefix_calls, prefix_bytes);
  printf("prefix.refused_bytes=%zu\n", refused_bytes);
  printf("prefix.same=%d\nclient.in_arena=%d\nclient.owned=%d\nclient.bytes=%d\n",
         same_prefix, (uintptr_t)block >= base && (uintptr_t)block < base + arena_size,
         mi_check_owned(block) && mi_heap_contains(mi_heap_main(), block), bytes);
  puts("CRABC_COLD_ARENA_PREFIX_RETRY_END");
  mi_free(block);
  return 0;
}
