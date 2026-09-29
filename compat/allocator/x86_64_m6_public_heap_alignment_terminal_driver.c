#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "mimalloc.h"

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set(mi_option_arena_reserve, 0);
  puts("CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_TERMINAL_BEGIN");
  mi_heap_t* heap = mi_heap_new();
  unsigned char* block = heap == NULL ? NULL :
      (unsigned char*)mi_heap_zalloc_aligned_at(heap, 81, 128, 11);
  bool ready = heap != NULL && block != NULL &&
      (((uintptr_t)block + 11) % 128) == 0 &&
      mi_heap_of(block) == heap && block[0] == 0 && block[80] == 0;
  printf("terminal.ready=%d\n", ready);
  if (heap != NULL) mi_heap_delete(heap);
  printf("terminal.deleted=%d,%d\n", block != NULL && mi_heap_of(block) == heap,
         block != NULL && block[0] == 0 && block[80] == 0);
  if (block != NULL) mi_free(block);
  puts("terminal.freed=1");
  mi_heap_t* destroyed = mi_heap_new();
  unsigned char* second = destroyed == NULL ? NULL :
      (unsigned char*)mi_heap_zalloc_aligned_at(destroyed, 81, 128, 11);
  bool second_ready = second != NULL && mi_heap_of(second) == destroyed &&
      second[0] == 0 && second[80] == 0;
  printf("terminal.second=%d\n", second_ready);
  if (destroyed != NULL) mi_heap_destroy(destroyed);
  puts("terminal.destroyed=1");
  errno = 0;
  void* after = mi_malloc(64);
  printf("terminal.after=%d,%d\n", after != NULL, errno == 0);
  if (after != NULL) mi_free(after);
  puts("CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_TERMINAL_END");
  _exit(ready && second_ready && after != NULL ? 0 : 2);
}
