#include <mimalloc.h>
#include <stdio.h>

int main(void) {
  mi_heap_t* heap = mi_heap_new();
  if (heap == NULL) return 1;
  mi_theap_t* selected = mi_heap_theap(heap);
  mi_theap_t* base = mi_theap_get_default();
  unsigned char* direct = mi_theap_realloc(selected, NULL, 0);
  if (direct == NULL) return 2;
  unsigned direct_byte = direct[0];
  mi_free(direct);
  mi_theap_set_default(selected);
  unsigned char* aligned = mi_realloc_aligned(NULL, 0, sizeof(void*));
  if (aligned == NULL) return 3;
  unsigned aligned_byte = aligned[0];
  mi_free(aligned);
  mi_theap_set_default(base);
  unsigned char* plain = mi_heap_realloc(heap, NULL, 0);
  if (plain == NULL) return 4;
  unsigned plain_byte = plain[0];
  mi_free(plain);
  unsigned char* at = mi_heap_realloc_aligned_at(heap, NULL, 0, sizeof(void*), 0);
  if (at == NULL) return 5;
  unsigned at_byte = at[0];
  mi_free(at);
  unsigned char* main_plain = mi_heap_realloc(mi_heap_main(), NULL, 0);
  if (main_plain == NULL) return 6;
  unsigned main_plain_byte = main_plain[0];
  mi_free(main_plain);
  unsigned char* main_aligned = mi_heap_realloc_aligned(mi_heap_main(), NULL, 0, sizeof(void*));
  if (main_aligned == NULL) return 7;
  unsigned main_aligned_byte = main_aligned[0];
  mi_free(main_aligned);
  mi_heap_delete(heap);
  printf("null-zero-bytes=%u,%u,%u,%u,%u,%u\n", direct_byte, aligned_byte, plain_byte, at_byte, main_plain_byte, main_aligned_byte);
  return aligned_byte != 0 || at_byte != 0 || main_aligned_byte != 0;
}
