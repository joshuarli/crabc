/* Public remote free and owner collection on an ordinary debug page. */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include "mimalloc.h"

static unsigned char *blocks[3];
static uintptr_t freed_addresses[2];

static void *free_remote(void *unused) {
  (void)unused;
  mi_free(blocks[0]);
  mi_free(blocks[1]);
  return NULL;
}

int main(void) {
  pthread_t worker;
  for (unsigned index = 0; index < 3; index++) {
    blocks[index] = mi_malloc(17);
    if (blocks[index] == NULL || mi_usable_size(blocks[index]) != 17) return 2;
    blocks[index][0] = (unsigned char)(0x31 + index);
  }
  freed_addresses[0] = (uintptr_t)blocks[0];
  freed_addresses[1] = (uintptr_t)blocks[1];
  if (pthread_create(&worker, NULL, free_remote, NULL) != 0) return 3;
  if (pthread_join(worker, NULL) != 0) return 4;
  if (blocks[2][0] != 0x33) return 5;
  mi_collect(true);
  unsigned char *first = mi_malloc(17);
  unsigned char *second = mi_malloc(17);
  if (first == NULL || second == NULL) return 6;
  printf("CRABC_MI_DEBUG_REMOTE_TRACE_BEGIN\n");
  printf("usable=%zu\n", mi_usable_size(first));
  printf("other_usable=%zu\n", mi_usable_size(second));
  printf("survivor=%u\n", blocks[2][0]);
  printf("first_fill=%u\n", first[0]);
  printf("second_fill=%u\n", second[0]);
  unsigned reused_remote = ((uintptr_t)first == freed_addresses[0] || (uintptr_t)first == freed_addresses[1])
                         + ((uintptr_t)second == freed_addresses[0] || (uintptr_t)second == freed_addresses[1]);
  printf("reused_remote=%u\n", reused_remote);
  printf("CRABC_MI_DEBUG_REMOTE_TRACE_END\n");
  mi_free(first);
  mi_free(second);
  mi_free(blocks[2]);
  return 0;
}
