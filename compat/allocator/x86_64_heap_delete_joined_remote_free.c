#define _GNU_SOURCE 1
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <mimalloc.h>
static void* release(void* argument) { mi_free(argument); return NULL; }
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);
  mi_heap_t* heap=mi_heap_new(); assert(heap);
  unsigned char* block=mi_heap_malloc(heap,80); assert(block);
  memset(block,0x5a,80);
  pthread_t t; assert(pthread_create(&t,NULL,release,block)==0);
  assert(pthread_join(t,NULL)==0);
  puts("remote-free-joined");
  mi_heap_delete(heap);
  puts("heap-deleted");
  return 0;
}
