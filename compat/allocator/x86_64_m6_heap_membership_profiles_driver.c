#define _GNU_SOURCE
#include "mimalloc.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static void required(int condition) { if (!condition) exit(2); }
static void membership(const char* key, mi_heap_t* owner, mi_heap_t* other, const void* p) {
  printf("%s=%d,%d,%d,%d,%d,%d\n", key, mi_heap_of(p)==owner,
      mi_heap_contains(owner,p), mi_heap_contains(other,p), mi_heap_contains(NULL,p),
      mi_any_heap_contains(p), mi_is_in_heap_region(p));
}

struct query { mi_heap_t* heap; void* p; int errors; };
static void* query_worker(void* argument) {
  struct query* q=argument;
  /* The owner retains this Heap and client and makes no allocation, free,
   * collection, or Heap move until both readers have joined. */
  for (size_t i=0; i<200; ++i)
    if (mi_heap_of(q->p)!=q->heap || !mi_heap_contains(q->heap,q->p) ||
        !mi_any_heap_contains(q->p) || !mi_is_in_heap_region(q->p)) q->errors++;
  return NULL;
}
static void* remote_free(void* argument) { mi_free(argument); return NULL; }

struct retained_owner {
  mi_subproc_id_t subprocess;
  int child;
  mi_heap_t* main;
  mi_heap_t* auxiliary;
  void* main_block;
  void* auxiliary_block;
};
static void* exiting_owner(void* argument) {
  struct retained_owner* owner=argument;
  if (owner->child) mi_subproc_add_current_thread(owner->subprocess);
  owner->main=mi_heap_main();
  owner->auxiliary=mi_heap_new();
  required(owner->main!=NULL && owner->auxiliary!=NULL);
  owner->main_block=mi_heap_malloc(owner->main,333);
  owner->auxiliary_block=mi_heap_malloc(owner->auxiliary,777);
  required(owner->main_block!=NULL && owner->auxiliary_block!=NULL);
  memset(owner->main_block,0x39,333);
  memset(owner->auxiliary_block,0x73,777);
  return NULL;
}
static void owner_exit_case(int child, mi_heap_t* root_main) {
  struct retained_owner owner={0};
  owner.child=child;
  if (child) { owner.subprocess=mi_subproc_new(); required(owner.subprocess._mi_subproc_id!=NULL); }
  pthread_t thread;
  required(pthread_create(&thread,NULL,exiting_owner,&owner)==0);
  required(pthread_join(thread,NULL)==0);
  printf("owner%d.identity=%d\n",child,owner.main==root_main);
  char key[80];
  snprintf(key,sizeof key,"owner%d.main",child);
  membership(key,owner.main,owner.auxiliary,owner.main_block);
  snprintf(key,sizeof key,"owner%d.auxiliary",child);
  membership(key,owner.auxiliary,owner.main,owner.auxiliary_block);
  mi_heap_delete(owner.auxiliary);
  /* Deletion moves live pages to the subprocess main Heap. The released
   * auxiliary identity is never passed to a later query. */
  snprintf(key,sizeof key,"owner%d.moved",child);
  membership(key,owner.main,root_main,owner.auxiliary_block);
  printf("owner%d.content=%d,%d\n",child,
      ((unsigned char*)owner.main_block)[332]==0x39,
      ((unsigned char*)owner.auxiliary_block)[776]==0x73);
  mi_free(owner.main_block); mi_free(owner.auxiliary_block);
  if (child) mi_subproc_destroy(owner.subprocess);
}

static void utilization_case(mi_heap_t* main) {
  enum { COUNT=512 };
  void* blocks[COUNT];
  uintptr_t pages[COUNT];
  size_t page_count=0, counts[COUNT]={0}, groups[COUNT];
  mi_heap_t* heap=mi_heap_new(); required(heap!=NULL);
  for (size_t i=0; i<COUNT; ++i) {
    blocks[i]=mi_heap_malloc(heap,1024); required(blocks[i]!=NULL);
    uintptr_t page=(uintptr_t)blocks[i]/65536;
    size_t group=0;
    while (group<page_count && pages[group]!=page) ++group;
    if (group==page_count) pages[page_count++]=page;
    groups[i]=group; counts[group]++;
  }
  required(page_count>=3 && counts[0]>2 && counts[1]>2);
  void* retained[2]={NULL,NULL};
  /* The first two ordinary 64-KiB pages fill before later pages.
   * Unfulling appends them behind the current allocation queue head. */
  for (size_t group=0; group<2; ++group)
    for (size_t i=0; i<COUNT; ++i) if (groups[i]==group) {
      if (retained[group]==NULL) retained[group]=blocks[i];
      else { mi_free(blocks[i]); blocks[i]=NULL; }
    }
  printf("utilization.geometry=%zu,%zu,%zu\n",page_count,counts[0],counts[1]);
  for (size_t i=0; i<2; ++i) {
    printf("utilization.page%zu=%d,%d,%d,%d,%d,%d\n",i,
        mi_unsafe_heap_page_is_under_utilized(heap,retained[i],0),
        mi_unsafe_heap_page_is_under_utilized(heap,retained[i],50),
        mi_unsafe_heap_page_is_under_utilized(heap,retained[i],100),
        mi_unsafe_heap_page_is_under_utilized(NULL,retained[i],100),
        mi_unsafe_heap_page_is_under_utilized(main,retained[i],100),
        mi_unsafe_heap_page_is_under_utilized(heap,retained[i],101));
  }
  required(mi_unsafe_heap_page_is_under_utilized(heap,retained[0],100));
  for (size_t i=0; i<COUNT; ++i) if (blocks[i]!=NULL) mi_free(blocks[i]);
  mi_heap_delete(heap);
}

int main(void) {
  mi_option_set(mi_option_show_errors,0);
  mi_heap_t* main=mi_heap_main(); mi_heap_t* heap=mi_heap_new(); required(main!=NULL && heap!=NULL);
  int stack=0;
  void* foreign=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  required(foreign!=MAP_FAILED);
  membership("null",NULL,heap,NULL);
  membership("stack",NULL,heap,&stack);
  membership("foreign",NULL,heap,foreign);
  printf("utilization.foreign=%d,%d,%d\n",
      mi_unsafe_heap_page_is_under_utilized(NULL,NULL,100),
      mi_unsafe_heap_page_is_under_utilized(heap,&stack,100),
      mi_unsafe_heap_page_is_under_utilized(NULL,foreign,100));
  required(munmap(foreign,4096)==0);
  const size_t sizes[]={1,16,64,512,1024,8192,262144,1048576};
  void* blocks[8];
  for (size_t i=0; i<8; ++i) {
    blocks[i]=mi_heap_malloc(heap,sizes[i]); required(blocks[i]!=NULL);
    memset(blocks[i],0x5a,sizes[i]);
    char key[80];snprintf(key,sizeof key,"live%zu.base",i);membership(key,heap,main,blocks[i]);
    snprintf(key,sizeof key,"live%zu.interior",i);
    membership(key,heap,main,(unsigned char*)blocks[i]+sizes[i]-1);
  }
  void* aligned=mi_heap_malloc_aligned(heap,73,256); required(aligned!=NULL);
  membership("aligned.base",heap,main,aligned);
  membership("aligned.interior",heap,main,(unsigned char*)aligned+72);
  struct query queries[2]={{heap,blocks[2],0},{heap,blocks[6],0}};
  pthread_t threads[2];
  for (size_t i=0;i<2;++i) required(pthread_create(&threads[i],NULL,query_worker,&queries[i])==0);
  for (size_t i=0;i<2;++i) required(pthread_join(threads[i],NULL)==0);
  printf("concurrent.errors=%d,%d\n",queries[0].errors,queries[1].errors);
  void* remote=mi_heap_malloc(heap,64); required(remote!=NULL);
  required(pthread_create(&threads[0],NULL,remote_free,remote)==0);
  required(pthread_join(threads[0],NULL)==0);
  membership("remote.joined",heap,main,blocks[2]);
  mi_heap_collect(heap,true);
  membership("remote.drained",heap,main,blocks[2]);
  mi_heap_delete(heap);
  for (size_t i=0; i<8; ++i) {
    char key[80];snprintf(key,sizeof key,"moved%zu",i);
    membership(key,main,main,(unsigned char*)blocks[i]+sizes[i]-1);
    printf("content%zu=%d\n",i,((unsigned char*)blocks[i])[sizes[i]-1]==0x5a);
    mi_free(blocks[i]);
  }
  membership("aligned.moved",main,main,aligned); mi_free(aligned);
  utilization_case(main);
  owner_exit_case(0,main); owner_exit_case(1,main);
  return 0;
}
