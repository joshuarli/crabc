#define _GNU_SOURCE 1
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mimalloc.h"

typedef struct {
  mi_subproc_id_t child;
  mi_arena_id_t arena;
  mi_heap_t* heap;
  unsigned char* block;
  bool ready;
} fixture_t;

typedef struct {
  pthread_mutex_t lock;
  pthread_cond_t changed;
  bool ready;
  bool finish;
  fixture_t owned;
} attached_t;

static void* owner(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  if (mi_reserve_os_memory_ex(128 * 1024 * 1024, true, false, true,
                              &fixture->arena) != 0) return NULL;
  fixture->heap = mi_heap_new_in_arena(fixture->arena);
  if (fixture->heap == NULL) return NULL;
  fixture->block = (unsigned char*)mi_heap_malloc(fixture->heap, 80);
  if (fixture->block == NULL) return NULL;
  fixture->block[0] = 71;
  fixture->ready = mi_heap_of(fixture->block) == fixture->heap;
  return NULL;
}

static void retire_copy(fixture_t* fixture, const char* prefix) {
  printf("%s.inherited=%d,%d\n", prefix, fixture->block[0] == 71,
         mi_heap_of(fixture->block) == fixture->heap);
  mi_free(fixture->block);
  printf("%s.remote=%d\n", prefix,
         !mi_is_in_heap_region(fixture->block));
  mi_heap_destroy(fixture->heap);
  printf("%s.heap_destroyed=1\n", prefix);
  mi_subproc_destroy(fixture->child);
  printf("%s.retired=%d\n", prefix,
         mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id);
}

static void* attached_owner(void* argument) {
  attached_t* attached = (attached_t*)argument;
  fixture_t* fixture = &attached->owned;
  mi_subproc_add_current_thread(fixture->child);
  if (mi_reserve_os_memory_ex(128 * 1024 * 1024, true, false, true,
                              &fixture->arena) == 0) {
    fixture->heap = mi_heap_new_in_arena(fixture->arena);
  }
  if (fixture->heap != NULL) fixture->block = (unsigned char*)mi_heap_malloc(fixture->heap, 80);
  if (fixture->block != NULL) fixture->block[0] = 83;
  pthread_mutex_lock(&attached->lock);
  fixture->ready = fixture->block != NULL && mi_heap_of(fixture->block) == fixture->heap;
  attached->ready = true;
  pthread_cond_signal(&attached->changed);
  while (fixture->ready && !attached->finish) pthread_cond_wait(&attached->changed, &attached->lock);
  pthread_mutex_unlock(&attached->lock);
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_CHILD_ARENA_FORK_OWNER_BEGIN");
  fixture_t fixture = { .child = mi_subproc_new() };
  if (fixture.child._mi_subproc_id == NULL) return 2;
  pthread_t thread;
  if (pthread_create(&thread, NULL, owner, &fixture) != 0) return 3;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 4;
  printf("fork.owner_exited=%d,%d\n", fixture.ready,
         mi_heap_of(fixture.block) == fixture.heap);
  pid_t child = fork();
  if (child < 0) return 5;
  if (child == 0) {
    retire_copy(&fixture, "fork.child");
    _exit(0);
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child) return 6;
  printf("fork.wait=%d\n", WIFEXITED(status) && WEXITSTATUS(status) == 0);
  retire_copy(&fixture, "fork.parent");

  attached_t attached = {
      .lock = PTHREAD_MUTEX_INITIALIZER,
      .changed = PTHREAD_COND_INITIALIZER,
      .owned = { .child = mi_subproc_new() },
  };
  if (attached.owned.child._mi_subproc_id == NULL) return 8;
  if (pthread_create(&thread, NULL, attached_owner, &attached) != 0) return 9;
  pthread_mutex_lock(&attached.lock);
  while (!attached.ready) pthread_cond_wait(&attached.changed, &attached.lock);
  pthread_mutex_unlock(&attached.lock);
  if (!attached.owned.ready) return 10;
  printf("fork.attached_live=%d,%d\n", attached.owned.block[0] == 83,
         mi_heap_of(attached.owned.block) == attached.owned.heap);
  pid_t attached_child = fork();
  if (attached_child < 0) return 11;
  if (attached_child == 0) {
    mi_subproc_destroy(attached.owned.child);
    printf("fork.vanished_retired=%d\n",
           mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id);
    _exit(0);
  }
  if (waitpid(attached_child, &status, 0) != attached_child) return 12;
  printf("fork.vanished_wait=%d\n", WIFEXITED(status) && WEXITSTATUS(status) == 0);
  pthread_mutex_lock(&attached.lock);
  attached.finish = true;
  pthread_cond_signal(&attached.changed);
  pthread_mutex_unlock(&attached.lock);
  if (pthread_join(thread, NULL) != 0) return 13;
  printf("fork.parent_owner_exited=%d\n", mi_heap_of(attached.owned.block) == attached.owned.heap);
  mi_subproc_destroy(attached.owned.child);
  printf("fork.parent_live_retired=%d\n",
         mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id);
  puts("CRABC_MI_M6_CHILD_ARENA_FORK_OWNER_END");
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 7;
}
