#include <errno.h>
#include <mimalloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

/* This passes the arena size precheck, then forces the aligned OS map and
   over-allocation map to fail in the kernel's finite user address space. */
enum { IMPOSSIBLE_RESERVATION_SHIFT = 62 };

typedef struct {
  mi_subproc_id_t child;
  int joined;
} worker_fixture;

static void* worker_main(void* argument) {
  worker_fixture* fixture = (worker_fixture*)argument;
  mi_subproc_add_current_thread(fixture->child);
  mi_subproc_id_t current = mi_subproc_current();
  mi_arena_id_t id = (mi_arena_id_t)(uintptr_t)1;
  errno = E2BIG;
  int result = mi_reserve_os_memory_ex((size_t)1 << IMPOSSIBLE_RESERVATION_SHIFT,
                                        true, false, true, &id);
  printf("child.reserve=%d,%d,%d,%d\n", current._mi_subproc_id == fixture->child._mi_subproc_id,
         result, id == NULL, errno);
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_enable(mi_option_show_errors);
  puts("CRABC_MI_M6_RESERVATION_WARNING_BEGIN");

  mi_arena_id_t id = (mi_arena_id_t)(uintptr_t)1;
  errno = E2BIG;
  int result = mi_reserve_os_memory_ex((size_t)1 << IMPOSSIBLE_RESERVATION_SHIFT,
                                        true, false, true, &id);
  printf("main.reserve=%d,%d,%d\n", result, id == NULL, errno);

  worker_fixture fixture = { mi_subproc_new(), 0 };
  pthread_t worker;
  if (fixture.child._mi_subproc_id == NULL || pthread_create(&worker, NULL, worker_main, &fixture) != 0) {
    return 2;
  }
  fixture.joined = pthread_join(worker, NULL) == 0;
  mi_subproc_destroy(fixture.child);
  printf("child.terminal=%d\n", fixture.joined);
  puts("CRABC_MI_M6_RESERVATION_WARNING_END");
  return 0;
}
