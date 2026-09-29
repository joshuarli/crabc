/* Two foreign frees straddle one normal owner exit. The first publication is
   collected by the exiting owner; the second claims its abandoned page. */
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private source fixture requires native Linux/x86-64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the pinned release configuration
#endif

#define REQUEST (64 * 1024)

static sem_t owner_ready;
static sem_t first_go;
static sem_t first_done;
static sem_t owner_exit_go;
static void* clients[3];
static mi_page_t* page;
static size_t capacity;
static int setup_valid;
static size_t first_usable;

static void* owner(void* ignored) {
  (void)ignored;
  mi_thread_init();
  for (size_t i = 0; i < 3; i++) {
    clients[i] = mi_malloc_aligned(REQUEST, 16);
    if (clients[i] == NULL) goto publish;
  }
  page = _mi_ptr_page(clients[0]);
  if (page == NULL) goto publish;
  capacity = page->reserved;
  setup_valid = capacity > 3 && _mi_ptr_page(clients[1]) == page
      && _mi_ptr_page(clients[2]) == page && page->used == 3;
publish:
  sem_post(&owner_ready);
  sem_wait(&owner_exit_go);
  mi_thread_done();
  return NULL;
}

static void* first_publisher(void* ignored) {
  (void)ignored;
  mi_thread_init();
  sem_wait(&first_go);
  first_usable = mi_usable_size(clients[0]);
  mi_free(clients[0]);
  sem_post(&first_done);
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_page_full_retain, -1);
  mi_option_set(mi_option_page_reclaim_on_free, 1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  if (sem_init(&owner_ready, 0, 0) != 0 || sem_init(&first_go, 0, 0) != 0
      || sem_init(&first_done, 0, 0) != 0 || sem_init(&owner_exit_go, 0, 0) != 0) return 2;
  pthread_t a;
  pthread_t b;
  if (pthread_create(&a, NULL, owner, NULL) != 0
      || pthread_create(&b, NULL, first_publisher, NULL) != 0) return 2;
  sem_wait(&owner_ready);
  if (!setup_valid) return 3;
  sem_post(&first_go);
  sem_wait(&first_done);
  if (pthread_join(b, NULL) != 0) return 2;
  int first_registered = _mi_safe_ptr_page(clients[2]) == page;
  size_t used_before_exit = page->used;
  int first_head_nonempty = mi_tf_block(mi_atomic_load_relaxed(&page->xthread_free)) != NULL;
  sem_post(&owner_exit_go);
  if (pthread_join(a, NULL) != 0) return 2;
  int registered_after_exit = _mi_safe_ptr_page(clients[2]) == page;
  size_t used_after_exit = page->used;
  int abandoned_after_exit = mi_page_is_abandoned(page);
  int unowned_after_exit = !mi_page_is_owned(page);
  size_t second_usable = mi_usable_size(clients[1]);
  mi_free(clients[1]);
  int registered_after_second = _mi_safe_ptr_page(clients[2]) == page;
  size_t used_after_second = page->used;
  int reclaimed_after_second = mi_page_is_owned(page) && !mi_page_is_abandoned(page)
      && page->theap == _mi_theap_default();
  mi_free(clients[2]);
  int registered_before_collect = _mi_safe_ptr_page(clients[2]) == page;
  size_t used_before_collect = page->used;
  unsigned retire_expire = page->retire_expire;
  mi_collect(true);
  int released_after_collect = !mi_is_in_heap_region(clients[2]);
  mi_collect(true);
  int still_released = !mi_is_in_heap_region(clients[2]);
  void* survivor = mi_malloc(64);
  int survivor_usable = survivor != NULL;
  mi_free(survivor);
  printf("CRABC_MI_M5_OWNER_EXIT_LATE_REMOTE_BEGIN\n");
  printf("full_retain_negative_one=%d\nreclaim_on_free=%ld\nrequest=%d\ncapacity=%zu\n",
      mi_option_get(mi_option_page_full_retain) == -1,
      mi_option_get(mi_option_page_reclaim_on_free), REQUEST, capacity);
  printf("setup_valid=%d\nfirst_usable=%zu\nfirst_registered=%d\nused_before_exit=%zu\nfirst_head_nonempty=%d\n",
      setup_valid, first_usable, first_registered, used_before_exit, first_head_nonempty);
  printf("registered_after_exit=%d\nused_after_exit=%zu\nabandoned_after_exit=%d\nunowned_after_exit=%d\n",
      registered_after_exit, used_after_exit, abandoned_after_exit, unowned_after_exit);
  printf("second_usable=%zu\nregistered_after_second=%d\nused_after_second=%zu\nreclaimed_after_second=%d\n",
      second_usable, registered_after_second, used_after_second, reclaimed_after_second);
  printf("registered_before_collect=%d\nused_before_collect=%zu\nretire_expire=%u\n",
      registered_before_collect, used_before_collect, retire_expire);
  printf("released_after_collect=%d\nstill_released=%d\nsurvivor_usable=%d\n",
      released_after_collect, still_released, survivor_usable);
  printf("CRABC_MI_M5_OWNER_EXIT_LATE_REMOTE_END\n");
  return 0;
}
