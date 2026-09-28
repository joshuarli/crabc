/* An active survivor reclaims a full medium page from an exited owner.
   Its last local free retires the regular page; forced collection later
   releases that page independently of the OS singleton. */
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

#define MEDIUM_REQUEST (64 * 1024)
#define MAX_CLIENTS 32
#define SINGLETON_ALIGNMENT (128 * 1024)

static sem_t ready;
static sem_t exit_go;
static void* medium[MAX_CLIENTS];
static size_t medium_count;
static void* singleton;
static mi_page_t* medium_page;
static mi_page_t* singleton_page;
static int setup_valid;

static void* owner(void* ignored) {
  (void)ignored;
  mi_thread_init();
  medium[0] = mi_malloc_aligned(MEDIUM_REQUEST, 16);
  if (medium[0] == NULL) goto publish;
  medium_page = _mi_ptr_page(medium[0]);
  if (medium_page == NULL || medium_page->reserved < 2 || medium_page->reserved > MAX_CLIENTS) goto publish;
  medium_count = medium_page->reserved;
  for (size_t i = 1; i < medium_count; i++) {
    medium[i] = mi_malloc_aligned(MEDIUM_REQUEST, 16);
    if (medium[i] == NULL || _mi_ptr_page(medium[i]) != medium_page) goto publish;
  }
  void* trigger = mi_malloc_aligned(MEDIUM_REQUEST, 16);
  if (trigger == NULL || _mi_ptr_page(trigger) == medium_page) goto publish;
  mi_free(trigger);
  singleton = mi_malloc_aligned(MI_SMALL_MAX_OBJ_SIZE + 1, SINGLETON_ALIGNMENT);
  if (singleton == NULL) goto publish;
  singleton_page = _mi_ptr_page(singleton);
  setup_valid = singleton_page != NULL && singleton_page != medium_page
      && medium_page->used == medium_count && mi_page_is_in_full(medium_page)
      && singleton_page->memid.memkind == MI_MEM_OS && singleton_page->used == 1
      && mi_page_is_in_full(singleton_page);
publish:
  sem_post(&ready);
  sem_wait(&exit_go);
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_page_full_retain, -1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  if (sem_init(&ready, 0, 0) != 0 || sem_init(&exit_go, 0, 0) != 0) return 2;
  pthread_t worker;
  if (pthread_create(&worker, NULL, owner, NULL) != 0) return 2;
  if (sem_wait(&ready) != 0) return 2;
  if (!setup_valid) return 3;
  mi_free(medium[0]);
  sem_post(&exit_go);
  if (pthread_join(worker, NULL) != 0) return 2;
  int remote_collected = medium_page->used == medium_count - 1;
  int singleton_live = _mi_ptr_page(singleton) == singleton_page;
  mi_free(singleton);
  int singleton_released = !mi_is_in_heap_region(singleton);
  int medium_reclaimed = 0;
  for (size_t i = 1; i < medium_count; i++) {
    mi_free(medium[i]);
    if (i == 1) {
      mi_page_t* live = _mi_safe_ptr_page(medium[2]);
      medium_reclaimed = live == medium_page && live->used == medium_count - 2
          && mi_page_is_owned(live) && !mi_page_is_abandoned(live)
          && live->theap == _mi_theap_default();
    }
  }
  mi_page_t* retired = _mi_safe_ptr_page(medium[1]);
  int medium_registered_before_collect = retired == medium_page;
  size_t medium_retired_used = retired == NULL ? (size_t)-1 : retired->used;
  unsigned medium_retired_expire = retired == NULL ? 0 : retired->retire_expire;
  mi_collect(true);
  int medium_released_after_collect = !mi_is_in_heap_region(medium[1]);
  void* survivor = mi_malloc(64);
  int survivor_usable = survivor != NULL;
  mi_free(survivor);
  printf("CRABC_MI_ACTIVE_MIXED_OWNER_EXIT_BEGIN\n");
  printf("full_retain=%ld\n", mi_option_get(mi_option_page_full_retain));
  printf("medium_capacity=%zu\n", medium_count);
  printf("medium_full=1\nsingleton_os_full=1\n");
  printf("remote_collected=%d\nsingleton_live_after_exit=%d\n", remote_collected, singleton_live);
  printf("singleton_released=%d\nmedium_reclaimed=%d\n", singleton_released, medium_reclaimed);
  printf("medium_retired_used=%zu\nmedium_retired_expire=%u\n", medium_retired_used, medium_retired_expire);
  printf("medium_registered_before_collect=%d\nmedium_released_after_collect=%d\n",
      medium_registered_before_collect, medium_released_after_collect);
  printf("survivor_usable=%d\n", survivor_usable);
  printf("CRABC_MI_ACTIVE_MIXED_OWNER_EXIT_END\n");
  return 0;
}
