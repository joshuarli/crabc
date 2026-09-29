/* A deferred-free callback allocates on the exiting owner's still-live Theap.
   Both clients must remain freeable after that Theap and its TLD are gone. */
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include <pthread.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this source fixture requires native Linux/x86-64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the pinned release configuration
#endif

#define REQUEST (64 * 1024)
static void* first;
static void* callback_client;
static mi_page_t* page;
static size_t callbacks;
static size_t callback_force;
static size_t callback_same_page;
static size_t callback_used;

static void deferred_callback(bool force, unsigned long long heartbeat, void* context) {
  (void)heartbeat;
  (void)context;
  callbacks++;
  callback_force += force;
  callback_client = mi_malloc_aligned(REQUEST, 16);
  if (callback_client != NULL) {
    callback_same_page = (_mi_ptr_page(callback_client) == page);
    callback_used = page->used;
  }
}

static void* owner(void* ignored) {
  (void)ignored;
  mi_thread_init();
  first = mi_malloc_aligned(REQUEST, 16);
  if (first == NULL) return NULL;
  page = _mi_ptr_page(first);
  mi_register_deferred_free(deferred_callback, NULL);
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_page_reclaim_on_free, 1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  pthread_t worker;
  if (pthread_create(&worker, NULL, owner, NULL) != 0 || pthread_join(worker, NULL) != 0) return 2;
  mi_register_deferred_free(NULL, NULL);
  if (page == NULL || callback_client == NULL) return 3;
  size_t first_usable = mi_usable_size(first);
  size_t callback_usable = mi_usable_size(callback_client);
  size_t used_after_exit = page->used;
  int abandoned_after_exit = mi_page_is_abandoned(page);
  int unowned_after_exit = !mi_page_is_owned(page);
  int first_registered = (_mi_safe_ptr_page(first) == page);
  int callback_registered = (_mi_safe_ptr_page(callback_client) == page);
  mi_free(first);
  size_t used_after_first = page->used;
  int reclaimed_after_first = mi_page_is_owned(page) && !mi_page_is_abandoned(page)
      && page->theap == _mi_theap_default();
  int second_registered = (_mi_safe_ptr_page(callback_client) == page);
  mi_free(callback_client);
  unsigned retire_expire = page->retire_expire;
  int registered_before_collect = (_mi_safe_ptr_page(callback_client) == page);
  mi_collect(true);
  int released_after_collect = !mi_is_in_heap_region(callback_client);
  printf("CRABC_MI_M5_EXIT_CALLBACK_SURVIVOR_BEGIN\n");
  printf("request=%d\ncallbacks=%zu\ncallback_force=%zu\ncallback_same_page=%zu\ncallback_used=%zu\n", REQUEST, callbacks, callback_force, callback_same_page, callback_used);
  printf("first_usable=%zu\ncallback_usable=%zu\nused_after_exit=%zu\n", first_usable, callback_usable, used_after_exit);
  printf("abandoned_after_exit=%d\nunowned_after_exit=%d\nfirst_registered=%d\ncallback_registered=%d\n", abandoned_after_exit, unowned_after_exit, first_registered, callback_registered);
  printf("used_after_first=%zu\nreclaimed_after_first=%d\nsecond_registered=%d\nretire_expire=%u\nregistered_before_collect=%d\nreleased_after_collect=%d\nwarnings=0\n", used_after_first, reclaimed_after_first, second_registered, retire_expire, registered_before_collect, released_after_collect);
  printf("CRABC_MI_M5_EXIT_CALLBACK_SURVIVOR_END\n");
  return 0;
}
