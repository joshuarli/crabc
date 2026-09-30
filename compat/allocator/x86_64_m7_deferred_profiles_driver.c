#define _GNU_SOURCE
#include <mimalloc.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this fixture requires native Linux/x86_64
#endif

struct event { unsigned long long heartbeat; int force, phase, context, owner, nested, suppressed; };
static struct event events[128];
static size_t count;
static int phase, marker, null_context, worker_case;
static size_t request = 524289;
static pthread_t expected_owner;
static _Thread_local int depth;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int ready, proceed;

static void fail(const char* stage) { fprintf(stderr, "deferred fixture failed: %s\n", stage); abort(); }

static void callback(bool force, unsigned long long heartbeat, void* argument) {
  if (depth || count == 128) fail("callback reentry or event overflow");
  depth++;
  size_t index = count++;
  events[index] = (struct event){ heartbeat, force, phase,
    argument == (null_context ? NULL : &marker), pthread_equal(pthread_self(), expected_owner), 0, 0 };
  size_t before = count;
  // A separate live allocation makes callback reentry cross the public API.
  // Its storage belongs to this invocation and never aliases an outer client.
  unsigned char* p = mi_malloc(request);
  if (p == NULL) {
    fprintf(stderr, "nested request=%zu errno=%d heartbeat=%llu force=%d phase=%d\n", request, errno, heartbeat, force, phase);
    fail("nested allocation");
  }
  p[0] = 0x41; p[request - 1] = 0x7d;
  if (p[0] != 0x41 || p[request - 1] != 0x7d) fail("nested content");
  mi_free(p);
  events[index].nested = 1;
  events[index].suppressed = count == before && depth == 1;
  depth--;
}

static void warm(void) {
  void* p = mi_malloc(33);
  if (!p) fail("warm allocation");
  mi_free(p);
}

static void* worker(void* unused) {
  (void)unused;
  warm();
  pthread_mutex_lock(&lock);
  expected_owner = pthread_self(); ready = 1;
  pthread_cond_broadcast(&condition);
  while (!proceed) pthread_cond_wait(&condition, &lock);
  pthread_mutex_unlock(&lock);
  phase = 2;
  mi_collect(false);
  phase = 3;
  // Returning, rather than an explicit teardown call, exercises the owning
  // allocator's pthread destructor while the callback context remains live.
  return NULL;
}

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  worker_case = strcmp(argv[1], "worker") == 0 || strcmp(argv[1], "worker-small") == 0;
  null_context = strcmp(argv[1], "null") == 0 || strcmp(argv[1], "null-small") == 0;
  if (!worker_case && !null_context && strcmp(argv[1], "same") != 0 && strcmp(argv[1], "same-small") != 0) return 2;
  if (strstr(argv[1], "-small")) request = 33;
  warm();
  pthread_t thread;
  if (worker_case) {
    if (pthread_create(&thread, NULL, worker, NULL)) fail("pthread_create");
    pthread_mutex_lock(&lock);
    while (!ready) pthread_cond_wait(&condition, &lock);
    pthread_mutex_unlock(&lock);
  } else expected_owner = pthread_self();
  marker = 23;
  mi_register_deferred_free(callback, null_context ? NULL : &marker);
  if (worker_case) {
    pthread_mutex_lock(&lock); proceed = 1;
    pthread_cond_broadcast(&condition); pthread_mutex_unlock(&lock);
    if (pthread_join(thread, NULL)) fail("pthread_join");
  } else {
    phase = 1; mi_collect(false);
    phase = 2; mi_collect(true);
    phase = 3; mi_collect(false);
  }
  size_t before = count;
  mi_register_deferred_free(NULL, NULL);
  phase = 4; mi_collect(false); mi_collect(true);
  warm();
  if (count != before || !count) fail("unregister or missing callback");
  int exit_forced = 0;
  for (size_t i = 0; i < count; i++) {
    const struct event* e = &events[i];
    if (!e->context || !e->owner || !e->nested || !e->suppressed) fail("callback ownership");
    if (worker_case && e->phase == 3 && e->force) exit_forced++;
    printf("event.%zu.heartbeat=%llu\nevent.%zu.force=%d\nevent.%zu.phase=%d\n", i, e->heartbeat, i, e->force, i, e->phase);
    printf("event.%zu.context=%d\nevent.%zu.owner=%d\nevent.%zu.nested=%d\nevent.%zu.suppressed=%d\n",
      i, e->context, i, e->owner, i, e->nested, i, e->suppressed);
  }
  if (worker_case && exit_forced != 1) fail("natural exit force selection");
  printf("allocation.request=%zu\n", request);
  printf("callback.count=%zu\nunregister.quiet=1\ncontext.null=%d\nworker.exit_forced=%d\n", count, null_context, exit_forced);
  return 0;
}
