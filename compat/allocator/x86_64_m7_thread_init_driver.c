/* Shared C driver for the allocator M7 thread-initialization failure
   differential.

   Linked once against the pinned mimalloc v3.5.0 release sources and once
   against the native Rust adapter, each run as its own process. Metadata
   allocation fails deterministically once `disallow_arena_alloc` and
   `disallow_os_alloc` are set and the metadata Theap has no free block of
   the requested size:

   - `tld`: the first worker ever needs a fresh TLD metadata page, so
     `mi_tld_create` fails (`src/init.c:267-269`), on each allocation, until
     the options are cleared;
   - `theap`: live filler threads fill the metadata Theap's `mi_theap_t` size
     class while its TLD class keeps room; a probe after each filler finds
     the first filler count at which `_mi_theap_alloc` fails
     (`src/theap.c:327-329`).

   Every worker still runs and exits normally. Output fragments are captured
   with the thread identity replaced by `0xTID`. Driven by
   `compat/allocator/x86_64_m7_gate.py --thread-init-differential`. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "mimalloc.h"

#define MAX_FILLERS 256

static char messages[8192];
static size_t message_length;

/* Appends one fragment with each `thread 0x<hex>: ` normalized. */
static void capture(const char* message, void* argument) {
  (void)argument;
  for (const char* p = message; *p != 0 && message_length + 16 < sizeof(messages); ) {
    if (strncmp(p, "thread 0x", 9) == 0) {
      const char* q = p + 9;
      while ((*q >= '0' && *q <= '9') || (*q >= 'A' && *q <= 'F')) q++;
      if (q[0] == ':' && q[1] == ' ') {
        memcpy(messages + message_length, "thread 0xTID: ", 14);
        message_length += 14;
        p = q + 2;
        continue;
      }
    }
    messages[message_length++] = *p++;
  }
  messages[message_length] = 0;
}

static void print_messages(const char* key) {
  printf("%s=", key);
  for (size_t i = 0; i < message_length; i++) printf("%02x", (unsigned char)messages[i]);
  printf("\n");
  message_length = 0;
  messages[0] = 0;
}

static void disallow(bool on) {
  mi_option_set_enabled(mi_option_disallow_os_alloc, on);
  mi_option_set_enabled(mi_option_disallow_arena_alloc, on);
}

static int worker_results[4];
static int worker_errnos[4];

static void* tld_worker(void* argument) {
  (void)argument;
  for (int i = 0; i < 2; i++) {
    errno = 0;
    void* p = mi_malloc(64);
    worker_results[i] = (p != NULL);
    worker_errnos[i] = errno;
    mi_free(p);
  }
  disallow(false);
  errno = 0;
  void* p = mi_malloc(64);
  worker_results[2] = (p != NULL);
  worker_errnos[2] = errno;
  mi_free(p);
  return NULL;
}

static sem_t filler_ready;
static sem_t release_fillers;

static void* filler(void* argument) {
  (void)argument;
  void* p = mi_malloc(8);
  sem_post(&filler_ready);
  sem_wait(&release_fillers);
  mi_free(p);
  return NULL;
}

static void* probe(void* argument) {
  (void)argument;
  errno = 0;
  void* p = mi_malloc(8);
  worker_results[0] = (p != NULL);
  worker_errnos[0] = errno;
  mi_free(p);
  return NULL;
}

int main(void) {
  mi_register_output(&capture, NULL);
  message_length = 0;
  mi_option_enable(mi_option_show_errors);
  printf("CRABC_MI_M7_THREAD_INIT_TRACE_BEGIN\n");
  void* initial = mi_malloc(64);
  printf("initial=%d\n", initial != NULL);
  mi_free(initial);

  disallow(true);
  pthread_t thread;
  if (pthread_create(&thread, NULL, tld_worker, NULL) != 0 || pthread_join(thread, NULL) != 0) return 3;
  printf("tld.results=%d,%d,%d\ntld.errno=%d,%d,%d\n", worker_results[0], worker_results[1], worker_results[2],
         worker_errnos[0], worker_errnos[1], worker_errnos[2]);
  print_messages("tld.messages");

  sem_init(&filler_ready, 0, 0);
  sem_init(&release_fillers, 0, 0);
  pthread_t fillers[MAX_FILLERS];
  int count = 0;
  for (; count < MAX_FILLERS; count++) {
    if (pthread_create(&fillers[count], NULL, filler, NULL) != 0) return 3;
    sem_wait(&filler_ready);
    disallow(true);
    message_length = 0;
    if (pthread_create(&thread, NULL, probe, NULL) != 0 || pthread_join(thread, NULL) != 0) return 3;
    disallow(false);
    if (strstr(messages, "meta-data") != NULL || strstr(messages, "thread local data") != NULL) break;
  }
  printf("theap.fillers=%d\ntheap.result=%d\ntheap.errno=%d\n", count + 1, worker_results[0], worker_errnos[0]);
  print_messages("theap.messages");
  for (int i = 0; i <= count && i < MAX_FILLERS; i++) sem_post(&release_fillers);
  for (int i = 0; i <= count && i < MAX_FILLERS; i++) pthread_join(fillers[i], NULL);
  printf("CRABC_MI_M7_THREAD_INIT_TRACE_END\n");
  return 0;
}
