/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned v3.5.0 arena abandonment interleavings that a foreign free or an
   arena reader reaches only between two source steps. Each scenario pauses
   one thread at a source memory access by revoking that access to one OS
   page; its SIGSEGV handler waits until the main thread has let another
   thread act and restored the page, and the access then retries.

   unown.first: the exiting owner's publication of its page's
   `pages_abandoned[bin]` bit (src/arena.c:1330-1331) faults. The freer frees
   the page's last block while the owner still holds the low owner bit
   (src/free.c:62-97), so `mi_abandoned_page_unown` sees it at its first head
   load and takes the all-free unabandon-and-free arm (src/arena.c:631-653).

   unown.cas and unown.cas_live: after that publication the owner's release
   CAS faults. The freer's publication makes the CAS fail; the retry collects
   it, and frees the page when no block is live, or releases ownership with
   the page still mapped when one block is.

   wait: the freer claims and collects the abandoned page, and the CAS of its
   `mi_bfield_atomic_clear_once_set` on that bitmap word faults
   (src/free.c:368-378, 483-515, src/arena.c:1384-1409). An arena reader then
   clears the bit and faults at its ownership claim (src/arena.c:655-671,
   725-778, src/bitmap.c:1340-1370). The freer's resumed CAS fails, so it
   counts one busy wait and spins (src/bitmap.c:109-129) until the reader's
   failed claim restores the bit, then frees the page.

   `crabc-mimalloc/tests/native_arena_abandonment_interleaving.rs` prints the
   same fields. */
#include "static.c"
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define REQUEST 10248
#define MAX_PAUSES 2

#define require(condition) \
  do { if (!(condition)) { fprintf(stderr, "m2_arena_abandonment_interleaving_x86_64.c:%d: %s\n", __LINE__, #condition); abort(); } } while (0)

enum { ROLE_OWNER = 1, ROLE_FREER = 2, ROLE_READER = 3, ROLE_COUNT = 4 };

typedef struct pause_s {
  _Atomic int role;
  _Atomic uintptr_t address;
  _Atomic int released;
} pause_t;

typedef struct mailbox_s {
  _Atomic int posted;
  _Atomic int completed;
} mailbox_t;

typedef struct span_s {
  mi_arena_t* arena;
  mi_arena_pages_t* pages;
  size_t slice;
  size_t count;
  size_t bin;
} span_t;

static uintptr_t os_page;
static _Atomic long role_tids[ROLE_COUNT];
static _Atomic uintptr_t armed[2];
static pause_t pauses[MAX_PAUSES];
static _Atomic int pause_count;
static struct sigaction default_fault;

static long current_tid(void) { return syscall(SYS_gettid); }

static int current_role(void) {
  const long tid = current_tid();
  for (int role = ROLE_OWNER; role < ROLE_COUNT; role++) {
    if (atomic_load_explicit(&role_tids[role], memory_order_acquire) == tid) return role;
  }
  return 0;
}

static void on_fault(int signal, siginfo_t* info, void* context) {
  (void)signal;
  (void)context;
  const uintptr_t address = (uintptr_t)info->si_addr;
  const uintptr_t base = address & ~(os_page - 1);
  const int role = current_role();
  const bool armed_page = base == atomic_load(&armed[0]) || base == atomic_load(&armed[1]);
  const int index = role != 0 && armed_page ? atomic_fetch_add(&pause_count, 1) : MAX_PAUSES;
  if (index >= MAX_PAUSES) {
    sigaction(SIGSEGV, &default_fault, NULL);
    return;
  }
  atomic_store_explicit(&pauses[index].address, address, memory_order_relaxed);
  atomic_store_explicit(&pauses[index].role, role, memory_order_release);
  while (!atomic_load_explicit(&pauses[index].released, memory_order_acquire)) sched_yield();
}

static double elapsed_since(const struct timespec* start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (double)(now.tv_sec - start->tv_sec) + (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

static void post(mailbox_t* box) { atomic_fetch_add_explicit(&box->posted, 1, memory_order_release); }

static void await_posted(mailbox_t* box, int count) {
  while (atomic_load_explicit(&box->posted, memory_order_acquire) < count) sched_yield();
}

static void complete(mailbox_t* box) { atomic_fetch_add_explicit(&box->completed, 1, memory_order_release); }

static void await_completed(mailbox_t* box, int count) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  while (atomic_load_explicit(&box->completed, memory_order_acquire) < count) {
    require(elapsed_since(&start) < 30);
    sched_yield();
  }
}

static void register_role(int role) {
  atomic_store_explicit(&role_tids[role], current_tid(), memory_order_release);
}

static void reset_pauses(void) {
  for (int i = 0; i < MAX_PAUSES; i++) {
    atomic_store(&pauses[i].role, 0);
    atomic_store(&pauses[i].address, 0);
    atomic_store(&pauses[i].released, 0);
  }
  atomic_store(&pause_count, 0);
}

static uintptr_t await_pause(int index, int role) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  while (atomic_load_explicit(&pauses[index].role, memory_order_acquire) == 0) {
    require(elapsed_since(&start) < 30);
    sched_yield();
  }
  require(atomic_load(&pauses[index].role) == role);
  return atomic_load_explicit(&pauses[index].address, memory_order_relaxed);
}

static void release_pause(int index) { atomic_store_explicit(&pauses[index].released, 1, memory_order_release); }

static uintptr_t page_of(uintptr_t address) { return address & ~(os_page - 1); }

static void restrict_page(int slot, uintptr_t address, int protection) {
  atomic_store(&armed[slot], page_of(address));
  require(mprotect((void*)page_of(address), os_page, protection) == 0);
}

static void restore_page(int slot, uintptr_t address) {
  require(mprotect((void*)page_of(address), os_page, PROT_READ | PROT_WRITE) == 0);
  atomic_store(&armed[slot], 0);
}

static span_t span_of(void* block) {
  mi_page_t* const page = _mi_ptr_page(block);
  require(page != NULL && page->memid.memkind == MI_MEM_ARENA);
  span_t span;
  span.arena = page->memid.mem.arena.arena;
  span.slice = page->memid.mem.arena.slice_index;
  span.count = page->memid.mem.arena.slice_count;
  span.bin = _mi_bin(mi_page_block_size(page));
  span.pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t,
      &mi_page_heap(page)->arena_pages[span.arena->arena_idx]);
  require(span.pages != NULL);
  return span;
}

static uintptr_t abandoned_word(const span_t* span) {
  mi_bitmap_t* const bitmap = span->pages->pages_abandoned[span->bin];
  return (uintptr_t)&bitmap->chunks[span->slice / MI_BCHUNK_BITS]
      .bfields[(span->slice % MI_BCHUNK_BITS) / MI_BFIELD_BITS];
}

static void emit(const char* name, const char* field, long long value) {
  printf("m2.arena_interleave.%s.%s=%lld\n", name, field, value);
}

static void emit_span(const char* name, const span_t* span) {
  size_t free_slices = 0, committed = 0, purge = 0;
  for (size_t i = span->slice; i < span->slice + span->count; i++) {
    free_slices += mi_bbitmap_is_setN(span->arena->slices_free, i, 1);
    committed += mi_bitmap_is_setN(span->arena->slices_committed, i, 1);
    purge += mi_bitmap_is_setN(span->arena->slices_purge, i, 1);
  }
  emit(name, "page", mi_bitmap_is_setN(span->pages->pages, span->slice, 1));
  emit(name, "abandoned", mi_bitmap_is_setN(span->pages->pages_abandoned[span->bin], span->slice, 1));
  emit(name, "free", (long long)free_slices);
  emit(name, "committed", (long long)committed);
  emit(name, "purge", (long long)purge);
}

static mailbox_t freer_box;
static _Atomic(void*) freer_job;
static int freer_jobs;

static void* freer(void* unused) {
  (void)unused;
  register_role(ROLE_FREER);
  mi_thread_init();
  void* const own = mi_malloc(REQUEST);
  require(own != NULL);
  complete(&freer_box);
  for (int job = 1;; job++) {
    await_posted(&freer_box, job);
    void* const block = atomic_load_explicit(&freer_job, memory_order_acquire);
    if (block == NULL) break;
    mi_free(block);
    complete(&freer_box);
  }
  mi_free(own);
  mi_thread_done();
  return NULL;
}

static void post_free(void* block) {
  atomic_store_explicit(&freer_job, block, memory_order_release);
  freer_jobs++;
  post(&freer_box);
}

static void await_free(void) { await_completed(&freer_box, freer_jobs + 1); }

typedef struct owner_s {
  size_t count;
  void* blocks[2];
  mailbox_t box;
  pthread_t thread;
} owner_t;

static void* owner(void* argument) {
  owner_t* const state = argument;
  register_role(ROLE_OWNER);
  mi_thread_init();
  for (size_t i = 0; i < state->count; i++) {
    state->blocks[i] = mi_malloc(REQUEST);
    require(state->blocks[i] != NULL && _mi_ptr_page(state->blocks[i]) == _mi_ptr_page(state->blocks[0]));
  }
  complete(&state->box);
  await_posted(&state->box, 1);
  mi_thread_done();
  complete(&state->box);
  return NULL;
}

static void start_owner(owner_t* state, size_t count) {
  state->count = count;
  require(pthread_create(&state->thread, NULL, owner, state) == 0);
  await_completed(&state->box, 1);
}

static void finish_owner(owner_t* state) {
  await_completed(&state->box, 2);
  require(pthread_join(state->thread, NULL) == 0);
  atomic_store(&role_tids[ROLE_OWNER], 0);
}

static void emit_layout(const char* name, const span_t* span, void* block) {
  mi_page_t* const page = _mi_ptr_page(block);
  const uintptr_t word = page_of(abandoned_word(span));
  const uintptr_t head = page_of((uintptr_t)&page->xthread_free);
  emit(name, "distinct_pages", word != head
      && word != page_of((uintptr_t)&span->pages->pages_abandoned[span->bin])
      && word != page_of((uintptr_t)span->arena));
}

static void unown_first(void) {
  owner_t state = {0};
  start_owner(&state, 1);
  const span_t span = span_of(state.blocks[0]);
  emit_layout("first", &span, state.blocks[0]);
  const uintptr_t word = abandoned_word(&span);
  reset_pauses();
  restrict_page(0, word, PROT_READ);
  post(&state.box);
  emit("first", "exit_pause_word", await_pause(0, ROLE_OWNER) == word);
  post_free(state.blocks[0]);
  await_free();
  emit("first", "freer_returned", 1);
  restore_page(0, word);
  release_pause(0);
  finish_owner(&state);
  emit("first", "pauses", atomic_load(&pause_count));
  emit_span("first.exit", &span);
}

static void unown_cas(const char* name, size_t count) {
  owner_t state = {0};
  start_owner(&state, count);
  const span_t span = span_of(state.blocks[0]);
  emit_layout(name, &span, state.blocks[0]);
  mi_page_t* const page = _mi_ptr_page(state.blocks[0]);
  const uintptr_t word = abandoned_word(&span);
  const uintptr_t head = (uintptr_t)&page->xthread_free;
  reset_pauses();
  restrict_page(0, word, PROT_READ);
  post(&state.box);
  emit(name, "exit_pause_word", await_pause(0, ROLE_OWNER) == word);
  restrict_page(1, head, PROT_READ);
  restore_page(0, word);
  release_pause(0);
  emit(name, "unown_pause_head", await_pause(1, ROLE_OWNER) == head);
  emit(name, "mapped_before_free", mi_bitmap_is_setN(span.pages->pages_abandoned[span.bin], span.slice, 1));
  restore_page(1, head);
  post_free(state.blocks[count - 1]);
  await_free();
  emit(name, "freer_returned", 1);
  release_pause(1);
  finish_owner(&state);
  emit(name, "pauses", atomic_load(&pause_count));
  char exit_name[32];
  snprintf(exit_name, sizeof exit_name, "%s.exit", name);
  emit_span(exit_name, &span);
  if (count > 1) {
    post_free(state.blocks[0]);
    await_free();
    char last_name[32];
    snprintf(last_name, sizeof last_name, "%s.last", name);
    emit_span(last_name, &span);
  }
}

typedef struct reader_s {
  mailbox_t box;
  void* block;
  bool owned;
  pthread_t thread;
} reader_t;

static void* reader(void* argument) {
  reader_t* const state = argument;
  register_role(ROLE_READER);
  mi_thread_init();
  void* const warm = mi_malloc(16);
  require(warm != NULL);
  complete(&state->box);
  await_posted(&state->box, 1);
  state->block = mi_malloc(REQUEST);
  state->owned = state->block != NULL && mi_page_thread_id(_mi_ptr_page(state->block)) == _mi_thread_id();
  complete(&state->box);
  await_posted(&state->box, 2);
  mi_free(state->block);
  mi_free(warm);
  mi_thread_done();
  return NULL;
}

static int64_t busy_waits(void) {
  return __atomic_load_n(&_mi_subproc_main()->stats.pages_unabandon_busy_wait.total, __ATOMIC_RELAXED);
}

static size_t main_heap_abandoned_count(void) {
  mi_heap_t* const heap = _mi_subproc_main()->heap_main;
  size_t count = 0;
  for (size_t bin = 0; bin < MI_BIN_COUNT; bin++) count += mi_atomic_load_relaxed(&heap->abandoned_count[bin]);
  return count;
}

static void unabandon_wait(void) {
  owner_t state = {0};
  start_owner(&state, 1);
  post(&state.box);
  finish_owner(&state);
  const span_t span = span_of(state.blocks[0]);
  emit_layout("wait", &span, state.blocks[0]);
  emit_span("wait.abandoned", &span);
  mi_page_t* const page = _mi_ptr_page(state.blocks[0]);
  const uintptr_t word = abandoned_word(&span);
  const uintptr_t head = (uintptr_t)&page->xthread_free;

  reader_t observer = {0};
  require(pthread_create(&observer.thread, NULL, reader, &observer) == 0);
  await_completed(&observer.box, 1);
  const int64_t waits_before = busy_waits();
  reset_pauses();
  restrict_page(0, word, PROT_READ);
  post_free(state.blocks[0]);
  emit("wait", "freer_pause_word", await_pause(0, ROLE_FREER) == word);
  emit("wait", "freer_owns", (mi_atomic_load_relaxed(&page->xthread_free) & 1) == 1);
  restrict_page(1, head, PROT_READ);
  restore_page(0, word);
  post(&observer.box);
  emit("wait", "reader_pause_head", await_pause(1, ROLE_READER) == head);
  emit("wait", "reader_cleared", !mi_bitmap_is_setN(span.pages->pages_abandoned[span.bin], span.slice, 1));
  release_pause(0);
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  while (busy_waits() == waits_before && elapsed_since(&start) < 30) sched_yield();
  emit("wait", "freer_waiting", busy_waits() - waits_before);
  restore_page(1, head);
  release_pause(1);
  await_free();
  await_completed(&observer.box, 2);
  emit("wait", "busy_waits", busy_waits() - waits_before);
  emit("wait", "reader_owns", observer.owned);
  emit("wait", "pauses", atomic_load(&pause_count));
  emit("wait.freed", "abandoned_count", (long long)main_heap_abandoned_count());
  post(&observer.box);
  require(pthread_join(observer.thread, NULL) == 0);
  emit_span("wait.last", &span);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  os_page = (uintptr_t)sysconf(_SC_PAGESIZE);
  /* The suppressed process constructor's entry ends the preloading interval
     before `mi_process_init` (src/init.c:493-512), as in a loaded program. */
  _mi_auto_process_init();
  struct sigaction action = {0};
  action.sa_sigaction = on_fault;
  action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  require(sigaction(SIGSEGV, &action, &default_fault) == 0);

  pthread_t thread;
  require(pthread_create(&thread, NULL, freer, NULL) == 0);
  await_completed(&freer_box, 1);
  unown_first();
  unown_cas("cas", 1);
  unown_cas("cas_live", 2);
  unabandon_wait();
  atomic_store_explicit(&freer_job, NULL, memory_order_release);
  post(&freer_box);
  require(pthread_join(thread, NULL) == 0);
  return 0;
}
