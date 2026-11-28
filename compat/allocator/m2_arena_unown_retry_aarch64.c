/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned v3.5.0 `mi_abandoned_page_unown` release-CAS retry after a full
   unmapped or an OS-list page abandonment (src/arena.c:1339-1354, 631-653).
   Every source step between that page's collection and the release CAS
   writes only page metadata or the Heap's OS-list lock, so no page
   protection can isolate it. A forked tracer instead arms one AArch64
   hardware store watchpoint (NT_ARM_HW_WATCH) on the page's `xthread_free`
   word for the owner thread only. The watchpoint traps before the owner's
   first store to that word, which is its release CAS; while the owner is
   stopped a foreign thread frees blocks onto the owned list
   (src/free.c:62-97), then the tracer disarms and detaches and the CAS
   retries against the published list.

   full: a full small page abandoned unmapped at owner exit
   (src/theap.c:97-115, src/page.c:291-304). The foreign thread frees every
   block, so the retry collects them and unabandons and frees the page.

   full_live: the medium page that the 42nd allocation fills and the generic
   allocation path abandons at once (src/page.c:374-389, 1076-1079). One
   foreign free leaves 41 blocks live, so the retry collects it and releases
   ownership with the page still unmapped; the remaining frees later free it.

   os_singleton: a 32-MiB-aligned singleton the OS backs
   (src/arena.c:796-866), listed in `os_abandoned_pages` at owner exit; its
   foreign free makes the retry unlink and free it.

   os and os_live: under `disallow_arena_alloc=1` a medium page is OS-backed
   (src/arena.c:802-806) and listed at owner exit. With one block the retry
   unlinks and frees it; with two, one foreign free leaves the page listed
   and unowned until the last free.

   `crabc-mimalloc/tests/native_arena_unown_retry.rs` prints the same
   fields. */
#define _GNU_SOURCE
#include "static.c"
#include <elf.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "the unown-retry receiver pauses through AArch64 hardware watchpoints"
#endif

#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif

/* DBGWCR: enable, EL0 only, store accesses, all eight bytes of an aligned
   doubleword (Arm ARM D13.3.13). */
#define WATCH_STORE_DOUBLEWORD (1u | (2u << 1) | (2u << 3) | (0xffu << 5))

#define MEDIUM 10248
#define MEDIUM_BLOCKS 42
#define SMALL 8192
#define MAX_BLOCKS 64
#define OS_REQUEST 7
#define OS_ALIGNMENT (32 * 1024 * 1024)

#define require(condition) \
  do { if (!(condition)) { fprintf(stderr, "m2_arena_unown_retry_aarch64.c:%d: %s\n", __LINE__, #condition); abort(); } } while (0)

typedef struct watch_state_s {
  uint32_t dbg_info;
  uint32_t pad;
  struct { uint64_t addr; uint32_t ctrl; uint32_t pad; } regs[1];
} watch_state_t;

enum { TRACE_ARM = 1, TRACE_RELEASE = 2, TRACE_QUIT = 3 };

typedef struct tracer_s {
  _Atomic int request;
  _Atomic int done;
  _Atomic int command;
  _Atomic int tid;
  _Atomic uintptr_t address;
  _Atomic int hits;
  _Atomic uintptr_t hit_address;
  _Atomic int hit_code;
  _Atomic int failure;
} tracer_t;

static tracer_t* tracer;
static pid_t tracer_pid;
static int tracer_requests;

static double elapsed_since(const struct timespec* start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (double)(now.tv_sec - start->tv_sec) + (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

static void tracer_fail(int line) {
  int expected = 0;
  atomic_compare_exchange_strong(&tracer->failure, &expected, line);
  _exit(1);
}

static bool set_watch(pid_t tid, uintptr_t address, uint32_t control) {
  watch_state_t state;
  memset(&state, 0, sizeof state);
  state.regs[0].addr = address;
  state.regs[0].ctrl = control;
  struct iovec vector = { &state, sizeof state };
  return ptrace(PTRACE_SETREGSET, tid, (void*)NT_ARM_HW_WATCH, &vector) == 0;
}

static void tracer_arm(pid_t tid, uintptr_t address) {
  if (ptrace(PTRACE_SEIZE, tid, 0, 0) != 0) tracer_fail(__LINE__);
  if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) tracer_fail(__LINE__);
  int status;
  if (waitpid(tid, &status, __WALL) != tid || !WIFSTOPPED(status)) tracer_fail(__LINE__);
  const int pending = (status >> 16) == 0 ? WSTOPSIG(status) : 0;
  if (!set_watch(tid, address, WATCH_STORE_DOUBLEWORD)) tracer_fail(__LINE__);
  if (ptrace(PTRACE_CONT, tid, 0, (void*)(uintptr_t)pending) != 0) tracer_fail(__LINE__);
}

static void tracer_await_trap(pid_t tid) {
  for (;;) {
    int status;
    if (waitpid(tid, &status, __WALL) != tid || !WIFSTOPPED(status)) tracer_fail(__LINE__);
    int signal = WSTOPSIG(status);
    if ((status >> 16) != 0) signal = 0;
    else if (signal == SIGTRAP) {
      siginfo_t info;
      if (ptrace(PTRACE_GETSIGINFO, tid, 0, &info) != 0) tracer_fail(__LINE__);
      if (info.si_code == TRAP_HWBKPT) {
        atomic_store(&tracer->hit_address, (uintptr_t)info.si_addr);
        atomic_store(&tracer->hit_code, info.si_code);
        atomic_fetch_add(&tracer->hits, 1);
        return;
      }
    }
    if (ptrace(PTRACE_CONT, tid, 0, (void*)(uintptr_t)signal) != 0) tracer_fail(__LINE__);
  }
}

static void tracer_release(pid_t tid) {
  if (!set_watch(tid, 0, 0)) tracer_fail(__LINE__);
  if (ptrace(PTRACE_DETACH, tid, 0, 0) != 0) tracer_fail(__LINE__);
}

static _Noreturn void tracer_main(void) {
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) tracer_fail(__LINE__);
  int seen = 0;
  for (;;) {
    while (atomic_load(&tracer->request) == seen) sched_yield();
    seen = atomic_load(&tracer->request);
    const int command = atomic_load(&tracer->command);
    const pid_t tid = atomic_load(&tracer->tid);
    if (command == TRACE_QUIT) _exit(0);
    if (command == TRACE_ARM) {
      tracer_arm(tid, atomic_load(&tracer->address));
      atomic_store(&tracer->done, seen);
      tracer_await_trap(tid);
    } else if (command == TRACE_RELEASE) {
      tracer_release(tid);
      atomic_store(&tracer->done, seen);
    } else {
      tracer_fail(__LINE__);
    }
  }
}

static void start_tracer(void) {
  tracer = mmap(NULL, sizeof *tracer, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  require(tracer != MAP_FAILED);
  tracer_pid = fork();
  require(tracer_pid >= 0);
  if (tracer_pid == 0) tracer_main();
  /* Yama restricts PTRACE_SEIZE of a parent's thread; without Yama the
     request is EINVAL. */
  require(prctl(PR_SET_PTRACER, tracer_pid, 0, 0, 0) == 0 || errno == EINVAL);
}

static void tracer_command(int command) {
  atomic_store(&tracer->command, command);
  atomic_store(&tracer->request, ++tracer_requests);
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  while (atomic_load(&tracer->done) != tracer_requests) {
    require(atomic_load(&tracer->failure) == 0);
    require(elapsed_since(&start) < 30);
    sched_yield();
  }
}

static void arm_watch(long tid, uintptr_t address) {
  atomic_store(&tracer->hits, 0);
  atomic_store(&tracer->hit_address, 0);
  atomic_store(&tracer->hit_code, 0);
  atomic_store(&tracer->tid, (int)tid);
  atomic_store(&tracer->address, address);
  tracer_command(TRACE_ARM);
}

static uintptr_t await_hit(void) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  while (atomic_load(&tracer->hits) == 0) {
    require(atomic_load(&tracer->failure) == 0);
    require(elapsed_since(&start) < 30);
    sched_yield();
  }
  return atomic_load(&tracer->hit_address);
}

static void stop_tracer(void) {
  atomic_store(&tracer->command, TRACE_QUIT);
  atomic_store(&tracer->request, ++tracer_requests);
  int status;
  require(waitpid(tracer_pid, &status, 0) == tracer_pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  require(atomic_load(&tracer->failure) == 0);
}

typedef struct mailbox_s {
  _Atomic int posted;
  _Atomic int completed;
} mailbox_t;

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

static void emit(const char* name, const char* field, long long value) {
  printf("m2.arena_unown_retry.%s.%s=%lld\n", name, field, value);
}

static void emit_at(const char* name, const char* stage, const char* field, long long value) {
  printf("m2.arena_unown_retry.%s.%s.%s=%lld\n", name, stage, field, value);
}

typedef struct span_s {
  mi_arena_t* arena;
  mi_arena_pages_t* pages;
  size_t slice;
  size_t count;
  size_t bin;
} span_t;

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

static void emit_span(const char* name, const char* stage, const span_t* span) {
  size_t free_slices = 0, committed = 0, purge = 0;
  for (size_t i = span->slice; i < span->slice + span->count; i++) {
    free_slices += mi_bbitmap_is_setN(span->arena->slices_free, i, 1);
    committed += mi_bitmap_is_setN(span->arena->slices_committed, i, 1);
    purge += mi_bitmap_is_setN(span->arena->slices_purge, i, 1);
  }
  emit_at(name, stage, "page", mi_bitmap_is_setN(span->pages->pages, span->slice, 1));
  emit_at(name, stage, "abandoned", mi_bitmap_is_setN(span->pages->pages_abandoned[span->bin], span->slice, 1));
  emit_at(name, stage, "free", (long long)free_slices);
  emit_at(name, stage, "committed", (long long)committed);
  emit_at(name, stage, "purge", (long long)purge);
}

static bool os_listed(void) {
  return _mi_subproc_main()->heap_main->os_abandoned_pages != NULL;
}

static uintptr_t head_word(uintptr_t head) {
  return mi_atomic_load_relaxed((_Atomic(uintptr_t)*)head);
}

static void emit_head(const char* name, const char* stage, uintptr_t head) {
  const uintptr_t word = head_word(head);
  emit_at(name, stage, "owned", (long long)(word & 1));
  emit_at(name, stage, "pending", (word & ~(uintptr_t)1) != 0);
}

enum { JOB_FREE = 1 };

static mailbox_t freer_box;
static _Atomic(void*) freer_job;
static int freer_jobs;

static void* freer(void* unused) {
  (void)unused;
  mi_thread_init();
  void* const own = mi_malloc(MEDIUM);
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

static void foreign_free(void* block) {
  atomic_store_explicit(&freer_job, block, memory_order_release);
  freer_jobs++;
  post(&freer_box);
  await_completed(&freer_box, freer_jobs + 1);
}

typedef struct owner_s {
  size_t size;
  size_t alignment;
  size_t count;
  bool fill_page;
  bool allocate_last_on_step;
  void* blocks[MAX_BLOCKS];
  _Atomic long tid;
  mailbox_t box;
  pthread_t thread;
} owner_t;

static void* owner_allocate(const owner_t* state) {
  void* const block = state->alignment == 0 ? mi_malloc(state->size) : mi_malloc_aligned(state->size, state->alignment);
  require(block != NULL);
  return block;
}

static void* owner(void* argument) {
  owner_t* const state = argument;
  atomic_store(&state->tid, syscall(SYS_gettid));
  mi_thread_init();
  state->blocks[0] = owner_allocate(state);
  if (state->fill_page) state->count = _mi_ptr_page(state->blocks[0])->reserved;
  require(state->count <= MAX_BLOCKS);
  const size_t first_step = state->allocate_last_on_step ? state->count - 1 : state->count;
  for (size_t i = 1; i < first_step; i++) {
    state->blocks[i] = owner_allocate(state);
    require(_mi_ptr_page(state->blocks[i]) == _mi_ptr_page(state->blocks[0]));
  }
  complete(&state->box);
  await_posted(&state->box, 1);
  if (state->allocate_last_on_step) {
    state->blocks[state->count - 1] = owner_allocate(state);
    require(_mi_ptr_page(state->blocks[state->count - 1]) == _mi_ptr_page(state->blocks[0]));
    complete(&state->box);
    await_posted(&state->box, 2);
  }
  mi_thread_done();
  complete(&state->box);
  return NULL;
}

static void start_owner(owner_t* state) {
  require(pthread_create(&state->thread, NULL, owner, state) == 0);
  await_completed(&state->box, 1);
}

static void finish_owner(owner_t* state, int completions) {
  await_completed(&state->box, completions);
  require(pthread_join(state->thread, NULL) == 0);
}

static uintptr_t pause_at_release(const char* name, owner_t* state) {
  mi_page_t* const page = _mi_ptr_page(state->blocks[0]);
  const uintptr_t head = (uintptr_t)&page->xthread_free;
  emit(name, "arena", page->memid.memkind == MI_MEM_ARENA);
  emit(name, "blocks", (long long)state->count);
  arm_watch(atomic_load(&state->tid), head);
  post(&state->box);
  emit(name, "pause_head", await_hit() == head);
  emit(name, "pause_trap", atomic_load(&tracer->hit_code) == TRAP_HWBKPT);
  emit_head(name, "pause", head);
  return head;
}

static void release_owner(const char* name, uintptr_t head) {
  emit_head(name, "pushed", head);
  tracer_command(TRACE_RELEASE);
  emit(name, "hits", atomic_load(&tracer->hits));
}

static void full_all_free(void) {
  owner_t state = { .size = SMALL, .fill_page = true };
  start_owner(&state);
  const span_t span = span_of(state.blocks[0]);
  const uintptr_t head = pause_at_release("full", &state);
  emit_span("full", "pause", &span);
  for (size_t i = 0; i < state.count; i++) foreign_free(state.blocks[i]);
  release_owner("full", head);
  finish_owner(&state, 2);
  emit_span("full", "exit", &span);
}

static void full_live(void) {
  owner_t state = { .size = MEDIUM, .count = MEDIUM_BLOCKS, .allocate_last_on_step = true };
  start_owner(&state);
  const span_t span = span_of(state.blocks[0]);
  const uintptr_t head = pause_at_release("full_live", &state);
  emit_span("full_live", "pause", &span);
  foreign_free(state.blocks[0]);
  release_owner("full_live", head);
  await_completed(&state.box, 2);
  emit_span("full_live", "exit", &span);
  emit_head("full_live", "exit", head);
  post(&state.box);
  finish_owner(&state, 3);
  for (size_t i = 1; i < state.count; i++) foreign_free(state.blocks[i]);
  emit_span("full_live", "last", &span);
}

static void os_scenario(const char* name, owner_t* state, size_t frees) {
  start_owner(state);
  const uintptr_t head = pause_at_release(name, state);
  emit_at(name, "pause", "listed", os_listed());
  for (size_t i = 0; i < frees; i++) foreign_free(state->blocks[state->count - 1 - i]);
  release_owner(name, head);
  finish_owner(state, 2);
  emit_at(name, "exit", "listed", os_listed());
  if (frees < state->count) {
    emit_head(name, "exit", head);
    for (size_t i = frees; i < state->count; i++) foreign_free(state->blocks[state->count - 1 - i]);
    emit_at(name, "last", "listed", os_listed());
  }
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  /* The suppressed process constructor's entry ends the preloading interval
     before `mi_process_init` (src/init.c:493-512), as in a loaded program. */
  _mi_auto_process_init();
  start_tracer();
  pthread_t thread;
  require(pthread_create(&thread, NULL, freer, NULL) == 0);
  await_completed(&freer_box, 1);

  full_all_free();
  full_live();
  owner_t singleton = { .size = OS_REQUEST, .alignment = OS_ALIGNMENT, .count = 1 };
  os_scenario("os_singleton", &singleton, 1);
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  owner_t single = { .size = MEDIUM, .count = 1 };
  os_scenario("os", &single, 1);
  owner_t pair = { .size = MEDIUM, .count = 2 };
  os_scenario("os_live", &pair, 1);
  mi_option_set(mi_option_disallow_arena_alloc, 0);

  atomic_store_explicit(&freer_job, NULL, memory_order_release);
  post(&freer_box);
  require(pthread_join(thread, NULL) == 0);
  stop_tracer();
  return 0;
}
