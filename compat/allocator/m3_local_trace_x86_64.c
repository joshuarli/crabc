/* SPDX-License-Identifier: MIT
 *
 * Pinned-C half of the M3 deterministic local-engine differential.
 *
 * `compat/allocator/m3_x86_64.py` compiles this driver together with the
 * pinned mimalloc v3.5.0 release source set and runs it with
 * `MIMALLOC_PAGE_FULL_RETAIN=-1`, so the default Theap is the source
 * non-abandoning local profile. The driver manages one committed, pinned,
 * zero in-place arena of the workload's size, then applies each workload
 * operation through `mi_malloc`/`mi_free` on the current thread.
 *
 * After every operation it normalizes the default Theap exactly as
 * `crabc-mimalloc/src/single_thread/local_trace.rs` does for the Rust engine:
 * logical allocation IDs, discovery-ordered page IDs, block indices instead
 * of addresses, arena-slice page slots, queue order/counts, the direct-page
 * cache, and Theap counters. Only changed facts are emitted. Any format
 * change must be made identically in both producers.
 */
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error the M3 local trace driver requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error the M3 local trace driver requires the fixed release profile
#endif
#if MI_PADDING != 0 || MI_ENCODE_FREELIST != 0
#error the M3 local trace driver requires unpadded, unencoded release free lists
#endif

#define WORKLOAD_MAGIC "m3-local-trace 1"

typedef struct page_record_s {
  mi_page_t* page;
  unsigned long pid;
  bool seen;
  char line[192];
} page_record_t;

static FILE* out;
static uintptr_t arena_base;
static size_t slot_count;
static page_record_t* records;  /* indexed by arena slice slot; page==NULL is empty */
static unsigned long next_pid = 1;
static char* queue_lines[MI_BIN_COUNT];
static unsigned long direct_pids[MI_PAGES_DIRECT];
static char global_line[256];

static void fail(const char* message) {
  fprintf(stderr, "m3-local-trace-c: %s\n", message);
  exit(2);
}

/* Names a page by the arena slice holding its first block. Page metadata
   itself lives in the arena's aligned metadata array, not at the slice. */
static size_t slot_of(const mi_page_t* page) {
  const uintptr_t address = (uintptr_t)mi_page_start(page);
  if (address < arena_base) fail("page precedes the traced arena");
  const size_t slot = (address - arena_base) / MI_ARENA_SLICE_SIZE;
  if (slot >= slot_count) fail("page lies outside the traced arena");
  return slot;
}

static void block_index(char* buffer, size_t size, const mi_page_t* page, const void* block) {
  if (block == NULL) {
    snprintf(buffer, size, "-");
    return;
  }
  const size_t offset = (uintptr_t)block - (uintptr_t)mi_page_start(page);
  const size_t block_size = mi_page_block_size(page);
  if (offset % block_size == 0) {
    snprintf(buffer, size, "%zu", offset / block_size);
  }
  else {
    snprintf(buffer, size, "%zur%zu", offset / block_size, offset % block_size);
  }
}

static bool pid_of(const mi_page_t* page, unsigned long* pid) {
  const page_record_t* record = &records[slot_of(page)];
  if (record->page == NULL) return false;
  if (record->page != page) fail("slot record names another page");
  *pid = record->pid;
  return true;
}

static void append(char** buffer, size_t* length, size_t* capacity, const char* text) {
  const size_t add = strlen(text);
  if (*length + add + 1 > *capacity) {
    size_t next = (*capacity == 0 ? 256 : *capacity * 2);
    while (*length + add + 1 > next) next *= 2;
    char* grown = realloc(*buffer, next);
    if (grown == NULL) fail("out of trace memory");
    *buffer = grown;
    *capacity = next;
  }
  memcpy(*buffer + *length, text, add + 1);
  *length += add;
}

static void bootstrap(mi_theap_t* theap) {
  fprintf(out, "T retain%ld abandon%d reclaim%d\n", theap->page_full_retain,
          theap->allow_page_abandon ? 1 : 0, theap->allow_page_reclaim ? 1 : 0);
  for (size_t bin = 0; bin < MI_BIN_COUNT; bin++) {
    fprintf(out, "B%zu %zu\n", bin, theap->pages[bin].block_size);
  }
}

static void snapshot(mi_theap_t* theap) {
  for (size_t slot = 0; slot < slot_count; slot++) records[slot].seen = false;
  for (size_t bin = 0; bin < MI_BIN_COUNT; bin++) {
    const mi_page_queue_t* queue = &theap->pages[bin];
    char* members = NULL;
    size_t members_length = 0, members_capacity = 0;
    append(&members, &members_length, &members_capacity, "");
    size_t walked = 0;
    for (mi_page_t* page = queue->first; page != NULL; page = page->next) {
      if (++walked > slot_count) fail("queue does not terminate");
      const size_t slot = slot_of(page);
      char free_index[48], local_index[48], line[192];
      block_index(free_index, sizeof(free_index), page, page->free);
      block_index(local_index, sizeof(local_index), page, page->local_free);
      snprintf(line, sizeof(line), "q%zu s%zu c%u r%u u%zu f%s l%s x%u F%d z%d S%zu",
               bin, mi_page_block_size(page), (unsigned)page->capacity, (unsigned)page->reserved,
               (size_t)page->used, free_index, local_index, (unsigned)page->retire_expire,
               mi_page_is_in_full(page) ? 1 : 0, page->free_is_zero ? 1 : 0, slot);
      page_record_t* record = &records[slot];
      unsigned long pid;
      if (record->page != NULL) {
        if (record->page != page) fail("slot record names another page");
        if (record->seen) fail("page occurs in two queues");
        record->seen = true;
        if (strcmp(record->line, line) != 0) {
          fprintf(out, "~P%lu %s\n", record->pid, line);
          snprintf(record->line, sizeof(record->line), "%s", line);
        }
        pid = record->pid;
      }
      else {
        pid = next_pid++;
        fprintf(out, "+P%lu %s\n", pid, line);
        record->page = page;
        record->pid = pid;
        record->seen = true;
        snprintf(record->line, sizeof(record->line), "%s", line);
      }
      char member[32];
      snprintf(member, sizeof(member), "%lu,", pid);
      append(&members, &members_length, &members_capacity, member);
    }
    char count[32];
    snprintf(count, sizeof(count), " n%zu", queue->count);
    append(&members, &members_length, &members_capacity, count);
    if (queue_lines[bin] == NULL || strcmp(queue_lines[bin], members) != 0) {
      fprintf(out, "Q%zu %s\n", bin, members);
      free(queue_lines[bin]);
      queue_lines[bin] = members;
    }
    else {
      free(members);
    }
  }
  /* Removed pages in ascending logical-page order. */
  for (;;) {
    page_record_t* lowest = NULL;
    for (size_t slot = 0; slot < slot_count; slot++) {
      page_record_t* record = &records[slot];
      if (record->page != NULL && !record->seen && (lowest == NULL || record->pid < lowest->pid)) {
        lowest = record;
      }
    }
    if (lowest == NULL) break;
    fprintf(out, "-P%lu\n", lowest->pid);
    lowest->page = NULL;
  }
  for (size_t index = 0; index < MI_PAGES_DIRECT; index++) {
    const mi_page_t* page = theap->pages_free_direct[index];
    unsigned long pid = 0;
    if (page != _mi_page_empty_get() && !pid_of(page, &pid)) pid = (unsigned long)-1;
    if (pid != direct_pids[index]) {
      if (pid == 0) fprintf(out, "D%zu -\n", index);
      else if (pid == (unsigned long)-1) fprintf(out, "D%zu ?\n", index);
      else fprintf(out, "D%zu %lu\n", index, pid);
      direct_pids[index] = pid;
    }
  }
  char global[256];
  snprintf(global, sizeof(global), "pc%zu rmin%zu rmax%zu pfs%zu gc%ld gcc%ld hb%llu",
           theap->page_count, theap->page_retired_min, theap->page_retired_max,
           theap->pages_full_size, theap->generic_count, theap->generic_collect_count,
           theap->heartbeat);
  if (strcmp(global, global_line) != 0) {
    fprintf(out, "G %s\n", global);
    snprintf(global_line, sizeof(global_line), "%s", global);
  }
}

static bool read_line(FILE* input, char* buffer, size_t size) {
  while (fgets(buffer, (int)size, input) != NULL) {
    const size_t length = strlen(buffer);
    if (length > 0 && buffer[length - 1] != '\n' && !feof(input)) fail("workload line too long");
    buffer[strcspn(buffer, "\r\n")] = '\0';
    if (buffer[0] == '\0' || buffer[0] == '#') continue;
    return true;
  }
  return false;
}

int main(int argc, char** argv) {
  if (argc != 3) fail("usage: m3-local-trace-c WORKLOAD OUTPUT");
  FILE* input = fopen(argv[1], "r");
  if (input == NULL) fail("cannot open workload");
  out = fopen(argv[2], "w");
  if (out == NULL) fail("cannot create trace output");
  static char output_buffer[1 << 20];
  setvbuf(out, output_buffer, _IOFBF, sizeof(output_buffer));

  char line[256];
  if (!read_line(input, line, sizeof(line)) || strcmp(line, WORKLOAD_MAGIC) != 0) fail("bad workload header");
  size_t arena_bytes = 0, ids = 0;
  if (!read_line(input, line, sizeof(line)) || sscanf(line, "arena_bytes=%zu ids=%zu", &arena_bytes, &ids) != 2) {
    fail("bad workload geometry");
  }
  if (arena_bytes < MI_ARENA_MIN_SIZE || arena_bytes % MI_ARENA_MIN_SIZE != 0) fail("bad arena size");

  /* Mirror the Rust fixture: one ARENA_ALIGNMENT-aligned, committed, zero
     region managed in place as a pinned, nonexclusive arena. */
  const size_t mapping_size = arena_bytes + MI_ARENA_ALIGNMENT;
  uint8_t* mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (mapping == MAP_FAILED) fail("cannot map the trace arena");
  arena_base = _mi_align_up((uintptr_t)mapping, MI_ARENA_ALIGNMENT);
  slot_count = arena_bytes / MI_ARENA_SLICE_SIZE;
  records = calloc(slot_count, sizeof(page_record_t));
  void** blocks = calloc(ids == 0 ? 1 : ids, sizeof(void*));
  if (records == NULL || blocks == NULL) fail("out of driver memory");

  mi_thread_init();
  mi_theap_t* theap = _mi_theap_default();
  if (!mi_theap_is_initialized(theap)) fail("default theap is not initialized");
  mi_arena_id_t arena_id = _mi_arena_id_none();
  if (!mi_manage_os_memory_ex((void*)arena_base, arena_bytes, true, true, true, -1, false, &arena_id)) {
    fail("cannot manage the trace arena");
  }

  bootstrap(theap);
  snapshot(theap);
  size_t step = 0;
  while (read_line(input, line, sizeof(line))) {
    step++;
    size_t id = 0, size = 0;
    if (sscanf(line, "a %zu %zu", &id, &size) == 2) {
      if (id >= ids || blocks[id] != NULL || size == 0) fail("bad allocation operation");
      fprintf(out, "@%zu a%zu %zu\n", step, id, size);
      void* block = mi_malloc(size);
      blocks[id] = block;
      snapshot(theap);
      if (block == NULL) {
        fprintf(out, "= null\n");
      }
      else {
        const mi_page_t* page = _mi_ptr_page(block);
        unsigned long pid;
        if (page == NULL || !pid_of(page, &pid)) {
          fprintf(out, "= ?\n");
        }
        else {
          char index[48];
          block_index(index, sizeof(index), page, block);
          fprintf(out, "= P%lu i%s\n", pid, index);
        }
      }
    }
    else if (sscanf(line, "f %zu", &id) == 1) {
      /* The generator never reuses an ID. A failed allocation left NULL,
         which the Rust driver skips and `mi_free` accepts as a no-op. */
      if (id >= ids) fail("bad free operation");
      fprintf(out, "@%zu f%zu\n", step, id);
      mi_free(blocks[id]);
      blocks[id] = NULL;
      snapshot(theap);
    }
    else {
      fail("unknown workload operation");
    }
  }
  fprintf(out, "E\n");
  for (size_t id = 0; id < ids; id++) {
    if (blocks[id] != NULL) fail("workload left a live allocation");
  }
  if (fclose(out) != 0) fail("cannot finish trace output");
  fclose(input);
  return 0;
}
