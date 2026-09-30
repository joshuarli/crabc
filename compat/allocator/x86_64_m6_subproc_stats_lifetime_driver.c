#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

#ifdef CRABC_MI_SUBPROC_CURRENT_ONLY
static mi_subproc_id_t child;
static void* worker(void* unused) {
  (void)unused;
  mi_subproc_add_current_thread(child);
  void* p = mi_malloc(80);
  assert(p);
  mi_stats_t_decl(all);
  assert(mi_stats_get(&all));
  printf("child.current=%d\nchild.stats.pages=%lld\n", mi_subproc_current()._mi_subproc_id == child._mi_subproc_id, (long long)all.pages.current);
  fflush(stdout);
  return (void*)(uintptr_t)(all.pages.current == 1);
}
int main(void) {
  mi_heap_t* heaps[10];
  for(int i=0;i<10;i++) { heaps[i]=mi_heap_new(); assert(heaps[i] && mi_heap_malloc(heaps[i],192)); }
  child=mi_subproc_new(); assert(child._mi_subproc_id);
  pthread_t thread; void* result;
  assert(pthread_create(&thread,NULL,worker,NULL)==0);
  assert(pthread_join(thread,&result)==0);
  _exit(result==(void*)1 ? 0 : 1);
}

#else
/* Snapshot owners park outside allocator operations. No getter races a
   thread-local counter mutation or observes a destroyed Heap or subprocess. */
typedef struct {
  mi_subproc_id_t outer, inner;
  mi_heap_t* outer_main;
  mi_heap_t* inner_main;
  mi_heap_t* outer_extra;
  mi_heap_t* inner_extra;
  void* outer_block;
  void* inner_block;
  void* outer_extra_block;
  void* inner_extra_block;
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  int outer_ready, inner_ready, outer_release, inner_release;
} fixture_t;
static unsigned char* parent_block;
static mi_heap_t* parent_heap;
static char json_buffer[65536];

static void check(const char* name, bool value) {
  printf("%s=%d\n", name, value);
  fflush(stdout);
  assert(value);
}
static void print_stats(const char* label, const mi_stats_t* stats) {
  printf("%s.header=%zu,%zu\n", label, stats->size, stats->version);
#define MI_STAT_COUNT(name) printf("%s." #name "=%lld,%lld,%lld\n", label, (long long)stats->name.total, (long long)stats->name.peak, (long long)stats->name.current);
#define MI_STAT_COUNTER(name) printf("%s." #name "=%lld\n", label, (long long)stats->name.total);
  MI_STAT_FIELDS()
#undef MI_STAT_COUNT
#undef MI_STAT_COUNTER
  for (size_t i = 0; i < 4; ++i) {
    printf("%s.reserved_count%zu=%lld,%lld,%lld\n", label, i, (long long)stats->_stat_reserved[i].total, (long long)stats->_stat_reserved[i].peak, (long long)stats->_stat_reserved[i].current);
    printf("%s.reserved_counter%zu=%lld\n", label, i, (long long)stats->_stat_counter_reserved[i].total);
  }
  for (size_t i = 0; i <= MI_BIN_HUGE; ++i) {
    printf("%s.malloc_bin%zu=%lld,%lld,%lld\n", label, i, (long long)stats->malloc_bins[i].total, (long long)stats->malloc_bins[i].peak, (long long)stats->malloc_bins[i].current);
    printf("%s.page_bin%zu=%lld,%lld,%lld\n", label, i, (long long)stats->page_bins[i].total, (long long)stats->page_bins[i].peak, (long long)stats->page_bins[i].current);
  }
  for (size_t i = 0; i < MI_CBIN_COUNT; ++i)
    printf("%s.chunk_bin%zu=%lld,%lld,%lld\n", label, i, (long long)stats->chunk_bins[i].total, (long long)stats->chunk_bins[i].peak, (long long)stats->chunk_bins[i].current);
}
static bool has_digit(const char* token, size_t length) {
  for (size_t i = 0; i < length; i++) if (token[i] >= '0' && token[i] <= '9') return true;
  return false;
}

static bool is_unit(const char* token, size_t length) {
  static const char* units[] = { "B", "KiB", "MiB", "GiB", "K", "M", "G", "s", "avg" };
  for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
    if (strlen(units[i]) == length && strncmp(units[i], token, length) == 0) return true;
  }
  return false;
}

static void print_hex(const char* key, const char* text) {
  printf("%s=", key);
  for (const unsigned char* p = (const unsigned char*)text; *p; ++p) printf("%02x", *p);
  printf("\n");
}

/* Preserve selected subprocess and Heap identities separately from rounded
   human-readable statistic columns. */
static void print_headers(const char* key, const char* text) {
  printf("%s=", key);
  for (const char* p = text; *p; ) {
    const char* end = strchr(p, '\n');
    if (!end) end = p + strlen(p);
    if (strncmp(p, "subproc ", 8) == 0 || strncmp(p, "heap ", 5) == 0 || strncmp(p, "meta ", 5) == 0) {
      for (const char* q = p; q < end; ++q) printf("%02x", (unsigned char)*q);
      printf("0a");
    }
    p = (*end == '\n') ? end + 1 : end;
  }
  printf("\n");
}

/* Prints `text` as hex after normalizing each line's tokens. */
static void print_normalized(const char* key, const char* text) {
  printf("%s=", key);
  const char* p = text;
  while (*p != 0) {
    const char* end = strchr(p, '\n');
    if (end == NULL) end = p + strlen(p);
    bool first = true;
    bool previous_number = false;
    for (const char* q = p; q < end; ) {
      while (q < end && *q == ' ') q++;
      const char* t = q;
      while (q < end && *q != ' ') q++;
      size_t length = (size_t)(q - t);
      if (length == 0) break;
      if (previous_number && is_unit(t, length)) { previous_number = false; continue; }
      if (!first) printf("20");
      first = false;
      if (has_digit(t, length)) {
        printf("4e");
        previous_number = true;
      } else {
        for (size_t i = 0; i < length; i++) printf("%02x", (unsigned char)t[i]);
        previous_number = false;
      }
    }
    printf("0a");
    p = (*end == '\n') ? end + 1 : end;
  }
  printf("\n");
}


typedef struct {
  char text[131072];
  size_t used, calls;
  mi_subproc_id_t id;
  mi_heap_t* heap;
  bool entered, completed, aggregate;
} output_t;
static void capture(const char* message, void* argument) {
  output_t* output = argument;
  size_t length = strlen(message);
  assert(length < sizeof(output->text) - output->used);
  memcpy(output->text + output->used, message, length + 1);
  output->used += length;
  output->calls++;
  if (output->entered) return;
  output->entered = true;
  mi_stats_t_decl(exclusive);
  assert(mi_subproc_stats_get_exclusive(output->id, &exclusive));
  /* Per-Heap printing holds the Heap-list lock. Existing-Heap allocation
     and the exclusive getter do not reacquire that lock. */
  unsigned char* p = mi_heap_malloc(output->heap, 73);
  assert(p && mi_heap_of(p) == output->heap);
  memset(p, 0xa7, 73);
  assert(p[72] == 0xa7);
  mi_free(p);
  if (output->aggregate) {
    mi_stats_t_decl(merged);
    assert(mi_subproc_stats_get(output->id, &merged));
    char nested_json[65536];
    assert(mi_subproc_stats_get_json(output->id, sizeof(nested_json), nested_json) == nested_json);
  }
  output->completed = true;
}
static void observe(const char* stage, mi_subproc_id_t id, mi_heap_t* heap, bool owner) {
  char key[128];
  mi_stats_t_decl(before);
  mi_stats_t_decl(after);
  mi_stats_t_decl(merged);
  mi_stats_t_decl(repeated);
  assert(mi_subproc_stats_get_exclusive(id, &before));
  assert(mi_subproc_stats_get(id, &merged));
  assert(mi_subproc_stats_get(id, &repeated));
  assert(mi_subproc_stats_get_exclusive(id, &after));
  check("snapshot.repeat_and_exclusive_preserved", memcmp(&before, &after, sizeof(before)) == 0 && memcmp(&merged, &repeated, sizeof(merged)) == 0);
  snprintf(key, sizeof(key), "%s.exclusive", stage); print_stats(key, &before);
  snprintf(key, sizeof(key), "%s.merged", stage); print_stats(key, &merged);
  mi_stats_t invalid;
  memset(&invalid, 0xa5, sizeof(invalid));
  invalid.size = sizeof(invalid); invalid.version = MI_STAT_VERSION + 1;
  mi_stats_t saved = invalid;
  check("snapshot.bad_version", !mi_subproc_stats_get(id, &invalid) && memcmp(&saved, &invalid, sizeof(saved)) == 0);
  invalid.version = MI_STAT_VERSION; invalid.size--;
  saved = invalid;
  check("snapshot.bad_size", !mi_subproc_stats_get_exclusive(id, &invalid) && memcmp(&saved, &invalid, sizeof(saved)) == 0);
  check("snapshot.null_output", !mi_subproc_stats_get(id, NULL) && !mi_subproc_stats_get_exclusive(id, NULL));
  check("json.fixed", mi_subproc_stats_get_json(id, sizeof(json_buffer), json_buffer) == json_buffer);
  snprintf(key, sizeof(key), "%s.json", stage); print_hex(key, json_buffer);
  char short_buffer[80]; memset(short_buffer, 'x', sizeof(short_buffer));
  check("json.short", mi_subproc_stats_get_json(id, sizeof(short_buffer), short_buffer) == NULL);
  if (owner) {
    char* allocated = mi_subproc_stats_get_json(id, 0, NULL);
    check("json.owned", allocated && mi_heap_of(allocated) == mi_heap_main());
    mi_free(allocated);
    output_t output = {.id = id, .heap = heap, .aggregate = true};
    mi_subproc_stats_print_out(id, capture, &output);
    check("print.aggregate_reentry", output.calls > 0 && output.completed);
    snprintf(key, sizeof(key), "%s.print", stage); print_normalized(key, output.text);
    snprintf(key, sizeof(key), "%s.print_headers", stage); print_headers(key, output.text);
    output_t heaps = {.id = id, .heap = heap};
    mi_subproc_heap_stats_print_out(id, capture, &heaps);
    check("print.heaps_reentry", heaps.calls > 0 && heaps.completed);
    snprintf(key, sizeof(key), "%s.heaps", stage); print_normalized(key, heaps.text);
    snprintf(key, sizeof(key), "%s.heap_headers", stage); print_headers(key, heaps.text);
    mi_stats_t_decl(current);
    mi_stats_t_decl(explicit);
    assert(mi_stats_get(&current) && mi_subproc_stats_get(id, &explicit));
    check("snapshot.current", memcmp(&current, &explicit, sizeof(current)) == 0);
  }
}
static void* outer_owner(void* argument) {
  fixture_t* f = argument;
  mi_subproc_add_current_thread(f->outer);
  f->outer_main = mi_heap_main();
  f->outer_extra = mi_heap_new();
  f->outer_block = mi_heap_malloc(f->outer_main, 80);
  f->outer_extra_block = mi_heap_malloc(f->outer_extra, 192);
  assert(f->outer_block && f->outer_extra_block);
  memset(f->outer_block, 0x51, 80); memset(f->outer_extra_block, 0x52, 192);
  f->inner = mi_subproc_new();
  assert(f->inner._mi_subproc_id);
  check("nested.metadata_parent", mi_heap_of(f->inner._mi_subproc_id) == f->outer_main);
  observe("outer.owner", f->outer, f->outer_extra, true);
  mi_stats_t_decl(before); mi_stats_t_decl(after);
  assert(mi_subproc_stats_get(f->outer, &before));
  mi_heap_stats_merge_to_subproc(f->outer_extra);
  assert(mi_subproc_stats_get(f->outer, &after));
  check("snapshot.explicit_merge_preserves_total", before.pages.total == after.pages.total && before.pages.current == after.pages.current && before.malloc_normal.total == after.malloc_normal.total && before.malloc_normal.current == after.malloc_normal.current);
  pthread_mutex_lock(&f->mutex);
  f->outer_ready = 1; pthread_cond_broadcast(&f->condition);
  while (!f->outer_release) pthread_cond_wait(&f->condition, &f->mutex);
  pthread_mutex_unlock(&f->mutex);
  return NULL;
}
static void* inner_owner(void* argument) {
  fixture_t* f = argument;
  mi_subproc_add_current_thread(f->inner);
  f->inner_main = mi_heap_main();
  f->inner_extra = mi_heap_new();
  f->inner_block = mi_heap_malloc(f->inner_main, 128);
  f->inner_extra_block = mi_heap_malloc(f->inner_extra, 256);
  assert(f->inner_block && f->inner_extra_block);
  memset(f->inner_block, 0x61, 128); memset(f->inner_extra_block, 0x62, 256);
  observe("inner.owner", f->inner, f->inner_extra, true);
  pthread_mutex_lock(&f->mutex);
  f->inner_ready = 1; pthread_cond_broadcast(&f->condition);
  while (!f->inner_release) pthread_cond_wait(&f->condition, &f->mutex);
  pthread_mutex_unlock(&f->mutex);
  return NULL;
}
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  parent_heap = mi_heap_main();
  parent_block = mi_heap_malloc(parent_heap, 73);
  assert(parent_block); memset(parent_block, 0x41, 73);
  observe("root.before", mi_subproc_main(), parent_heap, true);
  fixture_t f = {.mutex = PTHREAD_MUTEX_INITIALIZER, .condition = PTHREAD_COND_INITIALIZER, .outer = mi_subproc_new()};
  assert(f.outer._mi_subproc_id);
  pthread_t outer, inner;
  /* Stack-resident report buffers and nested callback snapshots require more
     than the default musl worker stack. The caller owns this stack choice. */
  pthread_attr_t attributes;
  assert(pthread_attr_init(&attributes) == 0);
  assert(pthread_attr_setstacksize(&attributes, 2 * 1024 * 1024) == 0);
  assert(pthread_create(&outer, &attributes, outer_owner, &f) == 0);
  pthread_mutex_lock(&f.mutex);
  while (!f.outer_ready) pthread_cond_wait(&f.condition, &f.mutex);
  pthread_mutex_unlock(&f.mutex);
  assert(pthread_create(&inner, &attributes, inner_owner, &f) == 0);
  pthread_mutex_lock(&f.mutex);
  while (!f.inner_ready) pthread_cond_wait(&f.condition, &f.mutex);
  pthread_mutex_unlock(&f.mutex);
  observe("outer.live", f.outer, f.outer_main, false);
  observe("inner.live", f.inner, f.inner_main, false);
  check("live.payload_and_owner", ((unsigned char*)f.outer_block)[79] == 0x51 && ((unsigned char*)f.inner_block)[127] == 0x61 && mi_heap_of(f.outer_block) == f.outer_main && mi_heap_of(f.inner_block) == f.inner_main);
  pthread_mutex_lock(&f.mutex); f.inner_release = 1; pthread_cond_broadcast(&f.condition); pthread_mutex_unlock(&f.mutex);
  assert(pthread_join(inner, NULL) == 0);
  observe("inner.joined", f.inner, f.inner_main, false);
  mi_free(f.inner_extra_block);
  observe("root.pre_inner_destroy", mi_subproc_main(), parent_heap, false);
  mi_subproc_destroy(f.inner);
  /* Destruction consumes the nested live client; never inspect its address. */
  observe("root.post_inner_destroy", mi_subproc_main(), parent_heap, false);
  observe("outer.post_inner_destroy", f.outer, f.outer_main, false);
  pthread_mutex_lock(&f.mutex); f.outer_release = 1; pthread_cond_broadcast(&f.condition); pthread_mutex_unlock(&f.mutex);
  assert(pthread_join(outer, NULL) == 0);
  observe("outer.joined", f.outer, f.outer_main, false);
  mi_free(f.outer_block);
  mi_subproc_destroy(f.outer);
  observe("root.post_outer_destroy", mi_subproc_main(), parent_heap, true);
  check("parent.preserved", parent_block[72] == 0x41 && mi_heap_of(parent_block) == parent_heap);
  mi_subproc_id_t null_id = {NULL};
  mi_stats_t_decl(null_stats);
  check("null.getters", !mi_subproc_stats_get(null_id, &null_stats) && !mi_subproc_stats_get_exclusive(null_id, &null_stats) && !mi_subproc_stats_get_json(null_id, sizeof(json_buffer), json_buffer));
  output_t output = {0};
  mi_subproc_stats_print_out(null_id, capture, &output); mi_subproc_heap_stats_print_out(null_id, capture, &output);
  check("null.callbacks", output.calls == 0);
  mi_subproc_destroy(null_id); mi_subproc_destroy(mi_subproc_main());
  check("main.destroy_refused", parent_block[72] == 0x41 && mi_heap_of(parent_block) == parent_heap);
  mi_free(parent_block);
  pthread_attr_destroy(&attributes);
  pthread_cond_destroy(&f.condition); pthread_mutex_destroy(&f.mutex);
  _exit(0);
}

#endif
