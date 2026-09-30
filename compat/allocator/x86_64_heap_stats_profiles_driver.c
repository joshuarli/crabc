#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

/* All statistics calls use live identities from this owner. No client reads
   counters while another thread mutates the selected Heap or Theap. */
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
static void print_hex(const char* key, const char* text) {
  printf("%s=", key);
  for (const unsigned char* p = (const unsigned char*)text; *p; ++p) printf("%02x", *p);
  printf("\n");
}


static char json_buffer[65536];
static mi_heap_t* allocation_default;
typedef struct {
  char text[131072];
  size_t used, calls;
  mi_heap_t* heap;
  bool entered, completed;
} output_t;
static void capture(const char* text, void* arg) {
  output_t* output = arg;
  size_t size = strlen(text);
  assert(size < sizeof(output->text) - output->used);
  memcpy(output->text + output->used, text, size + 1);
  output->used += size; output->calls++;
  if (!output->entered) {
    output->entered = true;
    mi_stats_t_decl(stats);
    /* The printer has already merged this owner. A nested getter is
       idempotent and keeps the live Heap selected by the outer call. */
    assert(mi_heap_stats_get(output->heap, &stats));
    output->completed = true;
  }
}
static void observe(const char* label, mi_heap_t* heap) {
  char key[128];
  mi_stats_t_decl(stats); mi_stats_t_decl(repeated);
  assert(mi_heap_stats_get(heap, &stats));
  assert(mi_heap_stats_get(heap, &repeated));
  check("heap.snapshot_repeat", memcmp(&stats, &repeated, sizeof(stats)) == 0);
  snprintf(key, sizeof(key), "%s.stats", label); print_stats(key, &stats);
  assert(mi_heap_stats_get_json(heap, sizeof(json_buffer), json_buffer) == json_buffer);
  snprintf(key, sizeof(key), "%s.json", label); print_hex(key, json_buffer);
  char short_buffer[80]; memset(short_buffer, 0x37, sizeof(short_buffer));
  check("heap.json_short", mi_heap_stats_get_json(heap, sizeof(short_buffer), short_buffer) == NULL);
  output_t output = {.heap = heap};
  mi_heap_stats_print_out(heap, capture, &output);
  check("heap.print_reentry", output.calls > 0 && output.completed);
  snprintf(key, sizeof(key), "%s.print", label); print_hex(key, output.text);
  char* owned = mi_heap_stats_get_json(heap, 0, NULL);
  check("heap.json_owned", owned && mi_heap_of(owned) == allocation_default);
  printf("%s.json_owned_usable=%zu\n", label, mi_usable_size(owned));
  assert(strlen(owned) < sizeof(json_buffer));
  strcpy(json_buffer, owned);
  snprintf(key, sizeof(key), "%s.owned.json", label); print_hex(key, json_buffer);
  mi_free(owned);
}
static void rejection_merge(const char* label, mi_heap_t* heap, size_t bytes, int rejection) {
  unsigned char* client = mi_heap_malloc(heap, bytes);
  assert(client && mi_heap_of(client) == heap); memset(client, 0x75, bytes);
  mi_stats_t_decl(exclusive_before); mi_stats_t_decl(exclusive_pending);
  mi_subproc_id_t owner = mi_subproc_current();
  assert(mi_subproc_stats_get_exclusive(owner, &exclusive_before));
  mi_heap_stats_merge_to_subproc(heap);
  assert(mi_subproc_stats_get_exclusive(owner, &exclusive_pending));
  check("merge.does_not_merge_pending_theap", memcmp(&exclusive_before, &exclusive_pending, sizeof(exclusive_before)) == 0);
  mi_stats_t invalid; memset(&invalid, 0xa5, sizeof(invalid));
  mi_stats_header_init(&invalid);
  if (rejection == 1) invalid.version++;
  if (rejection == 2) invalid.size--;
  mi_stats_t saved = invalid;
  check("heap.header_rejected", !mi_heap_stats_get(heap, rejection == 0 ? NULL : &invalid));
  check("heap.rejected_image_preserved", memcmp(&saved, &invalid, sizeof(invalid)) == 0);
  /* The Heap getter merges its live Theap before checking the output.
     Transferring the Heap now must publish the pending page event. */
  mi_heap_stats_merge_to_subproc(heap);
  mi_stats_t_decl(after);
  assert(mi_subproc_stats_get_exclusive(owner, &after));
  check("heap.reject_still_merged", after.pages.total > exclusive_pending.pages.total);
  char key[128]; snprintf(key, sizeof(key), "%s.owner_exclusive", label); print_stats(key, &after);
  mi_stats_t_decl(cleared); assert(mi_heap_stats_get(heap, &cleared));
  check("merge.heap_cleared", cleared.pages.total == 0 && cleared.pages.current == 0);
  snprintf(key, sizeof(key), "%s.heap_cleared", label); print_stats(key, &cleared);
  check("client.preserved", client[0] == 0x75 && client[bytes - 1] == 0x75);
  mi_free(client);
}
static void owner_sequence(const char* prefix) {
  mi_heap_t* main_heap = mi_heap_main();
  mi_heap_t* extra = mi_heap_new(); assert(extra);
  char label[128];
  snprintf(label, sizeof(label), "%s.bad_version", prefix); rejection_merge(label, extra, 96, 1);
  snprintf(label, sizeof(label), "%s.bad_size", prefix); rejection_merge(label, extra, 8192, 2);
  snprintf(label, sizeof(label), "%s.null_output", prefix); rejection_merge(label, extra, 131072, 0);
  unsigned char* main_client = mi_heap_malloc(main_heap, 80);
  unsigned char* extra_client = mi_heap_malloc(extra, 192);
  assert(main_client && extra_client); memset(main_client, 0x41, 80); memset(extra_client, 0x42, 192);
  mi_theap_t* extra_theap = mi_heap_theap(extra); assert(extra_theap);
  mi_theap_t* previous = mi_theap_set_default(extra_theap);
  allocation_default = extra;
  check("default.selects_auxiliary", mi_theap_get_default() == extra_theap);
  unsigned char* default_client = mi_malloc(256); assert(default_client && mi_heap_of(default_client) == extra);
  memset(default_client, 0x43, 256);
  mi_stats_t_decl(null_stats); mi_stats_t_decl(main_stats);
  assert(mi_heap_stats_get(NULL, &null_stats) && mi_heap_stats_get(main_heap, &main_stats));
  check("null.selects_current_main", memcmp(&null_stats, &main_stats, sizeof(main_stats)) == 0);
  snprintf(label, sizeof(label), "%s.null", prefix); observe(label, NULL);
  snprintf(label, sizeof(label), "%s.main", prefix); observe(label, main_heap);
  snprintf(label, sizeof(label), "%s.auxiliary", prefix); observe(label, extra);
  mi_theap_set_default(previous);
  check("default.restored", mi_theap_get_default() == previous);
  check("clients.preserved", main_client[79] == 0x41 && extra_client[191] == 0x42 && default_client[255] == 0x43);
  mi_free(main_client); mi_free(extra_client); mi_free(default_client);
  mi_heap_destroy(extra);
}
static mi_subproc_id_t child;
static mi_heap_t* process_main;
static void* child_owner(void* unused) {
  (void)unused;
  mi_subproc_add_current_thread(child);
  check("child.current", mi_subproc_current()._mi_subproc_id == child._mi_subproc_id);
  check("child.main_distinct", mi_heap_main() != process_main);
  owner_sequence("child");
  mi_stats_t_decl(current); mi_stats_t_decl(explicit);
  assert(mi_stats_get(&current) && mi_subproc_stats_get(child, &explicit));
  check("child.current_stats", memcmp(&current, &explicit, sizeof(current)) == 0);
  return NULL;
}
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  process_main = mi_heap_main();
  owner_sequence("root");
  child = mi_subproc_new(); assert(child._mi_subproc_id);
  pthread_attr_t attr; pthread_t thread;
  assert(pthread_attr_init(&attr) == 0 && pthread_attr_setstacksize(&attr, 2 * 1024 * 1024) == 0);
  assert(pthread_create(&thread, &attr, child_owner, NULL) == 0);
  assert(pthread_attr_destroy(&attr) == 0 && pthread_join(thread, NULL) == 0);
  /* Only joined owners are destroyed; no Heap or client is inspected after
     its selected lifetime ends. */
  mi_subproc_destroy(child);
  _exit(0);
}
