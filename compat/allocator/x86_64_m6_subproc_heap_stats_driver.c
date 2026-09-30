#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <mimalloc.h>
#include <mimalloc-stats.h>

struct output {
  char text[65536];
  size_t used;
  size_t calls;
  bool reenter;
};

static void capture(const char* message, void* argument) {
  struct output* output = argument;
  assert(output != NULL);
  const size_t length = strlen(message);
  assert(length < sizeof(output->text) - output->used);
  memcpy(output->text + output->used, message, length + 1);
  output->used += length;
  output->calls++;
  if (output->reenter) {
    output->reenter = false;
    unsigned char* block = mi_malloc(37);
    assert(block != NULL && mi_usable_size(block) >= 37);
    memset(block, 0xa7, 37);
    assert(block[36] == 0xa7);
    mi_free(block);
  }
}

static mi_theap_t* require_unmerged_pages(mi_heap_t* heap) {
  mi_theap_t* theap = mi_heap_theap(heap);
  mi_stats_t_decl(stats);
  assert(theap != NULL && mi_theap_stats_get(theap, &stats));
  assert(stats.pages.total > 0);
  return theap;
}

static void require_merged_pages(mi_theap_t* theap) {
  mi_stats_t_decl(stats);
  assert(mi_theap_stats_get(theap, &stats));
  assert(stats.pages.total == 0 && stats.pages.current == 0);
}

static void show_headers(const struct output* output, bool has_allocations) {
  assert(output->calls > 0 && !output->reenter);
  const char* line = output->text;
  size_t headers = 0;
  while (*line != '\0') {
    const char* end = strchr(line, '\n');
    assert(end != NULL);
    if (strncmp(line, "heap ", 5) == 0 || strncmp(line, "meta ", 5) == 0 || strncmp(line, "subproc ", 8) == 0) {
      printf("%.*s\n", (int)(end - line), line);
      headers++;
    }
    line = end + 1;
  }
  assert(headers > 0);
  if (has_allocations) {
    assert(strstr(output->text, " pages           peak       total     current       block      total#   \n") != NULL);
  }
  assert(strstr(output->text, " process         peak       total     current       block      total#   \n") != NULL);
  assert(strstr(output->text, "  numa nodes:") != NULL);
  puts("format-and-reentry=ok");
}

struct child_input { mi_subproc_id_t id; };
static void* child_print(void* argument) {
  struct child_input* input = argument;
  mi_subproc_add_current_thread(input->id);
  mi_heap_t* first = mi_heap_new();
  mi_heap_t* second = mi_heap_new();
  assert(first != NULL && second != NULL);
  void* a = mi_heap_malloc(first, 43);
  void* b = mi_heap_malloc(second, 53);
  assert(a != NULL && b != NULL);
  mi_theap_t* selected = require_unmerged_pages(second);
  struct output output = {.reenter = true};
  mi_subproc_heap_stats_print_out(mi_subproc_current(), capture, &output);
  require_merged_pages(selected);
  show_headers(&output, true);
  mi_free(a);
  mi_free(b);
  mi_heap_delete(second);
  mi_heap_delete(first);
  return NULL;
}

int main(int argc, char** argv) {
  assert(argc == 2);
  void* initial = mi_malloc(19);
  assert(initial != NULL);
  if (strcmp(argv[1], "null") == 0) {
    mi_subproc_id_t null_id = {NULL};
    struct output output = {0};
    mi_subproc_heap_stats_print_out(null_id, capture, &output);
    mi_subproc_heap_stats_print_out(null_id, NULL, NULL);
    assert(output.calls == 0 && output.used == 0);
    puts("null-output=empty");
  } else if (strcmp(argv[1], "main") == 0) {
    mi_heap_t* first = mi_heap_new();
    mi_heap_t* second = mi_heap_new();
    assert(first != NULL && second != NULL);
    void* a = mi_heap_malloc(first, 43);
    void* b = mi_heap_malloc(second, 53);
    assert(a != NULL && b != NULL);
    mi_theap_t* selected = require_unmerged_pages(second);
    struct output output = {.reenter = true};
    mi_subproc_heap_stats_print_out(mi_subproc_main(), capture, &output);
    require_merged_pages(selected);
    show_headers(&output, true);
    mi_free(a);
    mi_free(b);
    mi_heap_delete(second);
    mi_heap_delete(first);
  } else if (strcmp(argv[1], "empty") == 0 || strcmp(argv[1], "default") == 0) {
    mi_subproc_id_t child = mi_subproc_new();
    assert(child._mi_subproc_id != NULL);
    if (strcmp(argv[1], "default") == 0) {
      mi_subproc_heap_stats_print_out(child, NULL, NULL);
      puts("default-route=stderr");
    } else {
      struct output output = {.reenter = true};
      mi_subproc_heap_stats_print_out(child, capture, &output);
      show_headers(&output, false);
    }
    mi_subproc_destroy(child);
  } else {
    assert(strcmp(argv[1], "live-child") == 0);
    struct child_input input = {.id = mi_subproc_new()};
    assert(input.id._mi_subproc_id != NULL);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, child_print, &input) == 0);
    assert(pthread_join(thread, NULL) == 0);
    mi_subproc_destroy(input.id);
  }
  mi_free(initial);
  return 0;
}
