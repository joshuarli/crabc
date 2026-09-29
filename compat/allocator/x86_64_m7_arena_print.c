#define _GNU_SOURCE
#include <mimalloc.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static void require(bool condition) {
  if (!condition) abort();
}

static bool printing;
static size_t lengths[256];
static size_t length_count;

static void output(const char* text, void* argument) {
  require(argument == (void*)0x1234);
  if (printing) {
    require(length_count < 256);
    lengths[length_count++] = strlen(text);
    fputs(text, stdout);
  }
}

int main(int argc, char** argv) {
  require(argc == 5);
  const char* state = argv[1];
  mi_option_set(mi_option_arena_reserve, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_arena_id_t arena = NULL;
  if (strcmp(state, "empty") != 0) {
    if (strcmp(state, "managed") == 0) {
      size_t size = 64 * 1024 * 1024;
      size_t alignment = 256 * 1024 * 1024;
      void* region = mmap(NULL, size + alignment, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      require(region != MAP_FAILED);
      region = (void*)(((uintptr_t)region + alignment - 1) & ~(uintptr_t)(alignment - 1));
      require(mi_manage_os_memory_ex(region, size, true, false, true, -1, false, &arena));
    }
    else {
      require(mi_reserve_os_memory_ex(64 * 1024 * 1024, false, false, false, &arena) == 0);
    }
    require(arena != NULL);
  }
  if (strcmp(state, "allocated") == 0 || strcmp(state, "freed") == 0 || strcmp(state, "purged") == 0) {
    void* p = mi_malloc(64);
    require(p != NULL);
    memset(p, 42, 64);
    if (strcmp(state, "allocated") != 0) mi_free(p);
    if (strcmp(state, "purged") == 0) {
      mi_option_set(mi_option_purge_delay, 0);
      mi_collect(true);
    }
  }
  if (strcmp(state, "usage-40") == 0 || strcmp(state, "usage-60") == 0 ||
      strcmp(state, "usage-90") == 0 || strcmp(state, "full") == 0) {
    size_t count = strcmp(state, "usage-40") == 0 ? 400 :
                   strcmp(state, "usage-60") == 0 ? 600 :
                   strcmp(state, "usage-90") == 0 ? 900 : 1024;
    for (size_t i = 0; i < count; i++) require(mi_malloc(64) != NULL);
  }
  if (strcmp(state, "singleton") == 0 || strcmp(state, "medium") == 0) {
    require(mi_malloc(strcmp(state, "singleton") == 0 ? 589824 : 32768) != NULL);
  }
  printf("ARENA_ID=%" PRIXPTR "\n", (uintptr_t)arena);
  mi_option_set(mi_option_verbose, atol(argv[4]));
  if (strcmp(argv[3], "callback") == 0) mi_register_output(output, (void*)0x1234);
  puts("CRABC_MI_ARENA_PRINT_BEGIN");
  printing = true;
  if (strcmp(argv[2], "show") == 0) mi_debug_show_arenas();
  else mi_arenas_print();
  printing = false;
  puts("CRABC_MI_ARENA_PRINT_END");
  mi_option_set(mi_option_verbose, 0);
  printf("CALLBACK_LENGTHS=");
  for (size_t i = 0; i < length_count; i++) printf("%s%zu", i == 0 ? "" : ",", lengths[i]);
  putchar('\n');
  return 0;
}
