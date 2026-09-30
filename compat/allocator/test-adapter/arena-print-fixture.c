#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef CRABC_PREFIXED
#include "crabc-mimalloc-test-adapter.h"
#define allocate crabc_test_malloc
#define release crabc_test_free
#define register_output crabc_test_register_output
#define show_arenas crabc_test_debug_show_arenas
#define print_arenas crabc_test_arenas_print
#else
#include <mimalloc.h>
#define allocate mi_malloc
#define release mi_free
#define register_output mi_register_output
#define show_arenas mi_debug_show_arenas
#define print_arenas mi_arenas_print
#endif

static void require(bool condition) { if (!condition) abort(); }

static bool printing;
static bool reentered;
static size_t lengths[128];
static size_t count;
static int callback_cookie;
static int callback_errno;
static size_t callback_calls;
static void output(const char *text, void *argument) {
  require(argument == &callback_cookie);
  callback_calls++;
  if (callback_errno != 0) errno = callback_errno;
  if (!printing) return;
  require(count < sizeof(lengths)/sizeof(lengths[0]));
  lengths[count++] = strlen(text);
  fputs(text, stdout);
  if (!reentered) {
    reentered = true;
    void *block = allocate(33);
    require(block != NULL);
    release(block);
  }
}
int main(int argc, char **argv) {
  require(argc == 2);
#ifdef CRABC_PREFIXED
  errno = 71;
  show_arenas(); print_arenas(); register_output(output, &callback_cookie);
  require(errno == 71 && count == 0);
  require(crabc_test_init() == 0);
#else
  mi_option_set(mi_option_arena_reserve, 0);
  mi_option_set(mi_option_purge_delay, -1);
  require(mi_reserve_os_memory(mi_arena_min_size(), true, false) == 0);
#endif
  void *block = allocate(33);
  require(block != NULL);
  callback_errno = strstr(argv[1], "errno") ? 72 : 0;
  bool stderr_route = strstr(argv[1], "stderr") != NULL;
  errno = 71;
  register_output(stderr_route ? NULL : output, stderr_route ? NULL : &callback_cookie);
  if (callback_errno && callback_calls) {
    if (errno != callback_errno) {
      fprintf(stderr, "registration callback errno observed %d expected %d\n", errno, callback_errno);
      abort();
    }
  }
  errno = 71;
  printing = true;
  if (strncmp(argv[1], "show", 4) == 0) show_arenas();
  else { require(strncmp(argv[1], "print", 5) == 0); print_arenas(); }
  printing = false;
  require(reentered == !stderr_route);
  if (errno != (callback_errno ? callback_errno : 71)) {
    fprintf(stderr, "print callback errno observed %d expected %d\n", errno, callback_errno ? callback_errno : 71);
    abort();
  }
  fputs("CALLBACK_LENGTHS=", stdout);
  for (size_t i = 0; i < count; i++) printf("%s%zu", i ? "," : "", lengths[i]);
  putchar('\n');
  release(block);
  register_output(NULL, NULL);
#ifdef CRABC_PREFIXED
  require(crabc_test_shutdown() == 0);
  count = 0;
  show_arenas(); print_arenas(); register_output(output, &callback_cookie);
  require(count == 0);
#else
  mi_collect(true);
#endif
  return 0;
}
