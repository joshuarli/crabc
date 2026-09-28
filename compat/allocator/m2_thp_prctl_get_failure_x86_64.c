/* A failed process-local THP GET at the ordinary pinned startup caller.
 * `os.c` keeps the selected configuration visible, while unchanged `init.c`
 * provides the process-once transition. The remaining release objects link
 * once, and the linker wraps only the primitive's two THP prctl tuples.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

#include "os.c"
#include "init.c"

static unsigned prctl_count;
static unsigned get_count;
static unsigned set_count;
static bool tuples_match = true;

int __real_prctl(int option, ...);

int __wrap_prctl(int option, unsigned long a0, unsigned long a1,
                 unsigned long a2, unsigned long a3) {
  prctl_count++;
  if (option == PR_GET_THP_DISABLE) {
    get_count++;
    tuples_match &= a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0;
    errno = EPERM;
    return -1;
  }
  if (option == PR_SET_THP_DISABLE) {
    set_count++;
    tuples_match = false;
    errno = EINVAL;
    return -1;
  }
  return __real_prctl(option, a0, a1, a2, a3);
}

int main(void) {
  if (clearenv() != 0 || setenv("mimalloc_allow_thp", "0", 1) != 0) return 1;
  mi_process_init();
  const unsigned first_count = prctl_count;
  void* block = mi_malloc(79);
  const bool allocation_succeeded = block != NULL;
  if (block != NULL) mi_free(block);
  mi_process_init();

  puts("CRABC_M2_THP_PRCTL_C_TRACE_BEGIN");
  printf("selected_allow_thp_raw=%ld\n", mi_option_get(mi_option_allow_thp));
  printf("config_has_transparent_huge_pages=%u\n", (unsigned)mi_os_mem_config.has_transparent_huge_pages);
  printf("process_ready=%u\n", (unsigned)_mi_process_is_initialized);
  printf("allocation_succeeded=%u\n", (unsigned)allocation_succeeded);
  printf("first_prctl_count=%u\n", first_count);
  printf("retry_prctl_count=%u\n", prctl_count);
  printf("get_count=%u\n", get_count);
  printf("set_count=%u\n", set_count);
  printf("tuples_match=%u\n", (unsigned)tuples_match);
  puts("CRABC_M2_THP_PRCTL_C_TRACE_END");

  return _mi_process_is_initialized && allocation_succeeded && !mi_os_mem_config.has_transparent_huge_pages
      && first_count == 1 && prctl_count == 1 && get_count == 1 && set_count == 0 && tuples_match
      ? 0 : 2;
}
