/* Native x86-64 runtime-source THP configuration oracle.
 *
 * Each binary is one clean environment image for pinned mimalloc v3.5.0's
 * normal `mi_process_init()` route. It directly includes `src/os.c` and
 * `src/init.c`: `os.c` keeps its private `mi_os_mem_config` visible after
 * `_mi_os_init`, while `init.c` supplies the unchanged process-once body.
 * The Python producer links every remaining release source exactly once and
 * deliberately omits these two included source objects. This records only
 * the selected raw `allow_thp` option and the retained configuration bit; it
 * does not claim a host THP mode, a syscall outcome, or allocator behavior.
 */
#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

/* Resolved through `-I <pinned-source>/src`. The two direct-included source
 * units are intentionally absent from the ordinary link closure. */
#include "os.c"
#include "init.c"

#if defined(CRABC_RUNTIME_THP_IMAGE_DISABLED) == defined(CRABC_RUNTIME_THP_IMAGE_MODE_TWO)
#error "exactly one runtime THP configuration image is required"
#endif

#if defined(CRABC_RUNTIME_THP_IMAGE_DISABLED)
#define IMAGE_ALLOW_THP "0"
#define TRACE_BEGIN "CRABC_MI_RUNTIME_THP_C_DISABLED_TRACE_BEGIN"
#define TRACE_END "CRABC_MI_RUNTIME_THP_C_DISABLED_TRACE_END"
#else
#define IMAGE_ALLOW_THP "2"
#define TRACE_BEGIN "CRABC_MI_RUNTIME_THP_C_MODE_TWO_TRACE_BEGIN"
#define TRACE_END "CRABC_MI_RUNTIME_THP_C_MODE_TWO_TRACE_END"
#endif

static void trace_unsigned(const char* name, size_t value) {
  printf("%s=%zu\n", name, value);
}

int main(void) {
  if (clearenv() != 0 || setenv("mimalloc_allow_thp", IMAGE_ALLOW_THP, 1) != 0) {
    return 1;
  }

  /* With MI_PRIM_HAS_PROCESS_ATTACH, the linked Unix primitive leaves this
   * one normal source process initialization to the explicit call below. */
  mi_process_init();

  const long selected_allow_thp_raw = mi_option_get(mi_option_allow_thp);
  const bool config_has_transparent_huge_pages =
      mi_os_mem_config.has_transparent_huge_pages;
  puts(TRACE_BEGIN);
  trace_unsigned("selected_allow_thp_raw", (size_t)selected_allow_thp_raw);
  trace_unsigned("config_has_transparent_huge_pages",
      config_has_transparent_huge_pages);
  puts(TRACE_END);

#if defined(CRABC_RUNTIME_THP_IMAGE_DISABLED)
  return (selected_allow_thp_raw == 0 && !config_has_transparent_huge_pages)
      ? 0
      : 2;
#else
  return selected_allow_thp_raw == 2 ? 0 : 2;
#endif
}
