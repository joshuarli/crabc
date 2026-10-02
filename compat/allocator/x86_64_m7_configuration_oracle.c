/* Snapshot selected compile-time layout and public guarded option defaults. */
#define _GNU_SOURCE 1
#include <stdio.h>
#include "static.c"

/* Undefined source switches have value zero in preprocessor conditions. */
#ifndef MI_FREE_IS_CHECKED
#define MI_FREE_IS_CHECKED 0
#endif
#ifndef MI_FREE_USE_PAGEMAP
#define MI_FREE_USE_PAGEMAP 0
#endif
#ifndef MI_OPT_FREE_SMALL
#define MI_OPT_FREE_SMALL 0
#endif

#define VALUE(name) printf(#name "=%zu\n", (size_t)(name))
int main(void) {
  puts("CRABC_GUARDED_CONFIG_BEGIN");
  VALUE(MI_GUARDED); VALUE(MI_DEBUG); VALUE(MI_SECURE); VALUE(MI_STAT);
  VALUE(MI_PADDING_SIZE); VALUE(MI_PADDING_WSIZE); VALUE(MI_PAGE_KEY_COUNT);
  VALUE(MI_ENCODE_FREELIST); VALUE(MI_FREE_IS_CHECKED); VALUE(MI_FREE_USE_PAGEMAP);
  VALUE(MI_OPT_FREE_SMALL); VALUE(MI_PAGE_META_IS_SEPARATED);
  VALUE(MI_PAGE_META_IS_ALIGNED); VALUE(MI_PAGES_DIRECT);
  printf("guarded_min=%ld\n", mi_option_get(mi_option_guarded_min));
  printf("guarded_max=%ld\n", mi_option_get(mi_option_guarded_max));
  printf("guarded_precise=%ld\n", mi_option_get(mi_option_guarded_precise));
  printf("guarded_sample_rate=%ld\n", mi_option_get(mi_option_guarded_sample_rate));
  printf("guarded_sample_seed=%ld\n", mi_option_get(mi_option_guarded_sample_seed));
  puts("CRABC_GUARDED_CONFIG_END");
  return 0;
}
