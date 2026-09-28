#include <errno.h>
#include <mimalloc.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
  mi_option_set(mi_option_show_errors, 1);
  puts("CRABC_MI_M6_HUGE_AT_EX_BEGIN");

  mi_arena_id_t id = (mi_arena_id_t)(uintptr_t)1;
  errno = E2BIG;
  int result = mi_reserve_huge_os_pages_at_ex(0, -2, 0, true, &id);
  printf("zero.negative=%d,%d,%d\n", result, id == NULL, errno == E2BIG);

  id = (mi_arena_id_t)(uintptr_t)1;
  errno = E2BIG;
  result = mi_reserve_huge_os_pages_at_ex(0, 0, SIZE_MAX, false, &id);
  printf("zero.timeout=%d,%d,%d\n", result, id == NULL, errno == E2BIG);

  errno = E2BIG;
  result = mi_reserve_huge_os_pages_at_ex(0, 0, 1, true, NULL);
  printf("zero.null=%d,%d\n", result, errno == E2BIG);

  id = (mi_arena_id_t)(uintptr_t)1;
  errno = E2BIG;
  result = mi_reserve_huge_os_pages_at_ex(1, -2, 0, true, &id);
  printf("one.negative=%d,%d,%d\n", result, id == NULL, errno);

  id = (mi_arena_id_t)(uintptr_t)1;
  errno = E2BIG;
  result = mi_reserve_huge_os_pages_at_ex(1, 0, 1, false, &id);
  printf("one.node_zero=%d,%d,%d\n", result, id == NULL, errno);

  puts("CRABC_MI_M6_HUGE_AT_EX_END");
  return 0;
}
