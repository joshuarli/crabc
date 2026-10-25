#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "static.c"

static size_t preferred_calls;
static size_t fallback_calls;

int __real_clock_gettime(clockid_t clock_id, struct timespec* value);
int __wrap_clock_gettime(clockid_t clock_id, struct timespec* value) {
  if (clock_id == CLOCK_MONOTONIC) {
    preferred_calls++;
    errno = EIO;
    return -1;
  }
  return __real_clock_gettime(clock_id, value);
}

clock_t __wrap_clock(void) {
  fallback_calls++;
  return 1234567;
}

int main(void) {
  const mi_msecs_t milliseconds = _mi_prim_clock_now();
  puts("CRABC_M1_CLOCK_FALLBACK_BEGIN");
  printf("preferred.calls=%zu\nfallback.calls=%zu\nclock.milliseconds=%lld\n",
         preferred_calls, fallback_calls, (long long)milliseconds);
  puts("CRABC_M1_CLOCK_FALLBACK_END");
  return preferred_calls == 1 && fallback_calls == 1 && milliseconds == 1234 ? 0 : 1;
}
