/* Static crabc-libc x86-64 selected clock_adjtime error-ABI fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a dependency-free -nostdlib -static candidate. It invokes only
 * Linux-rejected clock IDs with a writable zero timex record, so this fixture
 * never requests a valid clock adjustment. It observes the ordinary C
 * -1/errno conversion only, not authority, discipline, state, or policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <time.h>

typedef int (*clock_adjtime_signature)(clockid_t, struct timex *);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
_Static_assert(sizeof(struct timex) == 208 && _Alignof(struct timex) == 8,
    "x86 timex layout");
_Static_assert(offsetof(struct timex, time) == 72 &&
    offsetof(struct timex, tai) == 160 &&
    offsetof(struct timex, __padding) == 164, "x86 timex field offsets");
_Static_assert(SYS_clock_adjtime == 305, "x86 clock_adjtime syscall number");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1,
    "selected non-mutating clock IDs");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_adjtime),
    clock_adjtime_signature), "clock_adjtime declaration");

static volatile clock_adjtime_signature clock_adjtime_function = clock_adjtime;

static int record_is_zero(const struct timex *record)
{
    const unsigned char *bytes = (const unsigned char *)record;
    size_t index;

    for (index = 0; index < sizeof(*record); ++index) {
        if (bytes[index] != 0)
            return 0;
    }
    return 1;
}

static int check_rejected_clock(clockid_t clock_id, int sentinel)
{
    struct timex record = {0};

    errno = sentinel;
    if (clock_adjtime_function(clock_id, &record) != -1 ||
        (errno != EINVAL && errno != EPERM && errno != EOPNOTSUPP))
        return 1;
    return record_is_zero(&record) ? 0 : 2;
}

int crabc_x86_64_clock_adjtime_probe(void)
{
    int status = check_rejected_clock((clockid_t)-1, ERANGE);

    if (status != 0)
        return 10 + status;
    status = check_rejected_clock(CLOCK_MONOTONIC, E2BIG);
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_CLOCK_ADJTIME_FREESTANDING
int main(void)
{
    return crabc_x86_64_clock_adjtime_probe();
}
#endif
