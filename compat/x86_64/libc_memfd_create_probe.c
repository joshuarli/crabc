/* Static crabc-libc x86-64 GNU memfd_create fixture.
 *
 * The project-header C body first executes through pinned musl 1.2.6, then
 * through a freestanding executable linked solely with the selected crabc
 * archive. It selects only the direct memfd_create C ABI and initial-TLS
 * errno translation. Fixture-local raw close calls release returned
 * descriptors; they do not select C descriptor, fcntl, or sealing behavior.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_close == 3 && SYS_memfd_create == 319,
    "x86 selected memfd syscall numbers");
_Static_assert(MFD_CLOEXEC == 0x0001U && MFD_ALLOW_SEALING == 0x0002U &&
    MFD_HUGETLB == 0x0004U, "x86 GNU memfd flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memfd_create),
    int (*)(const char *, unsigned)), "memfd_create declaration");

static long raw_close(int descriptor)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"((long)SYS_close), "D"((long)descriptor)
        : "rcx", "r11", "memory"
    );
    return result;
}

static int close_descriptor(int descriptor)
{
    return raw_close(descriptor) == 0 ? 0 : -1;
}

static int check_valid_names_and_flags(void)
{
    static const char ordinary_name[] = "crabc-x86-static-memfd";
    static const char cloexec_name[] = "crabc-x86-static-memfd-cloexec";
    char boundary_name[251];
    int descriptor;
    unsigned index;

    for (index = 0; index < 249U; ++index)
        boundary_name[index] = 'x';
    boundary_name[249] = '\0';

    errno = EDOM;
    descriptor = memfd_create(ordinary_name, 0);
    if (descriptor < 0 || errno != EDOM)
        return 1;
    if (close_descriptor(descriptor) != 0)
        return 2;

    /* 249 content bytes are accepted by Linux 5.10; the NUL is excluded. */
    errno = ERANGE;
    descriptor = memfd_create(boundary_name, MFD_CLOEXEC);
    if (descriptor < 0 || errno != ERANGE)
        return 3;
    if (close_descriptor(descriptor) != 0)
        return 4;

    /* This only proves creation-flag forwarding, not a seal operation. */
    errno = EILSEQ;
    descriptor = memfd_create(cloexec_name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (descriptor < 0 || errno != EILSEQ)
        return 5;
    if (close_descriptor(descriptor) != 0)
        return 6;

    return 0;
}

static int check_direct_errors(void)
{
    static const char ordinary_name[] = "crabc-x86-static-memfd-error";
    char overlong_name[251];
    unsigned index;

    /* Linux 5.10 rejects exactly 250 content bytes with EINVAL. */
    for (index = 0; index < 250U; ++index)
        overlong_name[index] = 'x';
    overlong_name[250] = '\0';
    errno = 0;
    if (memfd_create(overlong_name, 0) != -1 || errno != EINVAL)
        return 1;

    /* Musl forwards an invalid flag word directly to Linux validation. */
    errno = 0;
    if (memfd_create(ordinary_name, UINT_MAX) != -1 || errno != EINVAL)
        return 2;

    /* Linux reads the label, so a non-null inaccessible pointer is EFAULT. */
    errno = 0;
    if (memfd_create((const char *)(uintptr_t)1, 0) != -1 || errno != EFAULT)
        return 3;

    return 0;
}

int crabc_x86_64_memfd_create_probe(void)
{
    int result = check_valid_names_and_flags();

    if (result != 0)
        return result;
    result = check_direct_errors();
    return result == 0 ? 0 : 10 + result;
}

#ifndef CRABC_MEMFD_CREATE_FREESTANDING
int main(void)
{
    return crabc_x86_64_memfd_create_probe();
}
#endif
