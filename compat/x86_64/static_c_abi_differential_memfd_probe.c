/* Deterministic shared workload for the private x86 static-C ABI differential.
 *
 * It is deliberately small: the workload observes the selected `memfd_create`
 * C ABI, direct errno translation, and no-result errno preservation. Both
 * executables emit the same normalized observable record. Raw write/close are
 * fixture plumbing only; they do not select a C descriptor runtime.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this workload requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

_Static_assert(SYS_close == 3 && SYS_memfd_create == 319,
    "selected x86 syscall numbers");
_Static_assert(MFD_CLOEXEC == 1, "selected GNU memfd flag");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memfd_create),
    int (*)(const char *, unsigned)), "memfd_create declaration");

static long raw_syscall3(long number, long first, long second, long third)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static int close_descriptor(int descriptor)
{
    return raw_syscall3(SYS_close, descriptor, 0, 0) == 0 ? 0 : -1;
}

static int emit(const char *bytes, unsigned length)
{
    while (length != 0) {
        long written = raw_syscall3(SYS_write, 1, (long)(uintptr_t)bytes, length);

        if (written <= 0 || (unsigned long)written > length)
            return -1;
        bytes += written;
        length -= (unsigned)written;
    }
    return 0;
}

int crabc_x86_64_static_c_abi_differential_probe(void)
{
    static const char name[] = "crabc-x86-static-abi-differential";
    int descriptor;

    errno = EDOM;
    descriptor = memfd_create(name, MFD_CLOEXEC);
    if (descriptor < 0 || errno != EDOM || close_descriptor(descriptor) != 0)
        return 10;

    errno = 0;
    if (memfd_create(name, UINT32_MAX) != -1 || errno != EINVAL)
        return 11;

    errno = 0;
    if (memfd_create((const char *)(uintptr_t)1, 0) != -1 || errno != EFAULT)
        return 12;

    /* The fixture emits booleans and errno constants, never unstable fd IDs. */
    return emit("memfd.success=1\n"
                "memfd.stale_errno=1\n"
                "memfd.invalid_flags_errno=22\n"
                "memfd.bad_pointer_errno=14\n", 92) == 0 ? 0 : 13;
}

#ifndef CRABC_STATIC_C_ABI_DIFFERENTIAL_FREESTANDING
int main(void)
{
    return crabc_x86_64_static_c_abi_differential_probe();
}
#endif
