/*
 * A normalized, local public-C allocation trace for comparing the ordinary
 * C-backed libc artifact with the selected native-mimalloc shadow artifact.
 *
 * This deliberately records semantic facts only. Pointer addresses, usable
 * allocation sizes, page layout, and allocation reuse are backend internals,
 * so including them would turn an ABI comparison into an accidental allocator
 * implementation comparison. Cross-owner paths have their own bounded
 * native-shadow fixtures and are explicitly excluded by the paired matrix.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int fail(const char *name)
{
    fputs(name, stderr);
    fputc('\n', stderr);
    return 1;
}

static int emit(const char *record, size_t length)
{
    return write(STDOUT_FILENO, record, length) == (ssize_t)length;
}

/* The Linux/AArch64 C allocation boundary used by both libc wrappers. */
#define C_MALLOC_ALIGNMENT 16

#define RESULT(name, value) \
    do { \
        static const char record[] = "case=" name " result=" value "\n"; \
        if (!emit(record, sizeof(record) - 1)) \
            return fail("report"); \
    } while (0)

#define PASS(name) RESULT(name, "pass")

int main(void)
{
    unsigned char *allocation;
    unsigned char *replacement;
    uintptr_t old_address;

    errno = EAGAIN;
    free(NULL);
    if (errno != EAGAIN)
        return fail("free-null-errno");
    PASS("free-null-preserves-errno");

    errno = ERANGE;
    allocation = malloc(33);
    if (allocation == NULL || (uintptr_t)allocation % C_MALLOC_ALIGNMENT != 0 || errno != ERANGE)
        return fail("malloc-local");
    allocation[0] = 0x31;
    allocation[32] = 0x32;
    PASS("malloc-local-content-and-errno");

    errno = EDOM;
    replacement = realloc(allocation, 8192);
    if (replacement == NULL || (uintptr_t)replacement % C_MALLOC_ALIGNMENT != 0
            || replacement[0] != 0x31 || replacement[32] != 0x32
            || errno != EDOM)
        return fail("realloc-grow");
    replacement[8191] = 0x7d;
    PASS("realloc-grow-preserves-prefix-and-errno");

    errno = EAGAIN;
    allocation = realloc(replacement, 17);
    if (allocation == NULL || (uintptr_t)allocation % C_MALLOC_ALIGNMENT != 0
            || allocation[0] != 0x31 || errno != EAGAIN)
        return fail("realloc-shrink");
    PASS("realloc-shrink-preserves-prefix-and-errno");

    errno = ERANGE;
    replacement = realloc(NULL, 0);
    if (replacement == NULL) {
        RESULT("realloc-null-zero-result", "null");
    } else if ((uintptr_t)replacement % C_MALLOC_ALIGNMENT != 0) {
        if (errno != ERANGE)
            RESULT("realloc-null-zero-result", "freeable-misaligned-errno-changed");
        else
            RESULT("realloc-null-zero-result", "freeable-misaligned-preserves-errno");
        free(replacement);
    } else if (errno != ERANGE) {
        RESULT("realloc-null-zero-result", "freeable-aligned-errno-changed");
        free(replacement);
    } else {
        RESULT("realloc-null-zero-result", "freeable-aligned-preserves-errno");
        free(replacement);
    }

    old_address = (uintptr_t)allocation;
    errno = EDOM;
    replacement = realloc(allocation, 0);
    if (replacement == NULL) {
        RESULT("realloc-zero-result", "null");
    } else if ((uintptr_t)replacement == old_address) {
        if (errno != EDOM)
            RESULT("realloc-zero-result", "same-address-errno-changed");
        else
            RESULT("realloc-zero-result", "same-address-preserves-errno");
        free(replacement);
    } else if ((uintptr_t)replacement % C_MALLOC_ALIGNMENT != 0) {
        if (errno != EDOM)
            RESULT("realloc-zero-result", "distinct-misaligned-errno-changed");
        else
            RESULT("realloc-zero-result", "distinct-misaligned-preserves-errno");
        free(replacement);
    } else if (errno != EDOM) {
        RESULT("realloc-zero-result", "distinct-aligned-errno-changed");
        free(replacement);
    } else {
        RESULT("realloc-zero-result", "distinct-aligned-preserves-errno");
        free(replacement);
    }

    allocation = malloc(33);
    if (allocation == NULL)
        return fail("realloc-failure-setup");
    allocation[0] = 0x41;
    allocation[32] = 0x42;
    errno = 0;
    replacement = realloc(allocation, SIZE_MAX);
    if (replacement != NULL || errno != ENOMEM
            || allocation[0] != 0x41 || allocation[32] != 0x42)
        return fail("realloc-failure");
    PASS("realloc-failure-preserves-source-and-sets-enomem");

    errno = EAGAIN;
    free(allocation);
    if (errno != EAGAIN)
        return fail("free-local-errno");
    PASS("free-local-preserves-errno");

    return 0;
}
