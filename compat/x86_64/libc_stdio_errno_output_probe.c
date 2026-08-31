/* Static x86-64 errno-message stdio-output behavior fixture.
 *
 * The fixture exercises musl's GNU `%m` extension only through the bounded
 * byte-buffer formatter in libc/src/c_abi/x86_64/stdio_format_scan.rs.  Its
 * shared body first runs against pinned musl, then as a true -nostdlib static
 * candidate.  It deliberately neither calls strerror nor reaches a FILE,
 * stream, locale, allocation, or ambient-formatting boundary.
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(long long) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(size_t) == 8, "x86 size_t width");

typedef int (*crabc_snprintf_signature)(char *, size_t, const char *, ...);
typedef int (*crabc_vsnprintf_signature)(char *, size_t, const char *, va_list);

#define CRABC_TYPE_IS(left, right) __builtin_types_compatible_p(left, right)
_Static_assert(CRABC_TYPE_IS(__typeof__(&snprintf), crabc_snprintf_signature),
    "snprintf declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&vsnprintf), crabc_vsnprintf_signature),
    "vsnprintf declaration");

static size_t byte_length(const char *text)
{
    size_t length = 0;
    while (text[length] != '\0')
        ++length;
    return length;
}

static int equal_text(const char *actual, const char *expected)
{
    size_t index = 0;
    for (;;) {
        if (actual[index] != expected[index])
            return 0;
        if (actual[index] == '\0')
            return 1;
        ++index;
    }
}

static int call_vsnprintf(char *output, size_t size, const char *format, ...)
{
    va_list arguments;
    int result;

    va_start(arguments, format);
    result = vsnprintf(output, size, format, arguments);
    va_end(arguments);
    return result;
}

static int check_errno_message_output(void)
{
    static const char width_precision_expected[] =
        "[Permissi            ][   Permission denied][]";
    static const char ignored_flags_expected[] =
        "No such file or directory|No such file or directory|"
        "No such file or directory";
    char output[128];
    char truncated[10];
    int count = -1;
    int result;

    errno = EACCES;
    result = snprintf(output, sizeof(output), "[%-20.8m][%020m][%#.0m]");
    if (result != (int)byte_length(width_precision_expected) ||
        !equal_text(output, width_precision_expected) || errno != EACCES)
        return 1;

    errno = ENOENT;
    result = snprintf(output, sizeof(output), "%+m|% m|%#m");
    if (result != (int)byte_length(ignored_flags_expected) ||
        !equal_text(output, ignored_flags_expected) || errno != ENOENT)
        return 2;

    errno = EACCES;
    result = snprintf(truncated, sizeof(truncated), "[%m]");
    if (result != 19 || !equal_text(truncated, "[Permissi") || errno != EACCES)
        return 3;

    errno = EACCES;
    result = snprintf((char *)0, 0, "%m");
    if (result != 17 || errno != EACCES)
        return 4;

    errno = EINVAL;
    result = snprintf(output, sizeof(output), "x%m%n", &count);
    if (result != 17 || !equal_text(output, "xInvalid argument") || count != 17 ||
        errno != EINVAL)
        return 5;

    errno = EINTR;
    result = call_vsnprintf(output, sizeof(output), "%m/%d/%m", 7);
    if (result != 49 ||
        !equal_text(output, "Interrupted system call/7/Interrupted system call") ||
        errno != EINTR)
        return 6;

    errno = EACCES;
    result = call_vsnprintf(output, sizeof(output), "[%*.*m]", 12, 4);
    if (result != 14 || !equal_text(output, "[        Perm]") || errno != EACCES)
        return 7;

    return 0;
}

#ifdef CRABC_STDIO_ERRNO_OUTPUT_FREESTANDING
static int check_candidate_limitations(void)
{
    char output[32] = { 'X', '\0' };
    int result;

    errno = 0;
    result = snprintf(output, sizeof(output), "%lm");
    if (result != -1 || errno != EINVAL)
        return 1;

    errno = 0;
    result = snprintf(output, sizeof(output), "%1$m");
    if (result != -1 || errno != EINVAL)
        return 2;

    return 0;
}
#endif

int crabc_x86_64_stdio_errno_output_probe(void)
{
    int status = check_errno_message_output();
    if (status != 0)
        return status;
#ifdef CRABC_STDIO_ERRNO_OUTPUT_FREESTANDING
    status = check_candidate_limitations();
    if (status != 0)
        return 100 + status;
#endif
    return 0;
}

#ifndef CRABC_STDIO_ERRNO_OUTPUT_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_errno_output_probe();
}
#endif
