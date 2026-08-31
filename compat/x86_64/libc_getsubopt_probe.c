/* Static crabc-libc Linux/x86-64 getsubopt differential fixture.
 *
 * The same project-header C body runs first through pinned musl 1.2.6 and
 * then through a true -nostdlib/static candidate.  It selects only the
 * caller-owned in-place token split and key/value lookup; it does not create
 * parser, environment, locale, stdio, allocation, errno, or TLS state.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

#ifndef CRABC_GETSUBOPT_FREESTANDING
#include <errno.h>
#endif

#define CRABC_TYPE_IS(left, right) __builtin_types_compatible_p(left, right)
typedef int (*getsubopt_signature)(char **, char *const *, char **);

_Static_assert(CRABC_TYPE_IS(__typeof__(&getsubopt), getsubopt_signature),
    "getsubopt declaration");

static int same_text(const char *left, const char *right)
{
    size_t index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int check_primary_sequence(getsubopt_signature parse)
{
    char options[] = "ro,size=42,size=,unknown=ignored,,mode";
    char key_ro[] = "ro";
    char key_size[] = "size";
    char key_mode[] = "mode";
    char *keys[] = { key_ro, key_size, key_mode, NULL };
    char *cursor = options;
    char *value = options;

    if (parse(&cursor, keys, &value) != 0 || value != NULL ||
        options[2] != '\0' || cursor != options + 3)
        return 1;
    value = options;
    if (parse(&cursor, keys, &value) != 1 || !same_text(value, "42") ||
        cursor != options + 11)
        return 2;
    value = options;
    if (parse(&cursor, keys, &value) != 1 || value == NULL || *value != '\0' ||
        cursor != options + 17)
        return 3;
    value = options;
    if (parse(&cursor, keys, &value) != -1 || value != NULL ||
        cursor != options + 33)
        return 4;
    value = options;
    if (parse(&cursor, keys, &value) != -1 || value != NULL ||
        cursor != options + 34)
        return 5;
    value = options;
    if (parse(&cursor, keys, &value) != 2 || value != NULL ||
        *cursor != '\0')
        return 6;
    return 0;
}

static int check_exact_key_matching(getsubopt_signature parse)
{
    char options[] = "readwrite,read=one,reader,read";
    char key_read[] = "read";
    char key_readwrite[] = "readwrite";
    char *keys[] = { key_read, key_readwrite, NULL };
    char *cursor = options;
    char *value = NULL;

    if (parse(&cursor, keys, &value) != 1 || value != NULL ||
        !same_text(options, "readwrite"))
        return 1;
    value = NULL;
    if (parse(&cursor, keys, &value) != 0 || !same_text(value, "one"))
        return 2;
    value = options;
    if (parse(&cursor, keys, &value) != -1 || value != NULL)
        return 3;
    value = options;
    if (parse(&cursor, keys, &value) != 0 || value != NULL || *cursor != '\0')
        return 4;
    return 0;
}

static int check_interleaved_cursors(getsubopt_signature parse)
{
    char left_options[] = "one,two";
    char right_options[] = "two,one";
    char key_one[] = "one";
    char key_two[] = "two";
    char *keys[] = { key_one, key_two, NULL };
    char *left = left_options;
    char *right = right_options;
    char *value = left_options;

    if (parse(&left, keys, &value) != 0 || value != NULL) return 1;
    value = right_options;
    if (parse(&right, keys, &value) != 1 || value != NULL) return 2;
    value = left_options;
    if (parse(&left, keys, &value) != 1 || value != NULL || *left != '\0') return 3;
    value = right_options;
    if (parse(&right, keys, &value) != 0 || value != NULL || *right != '\0') return 4;
    return 0;
}

static int check_empty_key(getsubopt_signature parse)
{
    char options[] = "=value,";
    char empty_key[] = "";
    char *keys[] = { empty_key, NULL };
    char *cursor = options;
    char *value = NULL;

    if (parse(&cursor, keys, &value) != 0 || !same_text(value, "value") ||
        cursor != options + 7)
        return 1;
    value = options;
    if (parse(&cursor, keys, &value) != 0 || value != NULL || *cursor != '\0')
        return 2;
    return 0;
}

int crabc_x86_64_getsubopt_probe(void)
{
    getsubopt_signature parse = getsubopt;
    int status;

#ifndef CRABC_GETSUBOPT_FREESTANDING
    errno = E2BIG;
#endif

    status = check_primary_sequence(parse);
    if (status != 0) return status;
    status = check_exact_key_matching(parse);
    if (status != 0) return 20 + status;
    status = check_interleaved_cursors(parse);
    if (status != 0) return 40 + status;
    status = check_empty_key(parse);
    if (status != 0) return 50 + status;

#ifndef CRABC_GETSUBOPT_FREESTANDING
    if (errno != E2BIG) return 70;
#endif
    return 0;
}

#ifndef CRABC_GETSUBOPT_FREESTANDING
int main(void)
{
    return crabc_x86_64_getsubopt_probe();
}
#endif
