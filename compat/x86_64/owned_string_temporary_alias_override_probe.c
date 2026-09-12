/* A strong application spelling must replace each weak public alias, while
 * source-local libc callers retain the strong __ provider. argv[1] names a
 * private existing directory for the mkostemp internal-provider observation. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

static int stpcpy_calls;
static int stpncpy_calls;
static int strchrnul_calls;
static int memrchr_calls;
static int mkostemps_calls;

char *stpcpy(char *destination, const char *source)
{
    ++stpcpy_calls;
    while ((*destination = *source) != '\0') {
        ++destination;
        ++source;
    }
    return destination;
}

char *stpncpy(char *destination, const char *source, size_t count)
{
    char *terminator;

    ++stpncpy_calls;
    while (count != 0 && (*destination = *source) != '\0') {
        ++destination;
        ++source;
        --count;
    }
    if (count == 0)
        return destination;

    terminator = destination;
    while (count != 0) {
        *destination++ = '\0';
        --count;
    }
    return terminator;
}

char *strchrnul(const char *string, int character)
{
    unsigned char target = (unsigned char)character;

    ++strchrnul_calls;
    while (*string != '\0' && (unsigned char)*string != target)
        ++string;
    return (char *)string;
}

void *memrchr(const void *memory, int character, size_t count)
{
    const unsigned char *bytes = memory;
    unsigned char target = (unsigned char)character;

    ++memrchr_calls;
    while (count != 0) {
        --count;
        if (bytes[count] == target)
            return (void *)(bytes + count);
    }
    return NULL;
}

int mkostemps(char *template, int suffix_length, int flags)
{
    (void)template;
    (void)suffix_length;
    (void)flags;
    ++mkostemps_calls;
    errno = EAGAIN;
    return -1;
}

int main(int argc, char **argv)
{
    char copied[16] = { 0 };
    char padded[16] = { 0xa5 };
    char internal_copied[16] = { 0 };
    char internal_padded[16] = { 0xa5 };
    const char searched[] = "abca";
    const unsigned char bytes[] = { 1, 2, 3, 2, 1 };
    char path[4096];
    int descriptor;
    int length;

    CHECK(argc == 2);
    CHECK(stpcpy(copied, "copy") == copied + 4 && !strcmp(copied, "copy") &&
        stpcpy_calls == 1);
    CHECK(strcpy(internal_copied, "inner") == internal_copied &&
        !strcmp(internal_copied, "inner") && stpcpy_calls == 1);
    CHECK(stpncpy(padded, "pad", 6) == padded + 3 &&
        !memcmp(padded, "pad\0\0\0", 6) && stpncpy_calls == 1);
    CHECK(strncpy(internal_padded, "inner", 7) == internal_padded &&
        !memcmp(internal_padded, "inner\0\0", 7) && stpncpy_calls == 1);
    CHECK(strchrnul(searched, 'z') == searched + 4 && strchrnul_calls == 1);
    CHECK(strchr(searched, 'c') == searched + 2 && strchrnul_calls == 1);
    CHECK(memrchr(bytes, 2, sizeof bytes) == bytes + 3 && memrchr_calls == 1);
    CHECK(strrchr(searched, 'a') == searched + 3 && memrchr_calls == 1);

    length = snprintf(path, sizeof path, "%s/override-XXXXXX", argv[1]);
    CHECK(length > 0 && (size_t)length < sizeof path);
    errno = 0;
    CHECK(mkostemps(path, 0, O_CLOEXEC) == -1 && errno == EAGAIN &&
        mkostemps_calls == 1);
    length = snprintf(path, sizeof path, "%s/internal-XXXXXX", argv[1]);
    CHECK(length > 0 && (size_t)length < sizeof path);
    descriptor = mkostemp(path, O_CLOEXEC);
    CHECK(descriptor >= 0 && mkostemps_calls == 1 && unlink(path) == 0 &&
        close(descriptor) == 0);

    CHECK(puts("owned-string-temporary-alias-override-ok") >= 0);
    return 0;
}
