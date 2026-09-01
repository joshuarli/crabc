/* Static Linux/x86-64 fopen64 LP64 macro-alias behavior fixture.
 *
 * The same project-header source first executes against pinned musl 1.2.6,
 * then against the dependency-free static crabc archive.  On Linux LP64,
 * `fopen64` is deliberately a preprocessing alias for `fopen`; this fixture
 * proves that the alias has the same function address and reuses only the
 * existing bounded `fopen("r")`/`fopen("w+")` path-stream behavior.  It does
 * not request, declare, link, or claim a distinct `fopen64` ELF symbol, and
 * it is not general stdio or stdio.path-stream completion.
 */

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#ifndef fopen64
#error "Linux LP64 must expose fopen64 as a preprocessing alias"
#endif

typedef FILE *(*fopen_signature)(const char *, const char *);
typedef int (*fclose_signature)(FILE *);
typedef int (*fseek_signature)(FILE *, long, int);
typedef int (*fgetc_signature)(FILE *);
typedef size_t (*fread_signature)(void *, size_t, size_t, FILE *);
typedef size_t (*fwrite_signature)(const void *, size_t, size_t, FILE *);
typedef int (*unlink_signature)(const char *);

static fopen_signature volatile fopen_entry = fopen;
/* This initializer must preprocess to the same `fopen` C spelling above. */
static fopen_signature volatile fopen64_macro_entry = fopen64;
static fclose_signature volatile fclose_entry = fclose;
static fseek_signature volatile fseek_entry = fseek;
static fgetc_signature volatile fgetc_entry = fgetc;
static fread_signature volatile fread_entry = fread;
static fwrite_signature volatile fwrite_entry = fwrite;
static unlink_signature volatile unlink_entry = unlink;

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    size_t index;

    for (index = 0; index != length; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

int crabc_x86_64_fopen64_alias_probe(void)
{
    static const char path[] = "/tmp/crabc-x86-fopen64-alias-probe";
    static const unsigned char payload[] = {0x66, 0x6f, 0x70, 0x65, 0x6e, 0};
    unsigned char observed[sizeof(payload)];
    FILE *stream;

    if (fopen_entry != fopen64_macro_entry)
        return 1;
    if (unlink_entry(path) != 0 && errno != ENOENT)
        return 2;

    errno = 0;
    if (fopen64_macro_entry(path, "r") != NULL || errno != ENOENT)
        return 3;

    stream = fopen64_macro_entry(path, "w+");
    if (stream == NULL)
        return 4;
    if (fwrite_entry(payload, 1, sizeof(payload), stream) != sizeof(payload) ||
        fseek_entry(stream, 0, SEEK_SET) != 0 ||
        fread_entry(observed, 1, sizeof(observed), stream) != sizeof(observed) ||
        !bytes_equal(observed, payload, sizeof(payload))) {
        (void)fclose_entry(stream);
        (void)unlink_entry(path);
        return 5;
    }
    if (fclose_entry(stream) != 0) {
        (void)unlink_entry(path);
        return 6;
    }

    stream = fopen64_macro_entry(path, "r");
    if (stream == NULL) {
        (void)unlink_entry(path);
        return 7;
    }
    if (fgetc_entry(stream) != payload[0]) {
        (void)fclose_entry(stream);
        (void)unlink_entry(path);
        return 8;
    }
    if (fclose_entry(stream) != 0) {
        (void)unlink_entry(path);
        return 9;
    }
    if (unlink_entry(path) != 0)
        return 10;
    return 0;
}

#ifndef CRABC_FOPEN64_ALIAS_FREESTANDING
int main(void)
{
    return crabc_x86_64_fopen64_alias_probe();
}
#endif
