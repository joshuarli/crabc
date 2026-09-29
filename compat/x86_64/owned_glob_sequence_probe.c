#define _GNU_SOURCE
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned callbacks;
static int abort_error;

static int error_callback(const char *path, int code)
{
    printf(" callback=%s:%d", path, code);
    callbacks++;
    return abort_error;
}

static void observe(const char *label, glob_t *result, const char *pattern, int flags)
{
    size_t i;
    int status;

    callbacks = 0;
    abort_error = (flags & 0x10000) != 0;
    flags &= ~0x10000;
    errno = 0;
    printf("%s pattern=%s flags=%d", label, pattern, flags);
    status = glob(pattern, flags, error_callback, result);
    printf(" status=%d count=%zu offs=%zu callbacks=%u errno=%d", status,
        result->gl_pathc, result->gl_offs, callbacks, errno);
    if (result->gl_pathv) {
        size_t offs = result->gl_offs;
        for (i = 0; i < offs; ++i)
            if (result->gl_pathv[i]) abort();
        if (result->gl_pathv[offs + result->gl_pathc]) abort();
        for (i = 0; i < result->gl_pathc; ++i)
            printf(" path=%s", result->gl_pathv[offs + i]);
    }
    putchar('\n');
}

static void one(const char *label, const char *pattern, int flags)
{
    glob_t result = {0};
    result.gl_offs = 2;
    observe(label, &result, pattern, flags);
    globfree(&result);
}

static void sequence(const char *label, int flags)
{
    glob_t result = {0};
    result.gl_offs = 2;
    observe(label, &result, "/fixture/dir/*", flags | GLOB_DOOFFS);
    observe(label, &result, "/fixture/link-dir/*", flags | GLOB_DOOFFS | GLOB_APPEND);
    observe(label, &result, "/fixture/missing*", flags | GLOB_DOOFFS | GLOB_APPEND);
    observe(label, &result, "/fixture/dangling", flags | GLOB_DOOFFS | GLOB_APPEND | GLOB_MARK);
    observe(label, &result, "/fixture/*-dir", flags | GLOB_DOOFFS | GLOB_APPEND | GLOB_MARK);
    globfree(&result);
}

static void append_lifetime(const char *label, size_t offsets)
{
    glob_t result = {0};
    char first[128];
    char *first_address;
    size_t i;

    result.gl_offs = offsets;
    observe(label, &result, "/fixture/dir/[az]*", offsets ? GLOB_DOOFFS : 0);
    if (result.gl_pathc != 2) abort();
    first_address = result.gl_pathv[offsets];
    if (strlen(first_address) >= sizeof first) abort();
    strcpy(first, first_address);
    observe(label, &result, "/fixture/absent*",
        GLOB_APPEND | (offsets ? GLOB_DOOFFS : 0));
    if (result.gl_pathc != 2 || result.gl_pathv[offsets] != first_address ||
        strcmp(result.gl_pathv[offsets], first)) abort();
    observe(label, &result, "/fixture/*-dir",
        GLOB_APPEND | GLOB_MARK | GLOB_NOSORT | (offsets ? GLOB_DOOFFS : 0));
    if (result.gl_pathc != 3 || result.gl_pathv[offsets] != first_address ||
        strcmp(result.gl_pathv[offsets], first)) abort();
    observe(label, &result, "/fixture/no-such-name",
        GLOB_APPEND | GLOB_NOCHECK | (offsets ? GLOB_DOOFFS : 0));
    if (result.gl_pathc != 4 || result.gl_pathv[offsets] != first_address ||
        strcmp(result.gl_pathv[offsets], first)) abort();
    for (i = 0; i < offsets; ++i)
        if (result.gl_pathv[i]) abort();
    globfree(&result);
    if (result.gl_pathc || result.gl_pathv) abort();
    printf("%s freed offs=%zu\n", label, result.gl_offs);
}

static void byte_names(void)
{
    glob_t result = {0};
    observe("byte-names", &result, "/fixture/dir/?name", 0);
    globfree(&result);
    result.gl_offs = 3;
    observe("byte-append", &result, "/fixture/dir/[az]*", GLOB_DOOFFS);
    observe("byte-append", &result, "/fixture/dir/?name",
        GLOB_DOOFFS | GLOB_APPEND | GLOB_NOSORT);
    globfree(&result);
}

static unsigned next_random(unsigned *state)
{
    unsigned value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return *state = value;
}

static void generated_sequences(void)
{
    static const char *const patterns[] = {
        "/fixture/*", "/fixture/dir/*", "/fixture/link-dir/*",
        "/fixture/dangling", "/fixture/loop/*", "/fixture/file/child",
        "/fixture/missing*", "/fixture/dir/../*", "/fixture/*-dir",
        "/fixture/[dl]*", "/fixture/blocked/*", "",
        "/fixture/dir/.*", "/fixture/dir/?name",
        "/fixture/escaped\\*", "/fixture/dir/[az]*",
    };
    static const int options[] = {
        0, GLOB_MARK, GLOB_NOCHECK, GLOB_NOSORT, GLOB_ERR,
        GLOB_MARK | GLOB_NOCHECK, GLOB_MARK | GLOB_NOSORT,
        GLOB_NOCHECK | GLOB_ERR, GLOB_MARK | GLOB_NOCHECK | GLOB_NOSORT,
        GLOB_PERIOD, GLOB_NOESCAPE, GLOB_PERIOD | GLOB_MARK,
        GLOB_NOESCAPE | GLOB_NOCHECK,
    };
    unsigned random = 0x6b67ae85;
    size_t sequence_index, call;

    for (sequence_index = 0; sequence_index < 400; ++sequence_index) {
        glob_t result = {0};
        char label[48];
        result.gl_offs = 2;
        for (call = 0; call < 4; ++call) {
            const char *pattern = patterns[next_random(&random) %
                (sizeof patterns / sizeof *patterns)];
            int flags = options[next_random(&random) %
                (sizeof options / sizeof *options)] | GLOB_DOOFFS;
            if (call) flags |= GLOB_APPEND;
            else flags |= GLOB_NOCHECK;
            snprintf(label, sizeof label, "generated-%zu-%zu", sequence_index, call);
            observe(label, &result, pattern, flags);
        }
        globfree(&result);
    }
}

int main(void)
{
    static const char *const patterns[] = {
        "/fixture/dir", "/fixture/link-dir", "/fixture/dangling",
        "/fixture/link-dir/", "/fixture/dangling/", "/fixture/link-dir/*",
        "/fixture/missing*", "/fixture/file/child", "/fixture/dir/*",
        "/fixture/*-dir", "/fixture/dir/../*", "/fixture/loop/*",
        "/fixture/blocked/*", "/fixture/blocked/missing",
        "/fixture/dir/.*", "/fixture/dir/?name",
        "/fixture/escaped\\*",
    };
    static const int flags[] = {
        0, GLOB_MARK, GLOB_NOCHECK, GLOB_NOSORT, GLOB_DOOFFS,
        GLOB_MARK | GLOB_NOCHECK, GLOB_MARK | GLOB_NOSORT,
        GLOB_MARK | GLOB_NOCHECK | GLOB_NOSORT | GLOB_DOOFFS,
        GLOB_ERR, GLOB_ERR | GLOB_NOCHECK,
        GLOB_PERIOD, GLOB_NOESCAPE,
    };
    size_t p, f;
    char label[48];

    setvbuf(stdout, 0, _IONBF, 0);

    for (p = 0; p < sizeof patterns / sizeof *patterns; ++p)
        for (f = 0; f < sizeof flags / sizeof *flags; ++f) {
            snprintf(label, sizeof label, "single-%zu-%zu", p, f);
            one(label, patterns[p], flags[f]);
        }
    for (f = 0; f < sizeof flags / sizeof *flags; ++f) {
        snprintf(label, sizeof label, "sequence-%zu", f);
        sequence(label, flags[f]);
    }
    append_lifetime("append-zero", 0);
    append_lifetime("append-one", 1);
    append_lifetime("append-seven", 7);
    byte_names();
    generated_sequences();
    if (setgid(65534) || setuid(65534)) return 2;
    one("denied-ignore", "/fixture/blocked/*", 0);
    one("denied-err", "/fixture/blocked/*", GLOB_ERR);
    one("denied-abort", "/fixture/blocked/*", 0x10000);
    one("denied-nocheck", "/fixture/blocked/*", GLOB_NOCHECK);
    one("denied-nocheck-err", "/fixture/blocked/*", GLOB_NOCHECK | GLOB_ERR);
    return fflush(stdout) != 0;
}
