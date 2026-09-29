#define _GNU_SOURCE
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
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
    };
    static const int options[] = {
        0, GLOB_MARK, GLOB_NOCHECK, GLOB_NOSORT, GLOB_ERR,
        GLOB_MARK | GLOB_NOCHECK, GLOB_MARK | GLOB_NOSORT,
        GLOB_NOCHECK | GLOB_ERR, GLOB_MARK | GLOB_NOCHECK | GLOB_NOSORT,
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
    };
    static const int flags[] = {
        0, GLOB_MARK, GLOB_NOCHECK, GLOB_NOSORT, GLOB_DOOFFS,
        GLOB_MARK | GLOB_NOCHECK, GLOB_MARK | GLOB_NOSORT,
        GLOB_MARK | GLOB_NOCHECK | GLOB_NOSORT | GLOB_DOOFFS,
        GLOB_ERR, GLOB_ERR | GLOB_NOCHECK,
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
    generated_sequences();
    if (setgid(65534) || setuid(65534)) return 2;
    one("denied-ignore", "/fixture/blocked/*", 0);
    one("denied-err", "/fixture/blocked/*", GLOB_ERR);
    one("denied-abort", "/fixture/blocked/*", 0x10000);
    one("denied-nocheck", "/fixture/blocked/*", GLOB_NOCHECK);
    one("denied-nocheck-err", "/fixture/blocked/*", GLOB_NOCHECK | GLOB_ERR);
    return fflush(stdout) != 0;
}
