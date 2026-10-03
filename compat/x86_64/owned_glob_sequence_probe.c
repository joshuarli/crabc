#define _GNU_SOURCE
#include <errno.h>
#include <glob.h>
#include <locale.h>
#include <pthread.h>
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

static void append_after_directory_error(void)
{
    glob_t result = {0};
    char first[128];
    char *first_address;

    result.gl_offs = 3;
    observe("error-append", &result, "/fixture/dir/[az]*", GLOB_DOOFFS);
    if (result.gl_pathc != 2 ||
        strlen(result.gl_pathv[result.gl_offs]) >= sizeof first) abort();
    first_address = result.gl_pathv[result.gl_offs];
    strcpy(first, first_address);

    observe("error-append", &result, "/fixture/blocked/*",
        GLOB_DOOFFS | GLOB_APPEND);
    observe("error-append", &result, "/fixture/blocked/*",
        GLOB_DOOFFS | GLOB_APPEND | GLOB_ERR);
    observe("error-append", &result, "/fixture/blocked/*",
        GLOB_DOOFFS | GLOB_APPEND | 0x10000);
    observe("error-append", &result, "/fixture/blocked/*",
        GLOB_DOOFFS | GLOB_APPEND | GLOB_NOCHECK | GLOB_ERR);
    observe("error-append", &result, "/fixture/dir/z*",
        GLOB_DOOFFS | GLOB_APPEND);

    if (result.gl_pathv[result.gl_offs] != first_address ||
        strcmp(result.gl_pathv[result.gl_offs], first)) abort();
    globfree(&result);
    if (result.gl_pathc || result.gl_pathv) abort();
    printf("error-append freed offs=%zu\n", result.gl_offs);
}

struct locale_worker {
    glob_t *result;
    locale_t c;
    locale_t utf8;
    char *first;
    unsigned callbacks;
    int callback_failed;
    int status;
};

static _Thread_local struct locale_worker *active_worker;

static int locale_error_callback(const char *path, int code)
{
    struct locale_worker *worker = active_worker;
    glob_t nested = {0};
    locale_t saved;
    worker->callbacks++;
    if (code != EACCES || strcmp(path, "/fixture/blocked/") ||
        uselocale(NULL) != worker->utf8 || MB_CUR_MAX != 4 ||
        worker->result->gl_pathc != 2 ||
        worker->result->gl_pathv[3] != worker->first ||
        strcmp(worker->first, "/fixture/dir/alpha")) worker->callback_failed = 1;
    saved = uselocale(worker->c);
    nested.gl_offs = 2;
    if (saved != worker->utf8 || MB_CUR_MAX != 1 ||
        glob("/fixture/dir/zeta", GLOB_DOOFFS, NULL, &nested) != 0 ||
        nested.gl_pathc != 1 || nested.gl_pathv[0] || nested.gl_pathv[1] ||
        strcmp(nested.gl_pathv[2], "/fixture/dir/zeta") || nested.gl_pathv[3])
        worker->callback_failed = 1;
    globfree(&nested);
    if (nested.gl_pathc || nested.gl_pathv ||
        uselocale(saved) != worker->c || MB_CUR_MAX != 4) worker->callback_failed = 1;
    errno = EINTR;
    return 1;
}

static void *locale_append_worker(void *argument)
{
    struct locale_worker *worker = argument;
    glob_t *result = worker->result;
    active_worker = worker;
    worker->status = 1;
    if (uselocale(NULL) != LC_GLOBAL_LOCALE ||
        uselocale(worker->utf8) != LC_GLOBAL_LOCALE || MB_CUR_MAX != 4) return NULL;
    worker->status = 2;
    if (glob("/fixture/dir/?name", GLOB_DOOFFS | GLOB_APPEND, NULL, result) != 0 ||
        result->gl_pathc != 2 || result->gl_pathv[3] != worker->first ||
        strcmp(result->gl_pathv[4], "/fixture/dir/\303\251name")) return NULL;
    worker->status = 3;
    if (glob("/fixture/blocked/*", GLOB_DOOFFS | GLOB_APPEND,
            locale_error_callback, result) != GLOB_ABORTED ||
        worker->callbacks != 1 || worker->callback_failed || errno != EINTR ||
        uselocale(NULL) != worker->utf8 || result->gl_pathc != 2 ||
        result->gl_pathv[3] != worker->first || result->gl_pathv[5]) return NULL;
    if (strcmp(result->gl_pathv[0], "glob-sequence")) return NULL;
    for (size_t i = 1; i < result->gl_offs; ++i)
        if (result->gl_pathv[i]) return NULL;
    worker->status = 0;
    return NULL;
}

/* Joining transfers exclusive access back to the caller. The callback uses
 * an independent glob owner and restores the worker's locale before returning. */
static int worker_locale_append_lifetime(void)
{
    glob_t result = {0};
    locale_t c = newlocale(LC_CTYPE_MASK, "C", NULL);
    locale_t utf8 = newlocale(LC_CTYPE_MASK, "C.UTF-8", NULL);
    locale_t previous;
    pthread_t thread;
    struct locale_worker worker = {0};
    int status = 0;
    if (!c || !utf8) return 1;
    previous = uselocale(c);
    result.gl_offs = 3;
    if (glob("/fixture/dir/alpha", GLOB_DOOFFS, NULL, &result) != 0 ||
        result.gl_pathc != 1) return 2;
    /* DOOFFS reserves caller-owned command argument slots before pathnames. */
    result.gl_pathv[0] = (char *)"glob-sequence";
    worker.result = &result;
    worker.c = c;
    worker.utf8 = utf8;
    worker.first = result.gl_pathv[3];
    worker.status = -1;
    if (pthread_create(&thread, NULL, locale_append_worker, &worker) != 0) return 3;
    if (pthread_join(thread, NULL) != 0) return 4;
    if (worker.status || uselocale(NULL) != c || MB_CUR_MAX != 1 ||
        result.gl_pathc != 2 || result.gl_pathv[3] != worker.first ||
        strcmp(result.gl_pathv[0], "glob-sequence") ||
        strcmp(result.gl_pathv[3], "/fixture/dir/alpha") ||
        strcmp(result.gl_pathv[4], "/fixture/dir/\303\251name")) status = 5;
    globfree(&result);
    if (result.gl_pathc || result.gl_pathv || result.gl_offs != 3) status = 6;
    if (uselocale(previous) != c) status = 7;
    freelocale(utf8);
    freelocale(c);
    printf("worker-locale-append status=%d callbacks=%u offs=%zu\n",
        status, worker.callbacks, result.gl_offs);
    return status;
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
    {
        FILE *file = fopen("/fixture/dir/\303\251name", "w");
        if (!file || fclose(file) != 0) return 3;
    }

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
    append_after_directory_error();
    if (worker_locale_append_lifetime() != 0) return 4;
    return fflush(stdout) != 0;
}
