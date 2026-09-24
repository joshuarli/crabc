/*
 * Same-source pinned-musl and installed-static-product witness for
 * application replacement of libc functions at final static link.
 *
 * Musl's libc.a gives each source file its own member, so an application
 * that defines one libc function links against the rest of libc without a
 * duplicate definition, and every libc caller that reaches that function
 * through its public symbol reaches the application's definition.  Each
 * CRABC_REPLACE_* role compiles one such application: it defines the named
 * functions, calls libc paths that musl routes through them, and prints the
 * observed owner of each result.  The runner requires the candidate's link
 * result and output to equal musl's.
 */
#define _GNU_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <locale.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

/*
 * CRABC_REPLACE_MALLOC_TRIO replaces musl's minimum allocator set, `malloc`,
 * `free` and `realloc`; CRABC_REPLACE_MALLOC_FULL also replaces `calloc`,
 * `reallocarray`, the aligned entries and `malloc_usable_size`.
 */
#if defined(CRABC_REPLACE_MALLOC_TRIO) || defined(CRABC_REPLACE_MALLOC_FULL)
#define CRABC_REPLACE_MALLOC 1
#endif

/* Write the probe's own records without entering stdio or the allocator. */
static void emit(const char *text)
{
    size_t length = 0;

    while (text[length]) length++;
    while (length) {
        ssize_t written = write(STDOUT_FILENO, text, length);
        if (written <= 0) _exit(90);
        text += written;
        length -= (size_t)written;
    }
}

static void emit_record(const char *operation, const char *field, const char *value)
{
    emit(operation);
    emit(" ");
    emit(field);
    emit("=");
    emit(value);
    emit("\n");
}

static void emit_flag(const char *operation, const char *field, int value)
{
    emit_record(operation, field, value ? "1" : "0");
}

#ifdef CRABC_REPLACE_MALLOC
/*
 * A bump arena whose blocks record their size.  Its `free` rejects any
 * pointer it did not allocate, so a libc path that releases private storage
 * through the public spelling terminates the witness.
 */
static _Alignas(64) unsigned char arena[1 << 22];
static size_t arena_used;
static unsigned long arena_allocations;
static unsigned long arena_releases;

static int arena_owns(const void *pointer)
{
    const unsigned char *byte = pointer;
    return byte >= arena && byte < arena + sizeof arena;
}

static void *arena_allocate(size_t size, size_t alignment)
{
    size_t start;

    if (size > sizeof arena) return 0;
    start = (arena_used + sizeof(size_t) + alignment - 1) & ~(alignment - 1);
    if (start + size > sizeof arena) {
        errno = ENOMEM;
        return 0;
    }
    ((size_t *)(arena + start))[-1] = size;
    arena_used = start + size;
    arena_allocations++;
    return arena + start;
}

static size_t arena_size(const void *pointer)
{
    return ((const size_t *)pointer)[-1];
}

void *malloc(size_t size)
{
    return arena_allocate(size, 16);
}

void free(void *pointer)
{
    if (!pointer) return;
    if (!arena_owns(pointer)) {
        emit("free received libc-owned storage\n");
        _exit(91);
    }
    arena_releases++;
}

void *realloc(void *pointer, size_t size)
{
    void *replacement = malloc(size);

    if (replacement && pointer) {
        size_t old = arena_size(pointer);
        memcpy(replacement, pointer, old < size ? old : size);
        free(pointer);
    }
    return replacement;
}

#ifdef CRABC_REPLACE_MALLOC_FULL
void *calloc(size_t count, size_t size)
{
    void *allocation;

    if (size && count > (size_t)-1 / size) {
        errno = ENOMEM;
        return 0;
    }
    allocation = malloc(count * size);
    if (allocation) memset(allocation, 0, count * size);
    return allocation;
}
#endif

#ifdef CRABC_REPLACE_MALLOC_FULL
void *aligned_alloc(size_t alignment, size_t size)
{
    return arena_allocate(size, alignment < 16 ? 16 : alignment);
}

int posix_memalign(void **result, size_t alignment, size_t size)
{
    void *allocation = aligned_alloc(alignment, size);
    if (!allocation) return ENOMEM;
    *result = allocation;
    return 0;
}

void *memalign(size_t alignment, size_t size)
{
    return aligned_alloc(alignment, size);
}

void *valloc(size_t size)
{
    return aligned_alloc(4096, size);
}

void *reallocarray(void *pointer, size_t count, size_t size)
{
    if (size && count > (size_t)-1 / size) {
        errno = ENOMEM;
        return 0;
    }
    return realloc(pointer, count * size);
}

size_t malloc_usable_size(void *pointer)
{
    return pointer ? arena_size(pointer) : 0;
}
#endif

struct arena_mark {
    unsigned long allocations;
    unsigned long releases;
};

static struct arena_mark arena_mark(void)
{
    struct arena_mark mark = {arena_allocations, arena_releases};
    return mark;
}

/* Report who owns `result` and whether the operation crossed the public
 * allocation and release spellings since `mark`. */
static void report(const char *operation, const void *result, struct arena_mark mark)
{
    if (result) emit_record(operation, "owner", arena_owns(result) ? "application" : "libc");
    emit_flag(operation, "allocated", arena_allocations != mark.allocations);
    emit_flag(operation, "released", arena_releases != mark.releases);
}

static int select_all(const struct dirent *entry)
{
    (void)entry;
    return 1;
}

static int run_allocation_clients(void)
{
    struct arena_mark mark;
    char *text;
    size_t capacity;
    FILE *stream;

    mark = arena_mark();
    text = malloc(24);
    report("malloc", text, mark);
    mark = arena_mark();
    text = realloc(text, 48);
    report("realloc", text, mark);
    mark = arena_mark();
    free(text);
    report("free", 0, mark);

    mark = arena_mark();
    text = calloc(3, 8);
    report("calloc", text, mark);
    if (text && arena_owns(text)) free(text);

    mark = arena_mark();
    text = reallocarray(0, 4, 8);
    report("reallocarray", text, mark);
    if (text && arena_owns(text)) free(text);

#ifdef CRABC_REPLACE_MALLOC_FULL
    /*
     * Libc's own aligned entries are not exercised with a replaced `malloc`
     * alone: a static musl program then receives mallocng storage that its
     * `free` cannot own, while crabc refuses (compat/allocator/
     * known-differences.md).
     */
    mark = arena_mark();
    text = aligned_alloc(64, 64);
    report("aligned_alloc", text, mark);
    emit_flag("aligned_alloc", "aligned", text && ((uintptr_t)text & 63) == 0);
    if (text && arena_owns(text)) free(text);

    {
        void *aligned = 0;
        mark = arena_mark();
        emit_flag("posix_memalign", "status", posix_memalign(&aligned, 128, 32) != 0);
        report("posix_memalign", aligned, mark);
        if (aligned && arena_owns(aligned)) free(aligned);
    }

    mark = arena_mark();
    text = memalign(32, 16);
    report("memalign", text, mark);
    if (text && arena_owns(text)) free(text);

    mark = arena_mark();
    text = valloc(16);
    report("valloc", text, mark);
    if (text && arena_owns(text)) free(text);

    mark = arena_mark();
    text = malloc(40);
    emit_flag("malloc_usable_size", "size", malloc_usable_size(text) == 40);
    report("malloc_usable_size", 0, mark);
    free(text);
#endif

    mark = arena_mark();
    text = strdup("replacement");
    report("strdup", text, mark);
    if (text && arena_owns(text)) free(text);

    mark = arena_mark();
    text = strndup("replacement", 4);
    report("strndup", text, mark);
    if (text && arena_owns(text)) free(text);

    {
        wchar_t *wide;
        mark = arena_mark();
        wide = wcsdup(L"wide");
        report("wcsdup", wide, mark);
        if (wide && arena_owns(wide)) free(wide);
    }

    mark = arena_mark();
    text = 0;
    emit_flag("asprintf", "status", asprintf(&text, "%s-%d", "formatted", 7) != 11);
    report("asprintf", text, mark);
    if (text && arena_owns(text)) free(text);

    mark = arena_mark();
    text = realpath("/", 0);
    report("realpath", text, mark);
    if (text && arena_owns(text)) free(text);

    mark = arena_mark();
    text = getcwd(0, 0);
    report("getcwd", text, mark);
    if (text && arena_owns(text)) free(text);

    mark = arena_mark();
    stream = fopen("/replacement-input", "w+");
    report("fopen", stream, mark);
    if (!stream) return 10;
    if (fputs("first line\nsecond line\n", stream) < 0 || fflush(stream) || fseek(stream, 0, SEEK_SET))
        return 11;

    mark = arena_mark();
    text = 0;
    capacity = 0;
    emit_flag("getline", "status", getline(&text, &capacity, stream) != 11);
    report("getline", text, mark);

    mark = arena_mark();
    emit_flag("getdelim", "status", getdelim(&text, &capacity, '\n', stream) != 12);
    report("getdelim", text, mark);
    if (text && arena_owns(text)) free(text);

    mark = arena_mark();
    emit_flag("fclose", "status", fclose(stream) != 0);
    report("fclose", 0, mark);

    {
        char *buffer = 0;
        size_t size = 0;
        mark = arena_mark();
        stream = open_memstream(&buffer, &size);
        report("open_memstream", stream, mark);
        if (!stream) return 12;
        if (fputs("memory stream", stream) < 0 || fflush(stream)) return 13;
        report("open_memstream-buffer", buffer, mark);
        mark = arena_mark();
        emit_flag("open_memstream-fclose", "status", fclose(stream) != 0);
        report("open_memstream-fclose", buffer, mark);
        if (buffer && arena_owns(buffer)) free(buffer);
    }

    {
        struct dirent **entries = 0;
        int count;
        mark = arena_mark();
        count = scandir("/", &entries, select_all, alphasort);
        emit_flag("scandir", "status", count < 1);
        report("scandir", entries, mark);
        if (count > 0) {
            report("scandir-entry", entries[0], mark);
            if (arena_owns(entries)) {
                while (count--) free(entries[count]);
                free(entries);
            }
        }
    }

    {
        struct addrinfo hints, *result = 0;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        mark = arena_mark();
        emit_flag("getaddrinfo", "status", getaddrinfo("127.0.0.1", "80", &hints, &result) != 0);
        report("getaddrinfo", result, mark);
        mark = arena_mark();
        if (result) freeaddrinfo(result);
        report("freeaddrinfo", 0, mark);
    }

    mark = arena_mark();
    emit_flag("setenv", "status", setenv("CRABC_REPLACEMENT", "value", 1) != 0);
    report("setenv", getenv("CRABC_REPLACEMENT"), mark);
    mark = arena_mark();
    emit_flag("unsetenv", "status", unsetenv("CRABC_REPLACEMENT") != 0);
    report("unsetenv", 0, mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_STRINGS
/*
 * Counting definitions of `strlen` and `getenv`. Each computes the ordinary
 * result itself, so libc callers keep working; the counters show which libc
 * paths reach the public symbol.
 */
extern char **environ;
static unsigned long strlen_calls;
static unsigned long getenv_calls;

size_t strlen(const char *string)
{
    size_t length = 0;

    strlen_calls++;
    while (string[length]) length++;
    return length;
}

char *getenv(const char *name)
{
    size_t length = 0;
    char **entry;

    getenv_calls++;
    while (name[length] && name[length] != '=') length++;
    if (!length || name[length]) return 0;
    for (entry = environ; entry && *entry; entry++) {
        size_t index = 0;
        while (index < length && (*entry)[index] == name[index]) index++;
        if (index == length && (*entry)[length] == '=') return *entry + length + 1;
    }
    return 0;
}

static void report_calls(const char *operation, unsigned long strlen_mark, unsigned long getenv_mark)
{
    emit_flag(operation, "strlen", strlen_calls != strlen_mark);
    emit_flag(operation, "getenv", getenv_calls != getenv_mark);
}

static int run_string_clients(void)
{
    unsigned long strlen_mark, getenv_mark;
    char *text;
    FILE *stream;

#define MARK() (strlen_mark = strlen_calls, getenv_mark = getenv_calls)
    MARK();
    emit_flag("strlen", "value", strlen("replacement") == 11);
    report_calls("strlen", strlen_mark, getenv_mark);

    MARK();
    text = strdup("duplicate");
    report_calls("strdup", strlen_mark, getenv_mark);
    free(text);

    MARK();
    text = strndup("duplicate", 3);
    report_calls("strndup", strlen_mark, getenv_mark);
    free(text);

    MARK();
    text = strcasestr("Needle in haystack", "IN");
    report_calls("strcasestr", strlen_mark, getenv_mark);

    stream = fopen("/replacement-strings", "w");
    if (!stream) return 20;
    MARK();
    emit_flag("fputs", "status", fputs("line\n", stream) < 0);
    report_calls("fputs", strlen_mark, getenv_mark);
    MARK();
    emit_flag("fprintf", "status", fprintf(stream, "%s\n", "formatted") != 10);
    report_calls("fprintf", strlen_mark, getenv_mark);
    if (fclose(stream)) return 21;

    MARK();
    emit_flag("setenv", "status", setenv("CRABC_REPLACEMENT", "value", 1) != 0);
    report_calls("setenv", strlen_mark, getenv_mark);

    MARK();
    text = getenv("CRABC_REPLACEMENT");
    emit_flag("getenv", "value", text && !strcmp(text, "value"));
    report_calls("getenv", strlen_mark, getenv_mark);

    MARK();
    emit_flag("unsetenv", "status", unsetenv("CRABC_REPLACEMENT") != 0);
    report_calls("unsetenv", strlen_mark, getenv_mark);

    if (setenv("TZ", "UTC0", 1)) return 22;
    MARK();
    tzset();
    report_calls("tzset", strlen_mark, getenv_mark);

    /*
     * Only the environment edge is compared: musl's setlocale also measures
     * each category name with strlen while serializing its LC_ALL result,
     * which the fixed-profile implementation returns prebuilt.
     */
    MARK();
    emit_flag("setlocale", "status", setlocale(LC_ALL, "") == 0);
    emit_flag("setlocale", "getenv", getenv_calls != getenv_mark);
#undef MARK
    return 0;
}
#endif

int main(void)
{
#ifdef CRABC_REPLACE_MALLOC
    int status = run_allocation_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_STRINGS
    int status = run_string_clients();
    if (status) return status;
#endif
    emit("owned-static-replacement-ok\n");
    return 0;
}
