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
#include <fcntl.h>
#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <netdb.h>
#include <stdarg.h>
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

#if defined(CRABC_REPLACE_PRINTF) || defined(CRABC_REPLACE_VSNPRINTF) || defined(CRABC_REPLACE_SCANF) \
    || defined(CRABC_REPLACE_MATH) || defined(CRABC_REPLACE_WIDE) || defined(CRABC_REPLACE_SYSTEM) \
    || defined(CRABC_REPLACE_FILES) || defined(CRABC_REPLACE_NETWORK) || defined(CRABC_REPLACE_ACCOUNTS) \
    || defined(CRABC_REPLACE_THREADS) || defined(CRABC_REPLACE_PROCESS) || defined(CRABC_REPLACE_PUSHBACK) \
    || defined(CRABC_REPLACE_MAPPING)
static unsigned long replacement_calls;

static void report_replacement(const char *operation, unsigned long mark)
{
    emit_flag(operation, "replacement", replacement_calls != mark);
}
#endif

#ifdef CRABC_REPLACE_PRINTF
/*
 * Counting `vfprintf` and `vasprintf` with a minimal "%s"/"%d" formatter:
 * musl formats every printf-family call, including vsnprintf, through the
 * public vfprintf, so a replacement cannot delegate to libc formatting.
 * Musl's printf, vprintf and fprintf reach vfprintf, and asprintf vasprintf.
 */
static int format_minimal(char *buffer, size_t capacity, const char *format, va_list args)
{
    size_t length = 0;

    for (; *format; format++) {
        char digits[24];
        const char *text = digits;
        if (*format != '%') {
            digits[0] = *format;
            digits[1] = 0;
        } else if (*++format == 's') {
            text = va_arg(args, const char *);
        } else if (*format == 'd') {
            int value = va_arg(args, int);
            unsigned magnitude = value < 0 ? 0u - (unsigned)value : (unsigned)value;
            char reversed[16];
            size_t count = 0, index = 0;
            do reversed[count++] = (char)('0' + magnitude % 10); while (magnitude /= 10);
            if (value < 0) digits[index++] = '-';
            while (count) digits[index++] = reversed[--count];
            digits[index] = 0;
        } else {
            return -1;
        }
        while (*text) {
            if (length + 1 >= capacity) return -1;
            buffer[length++] = *text++;
        }
    }
    buffer[length] = 0;
    return (int)length;
}

int vfprintf(FILE *stream, const char *format, va_list args)
{
    char buffer[256];
    int length;

    replacement_calls++;
    length = format_minimal(buffer, sizeof buffer, format, args);
    if (length < 0) return -1;
    return fwrite(buffer, 1, (size_t)length, stream) == (size_t)length ? length : -1;
}

int vasprintf(char **destination, const char *format, va_list args)
{
    char buffer[256];
    int length;

    replacement_calls++;
    length = format_minimal(buffer, sizeof buffer, format, args);
    if (length < 0 || !(*destination = malloc((size_t)length + 1))) return -1;
    memcpy(*destination, buffer, (size_t)length + 1);
    return length;
}

static int call_vprintf(const char *format, ...)
{
    va_list args;
    int status;

    va_start(args, format);
    status = vprintf(format, args);
    va_end(args);
    return status;
}

static int run_printf_clients(void)
{
    unsigned long mark;
    FILE *stream;
    char *text = 0;

    mark = replacement_calls;
    emit_flag("printf", "status", printf("%s\n", "printed") != 8 || fflush(stdout));
    report_replacement("printf", mark);
    mark = replacement_calls;
    emit_flag("vprintf", "status", call_vprintf("%d\n", 7) != 2 || fflush(stdout));
    report_replacement("vprintf", mark);
    stream = fopen("/replacement-printf", "w");
    if (!stream) return 30;
    mark = replacement_calls;
    emit_flag("fprintf", "status", fprintf(stream, "%s", "file") != 4);
    report_replacement("fprintf", mark);
    if (fclose(stream)) return 31;
    mark = replacement_calls;
    emit_flag("asprintf", "status", asprintf(&text, "%s-%d", "value", 3) != 7 || strcmp(text, "value-3"));
    report_replacement("asprintf", mark);
    free(text);
    /* Musl's psignal formats with the public fprintf, and psiginfo calls
     * psignal; both write the description to standard error. */
    mark = replacement_calls;
    psignal(SIGTERM, "psignal");
    report_replacement("psignal", mark);
    {
        siginfo_t information = {.si_signo = SIGINT};
        mark = replacement_calls;
        psiginfo(&information, "psiginfo");
        report_replacement("psiginfo", mark);
    }
    return 0;
}
#endif

#ifdef CRABC_REPLACE_VSNPRINTF
/* A counting `vsnprintf` over a memory stream and libc's vfprintf. Musl's
 * snprintf, vsprintf (and so sprintf) and vasprintf format through it. */
int vsnprintf(char *destination, size_t capacity, const char *format, va_list args)
{
    char buffer[256];
    FILE *stream;
    int length;

    replacement_calls++;
    stream = fmemopen(buffer, sizeof buffer, "w");
    if (!stream) return -1;
    length = vfprintf(stream, format, args);
    if (fclose(stream) || length < 0 || (size_t)length >= sizeof buffer) return -1;
    buffer[length] = 0;
    if (capacity) {
        size_t copied = (size_t)length < capacity ? (size_t)length : capacity - 1;
        memcpy(destination, buffer, copied);
        destination[copied] = 0;
    }
    return length;
}

static int run_vsnprintf_clients(void)
{
    unsigned long mark;
    char buffer[32];
    char *text = 0;

    mark = replacement_calls;
    emit_flag("snprintf", "status", snprintf(buffer, sizeof buffer, "%d:%s", 5, "x") != 3 || strcmp(buffer, "5:x"));
    report_replacement("snprintf", mark);
    mark = replacement_calls;
    emit_flag("sprintf", "status", sprintf(buffer, "%s", "spr") != 3 || strcmp(buffer, "spr"));
    report_replacement("sprintf", mark);
    mark = replacement_calls;
    emit_flag("asprintf", "status", asprintf(&text, "%d", 42) != 2 || strcmp(text, "42"));
    report_replacement("asprintf", mark);
    free(text);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_SCANF
/* A counting `vfscanf` that accepts exactly one "%d" directive. Musl's scanf,
 * vscanf and fscanf scan through the public vfscanf. */
int vfscanf(FILE *stream, const char *format, va_list args)
{
    int character, value = 0, digits = 0, negative = 0;

    replacement_calls++;
    if (strcmp(format, "%d")) return -1;
    do character = getc(stream); while (character == ' ' || character == '\n');
    if (character == '-') {
        negative = 1;
        character = getc(stream);
    }
    while (character >= '0' && character <= '9') {
        value = value * 10 + (character - '0');
        digits++;
        character = getc(stream);
    }
    if (character != EOF) ungetc(character, stream);
    if (!digits) return character == EOF ? EOF : 0;
    *va_arg(args, int *) = negative ? -value : value;
    return 1;
}

static int call_vscanf(const char *format, ...)
{
    va_list args;
    int status;

    va_start(args, format);
    status = vscanf(format, args);
    va_end(args);
    return status;
}

static int run_scanf_clients(void)
{
    unsigned long mark;
    FILE *stream;
    int value = 0;

    stream = fopen("/replacement-scanf", "w+");
    if (!stream || fputs("-42\n", stream) < 0 || fseek(stream, 0, SEEK_SET)) return 40;
    mark = replacement_calls;
    emit_flag("fscanf", "status", fscanf(stream, "%d", &value) != 1 || value != -42);
    report_replacement("fscanf", mark);
    if (fclose(stream)) return 41;
    /* The runner supplies an empty standard input. */
    mark = replacement_calls;
    emit_flag("scanf", "status", scanf("%d", &value) != EOF);
    report_replacement("scanf", mark);
    mark = replacement_calls;
    emit_flag("vscanf", "status", call_vscanf("%d", &value) != EOF);
    report_replacement("vscanf", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_MATH
#include <complex.h>
#include <math.h>
/*
 * Counting `hypot` and `log1p`. Musl's cabs calls hypot, and its acosh calls
 * log1p for arguments below two.
 */
double hypot(double x, double y)
{
    replacement_calls++;
    return sqrt(x * x + y * y);
}

double log1p(double x)
{
    replacement_calls++;
    return log(1 + x);
}

static int run_math_clients(void)
{
    unsigned long mark;
    volatile double real = 3, imaginary = 4, argument = 1.5;

    mark = replacement_calls;
    emit_flag("cabs", "value", cabs(real + imaginary * I) == 5);
    report_replacement("cabs", mark);
    mark = replacement_calls;
    emit_flag("acosh", "finite", isfinite(acosh(argument)));
    report_replacement("acosh", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_WIDE
/*
 * Counting `wcwidth`, `wcslen`, `mbsrtowcs` and `wcsrtombs` over ASCII.
 * Musl's wcswidth calls wcwidth, wcsdup wcslen, mbstowcs mbsrtowcs and
 * wcstombs wcsrtombs.
 */
int wcwidth(wchar_t character)
{
    replacement_calls++;
    return character ? 1 : 0;
}

size_t wcslen(const wchar_t *string)
{
    size_t length = 0;
    replacement_calls++;
    while (string[length]) length++;
    return length;
}

size_t mbsrtowcs(wchar_t *restrict destination, const char **restrict source, size_t count, mbstate_t *restrict state)
{
    size_t index = 0;
    (void)state;
    replacement_calls++;
    for (; (*source)[index] && (!destination || index < count); index++)
        if (destination) destination[index] = (unsigned char)(*source)[index];
    if (destination && index < count) {
        destination[index] = 0;
        *source = 0;
    }
    return index;
}

size_t wcsrtombs(char *restrict destination, const wchar_t **restrict source, size_t count, mbstate_t *restrict state)
{
    size_t index = 0;
    (void)state;
    replacement_calls++;
    for (; (*source)[index] && (!destination || index < count); index++)
        if (destination) destination[index] = (char)(*source)[index];
    if (destination && index < count) {
        destination[index] = 0;
        *source = 0;
    }
    return index;
}

static int run_wide_clients(void)
{
    unsigned long mark;
    wchar_t wide[8];
    char narrow[8];
    wchar_t *copy;

    mark = replacement_calls;
    emit_flag("wcswidth", "value", wcswidth(L"abc", 3) == 3);
    report_replacement("wcswidth", mark);
    mark = replacement_calls;
    copy = wcsdup(L"abc");
    emit_flag("wcsdup", "value", copy && copy[2] == L'c' && !copy[3]);
    report_replacement("wcsdup", mark);
    free(copy);
    mark = replacement_calls;
    emit_flag("mbstowcs", "value", mbstowcs(wide, "abc", 8) == 3 && wide[1] == L'b');
    report_replacement("mbstowcs", mark);
    mark = replacement_calls;
    emit_flag("wcstombs", "value", wcstombs(narrow, L"abc", 8) == 3 && narrow[1] == 'b');
    report_replacement("wcstombs", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_SYSTEM
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
/*
 * Counting `nanosleep`, `open`, `unlink`, `rmdir`, `sendto` and `recvfrom`
 * that perform the plain system call. Musl's sleep and usleep call
 * nanosleep, creat calls open, remove calls unlink then rmdir, send calls
 * sendto, and recv calls recvfrom.
 */
int nanosleep(const struct timespec *request, struct timespec *remaining)
{
    replacement_calls++;
    return (int)syscall(SYS_nanosleep, request, remaining);
}

int open(const char *path, int flags, ...)
{
    va_list args;
    int mode;

    replacement_calls++;
    va_start(args, flags);
    mode = va_arg(args, int);
    va_end(args);
    return (int)syscall(SYS_open, path, flags, mode);
}

int unlink(const char *path)
{
    replacement_calls++;
    return (int)syscall(SYS_unlink, path);
}

int rmdir(const char *path)
{
    replacement_calls++;
    return (int)syscall(SYS_rmdir, path);
}

ssize_t sendto(int fd, const void *buffer, size_t length, int flags, const struct sockaddr *address, socklen_t size)
{
    replacement_calls++;
    return syscall(SYS_sendto, fd, buffer, length, flags, address, size);
}

ssize_t recvfrom(int fd, void *buffer, size_t length, int flags, struct sockaddr *restrict address, socklen_t *restrict size)
{
    replacement_calls++;
    return syscall(SYS_recvfrom, fd, buffer, length, flags, address, size);
}

static int run_system_clients(void)
{
    unsigned long mark;
    int pair[2];
    char byte = 0;

    mark = replacement_calls;
    emit_flag("sleep", "value", sleep(0) == 0);
    report_replacement("sleep", mark);
    mark = replacement_calls;
    emit_flag("usleep", "value", usleep(1) == 0);
    report_replacement("usleep", mark);
    mark = replacement_calls;
    {
        int fd = creat("/replacement-created", 0600);
        emit_flag("creat", "value", fd >= 0);
        if (fd >= 0) close(fd);
    }
    report_replacement("creat", mark);
    mark = replacement_calls;
    emit_flag("remove", "value", remove("/replacement-created") == 0);
    report_replacement("remove", mark);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 50;
    mark = replacement_calls;
    emit_flag("send", "value", send(pair[0], "x", 1, 0) == 1);
    report_replacement("send", mark);
    mark = replacement_calls;
    emit_flag("recv", "value", recv(pair[1], &byte, 1, 0) == 1 && byte == 'x');
    report_replacement("recv", mark);
    close(pair[0]);
    close(pair[1]);
    return 0;
}
#endif

#if defined(CRABC_REPLACE_STDIO_BLOCK) || defined(CRABC_REPLACE_FPUTS) || defined(CRABC_REPLACE_FFLUSH) || \
    defined(CRABC_REPLACE_GETDELIM) || defined(CRABC_REPLACE_SETVBUF) || defined(CRABC_REPLACE_WIDE_STREAM) || \
    defined(CRABC_REPLACE_FCLOSE) || defined(CRABC_REPLACE_BYTE)
#define CRABC_REPLACE_STDIO 1
static unsigned long stdio_calls;

static void report_stdio(const char *operation, unsigned long mark)
{
    emit_flag(operation, "replacement", stdio_calls != mark);
}

/* Read back a file the role wrote, through raw descriptors. */
static void emit_file(const char *operation, const char *path)
{
    char buffer[64];
    int descriptor = open(path, O_RDONLY);
    ssize_t count = descriptor < 0 ? -1 : read(descriptor, buffer, sizeof buffer - 1);
    if (descriptor >= 0) close(descriptor);
    buffer[count < 0 ? 0 : count] = 0;
    for (ssize_t index = 0; index < count; index++)
        if (buffer[index] == '\n') buffer[index] = '|';
    emit_record(operation, "file", buffer);
}
#endif

#ifdef CRABC_REPLACE_STDIO_BLOCK
/* Counting `fwrite` and `fread` over libc's byte entries. Musl's fputs
 * (and so puts), putw and perror write through the public fwrite; getw
 * reads through the public fread. */
size_t fwrite(const void *restrict source, size_t size, size_t count, FILE *restrict stream)
{
    const unsigned char *bytes = source;
    size_t total = size * count, index;

    stdio_calls++;
    for (index = 0; index < total; index++)
        if (fputc(bytes[index], stream) == EOF) break;
    return size ? index / size : 0;
}

size_t fread(void *restrict destination, size_t size, size_t count, FILE *restrict stream)
{
    unsigned char *bytes = destination;
    size_t total = size * count, index;
    int character;

    stdio_calls++;
    for (index = 0; index < total && (character = fgetc(stream)) != EOF; index++)
        bytes[index] = (unsigned char)character;
    return size ? index / size : 0;
}

static int run_stdio_clients(void)
{
    unsigned long mark;
    FILE *stream = fopen("/replacement-block", "w+");
    if (!stream) return 50;
    mark = stdio_calls;
    emit_flag("fputs", "status", fputs("line\n", stream) < 0);
    report_stdio("fputs", mark);
    mark = stdio_calls;
    emit_flag("putw", "status", putw(0x0a434241, stream) != 0);
    report_stdio("putw", mark);
    if (fseek(stream, 5, SEEK_SET)) return 51;
    mark = stdio_calls;
    emit_flag("getw", "status", getw(stream) != 0x0a434241);
    report_stdio("getw", mark);
    if (fclose(stream)) return 52;
    emit_file("block", "/replacement-block");
    mark = stdio_calls;
    emit_flag("puts", "status", puts("puts-line") < 0 || fflush(stdout));
    report_stdio("puts", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_FPUTS
/* A counting `fputs` over the public fwrite. Musl's puts calls it. */
int fputs(const char *restrict text, FILE *restrict stream)
{
    size_t length = strlen(text);

    stdio_calls++;
    return fwrite(text, 1, length, stream) == length ? 0 : EOF;
}

static int run_stdio_clients(void)
{
    unsigned long mark = stdio_calls;

    emit_flag("puts", "status", puts("puts-line") < 0 || fflush(stdout));
    report_stdio("puts", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_FFLUSH
/* A counting `fflush` that flushes nothing. Musl's fclose, freopen and
 * _flushlbf call it; __stdio_exit writes pending output itself, so the
 * buffered tail printed last still reaches standard output. */
int fflush(FILE *stream)
{
    (void)stream;
    stdio_calls++;
    return 0;
}

extern void _flushlbf(void);

static int run_stdio_clients(void)
{
    unsigned long mark;
    FILE *stream = fopen("/replacement-flush", "w");
    if (!stream) return 60;
    mark = stdio_calls;
    emit_flag("fclose", "status", fclose(stream) != 0);
    report_stdio("fclose", mark);
    stream = fopen("/replacement-flush", "r");
    if (!stream) return 61;
    mark = stdio_calls;
    emit_flag("freopen", "status", freopen("/replacement-flush", "r", stream) != stream);
    report_stdio("freopen", mark);
    mark = stdio_calls;
    _flushlbf();
    report_stdio("_flushlbf", mark);
    /* Left buffered: only __stdio_exit can write it. */
    if (fputs("exit-tail", stdout) < 0) return 62;
    return 0;
}
#endif

#ifdef CRABC_REPLACE_GETDELIM
/* A counting `getdelim` over libc's fgetc. Musl's getline calls it, and
 * fgetln reaches it through getline. */
ssize_t getdelim(char **restrict line, size_t *restrict capacity, int delimiter, FILE *restrict stream)
{
    size_t length = 0;
    int character;

    stdio_calls++;
    if (!*line || *capacity < 64) {
        char *grown = realloc(*line, 64);
        if (!grown) return -1;
        *line = grown;
        *capacity = 64;
    }
    while (length + 1 < *capacity && (character = fgetc(stream)) != EOF) {
        (*line)[length++] = (char)character;
        if (character == delimiter) break;
    }
    (*line)[length] = 0;
    return length ? (ssize_t)length : -1;
}

extern char *fgetln(FILE *, size_t *);

static int run_stdio_clients(void)
{
    unsigned long mark;
    char *line = 0;
    size_t capacity = 0, length = 0;
    FILE *stream = fopen("/replacement-getdelim", "w+");
    if (!stream || fputs("first\nsecond\n", stream) < 0 || fseek(stream, 0, SEEK_SET)) return 70;
    mark = stdio_calls;
    emit_flag("getline", "status", getline(&line, &capacity, stream) != 6 || strcmp(line, "first\n"));
    report_stdio("getline", mark);
    mark = stdio_calls;
    emit_flag("fgetln", "status", !fgetln(stream, &length) || length != 7);
    report_stdio("fgetln", mark);
    free(line);
    return fclose(stream) ? 71 : 0;
}
#endif

#ifdef CRABC_REPLACE_SETVBUF
/* A counting `setvbuf` that keeps libc's default buffering. Musl's setbuf,
 * setbuffer and setlinebuf call it. */
int setvbuf(FILE *restrict stream, char *restrict buffer, int mode, size_t size)
{
    (void)stream, (void)buffer, (void)mode, (void)size;
    stdio_calls++;
    return 0;
}

static int run_stdio_clients(void)
{
    static char buffer[BUFSIZ];
    unsigned long mark;
    FILE *stream = fopen("/replacement-setvbuf", "w");
    if (!stream) return 80;
    mark = stdio_calls;
    setbuf(stream, buffer);
    report_stdio("setbuf", mark);
    mark = stdio_calls;
    setbuffer(stream, buffer, sizeof buffer);
    report_stdio("setbuffer", mark);
    mark = stdio_calls;
    setlinebuf(stream);
    report_stdio("setlinebuf", mark);
    return fclose(stream) ? 81 : 0;
}
#endif

#ifdef CRABC_REPLACE_WIDE_STREAM
/* Counting single-byte `fgetwc` and `fputwc` over libc's fgetc and fputc,
 * in the C locale. Musl's getwc and getwchar read, and putwc and putwchar
 * write, through them. */
wint_t fgetwc(FILE *stream)
{
    int character;

    stdio_calls++;
    character = fgetc(stream);
    return character == EOF ? WEOF : (wint_t)character;
}

wint_t fputwc(wchar_t character, FILE *stream)
{
    stdio_calls++;
    return fputc((int)character, stream) == EOF ? WEOF : (wint_t)character;
}

static int run_stdio_clients(void)
{
    unsigned long mark;
    FILE *stream = fopen("/replacement-wide", "w+");
    if (!stream) return 90;
    mark = stdio_calls;
    emit_flag("putwc", "status", putwc(L'w', stream) != L'w');
    report_stdio("putwc", mark);
    if (fseek(stream, 0, SEEK_SET)) return 91;
    mark = stdio_calls;
    emit_flag("getwc", "status", getwc(stream) != L'w');
    report_stdio("getwc", mark);
    if (fclose(stream)) return 92;
    /* The runner supplies an empty standard input. */
    mark = stdio_calls;
    emit_flag("getwchar", "status", getwchar() != WEOF);
    report_stdio("getwchar", mark);
    mark = stdio_calls;
    emit_flag("putwchar", "status", putwchar(L'\n') != L'\n' || fflush(stdout));
    report_stdio("putwchar", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_BYTE
/* Counting `fgetc`, `fputc`, `getc_unlocked` and `putc_unlocked` over getc
 * and putc. Musl's getc, getchar, putc and putchar inline their own byte
 * transfer, and getchar_unlocked and putchar_unlocked use stdio_impl.h's
 * macros, so none of them reaches these definitions. */
int fgetc(FILE *stream)
{
    stdio_calls++;
    return getc(stream);
}

int fputc(int character, FILE *stream)
{
    stdio_calls++;
    return putc(character, stream);
}

int getc_unlocked(FILE *stream)
{
    stdio_calls++;
    return getc(stream);
}

int putc_unlocked(int character, FILE *stream)
{
    stdio_calls++;
    return putc(character, stream);
}

static int run_stdio_clients(void)
{
    unsigned long mark;
    FILE *stream = fopen("/replacement-byte", "w+");
    if (!stream) return 110;
    mark = stdio_calls;
    emit_flag("fputc", "status", fputc('a', stream) != 'a');
    report_stdio("fputc", mark);
    mark = stdio_calls;
    emit_flag("putc", "status", putc('b', stream) != 'b');
    report_stdio("putc", mark);
    if (fseek(stream, 0, SEEK_SET)) return 111;
    mark = stdio_calls;
    emit_flag("fgetc", "status", fgetc(stream) != 'a');
    report_stdio("fgetc", mark);
    mark = stdio_calls;
    emit_flag("getc", "status", getc(stream) != 'b');
    report_stdio("getc", mark);
    if (fclose(stream)) return 112;
    /* The runner supplies an empty standard input. */
    mark = stdio_calls;
    emit_flag("getchar", "status", getchar() != EOF);
    report_stdio("getchar", mark);
    mark = stdio_calls;
    emit_flag("getchar_unlocked", "status", getchar_unlocked() != EOF);
    report_stdio("getchar_unlocked", mark);
    mark = stdio_calls;
    emit_flag("putchar", "status", putchar('c') != 'c');
    report_stdio("putchar", mark);
    mark = stdio_calls;
    emit_flag("putchar_unlocked", "status", putchar_unlocked('\n') != '\n' || fflush(stdout));
    report_stdio("putchar_unlocked", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_FCLOSE
/* A counting `fclose` that flushes and closes the descriptor and leaks the
 * FILE. A freopen whose new open fails closes the old stream through it, as
 * musl's freopen.c does. */
int fclose(FILE *stream)
{
    int status = fflush(stream);

    stdio_calls++;
    return close(fileno(stream)) || status ? EOF : 0;
}

static int run_stdio_clients(void)
{
    unsigned long mark;
    FILE *stream = fopen("/replacement-fclose", "w");
    if (!stream) return 100;
    mark = stdio_calls;
    emit_flag("freopen", "status", freopen("/missing/replacement", "r", stream) != 0);
    report_stdio("freopen", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_FILES
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
/*
 * Counting `open`, `mknod` and `fcntl` that perform the plain system call.
 * Musl's opendir calls open, mkfifo calls mknod, and lockf calls fcntl.
 */
int open(const char *path, int flags, ...)
{
    va_list args;
    int mode;

    replacement_calls++;
    va_start(args, flags);
    mode = va_arg(args, int);
    va_end(args);
    return (int)syscall(SYS_open, path, flags, mode);
}

int mknod(const char *path, mode_t mode, dev_t device)
{
    replacement_calls++;
    return (int)syscall(SYS_mknod, path, mode, device);
}

int fcntl(int fd, int command, ...)
{
    va_list args;
    long argument;

    replacement_calls++;
    va_start(args, command);
    argument = va_arg(args, long);
    va_end(args);
    return (int)syscall(SYS_fcntl, fd, command, argument);
}

static int run_file_clients(void)
{
    unsigned long mark;
    DIR *directory;
    int fd;

    mark = replacement_calls;
    directory = opendir("/");
    emit_flag("opendir", "value", directory != 0);
    report_replacement("opendir", mark);
    if (directory) closedir(directory);
    mark = replacement_calls;
    emit_flag("mkfifo", "value", mkfifo("/replacement-fifo", 0600) == 0);
    report_replacement("mkfifo", mark);
    fd = (int)syscall(SYS_open, "/replacement-lock", O_RDWR | O_CREAT, 0600);
    if (fd < 0) return 60;
    mark = replacement_calls;
    emit_flag("lockf", "value", lockf(fd, F_TLOCK, 0) == 0);
    report_replacement("lockf", mark);
    close(fd);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_NETWORK
#include <netdb.h>
/*
 * Counting `gethostbyname2` and `getservbyname_r`. Musl's gethostbyname and
 * getservbyname call them.
 */
struct hostent *gethostbyname2(const char *name, int family)
{
    (void)name;
    (void)family;
    replacement_calls++;
    return 0;
}

int getservbyname_r(const char *name, const char *protocol, struct servent *entry,
                    char *buffer, size_t size, struct servent **result)
{
    (void)name; (void)protocol; (void)entry; (void)buffer; (void)size;
    replacement_calls++;
    *result = 0;
    return ENOENT;
}

static int run_network_clients(void)
{
    unsigned long mark;

    mark = replacement_calls;
    emit_flag("gethostbyname", "value", gethostbyname("replacement.invalid") == 0);
    report_replacement("gethostbyname", mark);
    mark = replacement_calls;
    emit_flag("getservbyname", "value", getservbyname("replacement", "tcp") == 0);
    report_replacement("getservbyname", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_ACCOUNTS
#include <grp.h>
/*
 * Counting `getgrouplist` and `setgroups`. Musl's initgroups calls both.
 */
int getgrouplist(const char *user, gid_t group, gid_t *groups, int *count)
{
    (void)user;
    replacement_calls++;
    if (*count < 1) {
        *count = 1;
        return -1;
    }
    groups[0] = group;
    *count = 1;
    return 1;
}

int setgroups(size_t count, const gid_t *groups)
{
    (void)count;
    (void)groups;
    replacement_calls++;
    return 0;
}

static int run_account_clients(void)
{
    unsigned long mark;

    mark = replacement_calls;
    emit_flag("initgroups", "value", initgroups("replacement", 7) == 0);
    report_replacement("initgroups", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_THREADS
#include <pthread.h>
#include <threads.h>
/*
 * Counting `pthread_mutex_lock` and `pthread_mutex_unlock` over libc's
 * trylock. Musl's mtx_lock and mtx_unlock reach its hidden
 * __pthread_mutex_* bodies instead, so these stay uncounted.
 */
int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    int status;

    replacement_calls++;
    while ((status = pthread_mutex_trylock(mutex)) == EBUSY)
        ;
    return status;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    (void)mutex;
    replacement_calls++;
    return 0;
}

static int run_thread_clients(void)
{
    unsigned long mark;
    mtx_t mutex;

    if (mtx_init(&mutex, mtx_plain) != thrd_success) return 70;
    mark = replacement_calls;
    emit_flag("mtx_lock", "value", mtx_lock(&mutex) == thrd_success);
    report_replacement("mtx_lock", mark);
    mark = replacement_calls;
    emit_flag("mtx_unlock", "value", mtx_unlock(&mutex) == thrd_success);
    report_replacement("mtx_unlock", mark);
    mtx_destroy(&mutex);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_PROCESS
#include <pthread.h>
#include <semaphore.h>
#include <setjmp.h>
#include <sys/wait.h>
/*
 * Counting replacements of entries whose musl objects other libc objects
 * reach only by public symbol or not at all. Musl's exit.c and fork.c carry
 * weak dummy `__funcs_on_exit` and `__fork_handler`, so replacing `atexit`
 * or `pthread_atfork` links neither registry. Its getlogin_r calls getlogin,
 * sem_wait sem_timedwait, atof strtod, and siglongjmp longjmp;
 * wcstod scans internally and stays uncounted.
 */
static void (*registered_exit_handler)(void);

int atexit(void (*function)(void))
{
    replacement_calls++;
    registered_exit_handler = function;
    return 0;
}

int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void))
{
    (void)prepare;
    (void)parent;
    (void)child;
    replacement_calls++;
    return 0;
}

char *getlogin(void)
{
    static char name[] = "replaced";

    replacement_calls++;
    return name;
}

int sem_timedwait(sem_t *restrict semaphore, const struct timespec *restrict deadline)
{
    (void)deadline;
    replacement_calls++;
    return sem_trywait(semaphore);
}

double strtod(const char *restrict text, char **restrict end)
{
    replacement_calls++;
    if (end) *end = (char *)text + strlen(text);
    return 42.0;
}

/* Musl's x86_64 longjmp.s, behind a counting C entry. */
_Noreturn void crabc_probe_jump(jmp_buf buffer, int value);
__asm__(
    ".text\n"
    ".type crabc_probe_jump,@function\n"
    "crabc_probe_jump:\n"
    "\txor %eax,%eax\n"
    "\tcmp $1,%esi\n"
    "\tadc %esi,%eax\n"
    "\tmov (%rdi),%rbx\n"
    "\tmov 8(%rdi),%rbp\n"
    "\tmov 16(%rdi),%r12\n"
    "\tmov 24(%rdi),%r13\n"
    "\tmov 32(%rdi),%r14\n"
    "\tmov 40(%rdi),%r15\n"
    "\tmov 48(%rdi),%rsp\n"
    "\tjmp *56(%rdi)\n"
    ".size crabc_probe_jump, .-crabc_probe_jump\n");

_Noreturn void longjmp(jmp_buf buffer, int value)
{
    replacement_calls++;
    crabc_probe_jump(buffer, value);
}

static void unexpected_exit_handler(void)
{
    emit("atexit handler ran\n");
}

static int run_process_clients(void)
{
    unsigned long mark;
    char name[16];
    sigjmp_buf jump;
    volatile int jumped = 0;
    sem_t semaphore;
    pid_t child;
    int status = 0;

    mark = replacement_calls;
    emit_flag("atexit", "value", atexit(unexpected_exit_handler) == 0 && registered_exit_handler);
    report_replacement("atexit", mark);
    mark = replacement_calls;
    emit_flag("pthread_atfork", "value", pthread_atfork(0, 0, 0) == 0);
    report_replacement("pthread_atfork", mark);
    mark = replacement_calls;
    child = fork();
    if (child == 0) _exit(7);
    emit_flag("fork", "value", child > 0 && waitpid(child, &status, 0) == child
        && WIFEXITED(status) && WEXITSTATUS(status) == 7);
    report_replacement("fork", mark);
    mark = replacement_calls;
    emit_flag("getlogin_r", "value", getlogin_r(name, sizeof name) == 0 && !strcmp(name, "replaced"));
    report_replacement("getlogin_r", mark);
    if (sem_init(&semaphore, 0, 1)) return 80;
    mark = replacement_calls;
    emit_flag("sem_wait", "value", sem_wait(&semaphore) == 0);
    report_replacement("sem_wait", mark);
    sem_destroy(&semaphore);
    mark = replacement_calls;
    emit_flag("atof", "value", atof("1.5") == 42.0);
    report_replacement("atof", mark);
    mark = replacement_calls;
    emit_flag("wcstod", "value", wcstod(L"1.5", 0) == 1.5);
    report_replacement("wcstod", mark);
    mark = replacement_calls;
    if (!sigsetjmp(jump, 0)) {
        jumped = 1;
        siglongjmp(jump, 1);
    }
    emit_flag("siglongjmp", "value", jumped);
    report_replacement("siglongjmp", mark);
    return 0;
}
#endif

#ifdef CRABC_REPLACE_EXIT
/* Musl's __libc_start_main reaches the application's `exit` when main returns. */
_Noreturn void exit(int status)
{
    emit_flag("exit", "replacement", 1);
    _exit(status);
}
#endif

#ifdef CRABC_REPLACE_PUSHBACK
/*
 * A counting `ungetc` that pushes nothing back. Musl's scanner steps its own
 * buffer position back instead of calling ungetc, so fscanf still sees each
 * delimiter and this stays uncounted.
 */
int ungetc(int character, FILE *stream)
{
    (void)character;
    (void)stream;
    replacement_calls++;
    return EOF;
}

static int run_pushback_clients(void)
{
    unsigned long mark;
    FILE *stream;
    int first = 0, second = 0;
    char word[8];

    stream = fopen("/replacement-pushback", "w+");
    if (!stream || fputs("12 34x\n", stream) < 0 || fseek(stream, 0, SEEK_SET)) return 85;
    mark = replacement_calls;
    emit_flag("fscanf", "value", fscanf(stream, "%d %d%2s", &first, &second, word) == 3
        && first == 12 && second == 34 && !strcmp(word, "x"));
    report_replacement("fscanf", mark);
    if (fclose(stream)) return 86;
    return 0;
}
#endif

#ifdef CRABC_REPLACE_MAPPING
#include <search.h>
#include <sys/mman.h>
#include <sys/syscall.h>
/*
 * A counting `mmap` over the raw system call. Musl's allocator maps through
 * its internal __mmap, so no allocation from process start, including one
 * large enough for its own mapping, and no libc caller that allocates
 * reaches it; a direct call does. (Musl's mallocng does free individual
 * mappings through the public munmap, so that one is not compared.)
 */
void *mmap(void *address, size_t length, int protection, int flags, int descriptor, off_t offset)
{
    replacement_calls++;
    return (void *)syscall(SYS_mmap, address, length, protection, flags, descriptor, offset);
}

static void ignore_node(void *node)
{
    (void)node;
}

static int compare_keys(const void *left, const void *right)
{
    return strcmp(left, right);
}

static int run_mapping_clients(void)
{
    static const size_t sizes[] = {16, 4096, 300000, 8u << 20, 64u << 20};
    unsigned long mark;
    void *root = 0, *mapping;
    size_t index;
    int ok = 1;

    /* Count from process start: startup allocation is libc-internal too. */
    mark = 0;
    for (index = 0; index < sizeof sizes / sizeof sizes[0]; index++) {
        char *block = malloc(sizes[index]), *grown;
        if (!block) return 95;
        block[0] = block[sizes[index] - 1] = 1;
        grown = realloc(block, sizes[index] * 2);
        if (!grown) return 96;
        ok &= grown[0] == 1;
        free(grown);
    }
    emit_flag("malloc", "value", ok);
    report_replacement("malloc", mark);
    mark = replacement_calls;
    emit_flag("tsearch", "value", tsearch("key", &root, compare_keys) != 0);
    report_replacement("tsearch", mark);
    tdestroy(root, ignore_node);
    mark = replacement_calls;
    mapping = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    emit_flag("mmap", "value", mapping != MAP_FAILED && munmap(mapping, 4096) == 0);
    report_replacement("mmap", mark);
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
#ifdef CRABC_REPLACE_PRINTF
    int status = run_printf_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_VSNPRINTF
    int status = run_vsnprintf_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_SCANF
    int status = run_scanf_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_WIDE
    int status = run_wide_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_SYSTEM
    int status = run_system_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_FILES
    int status = run_file_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_NETWORK
    int status = run_network_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_ACCOUNTS
    int status = run_account_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_THREADS
    int status = run_thread_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_MATH
    int status = run_math_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_STDIO
    int status = run_stdio_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_PROCESS
    int status = run_process_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_PUSHBACK
    int status = run_pushback_clients();
    if (status) return status;
#endif
#ifdef CRABC_REPLACE_MAPPING
    int status = run_mapping_clients();
    if (status) return status;
#endif
    emit("owned-static-replacement-ok\n");
    return 0;
}
