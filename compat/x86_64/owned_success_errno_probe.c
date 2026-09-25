/* errno after successful libc calls, differentially against pinned musl.
 *
 * Each process runs exactly one case: `probe CASE first` makes the measured
 * call (after only its own setup, such as readdir's opendir) before any other
 * libc work in main, so it is the process's first allocation when the case
 * allocates; `probe CASE later` warms the same call (and the allocator)
 * first, then measures a second call. `probe --list` prints the roster. The measured call
 * starts from an errno sentinel and the probe prints the errno it leaves.
 * POSIX and musl leave errno unchanged across these successful calls and
 * documented not-found results, so every value is compared with musl's
 * transcript rather than asserted here.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <grp.h>
#include <locale.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { success_errno_sentinel = 79 };

static void require(int condition, int code)
{
    if (!condition)
        _Exit(code);
}

static void allocate(void)
{
    void *block = malloc(24);
    require(block != 0, 90);
    free(block);
}

static void zero_allocate(void)
{
    void *block = calloc(3, 40);
    require(block != 0, 90);
    free(block);
}

static void reallocate(void)
{
    char *block = realloc(0, 16);
    require(block != 0, 90);
    block = realloc(block, 4096);
    require(block != 0, 90);
    free(block);
}

static void align_allocate(void)
{
    void *block = aligned_alloc(64, 128), *other = 0;
    require(block != 0 && !posix_memalign(&other, 256, 32), 90);
    free(block);
    free(other);
}

static void password_missing(void) { require(!getpwnam("crabc-no-such-user"), 91); }
static void password_found(void) { require(getpwnam("root") != 0, 91); }
static void password_uid_missing(void) { require(!getpwuid(4242), 91); }
static void password_uid_found(void) { require(getpwuid(0) != 0, 91); }
static void group_missing(void) { require(!getgrnam("crabc-no-such-group"), 91); }
static void group_found(void) { require(getgrnam("root") != 0, 91); }

static DIR *directory;

static void directory_open(void)
{
    DIR *handle = opendir("/work");
    require(handle != 0, 92);
    require(!closedir(handle), 92);
}

static void directory_end_prepare(void)
{
    directory = opendir("/work");
    require(directory != 0, 92);
}

static void directory_end(void)
{
    int entries = 0;
    while (readdir(directory))
        entries++;
    require(entries >= 2, 92);
}

static void directory_end_finish(void)
{
    require(!closedir(directory), 92);
}

static void integer_parse(void)
{
    char *end;
    require(strtol("-123", &end, 10) == -123 && !*end, 93);
    require(strtoul("0x7f", &end, 16) == 127 && !*end, 93);
    require(strtoll("9000000000", &end, 10) == 9000000000LL && !*end, 93);
    require(strtoull("77", &end, 8) == 63 && !*end, 93);
}

static void float_parse(void)
{
    char *end;
    require(strtod("1.5e3", &end) == 1500.0 && !*end, 93);
}

static void environment_found(void) { require(getenv("PATH") != 0, 94); }
static void environment_missing(void) { require(!getenv("CRABC_NO_SUCH_VARIABLE"), 94); }

static void stream_read(void)
{
    FILE *stream = fopen("/work/data", "r");
    require(stream != 0, 95);
    require(fgetc(stream) == 'd', 95);
    require(!fclose(stream), 95);
}

static void stream_write(void)
{
    FILE *stream = fopen("/tmp/written", "w");
    require(stream != 0, 95);
    require(fputs("written\n", stream) >= 0 && !fflush(stream), 95);
    require(!fclose(stream), 95);
}

static void formatted_output(void) { require(printf("printf-output\n") == 14, 95); }

static void output_flush(void)
{
    require(fputs("flush-output\n", stdout) >= 0, 95);
    require(!fflush(stdout), 95);
}

static void name_lookup(const char *node)
{
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *result = 0;
    require(!getaddrinfo(node, "80", &hints, &result) && result != 0, 96);
    freeaddrinfo(result);
}

static void hosts_lookup(void) { name_lookup("localhost"); }
static void numeric_lookup(void) { name_lookup("127.0.0.1"); }

static void locale_utf8(void) { require(setlocale(LC_ALL, "C.UTF-8") != 0, 97); }
static void locale_environment(void) { require(setlocale(LC_ALL, "") != 0, 97); }

static void duplicate(void)
{
    char *copy = strdup("duplicated");
    require(copy != 0 && !strcmp(copy, "duplicated"), 98);
    free(copy);
}

static int compare(const void *left, const void *right)
{
    return *(const int *)left - *(const int *)right;
}

static void sort(void)
{
    int values[64];
    for (int index = 0; index < 64; index++)
        values[index] = (index * 37) % 64;
    qsort(values, 64, sizeof *values, compare);
    for (int index = 0; index < 64; index++)
        require(values[index] == index, 98);
}

static void local_time(void)
{
    time_t when = 86400;
    require(localtime(&when) != 0, 99);
}

static void time_zone(void) { tzset(); }

static void library_open(void)
{
    void *handle = dlopen("libc.so", RTLD_NOW);
    require(handle != 0, 100);
    require(dlsym(handle, "strlen") != 0, 100);
    require(!dlclose(handle), 100);
}

static void nothing(void) {}

struct success_case {
    const char *name;
    void (*prepare)(void);
    void (*measure)(void);
    void (*finish)(void);
};

static const struct success_case cases[] = {
    {"malloc", nothing, allocate, nothing},
    {"calloc", nothing, zero_allocate, nothing},
    {"realloc", nothing, reallocate, nothing},
    {"aligned", nothing, align_allocate, nothing},
    {"getpwnam-missing", nothing, password_missing, nothing},
    {"getpwnam-found", nothing, password_found, nothing},
    {"getpwuid-missing", nothing, password_uid_missing, nothing},
    {"getpwuid-found", nothing, password_uid_found, nothing},
    {"getgrnam-missing", nothing, group_missing, nothing},
    {"getgrnam-found", nothing, group_found, nothing},
    {"opendir-closedir", nothing, directory_open, nothing},
    {"readdir-end", directory_end_prepare, directory_end, directory_end_finish},
    {"strtol-family", nothing, integer_parse, nothing},
    {"strtod", nothing, float_parse, nothing},
    {"getenv-found", nothing, environment_found, nothing},
    {"getenv-missing", nothing, environment_missing, nothing},
    {"fopen-fclose-read", nothing, stream_read, nothing},
    {"fopen-fflush-fclose-write", nothing, stream_write, nothing},
    {"printf", nothing, formatted_output, nothing},
    {"fflush-stdout", nothing, output_flush, nothing},
    {"getaddrinfo-hosts", nothing, hosts_lookup, nothing},
    {"getaddrinfo-numeric", nothing, numeric_lookup, nothing},
    {"setlocale-c-utf8", nothing, locale_utf8, nothing},
    {"setlocale-environment", nothing, locale_environment, nothing},
    {"strdup", nothing, duplicate, nothing},
    {"qsort", nothing, sort, nothing},
    {"localtime", nothing, local_time, nothing},
    {"tzset", nothing, time_zone, nothing},
    {"dlopen-libc", nothing, library_open, nothing},
};

int main(int argc, char **argv)
{
    const struct success_case *selected = 0;
    int later;

    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (size_t index = 0; index < sizeof cases / sizeof *cases; index++)
            puts(cases[index].name);
        return fflush(stdout) ? 101 : 0;
    }
    require(argc == 3, 2);
    later = !strcmp(argv[2], "later");
    require(later || !strcmp(argv[2], "first"), 2);
    for (size_t index = 0; index < sizeof cases / sizeof *cases; index++)
        if (!strcmp(cases[index].name, argv[1]))
            selected = &cases[index];
    require(selected != 0, 2);
    if (later) {
        selected->prepare();
        selected->measure();
        selected->finish();
    }
    selected->prepare();
    errno = success_errno_sentinel;
    selected->measure();
    int observed = errno;
    selected->finish();
    printf("case=%s position=%s errno=%d\n", argv[1], argv[2], observed);
    return fflush(stdout) ? 101 : 0;
}
