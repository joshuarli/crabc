/* Native Linux/x86-64 static process-name/getopt C ABI fixture.
 *
 * The same project-header body first executes through pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. It proves startup
 * publication of the program-name aliases before constructors, the mutable
 * same-address ELF alias contract, and the shared short/GNU-long option
 * parser state. Environment storage and mutation are intentionally outside
 * this fixture and remain owned by a separate C ABI slice.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <getopt.h>
#include <locale.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#define CRABC_TYPE_IS(actual, expected) \
    __builtin_types_compatible_p(actual, expected)

extern int __optpos;
extern int __optreset;
extern char *__progname;
extern char *__progname_full;
extern char *program_invocation_name;
extern char *program_invocation_short_name;
extern int __posix_getopt(int, char *const [], const char *);

_Static_assert(sizeof(int) == 4 && sizeof(void *) == 8,
    "x86 LP64 option/global scalar widths");
_Static_assert(sizeof(struct option) == 32 && _Alignof(struct option) == 8 &&
    offsetof(struct option, name) == 0 &&
    offsetof(struct option, has_arg) == 8 &&
    offsetof(struct option, flag) == 16 &&
    offsetof(struct option, val) == 24,
    "x86 GNU option record ABI");
_Static_assert(no_argument == 0 && required_argument == 1 &&
    optional_argument == 2, "GNU option argument values");
_Static_assert(CRABC_TYPE_IS(__typeof__(&getopt),
        int (*)(int, char *const [], const char *)) &&
    CRABC_TYPE_IS(__typeof__(&getopt_long),
        int (*)(int, char *const [], const char *, const struct option *, int *)) &&
    CRABC_TYPE_IS(__typeof__(&getopt_long_only),
        int (*)(int, char *const [], const char *, const struct option *, int *)),
    "selected getopt declarations");

static int constructor_status;

static const char *short_program_name(const char *full)
{
    const char *short_name = full;

    while (*full != '\0') {
        if (*full == '/') short_name = full + 1;
        ++full;
    }
    return short_name;
}

/* Musl initializes these names in __init_libc before application
 * constructors. The freestanding candidate's entry shim passes this exact
 * function as its bounded __libc_start_main init callback. */
__attribute__((constructor))
void crabc_x86_64_process_globals_getopt_init(void)
{
    if (__progname == NULL || __progname_full == NULL ||
        program_invocation_name == NULL ||
        program_invocation_short_name == NULL) {
        constructor_status = 1;
        return;
    }
    if (&program_invocation_name != &__progname_full ||
        &program_invocation_short_name != &__progname ||
        &optreset != &__optreset || __posix_getopt != getopt) {
        constructor_status = 2;
        return;
    }
    if (program_invocation_name != __progname_full ||
        program_invocation_short_name != __progname ||
        strcmp(__progname, short_program_name(__progname_full)) != 0) {
        constructor_status = 3;
        return;
    }
    if (optarg != NULL || optind != 1 || opterr != 1 || optopt != 0 ||
        __optpos != 0 || __optreset != 0 || optreset != 0) {
        constructor_status = 4;
        return;
    }
}

static int check_program_names(int argc, char **argv)
{
    static char replacement[] = "replacement";
    char *saved_short;

    if (constructor_status != 0 || argc <= 0 || argv == NULL || argv[0] == NULL)
        return 1;
    if (__progname_full != argv[0] || program_invocation_name != argv[0] ||
        __progname != short_program_name(argv[0]) ||
        program_invocation_short_name != __progname)
        return 2;

    saved_short = __progname;
    program_invocation_short_name = replacement;
    if (__progname != replacement)
        return 3;
    __progname = saved_short;
    if (program_invocation_short_name != saved_short)
        return 4;
    return 0;
}

static int check_short_options(void)
{
    char a0[] = "tool";
    char a1[] = "-abvalue";
    char a2[] = "tail";
    char *argv[] = { a0, a1, a2, NULL };
    char u0[] = "tool";
    char u1[] = "-\xce\xbbx";
    char *utf8_argv[] = { u0, u1, NULL };

    optind = 0;
    opterr = 0;
    if (getopt(3, argv, "ab:") != 'a' || __optpos == 0)
        return 1;
    if (getopt(3, argv, "ab:") != 'b' || optarg == NULL ||
        strcmp(optarg, "value") != 0 || __optpos != 0)
        return 2;
    if (getopt(3, argv, "ab:") != -1 || optind != 2)
        return 3;

    __optreset = 1;
    if (getopt(3, argv, "ab:") != 'a' || __optreset != 0 || optreset != 0)
        return 4;
    optreset = 1;
    if (getopt(3, argv, "ab:") != 'a' || optreset != 0 || __optreset != 0)
        return 5;
    optind = 0;
    if (__posix_getopt(3, argv, "ab:") != 'a')
        return 6;

    if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
        return 7;
    optind = 0;
    if (getopt(2, utf8_argv, "\xce\xbbx") != 0x03bb ||
        getopt(2, utf8_argv, "\xce\xbbx") != 'x' ||
        getopt(2, utf8_argv, "\xce\xbbx") != -1)
        return 8;
    return 0;
}

static int check_short_errors(void)
{
    char a0[] = "tool";
    char unknown_option[] = "-z";
    char missing_argument[] = "-b";
    char *unknown[] = { a0, unknown_option, NULL };
    char *missing[] = { a0, missing_argument, NULL };

    opterr = 0;
    optind = 0;
    if (getopt(2, unknown, "ab:") != '?' || optopt != 'z')
        return 1;
    optind = 0;
    if (getopt(2, missing, ":ab:") != ':' || optopt != 'b')
        return 2;
    return 0;
}

static int check_long_options(void)
{
    int flag = 0;
    int index = -1;
    struct option options[] = {
        { "alpha", no_argument, NULL, 'a' },
        { "alpine", no_argument, NULL, 'p' },
        { "beta", required_argument, NULL, 'b' },
        { "color", optional_argument, NULL, 'c' },
        { "flag", no_argument, &flag, 42 },
        { "verbose", no_argument, NULL, 'V' },
        { "v", no_argument, NULL, 'L' },
        { NULL, 0, NULL, 0 },
    };

    {
        char a0[] = "tool";
        char a1[] = "--beta=path";
        char *argv[] = { a0, a1, NULL };

        optind = 0;
        opterr = 0;
        if (getopt_long(2, argv, "abc:", options, &index) != 'b' ||
            index != 2 || optarg == NULL || strcmp(optarg, "path") != 0 ||
            optind != 2)
            return 1;
    }
    {
        char a0[] = "tool";
        char a1[] = "--color";
        char *argv[] = { a0, a1, NULL };

        optind = 0;
        optarg = (char *)"stale";
        if (getopt_long(2, argv, "abc:", options, &index) != 'c' ||
            index != 3 || optarg != NULL)
            return 2;
    }
    {
        char a0[] = "tool";
        char a1[] = "--flag";
        char *argv[] = { a0, a1, NULL };

        flag = 0;
        optind = 0;
        if (getopt_long(2, argv, "abc:", options, &index) != 0 ||
            index != 4 || flag != 42)
            return 3;
    }
    {
        char a0[] = "tool";
        char a1[] = "tail";
        char a2[] = "--alpha";
        char *argv[] = { a0, a1, a2, NULL };

        optind = 0;
        if (getopt_long(3, argv, "ab:", options, &index) != 'a' ||
            index != 0 || optind != 2 || argv[1] != a2 || argv[2] != a1)
            return 4;
    }
    {
        char a0[] = "tool";
        char a1[] = "--al";
        char *argv[] = { a0, a1, NULL };

        optind = 0;
        index = -1;
        if (getopt_long(2, argv, "ab:", options, &index) != '?' ||
            optopt != 0 || index != -1 || optind != 2)
            return 5;
    }
    {
        char a0[] = "tool";
        char a1[] = "-verbose";
        char *argv[] = { a0, a1, NULL };

        optind = 0;
        if (getopt_long_only(2, argv, "v", options, &index) != 'V' ||
            index != 5 || optind != 2)
            return 6;
    }
    {
        char a0[] = "tool";
        char a1[] = "-v";
        char *argv[] = { a0, a1, NULL };

        optind = 0;
        index = -1;
        if (getopt_long_only(2, argv, "v", options, &index) != 'v' ||
            index != -1 || optind != 2)
            return 7;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int result = check_program_names(argc, argv);

    if (result != 0) return 10 + result;
    result = check_short_options();
    if (result != 0) return 30 + result;
    result = check_short_errors();
    if (result != 0) return 50 + result;
    result = check_long_options();
    if (result != 0) return 70 + result;
    return 0;
}
