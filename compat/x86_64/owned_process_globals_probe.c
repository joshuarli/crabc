/* Installed-product differential for the frozen `process.globals` roster.
 *
 * One object is compiled per code model by the installed dynamic driver and
 * linked unchanged through pinned musl 1.2.6 and each owned x86 product mode.
 * The non-PIE object reads and writes every process global directly, so its
 * dynamic executable owns R_X86_64_COPY storage; libc must then publish and
 * consume the executable copy rather than a private shared-library copy.
 * Output is a deterministic transcript: the runner compares it, stderr, and
 * the exit status byte for byte with musl for the same object and link class.
 *
 * The 31 frozen names are the 24 data spellings below plus getenv, putenv,
 * getopt, __posix_getopt, getopt_long, getopt_long_only and
 * __h_errno_location. `__optpos` is ABI-only: musl binds its own accesses
 * locally in libc.so, so an executable COPY is observed but never updated.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <time.h>
#include <unistd.h>

/* netdb.h spells h_errno as the thread-local accessor; name the object too. */
#undef h_errno
extern int h_errno;

/* ABI-only spellings: no installed header declares these names. */
extern char **__environ, **_environ, **___environ;
extern int __optpos, __optreset;
extern char *__progname, *__progname_full;
extern int __signgam;
extern long __timezone;
extern int __daylight;
extern char *__tzname[2];
extern int __posix_getopt(int, char *const[], const char *);

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(char *) == 8,
    "x86 LP64 process-global widths");
_Static_assert(sizeof(__tzname) == 16 && sizeof(tzname) == 16,
    "tzname is two name pointers");

static const char *text(const char *value)
{
    return value == NULL ? "(null)" : value;
}

static void line(const char *key, const char *value)
{
    printf("%s=%s\n", key, text(value));
}

static void number(const char *key, long value)
{
    printf("%s=%ld\n", key, value);
}

static const char *base_name(const char *full)
{
    const char *base = full;

    for (; *full != '\0'; ++full)
        if (*full == '/') base = full + 1;
    return base;
}

static int environment_contains(char **vector, const char *entry)
{
    for (; vector != NULL && *vector != NULL; ++vector)
        if (*vector == entry) return 1;
    return 0;
}

/* Every same-storage spelling must name one object in the final process. */
static void aliases(void)
{
    number("alias.environ", &environ == &__environ && &_environ == &__environ &&
        &___environ == &__environ);
    number("alias.optreset", &optreset == &__optreset);
    number("alias.program_invocation_name", &program_invocation_name == &__progname_full);
    number("alias.program_invocation_short_name",
        &program_invocation_short_name == &__progname);
    number("alias.signgam", &signgam == &__signgam);
    number("alias.timezone", &timezone == &__timezone);
    number("alias.daylight", &daylight == &__daylight);
    number("alias.tzname", tzname == __tzname);
    /* Canonical non-PIE PLT addresses make distinct function spellings
     * unequal in both runtimes; the transcript records either result. */
    number("alias.posix_getopt", __posix_getopt == getopt);
}

static void startup(int argc, char **argv, char **envp)
{
    number("startup.environ_is_envp", environ == envp);
    line("startup.getenv", getenv("PG_PROBE"));
    number("startup.progname_full_is_argv0", argc > 0 && __progname_full == argv[0]);
    number("startup.program_invocation_name_is_argv0",
        argc > 0 && program_invocation_name == argv[0]);
    number("startup.progname_is_basename",
        argc > 0 && __progname == base_name(argv[0]));
    line("startup.progname", __progname);
    number("initial.optind", optind);
    number("initial.opterr", opterr);
    number("initial.optopt", optopt);
    number("initial.optarg_null", optarg == NULL);
    number("initial.optreset", optreset);
    number("initial.optpos", __optpos);
    number("initial.signgam", signgam);
    number("initial.h_errno", h_errno);
    number("initial.timezone", timezone);
    number("initial.daylight", daylight);
    number("initial.tzname_null", tzname[0] == NULL && tzname[1] == NULL);
}

static void environment(void)
{
    static char added[] = "PG_ADDED=beta";
    static char custom_entry[] = "PG_CUSTOM=gamma";
    static char *custom[] = { custom_entry, NULL };
    char **saved = environ;

    number("env.putenv", putenv(added));
    line("env.putenv_getenv", getenv("PG_ADDED"));
    number("env.putenv_in_environ", environment_contains(environ, added));
    number("env.putenv_in___environ", environment_contains(__environ, added));

    environ = custom;
    line("env.direct_getenv", getenv("PG_CUSTOM"));
    line("env.direct_hides_old", getenv("PG_PROBE"));
    __environ = saved;
    number("env.restored_through_alias", environ == saved);
    line("env.restored_getenv", getenv("PG_ADDED"));
}

static void short_options(void)
{
    char a0[] = "tool";
    char a1[] = "-ab";
    char a2[] = "value";
    char a3[] = "rest";
    char *argv[] = { a0, a1, a2, a3, NULL };
    int result;

    optind = 0;
    opterr = 0;
    result = getopt(4, argv, "ab:");
    number("short.first", result);
    number("short.first_optind", optind);
    number("short.first_optpos", __optpos);
    result = getopt(4, argv, "ab:");
    number("short.second", result);
    line("short.second_optarg", optarg);
    number("short.second_optind", optind);
    number("short.end", getopt(4, argv, "ab:"));
    number("short.end_optind", optind);

    optreset = 1;
    number("reset.alias_result", getopt(4, argv, "ab:"));
    number("reset.alias_optind", optind);
    number("reset.alias_cleared", __optreset);
    __optreset = 1;
    number("reset.canonical_result", __posix_getopt(4, argv, "ab:"));
    number("reset.canonical_cleared", optreset);
}

static void option_errors(void)
{
    char a0[] = "tool";
    char unknown[] = "-z";
    char missing[] = "-b";
    char *unknown_argv[] = { a0, unknown, NULL };
    char *missing_argv[] = { a0, missing, NULL };

    optind = 0;
    opterr = 0;
    number("quiet.unknown", getopt(2, unknown_argv, "ab:"));
    number("quiet.unknown_optopt", optopt);

    /* opterr is read from the executable's storage; the diagnostic text
     * goes to stderr and is compared with musl byte for byte. */
    fflush(stdout);
    optind = 0;
    opterr = 1;
    number("loud.unknown", getopt(2, unknown_argv, "ab:"));
    fflush(stdout);
    optind = 0;
    number("loud.missing", getopt(2, missing_argv, "ab:"));
    number("loud.missing_optopt", optopt);
    optind = 0;
    number("loud.colon_missing", getopt(2, missing_argv, ":ab:"));
    fflush(stdout);
}

static void long_options(void)
{
    int index = -1;
    int flag = 0;
    struct option options[] = {
        { "alpha", no_argument, NULL, 'a' },
        { "beta", required_argument, NULL, 'b' },
        { "gamma", no_argument, &flag, 7 },
        { NULL, 0, NULL, 0 },
    };
    char a0[] = "tool";
    char beta[] = "--beta=path";
    char gamma[] = "--gamma";
    char alpha[] = "-alpha";
    char unknown[] = "--unknown";
    char *long_argv[] = { a0, beta, gamma, NULL };
    char *only_argv[] = { a0, alpha, NULL };
    char *unknown_argv[] = { a0, unknown, NULL };

    optind = 0;
    opterr = 0;
    number("long.beta", getopt_long(3, long_argv, "ab:", options, &index));
    number("long.beta_index", index);
    line("long.beta_optarg", optarg);
    number("long.gamma", getopt_long(3, long_argv, "ab:", options, &index));
    number("long.gamma_flag", flag);
    number("long.end", getopt_long(3, long_argv, "ab:", options, &index));
    number("long.end_optind", optind);

    optind = 0;
    index = -1;
    number("long_only.alpha", getopt_long_only(2, only_argv, "b:", options, &index));
    number("long_only.alpha_index", index);

    fflush(stdout);
    optind = 0;
    opterr = 1;
    number("long.loud_unknown", getopt_long(2, unknown_argv, "ab:", options, &index));
    fflush(stdout);
}

static void *h_errno_worker(void *main_location)
{
    int *location = __h_errno_location();

    *location = TRY_AGAIN;
    return (void *)(long)(location != (int *)main_location &&
        location == __h_errno_location());
}

static void network_status(void)
{
    int *main_location = __h_errno_location();
    pthread_t worker;
    void *worker_result = NULL;

    number("h_errno.main_is_object", main_location == &h_errno);
    *main_location = HOST_NOT_FOUND;
    number("h_errno.object_after_accessor", h_errno);
    h_errno = NO_DATA;
    number("h_errno.accessor_after_object", *__h_errno_location());
    if (pthread_create(&worker, NULL, h_errno_worker, main_location) != 0 ||
        pthread_join(worker, &worker_result) != 0) {
        line("h_errno.worker", "failed");
        return;
    }
    number("h_errno.worker_distinct", (long)worker_result);
    number("h_errno.main_after_worker", h_errno);
}

static void gamma_sign(void)
{
    int explicit_sign = 0;

    signgam = 99;
    number("signgam.negative_finite", isfinite(lgamma(-0.5)));
    number("signgam.negative", signgam);
    number("signgam.negative_canonical", __signgam);
    number("signgam.positive_finite", isfinite(lgamma(0.5)));
    number("signgam.positive", signgam);
    __signgam = 42;
    number("signgam.reentrant_finite", isfinite(lgamma_r(-0.5, &explicit_sign)));
    number("signgam.reentrant_sign", explicit_sign);
    number("signgam.reentrant_unchanged", signgam);
}

static void timezone_state(void)
{
    number("tz.set_eastern", setenv("TZ", "EST5EDT,M3.2.0,M11.1.0", 1));
    tzset();
    number("tz.eastern_timezone", timezone);
    number("tz.eastern_canonical_timezone", __timezone);
    number("tz.eastern_daylight", daylight);
    line("tz.eastern_standard", tzname[0]);
    line("tz.eastern_daylight_name", __tzname[1]);

    number("tz.set_utc", setenv("TZ", "UTC0", 1));
    tzset();
    number("tz.utc_timezone", timezone);
    number("tz.utc_daylight", __daylight);
    line("tz.utc_standard", tzname[0]);
    line("tz.utc_daylight_name", tzname[1]);
}

/* Entered through a launcher that execs with an empty argv and envp. Linux
 * 5.18 and newer substitute one empty argv[0], so main() instead publishes
 * the empty program name; older supported kernels reach this AT_EXECFN path. */
static int empty_argv(void)
{
    const char *execfn = (const char *)getauxval(AT_EXECFN);

    number("empty.progname_full_is_execfn", __progname_full == execfn);
    number("empty.program_invocation_name_is_execfn", program_invocation_name == execfn);
    line("empty.progname_full", __progname_full);
    line("empty.progname", __progname);
    number("empty.environ_empty", environ != NULL && environ[0] == NULL);
    return fflush(stdout) == 0 ? 0 : 1;
}

int main(int argc, char **argv, char **envp)
{
    if (argc == 0) return empty_argv();
    if (argc != 1) return 2;
    aliases();
    startup(argc, argv, envp);
    environment();
    short_options();
    option_errors();
    long_options();
    network_status();
    gamma_sign();
    timezone_state();
    return fflush(stdout) == 0 ? 0 : 1;
}
