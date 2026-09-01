/* Static crabc-libc x86-64 bounded process-environment fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6 and
 * then through a true `-nostdlib -static` executable linked with the selected
 * crabc archive and its ratcheted pinned-musl backend-support tail.  It proves
 * the intentionally bounded C
 * getenv/setenv/putenv/unsetenv/clearenv and environ-alias boundary.  Its
 * fixed test vectors are fixture storage, not an allocator or a claim for a
 * general process-environment lifecycle, secure execution, exec/spawn, or
 * thread-safe environment mutation.  The ordinary `.init_array` constructor
 * observes initial publication before main and leaves one bounded mutation for
 * main to observe.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

extern char **__environ;
extern char **_environ;
extern char **___environ;

#define CRABC_TYPE_IS(expression, type) \
    __builtin_types_compatible_p(__typeof__(expression), type)

typedef char *(*getenv_signature)(const char *);
typedef int (*setenv_signature)(const char *, const char *, int);
typedef int (*putenv_signature)(char *);
typedef int (*unsetenv_signature)(const char *);
typedef int (*clearenv_signature)(void);

#ifdef CRABC_ENVIRONMENT_RUNTIME_CANDIDATE
extern size_t __crabc_x86_environment_runtime_v1(void);
#endif

_Static_assert(CRABC_TYPE_IS(&getenv, getenv_signature),
    "getenv declaration");
_Static_assert(CRABC_TYPE_IS(&setenv, setenv_signature),
    "setenv declaration");
_Static_assert(CRABC_TYPE_IS(&putenv, putenv_signature),
    "putenv declaration");
_Static_assert(CRABC_TYPE_IS(&unsetenv, unsetenv_signature),
    "unsetenv declaration");
_Static_assert(CRABC_TYPE_IS(&clearenv, clearenv_signature),
    "clearenv declaration");
_Static_assert(CRABC_TYPE_IS(environ, char **),
    "GNU environ declaration");
_Static_assert(sizeof(char *) == 8 && _Alignof(char *) == 8,
    "x86 LP64 environment pointer ABI");

/*
 * The native runner links both the pinned-musl reference and the candidate
 * with `--wrap=malloc` and `--wrap=realloc`.  This stays entirely inside the
 * fixture: normal calls still reach each executable's link-selected allocation entry
 * through the linker-provided `__real_*` spellings, while the three narrow
 * failure targets make one allocation fail only after main has established a
 * known environment state.  They cover allocation before any changed vector
 * can be published. The post-publication ownership-registry allocation failure is
 * deliberately outside this regression's claim.
 */
#ifdef CRABC_ENVIRONMENT_ALLOCATION_WRAP
enum environment_allocation_failure_target {
    CRABC_FAIL_NOTHING,
    CRABC_FAIL_REPLACEMENT_MALLOC,
    CRABC_FAIL_DIRECT_VECTOR_APPEND_MALLOC,
    CRABC_FAIL_OWNED_VECTOR_APPEND_REALLOC,
};

extern void *__real_malloc(size_t);
extern void *__real_realloc(void *, size_t);

static enum environment_allocation_failure_target allocation_failure_target;
static unsigned wrapped_malloc_calls;
static unsigned wrapped_realloc_calls;

static void begin_allocation_failure(
    enum environment_allocation_failure_target target)
{
    allocation_failure_target = target;
    wrapped_malloc_calls = 0;
    wrapped_realloc_calls = 0;
}

static void end_allocation_failure(void)
{
    allocation_failure_target = CRABC_FAIL_NOTHING;
}

void *__wrap_malloc(size_t size)
{
    ++wrapped_malloc_calls;
    if ((allocation_failure_target == CRABC_FAIL_REPLACEMENT_MALLOC &&
            wrapped_malloc_calls == 1) ||
        (allocation_failure_target == CRABC_FAIL_DIRECT_VECTOR_APPEND_MALLOC &&
            wrapped_malloc_calls == 2)) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_malloc(size);
}

void *__wrap_realloc(void *pointer, size_t size)
{
    ++wrapped_realloc_calls;
    if (allocation_failure_target ==
            CRABC_FAIL_OWNED_VECTOR_APPEND_REALLOC &&
        wrapped_realloc_calls == 1) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_realloc(pointer, size);
}
#endif

static int same_text(const char *left, const char *right)
{
    size_t index = 0;

    if (left == NULL || right == NULL)
        return left == right;
    for (;;) {
        if (left[index] != right[index])
            return 0;
        if (left[index] == '\0')
            return 1;
        ++index;
    }
}

static int aliases_match(char **expected)
{
    return &environ == &__environ && &environ == &_environ &&
        &environ == &___environ && environ == expected &&
        __environ == expected && _environ == expected &&
        ___environ == expected;
}

/* The ordinary pinned-musl startup and the candidate's real Rust CRT both
 * dispatch this `.init_array` entry.  Save the unmodified vector so main can
 * prove that the aliases were published from its actual envp before this
 * constructor appended the bounded test key. */
static unsigned constructor_runs;
static int constructor_status;
static char **constructor_initial_environment;

__attribute__((constructor))
void crabc_x86_64_environment_init(void)
{
    ++constructor_runs;
    if (environ == NULL || environ[0] == NULL || environ[1] != NULL) {
        constructor_status = 1;
        return;
    }
    if (!aliases_match(environ)) {
        constructor_status = 2;
        return;
    }
    if (!same_text(environ[0], "CRABC_X86_INITIAL=entry") ||
        !same_text(getenv("CRABC_X86_INITIAL"), "entry")) {
        constructor_status = 3;
        return;
    }

    constructor_initial_environment = environ;
    if (setenv("CRABC_X86_CONSTRUCTOR", "visible", 1) != 0) {
        constructor_status = 4;
        return;
    }
    if (!aliases_match(environ) ||
        !same_text(getenv("CRABC_X86_CONSTRUCTOR"), "visible"))
        constructor_status = 5;
}

static int check_constructor_environment(char **envp)
{
    if (constructor_runs != 1)
        return 9;
    if (constructor_status != 0)
        return constructor_status;
    if (constructor_initial_environment != envp)
        return 10;
    if (!aliases_match(environ))
        return 11;
    if (!same_text(getenv("CRABC_X86_CONSTRUCTOR"), "visible"))
        return 12;
    return 0;
}

static int check_startup_environment(int argc, char **argv, char **envp)
{
    if (argc != 1 || argv == NULL || argv[0] == NULL || argv[1] != NULL)
        return 1;
    if (envp == NULL || envp[0] == NULL || envp[1] != NULL)
        return 2;
    if (!same_text(envp[0], "CRABC_X86_INITIAL=entry") ||
        !same_text(getenv("CRABC_X86_INITIAL"), "entry"))
        return 3;
    return 0;
}

static int check_initial_and_mutation(void)
{
    static char base[] = "BASE=initial";
    static char duplicate_first[] = "DUP=first";
    static char duplicate_second[] = "DUP=second";
    static char beta[] = "BETA=initial";
    static char *initial[] = {
        base,
        duplicate_first,
        duplicate_second,
        beta,
        NULL,
    };
    char remove_duplicate[] = "DUP";
    char copied_value[] = "copied";
    char borrowed[] = "BORROW=borrowed";

    __environ = initial;
    if (!aliases_match(initial))
        return 1;
    if (!same_text(getenv("BASE"), "initial") ||
        !same_text(getenv("DUP"), "first"))
        return 2;

    /*
     * Musl replaces only the first duplicate in the caller-published vector.
     * The vector itself remains caller-owned: setenv must not silently swap
     * `environ` to private storage just because this replacement allocates.
     */
    if (setenv("DUP", "replacement", 1) != 0 || environ != initial ||
        !same_text(initial[1], "DUP=replacement") ||
        !same_text(initial[2], "DUP=second") ||
        !same_text(getenv("DUP"), "replacement"))
        return 3;

    if (putenv(remove_duplicate) != 0 || getenv("DUP") != NULL)
        return 4;
    if (!aliases_match(environ))
        return 5;

    errno = EINTR;
    if (setenv("BETA", "ignored", 0) != 0 ||
        !same_text(getenv("BETA"), "initial") || errno != EINTR)
        return 6;
    if (setenv("BETA", copied_value, 1) != 0)
        return 7;
    copied_value[0] = 'X';
    if (!same_text(getenv("BETA"), "copied"))
        return 8;

    if (putenv(borrowed) != 0 || !same_text(getenv("BORROW"), "borrowed"))
        return 9;
    if (getenv("BORROW") != borrowed + 7)
        return 10;
    borrowed[7] = 'B';
    if (!same_text(getenv("BORROW"), "Borrowed"))
        return 11;
    borrowed[6] = '_';
    if (getenv("BORROW") != NULL)
        return 12;
    borrowed[6] = '=';
    if (!same_text(getenv("BORROW"), "Borrowed"))
        return 13;

    errno = 0;
    if (setenv("", "value", 1) != -1 || errno != EINVAL)
        return 14;
    errno = 0;
    if (setenv("BAD=NAME", "value", 1) != -1 || errno != EINVAL)
        return 15;
    errno = 0;
    if (unsetenv("") != -1 || errno != EINVAL)
        return 16;
    errno = 0;
    if (unsetenv("BAD=NAME") != -1 || errno != EINVAL)
        return 17;
    errno = 0;
    if (putenv("=") != -1 || errno != EINVAL)
        return 18;
    return 0;
}

static int check_clear_and_direct_assignment(void)
{
    static char direct[] = "DIRECT=visible";
    static char *direct_environment[] = { direct, NULL };

    errno = EINTR;
    if (clearenv() != 0 || !aliases_match(NULL) || getenv("BETA") != NULL ||
        errno != EINTR)
        return 1;
    if (setenv("AFTER", "clear", 1) != 0 ||
        !same_text(getenv("AFTER"), "clear") || environ == NULL)
        return 2;

    environ = direct_environment;
    if (!aliases_match(direct_environment) ||
        !same_text(getenv("DIRECT"), "visible"))
        return 3;
    if (setenv("DIRECT", "copied", 1) != 0 ||
        environ != direct_environment ||
        !same_text(direct_environment[0], "DIRECT=copied") ||
        !same_text(getenv("DIRECT"), "copied") || !aliases_match(environ))
        return 4;
    return 0;
}

static int check_direct_reassignment_after_owned_vector(void)
{
    static char direct[] = "DIRECT=external";
    static char *direct_environment[] = { direct, NULL };
    char **owned_vector;

    if (clearenv() != 0 || setenv("OWNED", "prior", 1) != 0 ||
        environ == NULL)
        return 1;
    owned_vector = environ;

    /*
     * Musl retains its old append vector until a later append must replace a
     * directly assigned vector. A replacement itself stays in the caller's
     * direct vector; the subsequent append allocates/copies and retires the
     * old owned vector.
     */
    environ = direct_environment;
    if (setenv("DIRECT", "replacement", 1) != 0 ||
        environ != direct_environment ||
        !same_text(direct_environment[0], "DIRECT=replacement"))
        return 2;
    if (setenv("APPEND", "value", 1) != 0 || environ == direct_environment ||
        environ == owned_vector || !same_text(getenv("DIRECT"), "replacement") ||
        !same_text(getenv("APPEND"), "value"))
        return 3;
    if (clearenv() != 0 || environ != NULL)
        return 4;
    return 0;
}

static int check_direct_vector_unsetenv(void)
{
    static char first[] = "DUP=first";
    static char keep[] = "KEEP=visible";
    static char second[] = "DUP=second";
    static char *direct_environment[] = { first, keep, second, NULL };

    environ = direct_environment;
    errno = EINTR;
    if (unsetenv("DUP") != 0 || environ != direct_environment ||
        direct_environment[0] != keep || direct_environment[1] != NULL ||
        getenv("DUP") != NULL || !same_text(getenv("KEEP"), "visible") ||
        errno != EINTR)
        return 1;
    return 0;
}

static int check_allocation_failure_environment_unchanged(void)
{
#ifdef CRABC_ENVIRONMENT_ALLOCATION_WRAP
    static char replacement_entry[] = "REPLACE=old";
    static char *replacement_environment[] = { replacement_entry, NULL };
    static char direct_entry[] = "DIRECT=old";
    static char *direct_environment[] = { direct_entry, NULL };
    char **owned_environment;

    /* Fail the replacement copied-string malloc before the caller-owned
     * vector is changed. */
    environ = replacement_environment;
    errno = 0;
    begin_allocation_failure(CRABC_FAIL_REPLACEMENT_MALLOC);
    if (setenv("REPLACE", "new", 1) != -1 || errno != ENOMEM) {
        end_allocation_failure();
        return 1;
    }
    end_allocation_failure();
    if (!aliases_match(replacement_environment) ||
        replacement_environment[0] != replacement_entry ||
        replacement_environment[1] != NULL ||
        !same_text(replacement_entry, "REPLACE=old") ||
        !same_text(getenv("REPLACE"), "old"))
        return 2;

    /* The direct-vector append allocation first copies APPEND=value, then
     * needs a new vector. Fail that second malloc and retain the direct vector
     * exactly. */
    environ = direct_environment;
    errno = 0;
    begin_allocation_failure(CRABC_FAIL_DIRECT_VECTOR_APPEND_MALLOC);
    if (setenv("APPEND", "value", 1) != -1 || errno != ENOMEM) {
        end_allocation_failure();
        return 3;
    }
    end_allocation_failure();
    if (!aliases_match(direct_environment) || direct_environment[0] != direct_entry ||
        direct_environment[1] != NULL || !same_text(direct_entry, "DIRECT=old") ||
        !same_text(getenv("DIRECT"), "old") || getenv("APPEND") != NULL)
        return 4;

    /* Establish the append-owned vector without injection, then make its
     * owned-vector append realloc fail before the entry can become observable. */
    if (clearenv() != 0 || setenv("OWNED", "old", 1) != 0 || environ == NULL)
        return 5;
    owned_environment = environ;
    errno = 0;
    begin_allocation_failure(CRABC_FAIL_OWNED_VECTOR_APPEND_REALLOC);
    if (setenv("APPEND", "value", 1) != -1 || errno != ENOMEM) {
        end_allocation_failure();
        return 6;
    }
    end_allocation_failure();
    if (!aliases_match(owned_environment) || environ[0] == NULL ||
        environ[1] != NULL || !same_text(environ[0], "OWNED=old") ||
        !same_text(getenv("OWNED"), "old") || getenv("APPEND") != NULL)
        return 7;
    if (clearenv() != 0 || environ != NULL)
        return 8;
#endif
    return 0;
}

static int check_allocator_backed_growth_and_reclamation(void)
{
    enum { DIRECT_ENTRY_COUNT = 160, RECLAIM_ITERATIONS = 256 };
    static char entries[DIRECT_ENTRY_COUNT][16];
    static char *direct_environment[DIRECT_ENTRY_COUNT + 1];
    static char replacement_value[128];
    size_t index;
    size_t iteration;

    for (index = 0; index < DIRECT_ENTRY_COUNT; ++index) {
        char *entry = entries[index];

        entry[0] = 'E';
        entry[1] = (char)('0' + (index / 100));
        entry[2] = (char)('0' + ((index / 10) % 10));
        entry[3] = (char)('0' + (index % 10));
        entry[4] = '=';
        entry[5] = 'v';
        entry[6] = '\0';
        direct_environment[index] = entry;
    }
    direct_environment[DIRECT_ENTRY_COUNT] = NULL;
    environ = direct_environment;

    errno = EINTR;
    if (setenv("E159", "ignored", 0) != 0 ||
        environ != direct_environment || !same_text(getenv("E159"), "v") ||
        errno != EINTR)
        return 2;
    if (setenv("E158", "replacement", 1) != 0 ||
        environ != direct_environment ||
        !same_text(direct_environment[158], "E158=replacement"))
        return 3;
    if (unsetenv("E159") != 0 || environ != direct_environment ||
        direct_environment[159] != NULL || getenv("E159") != NULL)
        return 4;
    if (setenv("EXTRA", "value", 1) != 0 || environ == direct_environment ||
        !same_text(getenv("EXTRA"), "value"))
        return 5;
    if (clearenv() != 0 || environ != NULL)
        return 6;

    for (index = 0; index + 1 < sizeof(replacement_value); ++index)
        replacement_value[index] = 'x';
    replacement_value[sizeof(replacement_value) - 1] = '\0';
    for (iteration = 0; iteration < RECLAIM_ITERATIONS; ++iteration) {
        if (setenv("RECLAIM", replacement_value, 1) != 0 ||
            !same_text(getenv("RECLAIM"), replacement_value) ||
            unsetenv("RECLAIM") != 0 || getenv("RECLAIM") != NULL)
            return 7;
        if (setenv("CLEAR", replacement_value, 1) != 0 ||
            !same_text(getenv("CLEAR"), replacement_value) ||
            clearenv() != 0 || environ != NULL)
            return 8;
    }
    if (setenv("AFTER_RECLAIM", "live", 1) != 0 ||
        !same_text(getenv("AFTER_RECLAIM"), "live"))
        return 9;
    if (clearenv() != 0 || environ != NULL)
        return 10;
    return 0;
}

int crabc_x86_64_environment_probe(int argc, char **argv, char **envp)
{
    int status;

#ifdef CRABC_ENVIRONMENT_RUNTIME_CANDIDATE
    if (__crabc_x86_environment_runtime_v1() != 1)
        return 90;
#endif
    status = check_constructor_environment(envp);
    if (status != 0)
        return 1 + status;
    status = check_startup_environment(argc, argv, envp);
    if (status != 0)
        return 20 + status;
    status = check_initial_and_mutation();
    if (status != 0)
        return 10 + status;
    status = check_clear_and_direct_assignment();
    if (status != 0)
        return 30 + status;
    status = check_direct_reassignment_after_owned_vector();
    if (status != 0)
        return 40 + status;
    status = check_direct_vector_unsetenv();
    if (status != 0)
        return 50 + status;
    status = check_allocation_failure_environment_unchanged();
    if (status != 0)
        return 60 + status;
    status = check_allocator_backed_growth_and_reclamation();
    if (status != 0)
        return 70 + status;
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    return crabc_x86_64_environment_probe(argc, argv, envp);
}
