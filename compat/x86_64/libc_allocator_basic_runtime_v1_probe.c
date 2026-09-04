/*
 * Private Linux/x86-64 allocator-basic real-runtime capability probe.
 *
 * The same project-header C program first executes through pinned musl 1.2.6
 * and then through the real crabc crt1/crti/crtn, static startup, Initial TLS
 * v1, pthread, fork/atfork, and ordinary-exit composition.  It selects only
 * the nine `memory.allocator-basic` entries.  malloc_usable_size is used only
 * to observe live objects crossing that boundary; its strong public owner
 * remains the independently selected allocator-observability slice.
 *
 * Allocation-address reuse after free is deliberately not asserted: it is a
 * backend-private topology rather than a musl C ABI guarantee.
 */

#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "allocator-basic-runtime-v1 requires native Linux/x86-64 little-endian LP64"
#endif

#ifdef CRABC_ALLOCATOR_BASIC_RUNTIME_V1_CANDIDATE
extern size_t __crabc_x86_allocator_observability_v1(void);
#endif

/* musl 1.2.6 mallocng uses UNIT == 16 on the selected LP64 targets. */
static const size_t musl_mallocng_max_alignment = ((size_t)1 << 31) * 16;

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static int observe_live(void *pointer, size_t request, int expected_errno)
{
    errno = expected_errno;
    if (malloc_usable_size(pointer) < request || errno != expected_errno)
        return 0;
    return 1;
}

static int basic_success_probe(void)
{
    unsigned char *block;
    unsigned char *resized;
    void *aligned;

    block = malloc(31);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 31, EDOM))
        return 1;
    block[0] = 0x31;
    block[30] = 0x13;
    free(block);

    block = calloc(31, 7);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 31 * 7, ECHILD))
        return 2;
    for (size_t index = 0; index < 31 * 7; ++index) {
        if (block[index] != 0)
            return 3;
    }
    free(block);

    block = malloc(4);
    if (block == NULL)
        return 4;
    block[0] = 1;
    block[1] = 2;
    block[2] = 3;
    block[3] = 4;
    resized = realloc(block, 8192);
    if (resized == NULL || (uintptr_t)resized % 16 != 0 ||
        !bytes_equal(resized, (const unsigned char[]){ 1, 2, 3, 4 }, 4) ||
        !observe_live(resized, 8192, EAGAIN))
        return 5;
    block = realloc(resized, 2);
    if (block == NULL || (uintptr_t)block % 16 != 0 || block[0] != 1 ||
        block[1] != 2 || !observe_live(block, 2, EAGAIN))
        return 6;
    free(block);

    block = reallocarray(NULL, 4, sizeof(*block));
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 4, ENOTTY))
        return 7;
    for (size_t index = 0; index < 4; ++index)
        block[index] = (unsigned char)(index + 31);
    resized = reallocarray(block, 2048, sizeof(*block));
    if (resized == NULL || (uintptr_t)resized % 16 != 0 || resized[0] != 31 ||
        resized[3] != 34 || !observe_live(resized, 2048, ENOTTY))
        return 8;
    free(resized);

    aligned = aligned_alloc(64, 65);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0 ||
        !observe_live(aligned, 65, EINTR))
        return 9;
    free(aligned);

    aligned = (void *)(uintptr_t)1;
    errno = EDOM;
    if (posix_memalign(&aligned, 64, 33) != 0 ||
        (uintptr_t)aligned % 64 != 0 || !observe_live(aligned, 33, EDOM))
        return 10;
    free(aligned);

    aligned = memalign(64, 19);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0 ||
        !observe_live(aligned, 19, ECHILD))
        return 11;
    free(aligned);

    aligned = valloc(7);
    if (aligned == NULL || (uintptr_t)aligned % 4096 != 0 ||
        !observe_live(aligned, 7, EBUSY))
        return 12;
    free(aligned);

    return 0;
}

static int basic_error_probe(void)
{
    unsigned char *block;
    unsigned char *resized;
    unsigned char *zero_a;
    unsigned char *zero_b;
    void *aligned;

    errno = EDOM;
    if (malloc_usable_size(NULL) != 0 || errno != EDOM)
        return 20;

    errno = E2BIG;
    zero_a = malloc(0);
    zero_b = malloc(0);
    if (zero_a == NULL || zero_b == NULL || zero_a == zero_b ||
        (uintptr_t)zero_a % 16 != 0 || (uintptr_t)zero_b % 16 != 0 ||
        errno != E2BIG || !observe_live(zero_a, 0, E2BIG) ||
        !observe_live(zero_b, 0, E2BIG))
        return 21;
    free(zero_a);
    free(zero_b);
    if (errno != E2BIG)
        return 22;
    free(NULL);
    if (errno != E2BIG)
        return 23;

    errno = E2BIG;
    block = calloc(0, 17);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 0, E2BIG))
        return 44;
    free(block);
    if (errno != E2BIG)
        return 45;

    /* The multiplication order is not part of calloc's zero-product
     * contract: both zero factors must reach the malloc(0) compatibility
     * path rather than exposing a backend-specific null result. */
    errno = E2BIG;
    block = calloc(17, 0);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 0, E2BIG))
        return 54;
    free(block);
    if (errno != E2BIG)
        return 55;

    errno = E2BIG;
    block = realloc(NULL, 0);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 0, E2BIG))
        return 46;
    free(block);
    if (errno != E2BIG)
        return 47;

    errno = E2BIG;
    block = reallocarray(NULL, 0, 17);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 0, E2BIG))
        return 48;
    free(block);
    if (errno != E2BIG)
        return 49;

    aligned = NULL;
    errno = E2BIG;
    if (posix_memalign(&aligned, 64, 0) != 0 ||
        (uintptr_t)aligned % 64 != 0 || !observe_live(aligned, 0, E2BIG))
        return 50;
    free(aligned);
    if (errno != E2BIG)
        return 51;

    errno = E2BIG;
    aligned = valloc(0);
    if (aligned == NULL || (uintptr_t)aligned % 4096 != 0 ||
        !observe_live(aligned, 0, E2BIG))
        return 52;
    free(aligned);
    if (errno != E2BIG)
        return 53;

    errno = 0;
    if (malloc((size_t)-1) != NULL || errno != ENOMEM)
        return 24;

    errno = 0;
    if (calloc((size_t)-1, 2) != NULL || errno != ENOMEM)
        return 25;

    block = malloc(4);
    if (block == NULL)
        return 26;
    block[0] = 0x41;
    block[1] = 0x42;
    block[2] = 0x43;
    block[3] = 0x44;
    errno = 0;
    if (realloc(block, (size_t)-1) != NULL || errno != ENOMEM ||
        !bytes_equal(block, (const unsigned char[]){ 0x41, 0x42, 0x43, 0x44 }, 4) ||
        !observe_live(block, 4, ENOMEM))
        return 27;
    free(block);

    block = realloc(NULL, 17);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 17, ERANGE))
        return 28;
    block[0] = 0x58;
    block[16] = 0xb7;
    free(block);

    block = malloc(4);
    if (block == NULL)
        return 29;
    block = realloc(block, 0);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 0, ENOTTY))
        return 30;
    free(block);

    block = reallocarray(NULL, 4, sizeof(*block));
    if (block == NULL)
        return 31;
    block[0] = 0x51;
    block[3] = 0x54;
    resized = block;
    errno = 0;
    if (reallocarray(resized, (size_t)-1, 2) != NULL || errno != ENOMEM ||
        resized[0] != 0x51 || resized[3] != 0x54 ||
        !observe_live(resized, 4, ENOMEM))
        return 32;
    free(resized);

    aligned = aligned_alloc(64, 128);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0)
        return 33;
    free(aligned);
    errno = 0;
    if (aligned_alloc(3, 64) != NULL || errno != EINVAL)
        return 34;
    errno = EINTR;
    aligned = aligned_alloc(0, 7);
    if (aligned == NULL || (uintptr_t)aligned % 16 != 0 || errno != EINTR)
        return 35;
    free(aligned);
    errno = 0;
    if (aligned_alloc(64, (size_t)-64) != NULL || errno != ENOMEM)
        return 36;
    errno = 0;
    if (aligned_alloc(musl_mallocng_max_alignment, 1) != NULL ||
        errno != ENOMEM)
        return 37;

    aligned = (void *)(uintptr_t)1;
    errno = EDOM;
    if (posix_memalign(&aligned, sizeof(void *) / 2, 64) != EINVAL ||
        aligned != (void *)(uintptr_t)1 || errno != EDOM)
        return 38;
    aligned = (void *)(uintptr_t)1;
    errno = EDOM;
    if (posix_memalign(&aligned, 24, 64) != EINVAL ||
        aligned != (void *)(uintptr_t)1 || errno != EINVAL)
        return 39;
    aligned = (void *)(uintptr_t)1;
    errno = 0;
    if (posix_memalign(&aligned, 64, (size_t)-1) != ENOMEM ||
        aligned != (void *)(uintptr_t)1 || errno != ENOMEM)
        return 40;
    aligned = (void *)(uintptr_t)1;
    errno = 0;
    if (posix_memalign(&aligned, musl_mallocng_max_alignment, 1) != ENOMEM ||
        aligned != (void *)(uintptr_t)1 || errno != ENOMEM)
        return 41;

    errno = 0;
    if (memalign(24, 19) != NULL || errno != EINVAL)
        return 42;
    errno = ENOTTY;
    aligned = memalign(0, 7);
    if (aligned == NULL || (uintptr_t)aligned % 16 != 0 || errno != ENOTTY)
        return 43;
    free(aligned);

    return 0;
}

struct worker_result {
    unsigned char *pointer;
    size_t request;
    size_t usable;
    int failure;
};

static void *worker_main(void *opaque)
{
    struct worker_result *result = opaque;
    unsigned char *pointer;

    if (errno != 0) {
        result->failure = 1;
        return NULL;
    }
    pointer = malloc(result->request);
    if (pointer == NULL) {
        result->failure = 2;
        return NULL;
    }
    pointer[0] = (unsigned char)result->request;
    pointer[result->request - 1] = (unsigned char)(result->request + 1);
    errno = EINTR;
    result->usable = malloc_usable_size(pointer);
    if (result->usable < result->request || errno != EINTR) {
        result->failure = 3;
        free(pointer);
        return NULL;
    }
    result->pointer = pointer;
    return pointer;
}

static char atfork_trace[8];
static size_t atfork_trace_length;

static void atfork_record(char marker)
{
    if (atfork_trace_length == sizeof(atfork_trace))
        _exit(220);
    atfork_trace[atfork_trace_length++] = marker;
}

static void atfork_prepare_first(void) { atfork_record('A'); }
static void atfork_parent_first(void) { atfork_record('P'); }
static void atfork_child_first(void) { atfork_record('C'); }
static void atfork_prepare_second(void) { atfork_record('B'); }
static void atfork_parent_second(void) { atfork_record('Q'); }
static void atfork_child_second(void) { atfork_record('D'); }

static int atfork_trace_is(const char *expected, size_t length)
{
    if (atfork_trace_length != length)
        return 0;
    for (size_t index = 0; index < length; ++index) {
        if (atfork_trace[index] != expected[index])
            return 0;
    }
    return 1;
}

static int child_basic_success_probe(void *inherited, size_t inherited_usable)
{
    unsigned char *block;
    void *aligned;

    errno = ERANGE;
    if (malloc_usable_size(inherited) != inherited_usable || errno != ERANGE)
        return 1;

    block = malloc(23);
    if (block == NULL || !observe_live(block, 23, ECHILD))
        return 2;
    block = realloc(block, 41);
    if (block == NULL || !observe_live(block, 41, ECHILD))
        return 3;
    block = reallocarray(block, 3, 31);
    if (block == NULL || !observe_live(block, 93, ECHILD))
        return 4;
    free(block);

    block = calloc(7, 19);
    if (block == NULL || !observe_live(block, 133, ECHILD))
        return 5;
    for (size_t index = 0; index < 133; ++index) {
        if (block[index] != 0)
            return 6;
    }
    free(block);

    aligned = aligned_alloc(128, 17);
    if (aligned == NULL || (uintptr_t)aligned % 128 != 0 ||
        !observe_live(aligned, 17, ECHILD))
        return 7;
    free(aligned);

    aligned = NULL;
    if (posix_memalign(&aligned, 32, 9) != 0 ||
        (uintptr_t)aligned % 32 != 0 || !observe_live(aligned, 9, ECHILD))
        return 8;
    free(aligned);

    aligned = memalign(64, 13);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0 ||
        !observe_live(aligned, 13, ECHILD))
        return 9;
    free(aligned);

    aligned = valloc(5);
    if (aligned == NULL || (uintptr_t)aligned % 4096 != 0 ||
        !observe_live(aligned, 5, ECHILD))
        return 10;
    free(aligned);
    return 0;
}

static int worker_and_joined_fork_probe(void)
{
    struct worker_result workers[2] = {
        { NULL, 73, 0, 0 },
        { NULL, 65537, 0, 0 },
    };
    pthread_t threads[2];
    unsigned char *inherited;
    pid_t child;
    int status;

    for (size_t index = 0; index < 2; ++index) {
        if (pthread_create(&threads[index], NULL, worker_main, &workers[index]) != 0)
            return 50;
    }
    for (size_t index = 0; index < 2; ++index) {
        void *joined = NULL;

        if (pthread_join(threads[index], &joined) != 0 ||
            joined != workers[index].pointer || workers[index].failure != 0)
            return 51;
        if (workers[index].pointer[0] != (unsigned char)workers[index].request ||
            workers[index].pointer[workers[index].request - 1] !=
                (unsigned char)(workers[index].request + 1))
            return 61;
        errno = ENOENT;
        if (!observe_live(workers[index].pointer, workers[index].request, ENOENT))
            return 52;
        free(workers[index].pointer);
        if (errno != ENOENT)
            return 53;
    }

    inherited = malloc(333);
    if (inherited == NULL)
        return 54;
    inherited[0] = 0x33;
    inherited[332] = 0x66;
    errno = EBUSY;
    size_t inherited_usable = malloc_usable_size(inherited);
    if (inherited_usable < 333 || errno != EBUSY)
        return 55;

    if (pthread_atfork(atfork_prepare_first, atfork_parent_first,
            atfork_child_first) != 0 ||
        pthread_atfork(atfork_prepare_second, atfork_parent_second,
            atfork_child_second) != 0)
        return 56;

    /* This is the selected joined-worker-only fork boundary: all workers
     * above have completed pthread_join before the public fork() call. */
    child = fork();
    if (child < 0)
        return 57;
    if (child == 0) {
        int result;

        if (!atfork_trace_is("BACD", 4))
            _exit(230);
        result = child_basic_success_probe(inherited, inherited_usable);
        _exit(result == 0 ? 0 : 230 + result);
    }
    if (!atfork_trace_is("BAPQ", 4))
        return 58;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 59;
    errno = ENOTTY;
    if (malloc_usable_size(inherited) != inherited_usable || errno != ENOTTY ||
        inherited[0] != 0x33 || inherited[332] != 0x66)
        return 60;
    free(inherited);
    return 0;
}

static int strings_equal(const char *left, const char *right)
{
    for (;;) {
        if (*left != *right)
            return 0;
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
}

static int append_text(char *output, size_t capacity, size_t *length,
    const char *suffix)
{
    while (*suffix != '\0') {
        if (*length + 1 >= capacity)
            return 0;
        output[(*length)++] = *suffix++;
    }
    output[*length] = '\0';
    return 1;
}

static int append_decimal(char *output, size_t capacity, size_t *length,
    unsigned long value)
{
    char reverse[3 * sizeof(value)];
    size_t count = 0;

    do {
        reverse[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (count != 0) {
        if (*length + 1 >= capacity)
            return 0;
        output[(*length)++] = reverse[--count];
    }
    output[*length] = '\0';
    return 1;
}

static int append_path(char *output, size_t capacity, const char *base,
    const char *suffix)
{
    size_t length = 0;

    output[0] = '\0';
    return append_text(output, capacity, &length, base) &&
        append_text(output, capacity, &length, suffix);
}

static void remove_realpath_fixture(const char *root, const char *target,
    const char *nested, const char *link, const char *absolute_link,
    const char *trailing_link, const char *loop)
{
    (void)syscall(SYS_unlink, link);
    (void)syscall(SYS_unlink, absolute_link);
    (void)syscall(SYS_unlink, trailing_link);
    (void)syscall(SYS_unlink, loop);
    (void)syscall(SYS_rmdir, nested);
    (void)syscall(SYS_rmdir, target);
    (void)syscall(SYS_rmdir, root);
}

/* This is deliberately run below a disposable child: it creates a tiny
 * symlink graph in the repository-local .work tree and exercises abort's
 * terminal signal paths.  No surviving process or filesystem state is part
 * of the allocator runtime fixture's contract. */
static int realpath_support_probe(void)
{
    char root[192];
    char target[224];
    char nested[256];
    char link[224];
    char absolute_link[224];
    char trailing_link[224];
    char loop[224];
    char traversal[288];
    char trailing_traversal[288];
    char missing[224];
    char caller_result[4096];
    char expected[4096];
    char expected_nested[4096];
    char cwd[4096];
    char long_name[4097];
    char *allocated = NULL;
    size_t root_length = 0;
    size_t expected_length = 0;
    size_t expected_nested_length = 0;
    size_t sentinel_length;
    int result = 0;

    root[0] = '\0';
    if (!append_text(root, sizeof(root), &root_length,
            ".work/x86_64/owned-static-runtime-") ||
        !append_decimal(root, sizeof(root), &root_length,
            (unsigned long)syscall(SYS_getpid)) ||
        !append_path(target, sizeof(target), root, "/target") ||
        !append_path(nested, sizeof(nested), target, "/nested") ||
        !append_path(link, sizeof(link), root, "/link") ||
        !append_path(absolute_link, sizeof(absolute_link), root, "/absolute") ||
        !append_path(trailing_link, sizeof(trailing_link), root, "/trailing") ||
        !append_path(loop, sizeof(loop), root, "/loop") ||
        !append_path(traversal, sizeof(traversal), root,
            "/link/../target/.") ||
        !append_path(trailing_traversal, sizeof(trailing_traversal),
            trailing_link, "/nested") ||
        !append_path(missing, sizeof(missing), root, "/missing"))
        return 1;

    if (syscall(SYS_mkdir, root, 0700L) != 0)
        return 2;
    if (syscall(SYS_mkdir, target, 0700L) != 0) {
        result = 3;
        goto cleanup;
    }
    if (syscall(SYS_mkdir, nested, 0700L) != 0) {
        result = 4;
        goto cleanup;
    }
    if (syscall(SYS_symlink, "target/nested/..", link) != 0) {
        result = 5;
        goto cleanup;
    }
    if (syscall(SYS_symlink, "loop", loop) != 0) {
        result = 6;
        goto cleanup;
    }

    expected[0] = '\0';
    if (syscall(SYS_getcwd, cwd, sizeof(cwd)) < 0 ||
        !append_text(expected, sizeof(expected), &expected_length, cwd) ||
        !append_text(expected, sizeof(expected), &expected_length, "/") ||
        !append_text(expected, sizeof(expected), &expected_length, root) ||
        !append_text(expected, sizeof(expected), &expected_length, "/target")) {
        result = 7;
        goto cleanup;
    }
    expected_nested[0] = '\0';
    if (!append_text(expected_nested, sizeof(expected_nested),
            &expected_nested_length, expected) ||
        !append_text(expected_nested, sizeof(expected_nested),
            &expected_nested_length, "/nested")) {
        result = 8;
        goto cleanup;
    }
    if (syscall(SYS_symlink, expected, absolute_link) != 0) {
        result = 9;
        goto cleanup;
    }
    if (syscall(SYS_symlink, "target/", trailing_link) != 0) {
        result = 10;
        goto cleanup;
    }

    errno = 0;
    if (realpath(traversal, caller_result) != caller_result ||
        !strings_equal(caller_result, expected)) {
        result = 11;
        goto cleanup;
    }
    errno = 0;
    allocated = realpath(traversal, NULL);
    if (allocated == NULL || !strings_equal(allocated, expected)) {
        result = 12;
        goto cleanup;
    }
    free(allocated);
    allocated = NULL;

    errno = 0;
    if (realpath(absolute_link, caller_result) != caller_result ||
        !strings_equal(caller_result, expected)) {
        result = 13;
        goto cleanup;
    }
    errno = 0;
    if (realpath(trailing_traversal, caller_result) != caller_result ||
        !strings_equal(caller_result, expected_nested)) {
        result = 14;
        goto cleanup;
    }

    caller_result[0] = '\0';
    sentinel_length = 0;
    if (!append_text(caller_result, sizeof(caller_result), &sentinel_length,
            "caller-buffer-unchanged")) {
        result = 15;
        goto cleanup;
    }
    errno = 0;
    if (realpath(missing, caller_result) != NULL || errno != ENOENT ||
        !strings_equal(caller_result, "caller-buffer-unchanged")) {
        result = 16;
        goto cleanup;
    }
    errno = 0;
    if (realpath(loop, NULL) != NULL || errno != ELOOP) {
        result = 17;
        goto cleanup;
    }
    errno = 0;
    if (realpath(missing, NULL) != NULL || errno != ENOENT) {
        result = 18;
        goto cleanup;
    }
    errno = 0;
    if (realpath("", caller_result) != NULL || errno != ENOENT ||
        !strings_equal(caller_result, "caller-buffer-unchanged")) {
        result = 19;
        goto cleanup;
    }
    errno = 0;
    if (realpath(NULL, caller_result) != NULL || errno != EINVAL ||
        !strings_equal(caller_result, "caller-buffer-unchanged")) {
        result = 20;
        goto cleanup;
    }
    for (size_t index = 0; index + 1 < sizeof(long_name); ++index)
        long_name[index] = 'x';
    long_name[sizeof(long_name) - 1] = '\0';
    errno = 0;
    if (realpath(long_name, caller_result) != NULL || errno != ENAMETOOLONG ||
        !strings_equal(caller_result, "caller-buffer-unchanged")) {
        result = 21;
        goto cleanup;
    }

cleanup:
    free(allocated);
    remove_realpath_fixture(root, target, nested, link, absolute_link,
        trailing_link, loop);
    return result;
}

static int syscall_support_probe(void)
{
    unsigned char *mapping;
    long result;

    result = syscall(SYS_getpid);
    if (result <= 0 || result != (long)getpid())
        return 1;
    errno = EDOM;
    if (syscall(-1L) != -1 || errno != ENOSYS)
        return 2;

    mapping = (unsigned char *)(uintptr_t)syscall(SYS_mmap, 0L, 4096L,
        (long)(PROT_READ | PROT_WRITE), (long)(MAP_PRIVATE | MAP_ANONYMOUS),
        -1L, 0L);
    if (mapping == (void *)(intptr_t)-1)
        return 3;
    mapping[0] = 0x51;
    mapping[4095] = 0x15;
    if (mapping[0] != 0x51 || mapping[4095] != 0x15 ||
        syscall(SYS_munmap, mapping, 4096L) != 0)
        return 4;
    return 0;
}

static int prctl_support_probe(void)
{
    char original[16];
    char observed[16] = { 0 };
    static const char selected_name[] = "crabc-owned";

    /* The name operations consume only their pointer argument.  Omit the
     * trailing words so the candidate exercises the SysV variadic register
     * shim without asking the kernel to validate irrelevant garbage. */
    if (prctl(PR_GET_NAME, original) != 0)
        return 1;
    if (prctl(PR_SET_NAME, selected_name) != 0)
        return 2;
    if (prctl(PR_GET_NAME, observed) != 0 ||
        !strings_equal(observed, selected_name))
        return 3;
    if (prctl(PR_SET_NAME, original) != 0)
        return 4;
    if (prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) < 0)
        return 5;
    errno = EDOM;
    if (prctl(-1) != -1 || errno != EINVAL)
        return 6;
    return 0;
}

static void abort_returning_handler(int signal_number)
{
    (void)signal_number;
}

static int abort_case(int mode)
{
    pid_t child;
    int status;

    child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        if (mode == 1) {
            sigset_t blocked;

            if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGABRT) != 0 ||
                sigprocmask(SIG_BLOCK, &blocked, NULL) != 0)
                _exit(201);
        } else if (mode == 2) {
            if (signal(SIGABRT, SIG_IGN) == SIG_ERR)
                _exit(202);
        } else if (mode == 3) {
            if (signal(SIGABRT, abort_returning_handler) == SIG_ERR)
                _exit(203);
        }
        abort();
    }
    if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) ||
        WTERMSIG(status) != SIGABRT)
        return 2;
    return 0;
}

static int abort_support_probe(void)
{
    for (int mode = 0; mode != 4; ++mode) {
        if (abort_case(mode) != 0)
            return mode + 1;
    }
    return 0;
}

static int owned_static_runtime_support_body(void)
{
    int result;

    result = syscall_support_probe();
    if (result != 0)
        return result;
    result = prctl_support_probe();
    if (result != 0)
        return 20 + result;
    result = realpath_support_probe();
    if (result != 0)
        return 40 + result;
    result = abort_support_probe();
    if (result != 0)
        return 60 + result;
    return 0;
}

static int owned_static_runtime_support_probe(void)
{
    pid_t child;
    int status;

    child = fork();
    if (child < 0)
        return 1;
    if (child == 0)
        _exit(owned_static_runtime_support_body());
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 2;
    return 0;
}

static long raw_stdout_write(const void *buffer, size_t length)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(1L), "D"(1L), "S"(buffer), "d"(length)
        : "rcx", "r11", "memory");
    return result;
}

static void allocator_exit_probe(void)
{
    static const char marker[] = "ALLOCATOR_BASIC_RUNTIME_V1_ATEXIT\n";
    unsigned char *block;

    errno = EDOM;
    block = malloc(71);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !observe_live(block, 71, EDOM))
        _exit(240);
    block[0] = 0x71;
    block[70] = 0x17;
    free(block);
    if (errno != EDOM ||
        raw_stdout_write(marker, sizeof(marker) - 1) != (long)(sizeof(marker) - 1))
        _exit(241);
}

int main(void)
{
    int result;

#ifdef CRABC_ALLOCATOR_BASIC_RUNTIME_V1_CANDIDATE
    if (__crabc_x86_allocator_observability_v1() != 1)
        return 100;
#endif

    if (atexit(allocator_exit_probe) != 0)
        return 101;
    result = basic_success_probe();
    if (result != 0)
        return result;
    result = basic_error_probe();
    if (result != 0)
        return result;
    result = owned_static_runtime_support_probe();
    if (result != 0)
        return 70 + result;
    return worker_and_joined_fork_probe();
}
