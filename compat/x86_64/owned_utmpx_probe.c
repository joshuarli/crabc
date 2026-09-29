#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utmp.h>
#include <utmpx.h>
#include <unistd.h>

typedef void (*utmpx_void_signature)(void);
typedef struct utmpx *(*utmpx_cursor_signature)(void);
typedef struct utmpx *(*utmpx_query_signature)(const struct utmpx *);
typedef void (*utmpx_update_signature)(const char *, const struct utmpx *);
typedef int (*utmpx_name_signature)(const char *);

static utmpx_void_signature public_endutxent = endutxent;
static utmpx_void_signature public_setutxent = setutxent;
static utmpx_cursor_signature public_getutxent = getutxent;
static utmpx_query_signature public_getutxid = getutxid;
static utmpx_query_signature public_getutxline = getutxline;
static utmpx_query_signature public_pututxline = pututxline;
static utmpx_update_signature public_updwtmpx = updwtmpx;
static utmpx_void_signature public_endutent = endutent;
static utmpx_void_signature public_setutent = setutent;
static utmpx_cursor_signature public_getutent = getutent;
static utmpx_query_signature public_getutid = getutid;
static utmpx_query_signature public_getutline = getutline;
static utmpx_query_signature public_pututline = pututline;
static utmpx_update_signature public_updwtmp = updwtmp;
static utmpx_name_signature public_utmpname = utmpname;
static utmpx_name_signature public_utmpxname = utmpxname;

static void fail(void)
{
    _Exit(127);
}

#define CHECK(expression) do { if (!(expression)) fail(); } while (0)

static unsigned checksum(const unsigned char *input, size_t count)
{
    unsigned result = 0;
    for (size_t index = 0; index != count; ++index)
        result = result * 33u + input[index];
    return result;
}

static void record(const char *name, const struct utmpx *before,
    const struct utmpx *after, struct utmpx *result, int error)
{
    CHECK(memcmp(before, after, sizeof *before) == 0);
    printf("%s ptr=%d errno=%d input=%08x\n", name, result != NULL,
        error, checksum((const unsigned char *)after, sizeof *after));
}

static void call_void(const char *name, utmpx_void_signature function,
    const struct utmpx *input)
{
    errno = EDOM;
    function();
    CHECK(errno == EDOM);
    printf("%s ptr=0 errno=%d input=%08x\n", name, errno,
        checksum((const unsigned char *)input, sizeof *input));
}

static void call_cursor(const char *name, utmpx_cursor_signature function,
    const struct utmpx *input)
{
    errno = EDOM;
    struct utmpx *result = function();
    CHECK(result == NULL && errno == EDOM);
    printf("%s ptr=0 errno=%d input=%08x\n", name, errno,
        checksum((const unsigned char *)input, sizeof *input));
}

static void call_query(const char *name, utmpx_query_signature function,
    const struct utmpx *before, const struct utmpx *query)
{
    struct utmpx after = *query;
    errno = EDOM;
    struct utmpx *result = function(&after);
    int error = errno;
    CHECK(result == NULL && error == EDOM);
    record(name, before, &after, result, error);
}

static void call_query_null(const char *name, utmpx_query_signature function,
    const struct utmpx *input)
{
    errno = EINVAL;
    struct utmpx *result = function(NULL);
    CHECK(result == NULL && errno == EINVAL);
    printf("%s ptr=0 errno=%d input=%08x\n", name, errno,
        checksum((const unsigned char *)input, sizeof *input));
}

static void call_query_protected(const char *name, utmpx_query_signature function,
    const struct utmpx *input)
{
    errno = EILSEQ;
    struct utmpx *result = function((const struct utmpx *)(uintptr_t)1);
    CHECK(result == NULL && errno == EILSEQ);
    printf("%s ptr=0 errno=%d input=%08x\n", name, errno,
        checksum((const unsigned char *)input, sizeof *input));
}

static void call_update(const char *name, utmpx_update_signature function,
    const struct utmpx *input)
{
    errno = EDOM;
    function((const char *)(uintptr_t)1, (const struct utmpx *)(uintptr_t)1);
    CHECK(errno == EDOM);
    printf("%s ptr=0 errno=%d input=%08x\n", name, errno,
        checksum((const unsigned char *)input, sizeof *input));
}

static void call_update_null(const char *name, utmpx_update_signature function,
    const struct utmpx *input)
{
    errno = EINVAL;
    function(NULL, NULL);
    CHECK(errno == EINVAL);
    printf("%s ptr=0 errno=%d input=%08x\n", name, errno,
        checksum((const unsigned char *)input, sizeof *input));
}

static void call_name(const char *name, utmpx_name_signature function,
    const struct utmpx *input, const char *path)
{
    errno = EDOM;
    int result = function(path);
    CHECK(result == -1 && errno == ENOTSUP);
    printf("%s result=%d errno=%d input=%08x\n", name, result, errno,
        checksum((const unsigned char *)input, sizeof *input));
}

static const unsigned char old_record[] = "old-utmp-record";
static const unsigned char new_record[] = "new-utmp-record";
static pthread_barrier_t rotation_barrier;

static void wait_for_rotation(void)
{
    int result = pthread_barrier_wait(&rotation_barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void write_record(const char *path, const unsigned char *bytes, size_t count)
{
    int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(descriptor >= 0);
    CHECK(write(descriptor, bytes, count) == (ssize_t)count);
    CHECK(close(descriptor) == 0);
}

static void check_record(const char *path, const unsigned char *bytes, size_t count)
{
    unsigned char actual[sizeof old_record];
    int descriptor = open(path, O_RDONLY);
    CHECK(descriptor >= 0 && count <= sizeof actual);
    CHECK(read(descriptor, actual, sizeof actual) == (ssize_t)count);
    CHECK(memcmp(actual, bytes, count) == 0);
    CHECK(close(descriptor) == 0);
}

static unsigned open_descriptors(void)
{
    unsigned count = 0;
    for (int descriptor = 3; descriptor < 256; ++descriptor) {
        errno = 0;
        int result = fcntl(descriptor, F_GETFD);
        CHECK(result >= 0 || errno == EBADF);
        count += result >= 0;
    }
    return count;
}

static void exercise_inert_state(const struct utmpx *record)
{
    errno = EDOM;
    public_setutxent();
    public_updwtmpx("/state/append", record);
    CHECK(public_pututxline(record) == NULL);
    CHECK(public_getutxid(record) == NULL);
    CHECK(public_getutxline(record) == NULL);
    CHECK(public_getutxent() == NULL);
    public_endutxent();
    CHECK(errno == EDOM);
    CHECK(public_utmpxname("/state/utmp-live") == -1 && errno == ENOTSUP);
    CHECK(public_getutxent() == NULL && errno == ENOTSUP);
}

static void *concurrent_state(void *argument)
{
    const struct utmpx *record = argument;
    wait_for_rotation();
    for (unsigned phase = 0; phase < 2; ++phase) {
        for (unsigned iteration = 0; iteration < 128; ++iteration)
            exercise_inert_state(record);
        if (phase == 0)
            wait_for_rotation();
    }
    return NULL;
}

static void record_rotation_and_descriptor_lifecycle(const struct utmpx *record)
{
    pthread_t workers[4];
    write_record("/state/utmp-live", old_record, sizeof old_record);
    int sentinel = open("/state/sentinel", O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(sentinel >= 0 && write(sentinel, "guard", 5) == 5);
    CHECK(lseek(sentinel, 2, SEEK_SET) == 2);
    unsigned initial_descriptors = open_descriptors();
    exercise_inert_state(record);
    check_record("/state/utmp-live", old_record, sizeof old_record);
    CHECK(open_descriptors() == initial_descriptors);
    CHECK(pthread_barrier_init(&rotation_barrier, NULL, 5) == 0);
    for (unsigned index = 0; index < 4; ++index)
        CHECK(pthread_create(&workers[index], NULL, concurrent_state, (void *)record) == 0);
    wait_for_rotation();
    CHECK(rename("/state/utmp-live", "/state/utmp-rotated") == 0);
    write_record("/state/utmp-live", new_record, sizeof new_record);
    wait_for_rotation();
    for (unsigned index = 0; index < 4; ++index)
        CHECK(pthread_join(workers[index], NULL) == 0);
    CHECK(pthread_barrier_destroy(&rotation_barrier) == 0);
    check_record("/state/utmp-rotated", old_record, sizeof old_record);
    check_record("/state/utmp-live", new_record, sizeof new_record);
    CHECK(access("/state/append", F_OK) == -1 && errno == ENOENT);
    CHECK(open_descriptors() == initial_descriptors);
    CHECK(fcntl(sentinel, F_GETFD) >= 0 && lseek(sentinel, 0, SEEK_CUR) == 2);
    CHECK(close(sentinel) == 0);
    printf("lifecycle old=%08x new=%08x workers=4 descriptors=0\n",
        checksum(old_record, sizeof old_record), checksum(new_record, sizeof new_record));
}

int main(void)
{
    struct utmpx before;
    memset(&before, 0xa5, sizeof before);
    before.ut_type = USER_PROCESS;
    before.ut_pid = 314159;
    memcpy(before.ut_id, "utx6", 4);
    memcpy(before.ut_user, "caller-owned", sizeof "caller-owned" - 1);

    CHECK(public_endutxent == public_endutent);
    CHECK(public_setutxent == public_setutent);
    CHECK(public_getutxent == public_getutent);
    CHECK(public_getutxid == public_getutid);
    CHECK(public_getutxline == public_getutline);
    CHECK(public_pututxline == public_pututline);
    CHECK(public_updwtmpx == public_updwtmp);
    CHECK(public_utmpname == public_utmpxname);
    puts("aliases=1");

    call_void("endutxent", public_endutxent, &before);
    call_void("endutent", public_endutent, &before);
    call_void("setutxent", public_setutxent, &before);
    call_void("setutent", public_setutent, &before);
    call_cursor("getutxent", public_getutxent, &before);
    call_cursor("getutent", public_getutent, &before);

    call_query("getutxid", public_getutxid, &before, &before);
    call_query_null("getutxid-null", public_getutxid, &before);
    call_query_protected("getutxid-protected", public_getutxid, &before);
    call_query("getutid", public_getutid, &before, &before);
    call_query_null("getutid-null", public_getutid, &before);
    call_query_protected("getutid-protected", public_getutid, &before);

    call_query("getutxline", public_getutxline, &before, &before);
    call_query_null("getutxline-null", public_getutxline, &before);
    call_query_protected("getutxline-protected", public_getutxline, &before);
    call_query("getutline", public_getutline, &before, &before);
    call_query_null("getutline-null", public_getutline, &before);
    call_query_protected("getutline-protected", public_getutline, &before);

    call_query("pututxline", public_pututxline, &before, &before);
    call_query_null("pututxline-null", public_pututxline, &before);
    call_query_protected("pututxline-protected", public_pututxline, &before);
    call_query("pututline", public_pututline, &before, &before);
    call_query_null("pututline-null", public_pututline, &before);
    call_query_protected("pututline-protected", public_pututline, &before);

    call_update("updwtmpx", public_updwtmpx, &before);
    call_update_null("updwtmpx-null", public_updwtmpx, &before);
    call_update("updwtmp", public_updwtmp, &before);
    call_update_null("updwtmp-null", public_updwtmp, &before);

    call_name("utmpname-null", public_utmpname, &before, NULL);
    call_name("utmpname-protected", public_utmpname, &before,
        (const char *)(uintptr_t)1);
    call_name("utmpxname-null", public_utmpxname, &before, NULL);
    call_name("utmpxname-protected", public_utmpxname, &before,
        (const char *)(uintptr_t)1);

    /* The oracle's ordinary successful no-op call starts with errno zero. */
    errno = 0;
    public_pututxline(&before);
    CHECK(errno == 0);
    printf("pututxline-zero ptr=0 errno=%d input=%08x\n", errno,
        checksum((const unsigned char *)&before, sizeof before));

    record_rotation_and_descriptor_lifecycle(&before);

    puts("utmpx-ok");
    return 0;
}
