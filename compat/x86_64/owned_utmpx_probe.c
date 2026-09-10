#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utmpx.h>

typedef void (*utmpx_void_signature)(void);
typedef struct utmpx *(*utmpx_query_signature)(const struct utmpx *);
typedef struct utmpx *(*utmpx_cursor_signature)(void);

static utmpx_void_signature public_endutxent = endutxent;
static utmpx_void_signature public_setutxent = setutxent;
static utmpx_cursor_signature public_getutxent = getutxent;
static utmpx_query_signature public_getutxid = getutxid;
static utmpx_query_signature public_getutxline = getutxline;
static utmpx_query_signature public_pututxline = pututxline;

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

int main(void)
{
    struct utmpx before;
    struct utmpx after;
    struct utmpx *result;
    int error;

    memset(&before, 0xa5, sizeof before);
    before.ut_type = USER_PROCESS;
    before.ut_pid = 314159;
    memcpy(before.ut_id, "utx6", 4);
    memcpy(before.ut_user, "caller-owned", sizeof "caller-owned" - 1);

    errno = EDOM;
    public_endutxent();
    error = errno;
    CHECK(error == EDOM);
    printf("endutxent ptr=0 errno=%d input=%08x\n", error,
        checksum((const unsigned char *)&before, sizeof before));

    errno = EDOM;
    public_setutxent();
    error = errno;
    CHECK(error == EDOM);
    printf("setutxent ptr=0 errno=%d input=%08x\n", error,
        checksum((const unsigned char *)&before, sizeof before));

    errno = EDOM;
    result = public_getutxent();
    error = errno;
    CHECK(result == NULL && error == EDOM);
    printf("getutxent ptr=0 errno=%d input=%08x\n", error,
        checksum((const unsigned char *)&before, sizeof before));

    after = before;
    errno = EDOM;
    result = public_getutxid(&after);
    error = errno;
    CHECK(result == NULL && error == EDOM);
    record("getutxid", &before, &after, result, error);

    after = before;
    errno = EDOM;
    result = public_getutxline(&after);
    error = errno;
    CHECK(result == NULL && error == EDOM);
    record("getutxline", &before, &after, result, error);

    after = before;
    errno = EDOM;
    result = public_pututxline(&after);
    error = errno;
    CHECK(result == NULL && error == EDOM);
    record("pututxline", &before, &after, result, error);

    after = before;
    errno = 0;
    result = public_pututxline(&after);
    error = errno;
    CHECK(result == NULL && error == 0);
    record("pututxline-zero", &before, &after, result, error);

    puts("utmpx-ok");
    return 0;
}
