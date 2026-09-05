#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static_assert(sizeof(int) == 4, "native assertion line ABI");

static void require(int condition)
{
    if (!condition) _Exit(91);
}

static void forbidden_exit_hook(void)
{
    (void)write(STDERR_FILENO, "exit hook ran\n", 14);
}

static void *fail_assertion(void *unused)
{
    (void)unused;
#line 123 "owned-assert-fixture.c"
    assert(2 + 2 == 5);
    return NULL;
}

#define NDEBUG
#include <assert.h>
static void check_disabled_assertion(void)
{
    int calls = 0;
    assert(++calls);
    require(calls == 0);
}
#undef NDEBUG
#include <assert.h>

static void check_failure(int worker)
{
    int diagnostic[2];
    require(pipe(diagnostic) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(diagnostic[0]) == 0);
        require(dup2(diagnostic[1], STDERR_FILENO) == STDERR_FILENO);
        require(close(diagnostic[1]) == 0);
        require(atexit(forbidden_exit_hook) == 0);
        if (worker) {
            pthread_t thread;
            require(pthread_create(&thread, NULL, fail_assertion, NULL) == 0);
            require(pthread_join(thread, NULL) == 0);
        } else {
            fail_assertion(NULL);
        }
        _Exit(92);
    }
    require(close(diagnostic[1]) == 0);
    char text[256];
    size_t length = 0;
    for (;;) {
        ssize_t count = read(diagnostic[0], text + length, sizeof(text) - 1 - length);
        if (count < 0 && errno == EINTR) continue;
        require(count >= 0);
        if (!count) break;
        length += (size_t)count;
        require(length < sizeof(text) - 1);
    }
    text[length] = 0;
    require(close(diagnostic[0]) == 0);
    int status;
    require(waitpid(child, &status, 0) == child);
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    require(strcmp(text, "Assertion failed: 2 + 2 == 5 (owned-assert-fixture.c: fail_assertion: 123)\n") == 0);
}

int main(void)
{
    check_disabled_assertion();
    int calls = 0;
    assert(++calls == 1);
    require(calls == 1);
    check_failure(0);
    check_failure(1);
    puts("owned-assert-ok");
    return 0;
}
