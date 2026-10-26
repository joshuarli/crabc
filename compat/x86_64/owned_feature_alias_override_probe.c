#define _GNU_SOURCE 1
#include <errno.h>
#include <pwd.h>
#include <signal.h>

#if defined(CRABC_FEATURE_SIGNAL_OVERRIDE)
static void handler(int number)
{
    (void)number;
}

sighandler_t bsd_signal(int number, sighandler_t replacement)
{
    (void)number;
    (void)replacement;
    return handler;
}

sighandler_t __sysv_signal(int number, sighandler_t replacement)
{
    (void)number;
    (void)replacement;
    return handler;
}

int main(void)
{
    sighandler_t (*volatile first)(int, sighandler_t) = bsd_signal;
    sighandler_t (*volatile second)(int, sighandler_t) = __sysv_signal;
    if (first(0, SIG_DFL) != handler || second(0, SIG_DFL) != handler)
        return 1;
    errno = 0;
    return signal(0, SIG_DFL) == SIG_ERR && errno == EINVAL ? 0 : 2;
}
#elif defined(CRABC_FEATURE_PASSWD_OVERRIDE)
static int calls;

void endpwent(void)
{
    ++calls;
}

int main(void)
{
    void (*volatile end)(void) = endpwent;
    end();
    setpwent();
    return calls == 1 ? 0 : 1;
}
#else
#error "select a feature-alias override owner"
#endif
