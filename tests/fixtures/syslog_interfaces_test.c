#define _GNU_SOURCE 1

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

static void call_vsyslog(int priority, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsyslog(priority, format, ap);
    va_end(ap);
}

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    int old;

    old = setlogmask(LOG_MASK(LOG_ERR));
    CHECK(old == LOG_UPTO(LOG_DEBUG), "initial log mask");
    CHECK(setlogmask(0) == LOG_MASK(LOG_ERR), "zero mask query");
    CHECK(setlogmask(LOG_UPTO(LOG_INFO)) == LOG_MASK(LOG_ERR),
          "mask replacement");
    CHECK(setlogmask(0) == LOG_UPTO(LOG_INFO), "replacement query");

    /* LOG_PERROR makes the payload deterministic while LOG_NDELAY exercises
     * the real AF_UNIX /dev/log connection attempt without a host daemon. */
    openlog("cabi_sys", LOG_PERROR | LOG_NDELAY, LOG_LOCAL2);
    syslog(LOG_INFO, "hello %s %d", "world", 7);
    call_vsyslog(LOG_NOTICE, "notice %s", "ok");
    syslog(LOG_DEBUG, "suppressed");
    closelog();

    puts("c-abi syslog ok");
    return 0;
}
