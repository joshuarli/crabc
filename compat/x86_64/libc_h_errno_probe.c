/* Linux/x86-64 selected h_errno static-TLS differential fixture.
 *
 * This fixture intentionally names only the public netdb status accessor and
 * one selected pthread worker. It neither configures a resolver nor opens a
 * hosts/services/resolv.conf file, sends a DNS packet, creates a socket, or
 * calls a network-database API. The same source runs through pinned musl and
 * through the opt-in crabc h_errno archive profile.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#error "this fixture requires the GNU h_errno visibility profile"
#endif

#include <netdb.h>
#include <pthread.h>
#include <stdint.h>

/* netdb.h deliberately hides the compatibility object behind the accessor
 * macro. This alternate spelling lets the fixture prove the legacy link
 * object is the bootstrapped main task's exact fallback storage. */
extern int crabc_link_visible_h_errno __asm__("h_errno");

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)
typedef int *(*h_errno_location_signature)(void);

_Static_assert(CRABC_TYPE_IS(__typeof__(&__h_errno_location),
    h_errno_location_signature), "h_errno accessor declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&h_errno), int *),
    "h_errno accessor macro expression");

struct h_errno_thread_context {
    int *main_location;
    int *worker_location;
    int worker_value;
};

static void *check_h_errno_worker(void *opaque)
{
    struct h_errno_thread_context *context = opaque;

    context->worker_location = __h_errno_location();
    if (!context->worker_location ||
        context->worker_location == context->main_location)
        return (void *)(uintptr_t)1;
    if (*context->worker_location != 0)
        return (void *)(uintptr_t)2;

    h_errno = TRY_AGAIN;
    context->worker_value = h_errno;
    if (*context->worker_location != TRY_AGAIN ||
        __h_errno_location() != context->worker_location)
        return (void *)(uintptr_t)3;
    return 0;
}

int crabc_x86_64_h_errno_probe(void)
{
    struct h_errno_thread_context context = { 0 };
    pthread_t thread;
    void *worker_result = 0;

    context.main_location = __h_errno_location();
    if (!context.main_location ||
        context.main_location != &crabc_link_visible_h_errno)
        return 1;
    h_errno = NO_RECOVERY;
    if (h_errno != NO_RECOVERY ||
        *context.main_location != NO_RECOVERY ||
        crabc_link_visible_h_errno != NO_RECOVERY ||
        __h_errno_location() != context.main_location)
        return 2;

    if (pthread_create(&thread, 0, check_h_errno_worker, &context) != 0)
        return 3;
    if (pthread_join(thread, &worker_result) != 0)
        return 4;
    if (worker_result || !context.worker_location ||
        context.worker_location == context.main_location ||
        context.worker_value != TRY_AGAIN || h_errno != NO_RECOVERY ||
        *context.main_location != NO_RECOVERY ||
        crabc_link_visible_h_errno != NO_RECOVERY)
        return 5;
    return 0;
}

#ifndef CRABC_H_ERRNO_FREESTANDING
int main(void)
{
    return crabc_x86_64_h_errno_probe();
}
#endif
