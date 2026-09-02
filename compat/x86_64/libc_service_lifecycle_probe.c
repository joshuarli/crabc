/* Native Linux/x86-64 static musl service-lifecycle evidence. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <netdb.h>
#ifndef CRABC_SERVICE_LIFECYCLE_FREESTANDING
#include <errno.h>
#endif

typedef struct servent *(*getservent_signature)(void);
typedef void (*setservent_signature)(int);

int crabc_x86_64_service_lifecycle_probe(void)
{
    const getservent_signature get = getservent;
    const setservent_signature set = setservent;

#ifndef CRABC_SERVICE_LIFECYCLE_FREESTANDING
    errno = EALREADY;
#endif
    setservent(0);
    if (getservent() != 0) return 1;
#ifndef CRABC_SERVICE_LIFECYCLE_FREESTANDING
    if (errno != EALREADY) return 4;
#endif
    set(-1);
    if (get() != 0) return 2;
#ifndef CRABC_SERVICE_LIFECYCLE_FREESTANDING
    if (errno != EALREADY) return 5;
#endif
    set(1);
    if (get() != 0) return 3;
#ifndef CRABC_SERVICE_LIFECYCLE_FREESTANDING
    if (errno != EALREADY) return 6;
#endif
    return 0;
}

#ifndef CRABC_SERVICE_LIFECYCLE_FREESTANDING
int main(void) { return crabc_x86_64_service_lifecycle_probe(); }
#endif
