/* Static crabc-libc x86-64 UTS-namespace identity fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc `libc.a`. Each execution enters a fresh UTS namespace before it
 * changes the hostname or domain name, so the fixture proves a closed C
 * UTS-identity block without changing the container or host identity. It
 * selects only gethostname, sethostname, getdomainname, and setdomainname
 * atop the separately selected uname record seam. It is not namespace
 * management, gethostid, system-file parsing, sysconf, process identity,
 * CRT, pthread/TLS lifecycle, loader, sysroot, or public x86 support.
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
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

enum {
    UTS_FIELD_BYTES = 65,
    BUFFER_SENTINEL = 0xa5,
};

static const char EXPECTED_HOSTNAME[] = "crabc-uts-host";
static const char EXPECTED_DOMAINNAME[] = "crabc-uts-domain";

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct utsname) == 390 && _Alignof(struct utsname) == 1,
    "x86 utsname layout");
_Static_assert(offsetof(struct utsname, sysname) == 0 &&
    offsetof(struct utsname, nodename) == 65 &&
    offsetof(struct utsname, release) == 130 &&
    offsetof(struct utsname, version) == 195 &&
    offsetof(struct utsname, machine) == 260 &&
    offsetof(struct utsname, domainname) == 325,
    "x86 GNU utsname offsets");
_Static_assert(sizeof(((struct utsname *)0)->nodename) == UTS_FIELD_BYTES &&
    sizeof(((struct utsname *)0)->domainname) == UTS_FIELD_BYTES,
    "x86 UTS field widths");
_Static_assert(SYS_uname == 63 && SYS_sethostname == 170 &&
    SYS_setdomainname == 171,
    "x86 selected UTS-identity syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gethostname),
    int (*)(char *, size_t)), "gethostname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sethostname),
    int (*)(const char *, size_t)), "sethostname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getdomainname),
    int (*)(char *, size_t)), "getdomainname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setdomainname),
    int (*)(const char *, size_t)), "setdomainname declaration");

static size_t bytes_until_nul(const char *value)
{
    size_t length = 0;

    while (value[length] != '\0')
        length++;
    return length;
}

static void fill_bytes(void *value, size_t length, unsigned char byte)
{
    unsigned char *bytes = value;
    size_t index;

    for (index = 0; index < length; index++)
        bytes[index] = byte;
}

static int equal_bytes(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; index++)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static int has_string_and_sentinel_tail(const char *value, size_t length,
    const char *expected, size_t expected_length)
{
    size_t index;

    if (length < expected_length + 1 ||
        !equal_bytes(value, expected, expected_length) ||
        value[expected_length] != '\0')
        return 0;
    for (index = expected_length + 1; index < length; index++)
        if ((unsigned char)value[index] != BUFFER_SENTINEL)
            return 0;
    return 1;
}

static int has_sentinel_bytes(const char *value, size_t length)
{
    size_t index;

    for (index = 0; index < length; index++)
        if ((unsigned char)value[index] != BUFFER_SENTINEL)
            return 0;
    return 1;
}

static int check_selected_identity_setup(void)
{
    struct utsname observed;
    size_t hostname_length = sizeof(EXPECTED_HOSTNAME) - 1;
    size_t domainname_length = sizeof(EXPECTED_DOMAINNAME) - 1;

    errno = EINTR;
    if (sethostname(EXPECTED_HOSTNAME, hostname_length) != 0 || errno != EINTR)
        return 1;
    errno = EINTR;
    if (setdomainname(EXPECTED_DOMAINNAME, domainname_length) != 0 ||
        errno != EINTR)
        return 2;
    fill_bytes(&observed, sizeof(observed), BUFFER_SENTINEL);
    if (uname(&observed) != 0)
        return 3;
    if (!equal_bytes(observed.nodename, EXPECTED_HOSTNAME,
            hostname_length + 1))
        return 4;
    if (!equal_bytes(observed.domainname, EXPECTED_DOMAINNAME,
            domainname_length + 1))
        return 5;
    return 0;
}

static int check_hostname_copy_contract(void)
{
    char full[80];
    char truncated[8];
    size_t hostname_length = sizeof(EXPECTED_HOSTNAME) - 1;

    fill_bytes(full, sizeof(full), BUFFER_SENTINEL);
    errno = EINTR;
    if (gethostname(full, sizeof(full)) != 0 || errno != EINTR)
        return 1;
    if (!has_string_and_sentinel_tail(full, sizeof(full), EXPECTED_HOSTNAME,
            hostname_length))
        return 2;

    fill_bytes(truncated, sizeof(truncated), BUFFER_SENTINEL);
    errno = EINTR;
    if (gethostname(truncated, sizeof(truncated)) != 0 || errno != EINTR)
        return 3;
    if (!equal_bytes(truncated, EXPECTED_HOSTNAME, sizeof(truncated) - 1) ||
        truncated[sizeof(truncated) - 1] != '\0')
        return 4;

    errno = EINTR;
    if (gethostname(NULL, 0) != 0 || errno != EINTR)
        return 5;
    return 0;
}

static int check_domain_copy_contract(void)
{
    char full[80];
    char exact[32];
    size_t domainname_length = sizeof(EXPECTED_DOMAINNAME) - 1;

    fill_bytes(full, sizeof(full), BUFFER_SENTINEL);
    errno = EINTR;
    if (getdomainname(full, sizeof(full)) != 0 || errno != EINTR)
        return 1;
    if (!has_string_and_sentinel_tail(full, sizeof(full), EXPECTED_DOMAINNAME,
            domainname_length))
        return 2;

    fill_bytes(exact, sizeof(exact), BUFFER_SENTINEL);
    errno = 0;
    if (getdomainname(exact, domainname_length) != -1 || errno != EINVAL)
        return 3;
    if (!has_sentinel_bytes(exact, sizeof(exact)))
        return 4;

    errno = 0;
    if (getdomainname(NULL, 0) != -1 || errno != EINVAL)
        return 5;
    return 0;
}

static int check_setter_error_contract_and_stability(void)
{
    char overlong[UTS_FIELD_BYTES];
    char hostname[UTS_FIELD_BYTES];
    char domainname[UTS_FIELD_BYTES];
    size_t hostname_length = sizeof(EXPECTED_HOSTNAME) - 1;
    size_t domainname_length = sizeof(EXPECTED_DOMAINNAME) - 1;

    fill_bytes(overlong, sizeof(overlong), 'x');
    errno = 0;
    if (sethostname(NULL, 1) != -1 || errno != EFAULT)
        return 1;
    errno = 0;
    if (setdomainname(NULL, 1) != -1 || errno != EFAULT)
        return 2;
    errno = 0;
    if (sethostname(overlong, sizeof(overlong)) != -1 || errno != EINVAL)
        return 3;
    errno = 0;
    if (setdomainname(overlong, sizeof(overlong)) != -1 || errno != EINVAL)
        return 4;

    fill_bytes(hostname, sizeof(hostname), BUFFER_SENTINEL);
    if (gethostname(hostname, sizeof(hostname)) != 0 ||
        !has_string_and_sentinel_tail(hostname, sizeof(hostname),
            EXPECTED_HOSTNAME, hostname_length))
        return 5;
    fill_bytes(domainname, sizeof(domainname), BUFFER_SENTINEL);
    if (getdomainname(domainname, sizeof(domainname)) != 0 ||
        !has_string_and_sentinel_tail(domainname, sizeof(domainname),
            EXPECTED_DOMAINNAME, domainname_length))
        return 6;
    return 0;
}

int crabc_x86_64_uts_identity_probe(void)
{
    int status;

    status = check_selected_identity_setup();
    if (status != 0)
        return status;
    status = check_hostname_copy_contract();
    if (status != 0)
        return 10 + status;
    status = check_domain_copy_contract();
    if (status != 0)
        return 20 + status;
    status = check_setter_error_contract_and_stability();
    if (status != 0)
        return 30 + status;
    return 0;
}

#ifndef CRABC_UTS_IDENTITY_FREESTANDING
int main(void)
{
    return crabc_x86_64_uts_identity_probe();
}
#endif
