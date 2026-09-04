/* C++ companion for the native Linux/x86-64 param/resource source-form probe. */

#if defined(CRABC_PARAM_HEADER_SOURCE_FORM_DIRECT_RESOURCE)
#include <sys/resource.h>
#else
#include <sys/param.h>
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if defined(CRABC_PARAM_HEADER_SOURCE_FORM_DIRECT_RESOURCE)
#ifndef _SYS_RESOURCE_H
#error "direct sys/resource.h inclusion lost its public guard"
#endif

static_assert(RUSAGE_CHILDREN == -1,
    "direct sys/resource.h must retain the rusage child selector");

int crabc_x86_param_header_source_form_direct_resource_probe_cpp()
{
    return RUSAGE_CHILDREN;
}
#else
#ifndef _SYS_PARAM_H
#error "x86 sys/param.h must retain musl's public guard"
#endif
#ifdef _CRABC_SYS_PARAM_H
#error "x86 sys/param.h must not retain the legacy public guard"
#endif

static_assert(MAXSYMLINKS == 20 && MAXHOSTNAMELEN == 64 &&
    MAXNAMLEN == 255 && MAXPATHLEN == 4096 && NBBY == 8 && NGROUPS == 32 &&
    CANBSIZ == 255 && NOFILE == 256 && NCARGS == 131072 && DEV_BSIZE == 512 &&
    NOGROUP == -1, "C++ sys/param.h constants");
static_assert(MIN(3, 7) == 3 && MAX(3, 7) == 7,
    "C++ sys/param.h min/max macros");
static_assert(howmany(17, 8) == 3 && roundup(17, 8) == 24,
    "C++ sys/param.h rounding macros");
static_assert(powerof2(8) && !powerof2(6),
    "C++ sys/param.h power-of-two macro");
static_assert(RUSAGE_CHILDREN == -1,
    "sys/param.h must transitively retain the rusage child selector");

int crabc_x86_param_header_source_form_probe_cpp()
{
    unsigned char bits[2] = {};

    setbit(bits, 9);
    if (!isset(bits, 9))
        return 1;
    clrbit(bits, 9);
    if (!isclr(bits, 9))
        return 2;
    return MIN(5, 9) + MAX(5, 9) + howmany(9, 4) + roundup(9, 4) +
        powerof2(8);
}
#endif
