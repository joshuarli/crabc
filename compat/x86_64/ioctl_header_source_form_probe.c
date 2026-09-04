/* The source-form runner selects either direct ioctl header. */

#ifndef CRABC_IOCTL_SOURCE_FORM_HEADER
#error "source-form runner must select an ioctl header directly"
#endif
#include CRABC_IOCTL_SOURCE_FORM_HEADER

#if defined(__x86_64__)
#ifdef _BITS_IOCTL_H
#error "x86-64 bits/ioctl.h must remain deliberately unguarded"
#endif
#else
#ifndef _BITS_IOCTL_H
#error "frozen non-x86 bits/ioctl.h must retain its legacy guard"
#endif
#endif

_Static_assert(_IOC_NONE == 0U && _IOC_WRITE == 1U && _IOC_READ == 2U,
    "ioctl direction spelling");
_Static_assert(_IO('q', 0x12) == 0x00007112U,
    "ioctl composition spelling");

#ifdef CRABC_IOCTL_SOURCE_FORM_SYS
_Static_assert(SIOCSIFBRDADDR == 0x891a && SIOCGIFNETMASK == 0x891b &&
    SIOCSIFNETMASK == 0x891c && SIOCGIFMETRIC == 0x891d &&
    SIOCSIFMETRIC == 0x891e && SIOCGIFMEM == 0x891f,
    "interface ioctl literal values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ioctl),
    int (*)(int, int, ...)), "ioctl declaration");
#endif

int crabc_ioctl_header_source_form_c(void)
{
    return _IO('q', 0x12) == 0x00007112U ? 0 : 1;
}
