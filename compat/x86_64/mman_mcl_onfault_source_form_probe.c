/* The source-form runner selects <sys/mman.h> directly. */

#ifndef CRABC_MMAN_HEADER
#error "source-form runner must select <sys/mman.h> directly"
#endif
#include CRABC_MMAN_HEADER

#if defined(__x86_64__)
#ifndef MCL_ONFAULT
#error "x86-64 <sys/mman.h> must expose MCL_ONFAULT"
#endif
_Static_assert(MCL_CURRENT == 1, "MCL_CURRENT spelling");
_Static_assert(MCL_FUTURE == 2, "MCL_FUTURE spelling");
_Static_assert(MCL_ONFAULT == 4, "MCL_ONFAULT spelling");
_Static_assert(MAP_32BIT == 0x40, "x86 mapping declaration boundary");
#else
#ifdef MCL_ONFAULT
#error "frozen non-x86 <sys/mman.h> must not expose MCL_ONFAULT"
#endif
#ifdef MAP_32BIT
#error "frozen non-x86 <sys/mman.h> must not expose x86 mapping declarations"
#endif
_Static_assert(MCL_CURRENT == 1, "frozen MCL_CURRENT spelling");
_Static_assert(MCL_FUTURE == 2, "frozen MCL_FUTURE spelling");
#endif

int crabc_mman_mcl_onfault_source_form_c(void)
{
    return MCL_CURRENT + MCL_FUTURE;
}
