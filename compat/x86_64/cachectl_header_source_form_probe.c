/* Direct Linux/x86-64 sys/cachectl.h source-form probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sys/cachectl.h>

typedef int (*crabc_cachectl_signature)(void *, int, int);

_Static_assert(ICACHE == 1 && DCACHE == 2 && BCACHE == 3,
    "x86 cache selector values");
_Static_assert(CACHEABLE == 0 && UNCACHEABLE == 1,
    "x86 cacheability values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cachectl),
    crabc_cachectl_signature), "cachectl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cacheflush),
    crabc_cachectl_signature), "cacheflush declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&_flush_cache),
    crabc_cachectl_signature), "_flush_cache declaration");

int crabc_x86_cachectl_header_source_form_probe(void)
{
    return BCACHE;
}
