/* Direct Linux/x86-64 C++17 sys/cachectl.h source-form probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sys/cachectl.h>

using cachectl_signature = int (*)(void *, int, int);

static_assert(ICACHE == 1 && DCACHE == 2 && BCACHE == 3,
    "C++ x86 cache selector values");
static_assert(CACHEABLE == 0 && UNCACHEABLE == 1,
    "C++ x86 cacheability values");
static_assert(__is_same(decltype(&cachectl), cachectl_signature),
    "C++ cachectl linkage");
static_assert(__is_same(decltype(&cacheflush), cachectl_signature),
    "C++ cacheflush linkage");
static_assert(__is_same(decltype(&_flush_cache), cachectl_signature),
    "C++ _flush_cache linkage");

__attribute__((used)) static cachectl_signature crabc_cachectl_reference = cachectl;
__attribute__((used)) static cachectl_signature crabc_cacheflush_reference = cacheflush;
__attribute__((used)) static cachectl_signature crabc_flush_cache_reference = _flush_cache;

extern "C" int crabc_x86_cachectl_header_source_form_probe_cpp()
{
    return BCACHE;
}
