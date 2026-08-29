// Focused raw-GCC C++17 include-closure regression for headers whose C
// declarations need C++ spelling. This is compile-only: implementation and
// linkage ownership are established by their separate family artifacts.
#include <aio.h>
#include <err.h>
#include <iso646.h>
#include <regex.h>
#include <stdatomic.h>
#include <uchar.h>

static_assert(true and not false, "C++ alternative tokens remain language keywords");
static_assert(sizeof(char16_t) == 2, "char16_t must retain its C++ builtin width");
static_assert(sizeof(char32_t) == 4, "char32_t must retain its C++ builtin width");

int main()
{
    int (*listio)(int, struct aiocb *const __restrict *, int, struct sigevent *) = &lio_listio;
    int (*execute)(const regex_t *, const char *, size_t, regmatch_t *, int) = &regexec;
    size_t (*to16)(char *, char16_t, mbstate_t *) = &c16rtomb;
    size_t (*to32)(char *, char32_t, mbstate_t *) = &c32rtomb;

    return listio == 0 || execute == 0 || to16 == 0 || to32 == 0;
}
