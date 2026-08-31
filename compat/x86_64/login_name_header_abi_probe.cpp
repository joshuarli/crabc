/* C++ companion for the Linux/x86-64 login-name header ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <unistd.h>

using getlogin_signature = char *(*)(void);
using getlogin_r_signature = int (*)(char *, size_t);

static_assert(__is_same(decltype(&getlogin), getlogin_signature),
    "getlogin declaration");
static_assert(__is_same(decltype(&getlogin_r), getlogin_r_signature),
    "getlogin_r declaration");
static_assert(sizeof(size_t) == 8 && alignof(size_t) == 8,
    "x86 size_t ABI");

extern "C" void crabc_login_name_linkage_witness()
{
    static volatile getlogin_signature witness_getlogin = &getlogin;
    static volatile getlogin_r_signature witness_getlogin_r = &getlogin_r;
    (void)witness_getlogin;
    (void)witness_getlogin_r;
}
