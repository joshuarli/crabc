/* Linux/x86-64 getlogin/getlogin_r declaration and linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <unistd.h>

typedef char *(*getlogin_signature)(void);
typedef int (*getlogin_r_signature)(char *, size_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getlogin),
    getlogin_signature), "getlogin declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getlogin_r),
    getlogin_r_signature), "getlogin_r declaration");
_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8,
    "x86 size_t ABI");

static getlogin_signature getlogin_function = getlogin;
static getlogin_r_signature getlogin_r_function = getlogin_r;

int crabc_x86_64_login_name_header_abi_probe(void)
{
    char name[1];
    return getlogin_function() == 0 && getlogin_r_function(name, sizeof(name))
        != 0 ? 0 : 1;
}
