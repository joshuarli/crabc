/* C++17 companion for selected Linux/x86-64 chown headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <unistd.h>

using chown_signature = int (*)(const char *, uid_t, gid_t);

static_assert(sizeof(uid_t) == 4 && alignof(uid_t) == 4 &&
                  __is_same(uid_t, unsigned int),
              "C++ x86 chown uid_t ABI");
static_assert(sizeof(gid_t) == 4 && alignof(gid_t) == 4 &&
                  __is_same(gid_t, unsigned int),
              "C++ x86 chown gid_t ABI");
static_assert(__is_same(decltype(&chown), chown_signature),
              "C++ chown declaration");

__attribute__((used)) static chown_signature crabc_chown = chown;

int crabc_x86_64_chown_header_abi_probe_cpp()
{
    return chown("chown-header", (uid_t)-1, (gid_t)-1);
}
