/* C++17 companion for selected Linux/x86-64 mkdirat headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

using mkdirat_signature = int (*)(int, const char *, mode_t);

static_assert(sizeof(mode_t) == 4 && alignof(mode_t) == 4 &&
                  __is_same(mode_t, unsigned int),
              "C++ x86 mode_t ABI");
static_assert(S_IFMT == 0170000 && S_IFDIR == 0040000 && S_IRWXU == 0700 &&
                  S_IRWXG == 0070 && S_IRWXO == 0007,
              "C++ x86 directory mode constants");
static_assert(SYS_mkdirat == 258, "C++ Linux x86 mkdirat syscall number");
static_assert(__is_same(decltype(&mkdirat), mkdirat_signature),
              "C++ mkdirat declaration");

__attribute__((used)) static mkdirat_signature crabc_mkdirat = mkdirat;

int crabc_x86_64_mkdirat_header_abi_probe_cpp()
{
    return S_IFDIR;
}
