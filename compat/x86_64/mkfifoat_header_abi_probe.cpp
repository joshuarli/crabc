/* C++17 companion for selected Linux/x86-64 mkfifoat headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/stat.h>
#include <sys/types.h>

using mkfifoat_signature = int (*)(int, const char *, mode_t);

static_assert(sizeof(mode_t) == 4 && alignof(mode_t) == 4 &&
                  __is_same(mode_t, unsigned int),
              "C++ x86 mode_t ABI");
static_assert(S_IFMT == 0170000 && S_IFIFO == 0010000 && S_IRUSR == 0400 &&
                  S_IWUSR == 0200 && S_IRWXU == 0700,
              "C++ x86 FIFO mode constants");
static_assert(__is_same(decltype(&mkfifoat), mkfifoat_signature),
              "C++ mkfifoat declaration");

__attribute__((used)) static mkfifoat_signature crabc_mkfifoat = mkfifoat;

int crabc_x86_64_mkfifoat_header_abi_probe_cpp()
{
    return S_IFIFO;
}
