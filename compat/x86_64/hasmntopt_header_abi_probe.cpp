/* C++17 companion for selected Linux/x86-64 hasmntopt headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <mntent.h>
#include <stddef.h>

using hasmntopt_signature = char *(*)(const struct mntent *, const char *);

static_assert(sizeof(struct mntent) == 40 && alignof(struct mntent) == 8,
              "C++ x86 struct mntent ABI");
static_assert(offsetof(struct mntent, mnt_fsname) == 0, "mnt_fsname offset");
static_assert(offsetof(struct mntent, mnt_dir) == 8, "mnt_dir offset");
static_assert(offsetof(struct mntent, mnt_type) == 16, "mnt_type offset");
static_assert(offsetof(struct mntent, mnt_opts) == 24, "mnt_opts offset");
static_assert(offsetof(struct mntent, mnt_freq) == 32, "mnt_freq offset");
static_assert(offsetof(struct mntent, mnt_passno) == 36, "mnt_passno offset");
static_assert(__is_same(decltype(&hasmntopt), hasmntopt_signature),
              "C++ hasmntopt declaration");

__attribute__((used)) static hasmntopt_signature crabc_hasmntopt = hasmntopt;

int crabc_x86_64_hasmntopt_header_abi_probe_cpp()
{
    struct mntent entry = {};
    return hasmntopt(&entry, "rw") != nullptr;
}
