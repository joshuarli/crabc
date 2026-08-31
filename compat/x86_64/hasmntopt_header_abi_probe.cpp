/* Pinned-musl/project Linux/x86-64 <mntent.h> hasmntopt C++ linkage gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <mntent.h>
#include <stddef.h>

static_assert(sizeof(struct mntent) == 40, "mntent x86 LP64 size");
static_assert(alignof(struct mntent) == 8, "mntent x86 LP64 alignment");
static_assert(offsetof(struct mntent, mnt_fsname) == 0, "mntent fsname offset");
static_assert(offsetof(struct mntent, mnt_dir) == 8, "mntent directory offset");
static_assert(offsetof(struct mntent, mnt_type) == 16, "mntent type offset");
static_assert(offsetof(struct mntent, mnt_opts) == 24, "mntent options offset");
static_assert(offsetof(struct mntent, mnt_freq) == 32, "mntent frequency offset");
static_assert(offsetof(struct mntent, mnt_passno) == 36, "mntent pass-number offset");

#if defined(CRABC_EXPECT_HASMNTOPT)
using hasmntopt_signature = char *(*)(const struct mntent *, const char *);

static_assert(__is_same(decltype(&hasmntopt), hasmntopt_signature),
    "C++ hasmntopt declaration");

static hasmntopt_signature hasmntopt_function __attribute__((used)) = hasmntopt;
#endif

int crabc_x86_64_hasmntopt_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_HASMNTOPT)
    return hasmntopt_function == nullptr;
#else
    return 0;
#endif
}
