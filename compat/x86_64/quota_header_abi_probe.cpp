/* C++ companion for the native Linux/x86-64 <sys/quota.h> macro ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/quota.h>

#ifndef btodb
#error "musl quota disk-block conversion macro is missing"
#endif
#ifndef dbtob
#error "musl quota byte conversion macro is missing"
#endif
#ifndef fs_to_dq_blocks
#error "musl filesystem-to-quota conversion macro is missing"
#endif
#ifndef dqoff
#error "musl quota record-offset macro is missing"
#endif

static_assert(sizeof(unsigned int) == 4, "x86 unsigned int width");
static_assert(sizeof(struct dqblk) == 72, "musl x86 dqblk size");
static_assert(alignof(struct dqblk) == 8, "musl x86 dqblk alignment");
static_assert(__is_same(decltype(dbtob(1)), int),
    "dbtob signed C++ result type");
static_assert(__is_same(decltype(btodb(1)), int),
    "btodb signed C++ result type");
static_assert(__is_same(decltype(fs_to_dq_blocks(1, 1)), int),
    "fs_to_dq_blocks signed C++ result type");
static_assert(__is_same(decltype(dbtob(1U)), unsigned int),
    "dbtob C++ result type");
static_assert(__is_same(decltype(btodb(1U)), unsigned int),
    "btodb C++ result type");
static_assert(__is_same(decltype(fs_to_dq_blocks(1U, 512U)), unsigned int),
    "fs_to_dq_blocks C++ result type");
static_assert(__is_same(decltype(dqoff(1U)), unsigned long long),
    "dqoff LP64 C++ result type");
static_assert(dbtob(2U) == 2048U && btodb(2048U) == 2U,
    "musl quota binary-unit C++ conversions");
static_assert(fs_to_dq_blocks(3U, 512U) == 1U,
    "musl quota C++ product precedes division");
static_assert(dqoff(1U) == sizeof(struct dqblk),
    "musl quota C++ record offset");
static_assert(dqoff(-1) == ~0ULL - 71ULL,
    "musl quota C++ unsigned-modular LP64 arithmetic");
