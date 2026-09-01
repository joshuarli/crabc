/* Native Linux/x86-64 <sys/quota.h> conversion-macro ABI probe. */

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

_Static_assert(sizeof(unsigned int) == 4, "x86 unsigned int width");
_Static_assert(sizeof(struct dqblk) == 72, "musl x86 dqblk size");
_Static_assert(_Alignof(struct dqblk) == 8, "musl x86 dqblk alignment");
_Static_assert(__builtin_types_compatible_p(__typeof__(dbtob(1)), int),
    "dbtob signed result type");
_Static_assert(__builtin_types_compatible_p(__typeof__(btodb(1)), int),
    "btodb signed result type");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(fs_to_dq_blocks(1, 1)), int),
    "fs_to_dq_blocks signed result type");
_Static_assert(__builtin_types_compatible_p(__typeof__(dbtob(1U)), unsigned int),
    "dbtob result type");
_Static_assert(__builtin_types_compatible_p(__typeof__(btodb(1U)), unsigned int),
    "btodb result type");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(fs_to_dq_blocks(1U, 512U)), unsigned int),
    "fs_to_dq_blocks result type");
_Static_assert(__builtin_types_compatible_p(__typeof__(dqoff(1U)),
    unsigned long long), "dqoff LP64 result type");
_Static_assert(dbtob(2U) == 2048U && btodb(2048U) == 2U,
    "musl quota binary-unit conversions");
_Static_assert(fs_to_dq_blocks(3U, 512U) == 1U,
    "musl quota product precedes division");
_Static_assert(dqoff(1U) == sizeof(struct dqblk), "musl quota record offset");
_Static_assert(dqoff(-1) == ~0ULL - 71ULL,
    "musl quota offset has unsigned-modular LP64 arithmetic");
