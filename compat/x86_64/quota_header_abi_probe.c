/* Native Linux/x86-64 complete pinned-musl <sys/quota.h> ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/quota.h>
#include <stddef.h>

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
#ifndef _LINUX_QUOTA_VERSION
#error "musl quota header version macro is missing"
#endif
#ifndef INITQFNAMES
#error "musl quota filename initializer macro is missing"
#endif
#ifndef IIF_ALL
#error "musl quota information mask is missing"
#endif
#ifndef dq_bhardlimit
#error "musl quota legacy member aliases are missing"
#endif
#ifdef PRJQUOTA
#error "PRJQUOTA is not present in pinned musl 1.2.6"
#endif
#ifdef Q_GETNEXTQUOTA
#error "Q_GETNEXTQUOTA is not present in pinned musl 1.2.6"
#endif
#ifdef QFMT_SHMEM
#error "QFMT_SHMEM is not present in pinned musl 1.2.6"
#endif

typedef int (*quotactl_type)(int, const char *, int, char *);

static const char *const crabc_init_qfnames[] = INITQFNAMES

struct crabc_quota_aliases {
    struct dqblk dq_dqb;
};

static struct crabc_quota_aliases crabc_quota_aliases;

_Static_assert(sizeof(unsigned int) == 4, "x86 unsigned int width");
_Static_assert(sizeof(struct dqblk) == 72, "musl x86 dqblk size");
_Static_assert(_Alignof(struct dqblk) == 8, "musl x86 dqblk alignment");
_Static_assert(offsetof(struct dqblk, dqb_bhardlimit) == 0,
    "musl dqblk hard-limit offset");
_Static_assert(offsetof(struct dqblk, dqb_bsoftlimit) == 8,
    "musl dqblk soft-limit offset");
_Static_assert(offsetof(struct dqblk, dqb_curspace) == 16,
    "musl dqblk space offset");
_Static_assert(offsetof(struct dqblk, dqb_valid) == 64,
    "musl dqblk validity offset");
_Static_assert(sizeof(struct dqinfo) == 24, "musl x86 dqinfo size");
_Static_assert(_Alignof(struct dqinfo) == 8, "musl x86 dqinfo alignment");
_Static_assert(offsetof(struct dqinfo, dqi_bgrace) == 0,
    "musl dqinfo block-grace offset");
_Static_assert(offsetof(struct dqinfo, dqi_igrace) == 8,
    "musl dqinfo inode-grace offset");
_Static_assert(offsetof(struct dqinfo, dqi_flags) == 16,
    "musl dqinfo flags offset");
_Static_assert(offsetof(struct dqinfo, dqi_valid) == 20,
    "musl dqinfo validity offset");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(crabc_quota_aliases.dq_bhardlimit), uint64_t),
    "musl quota hard-limit alias type");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(crabc_quota_aliases.dq_valid), uint32_t),
    "musl quota validity alias type");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct dqinfo *)0)->dqi_bgrace), uint64_t),
    "musl quota block-grace type");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct dqinfo *)0)->dqi_valid), uint32_t),
    "musl quota info validity type");
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
_Static_assert(_LINUX_QUOTA_VERSION == 2 && MAX_IQ_TIME == 604800
    && MAX_DQ_TIME == 604800, "musl quota version and grace constants");
_Static_assert(MAXQUOTAS == 2 && USRQUOTA == 0 && GRPQUOTA == 1,
    "musl quota type constants");
_Static_assert(sizeof(crabc_init_qfnames) / sizeof(crabc_init_qfnames[0]) == 3,
    "musl quota filename initializer count");
_Static_assert(sizeof(QUOTAFILENAME) == sizeof("quota")
    && sizeof(QUOTAGROUP) == sizeof("staff"), "musl quota name spelling");
_Static_assert(NR_DQHASH == 43 && NR_DQUOTS == 256,
    "musl quota table constants");
_Static_assert(Q_SYNC == 0x800001 && Q_SETQUOTA == 0x800008,
    "musl quota command range");
_Static_assert(QFMT_VFS_OLD == 1 && QFMT_VFS_V0 == 2 && QFMT_OCFS2 == 3
    && QFMT_VFS_V1 == 4, "musl quota format constants");
_Static_assert(QIF_ALL == 63 && IIF_ALL == 7 && QCMD(1, 2) == 0x102,
    "musl quota information masks");
_Static_assert(__builtin_types_compatible_p(__typeof__(&quotactl), quotactl_type),
    "musl quotactl declaration");
