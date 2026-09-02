/* C++ companion for the native Linux/x86-64 complete <sys/quota.h> ABI probe. */

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

using quotactl_type = int (*)(int, const char *, int, char *);

static const char *const crabc_init_qfnames[] = INITQFNAMES

struct crabc_quota_aliases {
    struct dqblk dq_dqb;
};

static crabc_quota_aliases crabc_quota_aliases;

static_assert(sizeof(unsigned int) == 4, "x86 unsigned int width");
static_assert(sizeof(struct dqblk) == 72, "musl x86 dqblk size");
static_assert(alignof(struct dqblk) == 8, "musl x86 dqblk alignment");
static_assert(offsetof(struct dqblk, dqb_bhardlimit) == 0,
    "musl dqblk hard-limit offset");
static_assert(offsetof(struct dqblk, dqb_bsoftlimit) == 8,
    "musl dqblk soft-limit offset");
static_assert(offsetof(struct dqblk, dqb_curspace) == 16,
    "musl dqblk space offset");
static_assert(offsetof(struct dqblk, dqb_valid) == 64,
    "musl dqblk validity offset");
static_assert(sizeof(struct dqinfo) == 24, "musl x86 dqinfo size");
static_assert(alignof(struct dqinfo) == 8, "musl x86 dqinfo alignment");
static_assert(offsetof(struct dqinfo, dqi_bgrace) == 0,
    "musl dqinfo block-grace offset");
static_assert(offsetof(struct dqinfo, dqi_igrace) == 8,
    "musl dqinfo inode-grace offset");
static_assert(offsetof(struct dqinfo, dqi_flags) == 16,
    "musl dqinfo flags offset");
static_assert(offsetof(struct dqinfo, dqi_valid) == 20,
    "musl dqinfo validity offset");
static_assert(__is_same(decltype(crabc_quota_aliases.dq_bhardlimit), uint64_t),
    "musl quota hard-limit alias type");
static_assert(__is_same(decltype(crabc_quota_aliases.dq_valid), uint32_t),
    "musl quota validity alias type");
static_assert(__is_same(decltype(((struct dqinfo *)0)->dqi_bgrace), uint64_t),
    "musl quota block-grace type");
static_assert(__is_same(decltype(((struct dqinfo *)0)->dqi_valid), uint32_t),
    "musl quota info validity type");
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
static_assert(_LINUX_QUOTA_VERSION == 2 && MAX_IQ_TIME == 604800
    && MAX_DQ_TIME == 604800, "musl quota C++ version and grace constants");
static_assert(MAXQUOTAS == 2 && USRQUOTA == 0 && GRPQUOTA == 1,
    "musl quota C++ type constants");
static_assert(sizeof(crabc_init_qfnames) / sizeof(crabc_init_qfnames[0]) == 3,
    "musl quota C++ filename initializer count");
static_assert(sizeof(QUOTAFILENAME) == sizeof("quota")
    && sizeof(QUOTAGROUP) == sizeof("staff"), "musl quota C++ name spelling");
static_assert(NR_DQHASH == 43 && NR_DQUOTS == 256,
    "musl quota C++ table constants");
static_assert(Q_SYNC == 0x800001 && Q_SETQUOTA == 0x800008,
    "musl quota C++ command range");
static_assert(QFMT_VFS_OLD == 1 && QFMT_VFS_V0 == 2 && QFMT_OCFS2 == 3
    && QFMT_VFS_V1 == 4, "musl quota C++ format constants");
static_assert(QIF_ALL == 63 && IIF_ALL == 7 && QCMD(1, 2) == 0x102,
    "musl quota C++ information masks");
static_assert(__is_same(decltype(&quotactl), quotactl_type),
    "musl C++ quotactl declaration");
