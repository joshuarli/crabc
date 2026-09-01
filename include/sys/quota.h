#ifndef _SYS_QUOTA_H
#define _SYS_QUOTA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>

#define dbtob(num) ((num) << 10)
#define btodb(num) ((num) >> 10)
#define fs_to_dq_blocks(num, blksize) (((num) * (blksize)) / 1024)

#define MAXQUOTAS 3
#define USRQUOTA  0
#define GRPQUOTA  1
#define PRJQUOTA  2

#define SUBCMDMASK 0x00ff
#define SUBCMDSHIFT 8
#define QCMD(cmd, type) (((cmd) << SUBCMDSHIFT) | ((type) & SUBCMDMASK))

#define Q_SYNC       0x800001
#define Q_QUOTAON    0x800002
#define Q_QUOTAOFF   0x800003
#define Q_GETFMT     0x800004
#define Q_GETINFO    0x800005
#define Q_SETINFO    0x800006
#define Q_GETQUOTA   0x800007
#define Q_SETQUOTA   0x800008
#define Q_GETNEXTQUOTA 0x800009

#define QFMT_VFS_OLD 1
#define QFMT_VFS_V0  2
#define QFMT_OCFS2   3
#define QFMT_VFS_V1  4
#define QFMT_SHMEM   5

#define QIF_BLIMITS 1
#define QIF_SPACE   2
#define QIF_ILIMITS 4
#define QIF_INODES  8
#define QIF_BTIME   16
#define QIF_ITIME   32
#define QIF_LIMITS  (QIF_BLIMITS | QIF_ILIMITS)
#define QIF_USAGE   (QIF_SPACE | QIF_INODES)
#define QIF_TIMES   (QIF_BTIME | QIF_ITIME)
#define QIF_ALL     (QIF_LIMITS | QIF_USAGE | QIF_TIMES)

struct dqblk {
    uint64_t dqb_bhardlimit;
    uint64_t dqb_bsoftlimit;
    uint64_t dqb_curspace;
    uint64_t dqb_ihardlimit;
    uint64_t dqb_isoftlimit;
    uint64_t dqb_curinodes;
    uint64_t dqb_btime;
    uint64_t dqb_itime;
    uint32_t dqb_valid;
};

#define dqoff(UID) ((long long)(UID) * sizeof (struct dqblk))

int quotactl(int, const char *, int, char *);

#ifdef __cplusplus
}
#endif

#endif
