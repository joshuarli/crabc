#ifndef _BITS_STATFS_H
#define _BITS_STATFS_H

/*
 * Linux `statfs` is an architecture ABI record.  x86-64 uses musl's generic
 * LP64 layout; keeping it in the conventional bits leaf makes the public
 * `<sys/statfs.h>` dependency and its layout source explicit.
 */
struct statfs {
	unsigned long f_type, f_bsize;
	fsblkcnt_t f_blocks, f_bfree, f_bavail;
	fsfilcnt_t f_files, f_ffree;
	fsid_t f_fsid;
	unsigned long f_namelen, f_frsize, f_flags, f_spare[4];
};

#endif
