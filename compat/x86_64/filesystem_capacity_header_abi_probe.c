/* Linux/x86-64 <sys/statfs.h>/<sys/statvfs.h> header ABI profile probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_FILESYSTEM_CAPACITY_BASE) + \
    defined(CRABC_FILESYSTEM_CAPACITY_LARGEFILE64)) != 1
#error "select exactly one filesystem-capacity header profile class"
#endif

/* Include the shared type vocabulary first: both orderings must retain the
 * same pinned-musl fsblkcnt_t/fsfilcnt_t definitions. */
#include <stddef.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>

_Static_assert(sizeof(long) == 8 && sizeof(unsigned long) == 8,
    "x86 LP64 word widths");
_Static_assert(sizeof(fsblkcnt_t) == 8 && sizeof(fsfilcnt_t) == 8,
    "x86 filesystem counter widths");
_Static_assert((fsblkcnt_t)-1 > 0 && (fsfilcnt_t)-1 > 0,
    "x86 filesystem counters are unsigned");
_Static_assert(sizeof(fsid_t) == 8 && _Alignof(fsid_t) == 4 &&
    offsetof(fsid_t, __val) == 0, "x86 fsid_t ABI");

_Static_assert(sizeof(struct statfs) == 120 && _Alignof(struct statfs) == 8,
    "x86 struct statfs ABI");
_Static_assert(offsetof(struct statfs, f_type) == 0 &&
    offsetof(struct statfs, f_bsize) == 8 &&
    offsetof(struct statfs, f_blocks) == 16 &&
    offsetof(struct statfs, f_bfree) == 24 &&
    offsetof(struct statfs, f_bavail) == 32 &&
    offsetof(struct statfs, f_files) == 40 &&
    offsetof(struct statfs, f_ffree) == 48 &&
    offsetof(struct statfs, f_fsid) == 56 &&
    offsetof(struct statfs, f_namelen) == 64 &&
    offsetof(struct statfs, f_frsize) == 72 &&
    offsetof(struct statfs, f_flags) == 80 &&
    offsetof(struct statfs, f_spare) == 88,
    "x86 struct statfs field offsets");

_Static_assert(sizeof(struct statvfs) == 112 && _Alignof(struct statvfs) == 8,
    "x86 struct statvfs ABI");
_Static_assert(offsetof(struct statvfs, f_bsize) == 0 &&
    offsetof(struct statvfs, f_frsize) == 8 &&
    offsetof(struct statvfs, f_blocks) == 16 &&
    offsetof(struct statvfs, f_bfree) == 24 &&
    offsetof(struct statvfs, f_bavail) == 32 &&
    offsetof(struct statvfs, f_files) == 40 &&
    offsetof(struct statvfs, f_ffree) == 48 &&
    offsetof(struct statvfs, f_favail) == 56 &&
    offsetof(struct statvfs, f_fsid) == 64 &&
    offsetof(struct statvfs, f_flag) == 72 &&
    offsetof(struct statvfs, f_namemax) == 80 &&
    offsetof(struct statvfs, f_type) == 88 &&
    offsetof(struct statvfs, __reserved) == 92,
    "x86 struct statvfs field offsets");

_Static_assert(ST_RDONLY == 1 && ST_NOSUID == 2 && ST_NODEV == 4 &&
    ST_NOEXEC == 8 && ST_SYNCHRONOUS == 16 && ST_MANDLOCK == 64 &&
    ST_WRITE == 128 && ST_APPEND == 256 && ST_IMMUTABLE == 512 &&
    ST_NOATIME == 1024 && ST_NODIRATIME == 2048 && ST_RELATIME == 4096,
    "x86 statvfs flag values");

typedef int (*statfs_signature)(const char *, struct statfs *);
typedef int (*fstatfs_signature)(int, struct statfs *);
typedef int (*statvfs_signature)(const char *__restrict,
    struct statvfs *__restrict);
typedef int (*fstatvfs_signature)(int, struct statvfs *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&statfs),
    statfs_signature), "statfs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstatfs),
    fstatfs_signature), "fstatfs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&statvfs),
    statvfs_signature), "statvfs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstatvfs),
    fstatvfs_signature), "fstatvfs declaration");

#if defined(CRABC_FILESYSTEM_CAPACITY_BASE)
#ifdef _LARGEFILE64_SOURCE
#error "base filesystem-capacity profiles must not select large-file aliases"
#endif
#ifdef statfs64
#error "statfs64 must stay hidden without _LARGEFILE64_SOURCE"
#endif
#ifdef fstatfs64
#error "fstatfs64 must stay hidden without _LARGEFILE64_SOURCE"
#endif
#ifdef statvfs64
#error "statvfs64 must stay hidden without _LARGEFILE64_SOURCE"
#endif
#ifdef fstatvfs64
#error "fstatvfs64 must stay hidden without _LARGEFILE64_SOURCE"
#endif
#ifdef fsblkcnt64_t
#error "fsblkcnt64_t must stay hidden without _LARGEFILE64_SOURCE"
#endif
#ifdef fsfilcnt64_t
#error "fsfilcnt64_t must stay hidden without _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_FILESYSTEM_CAPACITY_LARGEFILE64)
#ifndef _LARGEFILE64_SOURCE
#error "large-file filesystem-capacity profiles require _LARGEFILE64_SOURCE"
#endif
#ifndef statfs64
#error "_LARGEFILE64_SOURCE must expose statfs64"
#endif
#ifndef fstatfs64
#error "_LARGEFILE64_SOURCE must expose fstatfs64"
#endif
#ifndef statvfs64
#error "_LARGEFILE64_SOURCE must expose statvfs64"
#endif
#ifndef fstatvfs64
#error "_LARGEFILE64_SOURCE must expose fstatvfs64"
#endif
#ifndef fsblkcnt64_t
#error "_LARGEFILE64_SOURCE must expose fsblkcnt64_t"
#endif
#ifndef fsfilcnt64_t
#error "_LARGEFILE64_SOURCE must expose fsfilcnt64_t"
#endif

typedef fsblkcnt64_t fsblkcnt64_alias;
typedef fsfilcnt64_t fsfilcnt64_alias;
_Static_assert(__builtin_types_compatible_p(fsblkcnt64_alias, fsblkcnt_t),
    "fsblkcnt64_t macro alias");
_Static_assert(__builtin_types_compatible_p(fsfilcnt64_alias, fsfilcnt_t),
    "fsfilcnt64_t macro alias");
_Static_assert(__builtin_types_compatible_p(__typeof__(&statfs64),
    statfs_signature), "statfs64 macro alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstatfs64),
    fstatfs_signature), "fstatfs64 macro alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&statvfs64),
    statvfs_signature), "statvfs64 macro alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstatvfs64),
    fstatvfs_signature), "fstatvfs64 macro alias declaration");
#endif

int crabc_x86_64_filesystem_capacity_header_abi_probe(void)
{
	return 0;
}
