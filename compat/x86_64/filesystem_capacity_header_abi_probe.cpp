/* C++17 Linux/x86-64 <sys/statfs.h>/<sys/statvfs.h> ABI profile probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_FILESYSTEM_CAPACITY_BASE) + \
    defined(CRABC_FILESYSTEM_CAPACITY_LARGEFILE64)) != 1
#error "select exactly one filesystem-capacity header profile class"
#endif

#include <stddef.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>

static_assert(sizeof(long) == 8 && sizeof(unsigned long) == 8,
    "x86 LP64 word widths");
static_assert(sizeof(fsblkcnt_t) == 8 && sizeof(fsfilcnt_t) == 8,
    "x86 filesystem counter widths");
static_assert(static_cast<fsblkcnt_t>(-1) > 0 &&
    static_cast<fsfilcnt_t>(-1) > 0, "x86 filesystem counters are unsigned");
static_assert(sizeof(fsid_t) == 8 && alignof(fsid_t) == 4 &&
    __builtin_offsetof(fsid_t, __val) == 0, "x86 fsid_t ABI");

static_assert(sizeof(struct statfs) == 120 && alignof(struct statfs) == 8,
    "x86 struct statfs ABI");
static_assert(__builtin_offsetof(struct statfs, f_type) == 0 &&
    __builtin_offsetof(struct statfs, f_bsize) == 8 &&
    __builtin_offsetof(struct statfs, f_blocks) == 16 &&
    __builtin_offsetof(struct statfs, f_bfree) == 24 &&
    __builtin_offsetof(struct statfs, f_bavail) == 32 &&
    __builtin_offsetof(struct statfs, f_files) == 40 &&
    __builtin_offsetof(struct statfs, f_ffree) == 48 &&
    __builtin_offsetof(struct statfs, f_fsid) == 56 &&
    __builtin_offsetof(struct statfs, f_namelen) == 64 &&
    __builtin_offsetof(struct statfs, f_frsize) == 72 &&
    __builtin_offsetof(struct statfs, f_flags) == 80 &&
    __builtin_offsetof(struct statfs, f_spare) == 88,
    "x86 struct statfs field offsets");

static_assert(sizeof(struct statvfs) == 112 && alignof(struct statvfs) == 8,
    "x86 struct statvfs ABI");
static_assert(__builtin_offsetof(struct statvfs, f_bsize) == 0 &&
    __builtin_offsetof(struct statvfs, f_frsize) == 8 &&
    __builtin_offsetof(struct statvfs, f_blocks) == 16 &&
    __builtin_offsetof(struct statvfs, f_bfree) == 24 &&
    __builtin_offsetof(struct statvfs, f_bavail) == 32 &&
    __builtin_offsetof(struct statvfs, f_files) == 40 &&
    __builtin_offsetof(struct statvfs, f_ffree) == 48 &&
    __builtin_offsetof(struct statvfs, f_favail) == 56 &&
    __builtin_offsetof(struct statvfs, f_fsid) == 64 &&
    __builtin_offsetof(struct statvfs, f_flag) == 72 &&
    __builtin_offsetof(struct statvfs, f_namemax) == 80 &&
    __builtin_offsetof(struct statvfs, f_type) == 88 &&
    __builtin_offsetof(struct statvfs, __reserved) == 92,
    "x86 struct statvfs field offsets");

static_assert(ST_RDONLY == 1 && ST_NOSUID == 2 && ST_NODEV == 4 &&
    ST_NOEXEC == 8 && ST_SYNCHRONOUS == 16 && ST_MANDLOCK == 64 &&
    ST_WRITE == 128 && ST_APPEND == 256 && ST_IMMUTABLE == 512 &&
    ST_NOATIME == 1024 && ST_NODIRATIME == 2048 && ST_RELATIME == 4096,
    "x86 statvfs flag values");

using statfs_signature = int (*)(const char *, struct statfs *);
using fstatfs_signature = int (*)(int, struct statfs *);
using statvfs_signature = int (*)(const char *__restrict,
    struct statvfs *__restrict);
using fstatvfs_signature = int (*)(int, struct statvfs *);

static_assert(__is_same(decltype(&statfs), statfs_signature),
    "statfs C++ declaration");
static_assert(__is_same(decltype(&fstatfs), fstatfs_signature),
    "fstatfs C++ declaration");
static_assert(__is_same(decltype(&statvfs), statvfs_signature),
    "statvfs C++ declaration");
static_assert(__is_same(decltype(&fstatvfs), fstatvfs_signature),
    "fstatvfs C++ declaration");

__attribute__((used)) static statfs_signature
    filesystem_capacity_cxx_statfs = statfs;
__attribute__((used)) static fstatfs_signature
    filesystem_capacity_cxx_fstatfs = fstatfs;
__attribute__((used)) static statvfs_signature
    filesystem_capacity_cxx_statvfs = statvfs;
__attribute__((used)) static fstatvfs_signature
    filesystem_capacity_cxx_fstatvfs = fstatvfs;

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

using fsblkcnt64_alias = fsblkcnt64_t;
using fsfilcnt64_alias = fsfilcnt64_t;
static_assert(__is_same(fsblkcnt64_alias, fsblkcnt_t),
    "fsblkcnt64_t macro alias");
static_assert(__is_same(fsfilcnt64_alias, fsfilcnt_t),
    "fsfilcnt64_t macro alias");
static_assert(__is_same(decltype(&statfs64), statfs_signature),
    "statfs64 macro alias declaration");
static_assert(__is_same(decltype(&fstatfs64), fstatfs_signature),
    "fstatfs64 macro alias declaration");
static_assert(__is_same(decltype(&statvfs64), statvfs_signature),
    "statvfs64 macro alias declaration");
static_assert(__is_same(decltype(&fstatvfs64), fstatvfs_signature),
    "fstatvfs64 macro alias declaration");

__attribute__((used)) static statfs_signature
    filesystem_capacity_cxx_statfs64 = statfs64;
__attribute__((used)) static fstatfs_signature
    filesystem_capacity_cxx_fstatfs64 = fstatfs64;
__attribute__((used)) static statvfs_signature
    filesystem_capacity_cxx_statvfs64 = statvfs64;
__attribute__((used)) static fstatvfs_signature
    filesystem_capacity_cxx_fstatvfs64 = fstatvfs64;
#endif

int crabc_x86_64_filesystem_capacity_header_abi_probe_cpp()
{
	return 0;
}
