/* C++17 Linux/x86-64 <dirent.h> header ABI profile probe.
 *
 * The `used` references are intentionally inspected with nm by the runner.
 * They prove only header-requested C spellings are unmangled; they never
 * link an archive or claim directory-stream runtime/linkage support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_DIRENT_SEEK_TELL_VISIBLE) + \
    defined(CRABC_DIRENT_SEEK_TELL_HIDDEN)) != 1
#error "select exactly one seekdir/telldir visibility class"
#endif
#if (defined(CRABC_DIRENT_GETDENTS_VISIBLE) + \
    defined(CRABC_DIRENT_GETDENTS_HIDDEN)) != 1
#error "select exactly one getdents/type-macro visibility class"
#endif
#if (defined(CRABC_DIRENT_VERSIONSORT_VISIBLE) + \
    defined(CRABC_DIRENT_VERSIONSORT_HIDDEN)) != 1
#error "select exactly one versionsort visibility class"
#endif
#if (defined(CRABC_DIRENT_BASE) + defined(CRABC_DIRENT_LARGEFILE64)) != 1
#error "select exactly one dirent large-file profile class"
#endif

#include <stddef.h>
#include <dirent.h>

static_assert(sizeof(long) == 8 && sizeof(unsigned long) == 8,
    "x86 LP64 word widths");
static_assert(sizeof(ino_t) == 8 && static_cast<ino_t>(-1) > 0,
    "x86 ino_t is unsigned 64-bit");
static_assert(sizeof(off_t) == 8 && static_cast<off_t>(-1) < 0,
    "x86 off_t is signed 64-bit");
static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8 &&
    static_cast<ssize_t>(-1) < 0, "x86 size types");
static_assert(sizeof(reclen_t) == 2 && static_cast<reclen_t>(-1) > 0,
    "x86 reclen_t is unsigned short");

static_assert(sizeof(struct dirent) == 280 && alignof(struct dirent) == 8,
    "x86 struct dirent ABI");
static_assert(__builtin_offsetof(struct dirent, d_ino) == 0 &&
    __builtin_offsetof(struct dirent, d_off) == 8 &&
    __builtin_offsetof(struct dirent, d_reclen) == 16 &&
    __builtin_offsetof(struct dirent, d_type) == 18 &&
    __builtin_offsetof(struct dirent, d_name) == 19 &&
    sizeof(((struct dirent *)0)->d_name) == 256,
    "x86 struct dirent field layout");
static_assert(sizeof(struct posix_dent) == 24 &&
    alignof(struct posix_dent) == 8, "x86 struct posix_dent ABI");
static_assert(__builtin_offsetof(struct posix_dent, d_ino) == 0 &&
    __builtin_offsetof(struct posix_dent, d_off) == 8 &&
    __builtin_offsetof(struct posix_dent, d_reclen) == 16 &&
    __builtin_offsetof(struct posix_dent, d_type) == 18 &&
    __builtin_offsetof(struct posix_dent, d_name) == 19,
    "x86 struct posix_dent field layout");

#ifndef d_fileno
#error "pinned musl exposes d_fileno as the d_ino compatibility spelling"
#endif
static_assert(__builtin_offsetof(struct dirent, d_fileno) ==
    __builtin_offsetof(struct dirent, d_ino), "d_fileno macro spelling");

static_assert(DT_UNKNOWN == 0 && DT_FIFO == 1 && DT_CHR == 2 &&
    DT_DIR == 4 && DT_BLK == 6 && DT_REG == 8 && DT_LNK == 10 &&
    DT_SOCK == 12 && DT_WHT == 14, "Linux dirent d_type values");

using closedir_signature = int (*)(DIR *);
using dirfd_signature = int (*)(DIR *);
using fdopendir_signature = DIR *(*)(int);
using opendir_signature = DIR *(*)(const char *);
using readdir_signature = struct dirent *(*)(DIR *);
using readdir_r_signature = int (*)(DIR *, struct dirent *, struct dirent **);
using rewinddir_signature = void (*)(DIR *);
using posix_getdents_signature = ssize_t (*)(int, void *, size_t, int);
using dirent_compare_signature = int (*)(const struct dirent **,
    const struct dirent **);
using scandir_signature = int (*)(const char *, struct dirent ***,
    int (*)(const struct dirent *), dirent_compare_signature);

static_assert(__is_same(decltype(&closedir), closedir_signature),
    "closedir declaration");
static_assert(__is_same(decltype(&dirfd), dirfd_signature), "dirfd declaration");
static_assert(__is_same(decltype(&fdopendir), fdopendir_signature),
    "fdopendir declaration");
static_assert(__is_same(decltype(&opendir), opendir_signature),
    "opendir declaration");
static_assert(__is_same(decltype(&readdir), readdir_signature),
    "readdir declaration");
static_assert(__is_same(decltype(&readdir_r), readdir_r_signature),
    "readdir_r declaration");
static_assert(__is_same(decltype(&rewinddir), rewinddir_signature),
    "rewinddir declaration");
static_assert(__is_same(decltype(&posix_getdents), posix_getdents_signature),
    "posix_getdents declaration");
static_assert(__is_same(decltype(&alphasort), dirent_compare_signature),
    "alphasort declaration");
static_assert(__is_same(decltype(&scandir), scandir_signature),
    "scandir declaration");

__attribute__((used)) static closedir_signature crabc_dirent_closedir = closedir;
__attribute__((used)) static dirfd_signature crabc_dirent_dirfd = dirfd;
__attribute__((used)) static fdopendir_signature crabc_dirent_fdopendir = fdopendir;
__attribute__((used)) static opendir_signature crabc_dirent_opendir = opendir;
__attribute__((used)) static readdir_signature crabc_dirent_readdir = readdir;
__attribute__((used)) static readdir_r_signature crabc_dirent_readdir_r = readdir_r;
__attribute__((used)) static rewinddir_signature crabc_dirent_rewinddir = rewinddir;
__attribute__((used)) static posix_getdents_signature crabc_dirent_posix_getdents = posix_getdents;
__attribute__((used)) static dirent_compare_signature crabc_dirent_alphasort = alphasort;
__attribute__((used)) static scandir_signature crabc_dirent_scandir = scandir;

#if defined(CRABC_DIRENT_SEEK_TELL_VISIBLE)
using seekdir_signature = void (*)(DIR *, long);
using telldir_signature = long (*)(DIR *);
static_assert(__is_same(decltype(&seekdir), seekdir_signature),
    "seekdir declaration");
static_assert(__is_same(decltype(&telldir), telldir_signature),
    "telldir declaration");
__attribute__((used)) static seekdir_signature crabc_dirent_seekdir = seekdir;
__attribute__((used)) static telldir_signature crabc_dirent_telldir = telldir;
#endif

#if defined(CRABC_DIRENT_GETDENTS_VISIBLE)
#ifndef IFTODT
#error "GNU/BSD dirent profile must expose IFTODT"
#endif
#ifndef DTTOIF
#error "GNU/BSD dirent profile must expose DTTOIF"
#endif
static_assert(IFTODT(0170000) == 017 && DTTOIF(DT_DIR) == 0040000,
    "GNU/BSD dirent type conversion macros");
using getdents_signature = int (*)(int, struct dirent *, size_t);
static_assert(__is_same(decltype(&getdents), getdents_signature),
    "getdents declaration");
#endif

#if defined(CRABC_DIRENT_VERSIONSORT_VISIBLE)
static_assert(__is_same(decltype(&versionsort), dirent_compare_signature),
    "versionsort declaration");
__attribute__((used)) static dirent_compare_signature crabc_dirent_versionsort = versionsort;
#endif

#if defined(CRABC_DIRENT_GETDENTS_VISIBLE)
__attribute__((used)) static getdents_signature crabc_dirent_getdents = getdents;
#endif

#if defined(CRABC_DIRENT_GETDENTS_HIDDEN)
#ifdef IFTODT
#error "non-GNU/BSD dirent profile must hide IFTODT"
#endif
#ifdef DTTOIF
#error "non-GNU/BSD dirent profile must hide DTTOIF"
#endif
#endif

#if defined(CRABC_DIRENT_BASE)
#ifdef dirent64
#error "dirent64 must stay hidden without _LARGEFILE64_SOURCE"
#endif
#ifdef readdir64
#error "readdir64 must stay hidden without _LARGEFILE64_SOURCE"
#endif
#ifdef versionsort64
#error "versionsort64 must stay hidden without _LARGEFILE64_SOURCE"
#endif
#ifdef getdents64
#error "getdents64 must stay hidden without _LARGEFILE64_SOURCE"
#endif
#endif

#if defined(CRABC_DIRENT_LARGEFILE64)
#ifndef _LARGEFILE64_SOURCE
#error "large-file dirent profile requires _LARGEFILE64_SOURCE"
#endif
#ifndef dirent64
#error "_LARGEFILE64_SOURCE must expose dirent64"
#endif
#ifndef readdir64
#error "_LARGEFILE64_SOURCE must expose readdir64"
#endif
#ifndef readdir64_r
#error "_LARGEFILE64_SOURCE must expose readdir64_r"
#endif
#ifndef scandir64
#error "_LARGEFILE64_SOURCE must expose scandir64"
#endif
#ifndef alphasort64
#error "_LARGEFILE64_SOURCE must expose alphasort64"
#endif
#ifndef versionsort64
#error "_LARGEFILE64_SOURCE must expose versionsort64"
#endif
#ifndef off64_t
#error "_LARGEFILE64_SOURCE must expose off64_t"
#endif
#ifndef ino64_t
#error "_LARGEFILE64_SOURCE must expose ino64_t"
#endif
#ifndef getdents64
#error "_LARGEFILE64_SOURCE must expose getdents64"
#endif
using dirent64_alias = dirent64;
using off64_t_alias = off64_t;
using ino64_t_alias = ino64_t;
static_assert(__is_same(dirent64_alias, struct dirent), "dirent64 macro alias");
static_assert(__is_same(off64_t_alias, off_t), "off64_t macro alias");
static_assert(__is_same(ino64_t_alias, ino_t), "ino64_t macro alias");
static_assert(__is_same(decltype(&readdir64), readdir_signature),
    "readdir64 macro alias declaration");
static_assert(__is_same(decltype(&readdir64_r), readdir_r_signature),
    "readdir64_r macro alias declaration");
static_assert(__is_same(decltype(&scandir64), scandir_signature),
    "scandir64 macro alias declaration");
static_assert(__is_same(decltype(&alphasort64), dirent_compare_signature),
    "alphasort64 macro alias declaration");
#if defined(CRABC_DIRENT_VERSIONSORT_VISIBLE)
static_assert(__is_same(decltype(&versionsort64), dirent_compare_signature),
    "versionsort64 macro alias declaration");
#endif
#if defined(CRABC_DIRENT_GETDENTS_VISIBLE)
static_assert(__is_same(decltype(&getdents64), getdents_signature),
    "getdents64 macro alias declaration");
#endif
__attribute__((used)) static readdir_signature crabc_dirent_readdir64 = readdir64;
__attribute__((used)) static readdir_r_signature crabc_dirent_readdir64_r = readdir64_r;
__attribute__((used)) static scandir_signature crabc_dirent_scandir64 = scandir64;
__attribute__((used)) static dirent_compare_signature crabc_dirent_alphasort64 = alphasort64;
#if defined(CRABC_DIRENT_VERSIONSORT_VISIBLE)
__attribute__((used)) static dirent_compare_signature crabc_dirent_versionsort64 = versionsort64;
#endif
#if defined(CRABC_DIRENT_GETDENTS_VISIBLE)
__attribute__((used)) static getdents_signature crabc_dirent_getdents64 = getdents64;
#endif
#endif

#ifdef CRABC_DIRENT_EXPECT_HIDDEN_DECLARATIONS
#if defined(CRABC_DIRENT_SEEK_TELL_HIDDEN)
static void (*crabc_dirent_hidden_seekdir)(DIR *, long) = seekdir;
static long (*crabc_dirent_hidden_telldir)(DIR *) = telldir;
#endif
#if defined(CRABC_DIRENT_GETDENTS_HIDDEN)
#if defined(CRABC_DIRENT_LARGEFILE64)
/* The alias exists in strict large-file mode but must expand to the still
 * hidden GNU/BSD declaration, rather than creating a new declaration. */
static int (*crabc_dirent_hidden_getdents)(int, struct dirent *, size_t) =
    getdents64;
#else
static int (*crabc_dirent_hidden_getdents)(int, struct dirent *, size_t) =
    getdents;
#endif
#endif
#if defined(CRABC_DIRENT_VERSIONSORT_HIDDEN)
#if defined(CRABC_DIRENT_LARGEFILE64)
static dirent_compare_signature crabc_dirent_hidden_versionsort = versionsort64;
#else
static dirent_compare_signature crabc_dirent_hidden_versionsort = versionsort;
#endif
#endif
#endif

int crabc_x86_64_dirent_header_abi_probe_cpp()
{
    return 0;
}
