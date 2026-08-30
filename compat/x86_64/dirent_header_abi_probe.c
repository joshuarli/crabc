/* Linux/x86-64 <dirent.h> header ABI profile probe.
 *
 * Pinned musl 1.2.6 defines the declaration, feature-selection, and LP64
 * layout contract. This probe deliberately selects headers only: it does not
 * link, call, or otherwise claim an x86 C directory-stream runtime.
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

_Static_assert(sizeof(long) == 8 && sizeof(unsigned long) == 8,
    "x86 LP64 word widths");
_Static_assert(sizeof(ino_t) == 8 && (ino_t)-1 > 0,
    "x86 ino_t is unsigned 64-bit");
_Static_assert(sizeof(off_t) == 8 && (off_t)-1 < 0,
    "x86 off_t is signed 64-bit");
_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8 &&
    (ssize_t)-1 < 0, "x86 size types");
_Static_assert(sizeof(reclen_t) == 2 && (reclen_t)-1 > 0,
    "x86 reclen_t is unsigned short");

_Static_assert(sizeof(struct dirent) == 280 && _Alignof(struct dirent) == 8,
    "x86 struct dirent ABI");
_Static_assert(offsetof(struct dirent, d_ino) == 0 &&
    offsetof(struct dirent, d_off) == 8 &&
    offsetof(struct dirent, d_reclen) == 16 &&
    offsetof(struct dirent, d_type) == 18 &&
    offsetof(struct dirent, d_name) == 19 &&
    sizeof(((struct dirent *)0)->d_name) == 256,
    "x86 struct dirent field layout");
_Static_assert(sizeof(struct posix_dent) == 24 &&
    _Alignof(struct posix_dent) == 8,
    "x86 struct posix_dent ABI");
_Static_assert(offsetof(struct posix_dent, d_ino) == 0 &&
    offsetof(struct posix_dent, d_off) == 8 &&
    offsetof(struct posix_dent, d_reclen) == 16 &&
    offsetof(struct posix_dent, d_type) == 18 &&
    offsetof(struct posix_dent, d_name) == 19,
    "x86 struct posix_dent field layout");

#ifndef d_fileno
#error "pinned musl exposes d_fileno as the d_ino compatibility spelling"
#endif
_Static_assert(offsetof(struct dirent, d_fileno) ==
    offsetof(struct dirent, d_ino), "d_fileno macro spelling");

_Static_assert(DT_UNKNOWN == 0 && DT_FIFO == 1 && DT_CHR == 2 &&
    DT_DIR == 4 && DT_BLK == 6 && DT_REG == 8 && DT_LNK == 10 &&
    DT_SOCK == 12 && DT_WHT == 14, "Linux dirent d_type values");

typedef int (*closedir_signature)(DIR *);
typedef int (*dirfd_signature)(DIR *);
typedef DIR *(*fdopendir_signature)(int);
typedef DIR *(*opendir_signature)(const char *);
typedef struct dirent *(*readdir_signature)(DIR *);
typedef int (*readdir_r_signature)(DIR *, struct dirent *, struct dirent **);
typedef void (*rewinddir_signature)(DIR *);
typedef ssize_t (*posix_getdents_signature)(int, void *, size_t, int);
typedef int (*dirent_compare_signature)(const struct dirent **,
    const struct dirent **);
typedef int (*scandir_signature)(const char *, struct dirent ***,
    int (*)(const struct dirent *), dirent_compare_signature);

_Static_assert(__builtin_types_compatible_p(__typeof__(&closedir),
    closedir_signature), "closedir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dirfd), dirfd_signature),
    "dirfd declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fdopendir),
    fdopendir_signature), "fdopendir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&opendir),
    opendir_signature), "opendir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readdir),
    readdir_signature), "readdir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readdir_r),
    readdir_r_signature), "readdir_r declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&rewinddir),
    rewinddir_signature), "rewinddir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_getdents),
    posix_getdents_signature), "posix_getdents declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&alphasort),
    dirent_compare_signature), "alphasort declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&scandir),
    scandir_signature), "scandir declaration");

#if defined(CRABC_DIRENT_SEEK_TELL_VISIBLE)
typedef void (*seekdir_signature)(DIR *, long);
typedef long (*telldir_signature)(DIR *);
_Static_assert(__builtin_types_compatible_p(__typeof__(&seekdir),
    seekdir_signature), "seekdir declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&telldir),
    telldir_signature), "telldir declaration");
#endif

#if defined(CRABC_DIRENT_GETDENTS_VISIBLE)
#ifndef IFTODT
#error "GNU/BSD dirent profile must expose IFTODT"
#endif
#ifndef DTTOIF
#error "GNU/BSD dirent profile must expose DTTOIF"
#endif
_Static_assert(IFTODT(0170000) == 017 && DTTOIF(DT_DIR) == 0040000,
    "GNU/BSD dirent type conversion macros");
typedef int (*getdents_signature)(int, struct dirent *, size_t);
_Static_assert(__builtin_types_compatible_p(__typeof__(&getdents),
    getdents_signature), "getdents declaration");
#endif

#if defined(CRABC_DIRENT_VERSIONSORT_VISIBLE)
_Static_assert(__builtin_types_compatible_p(__typeof__(&versionsort),
    dirent_compare_signature), "versionsort declaration");
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
/* The seven base profiles intentionally do not select musl's large-file
 * spelling aliases. */
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
typedef struct dirent64 dirent64_alias;
typedef off64_t off64_t_alias;
typedef ino64_t ino64_t_alias;
_Static_assert(__builtin_types_compatible_p(dirent64_alias, struct dirent),
    "dirent64 macro alias");
_Static_assert(__builtin_types_compatible_p(off64_t_alias, off_t),
    "off64_t macro alias");
_Static_assert(__builtin_types_compatible_p(ino64_t_alias, ino_t),
    "ino64_t macro alias");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readdir64),
    readdir_signature), "readdir64 macro alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&readdir64_r),
    readdir_r_signature), "readdir64_r macro alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&scandir64),
    scandir_signature), "scandir64 macro alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&alphasort64),
    dirent_compare_signature), "alphasort64 macro alias declaration");
#if defined(CRABC_DIRENT_VERSIONSORT_VISIBLE)
_Static_assert(__builtin_types_compatible_p(__typeof__(&versionsort64),
    dirent_compare_signature), "versionsort64 macro alias declaration");
#endif
#if defined(CRABC_DIRENT_GETDENTS_VISIBLE)
_Static_assert(__builtin_types_compatible_p(__typeof__(&getdents64),
    getdents_signature), "getdents64 macro alias declaration");
#endif
#endif

/* The runner compiles this mode expecting a diagnostic. It is the direct
 * negative proof for function-name visibility; preprocessor tests alone
 * cannot observe hidden declarations. */
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

int crabc_x86_64_dirent_header_abi_probe(void)
{
    return 0;
}
