/* Direct Linux/x86-64 <sys/stat.h> through <ftw.h> C++ source-form witness. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <ftw.h>

using crabc_stat_signature = int (*)(const char *__restrict,
    struct stat *__restrict);
using crabc_lstat_signature = int (*)(const char *__restrict,
    struct stat *__restrict);
using crabc_fstatat_signature = int (*)(int, const char *__restrict,
    struct stat *__restrict, int);
using crabc_ftw_signature = int (*)(const char *,
    int (*)(const char *, const struct stat *, int), int);
using crabc_nftw_signature = int (*)(const char *,
    int (*)(const char *, const struct stat *, int, struct FTW *), int, int);

static_assert(__is_same(decltype(&stat), crabc_stat_signature),
    "stat declaration");
static_assert(__is_same(decltype(&lstat), crabc_lstat_signature),
    "lstat declaration");
static_assert(__is_same(decltype(&fstatat), crabc_fstatat_signature),
    "fstatat declaration");
static_assert(__is_same(decltype(&ftw), crabc_ftw_signature),
    "ftw declaration");
static_assert(__is_same(decltype(&nftw), crabc_nftw_signature),
    "nftw declaration");
static_assert(S_ISDIR(S_IFDIR) && S_ISCHR(S_IFCHR) && S_ISBLK(S_IFBLK) &&
    S_ISREG(S_IFREG) && S_ISFIFO(S_IFIFO) && S_ISLNK(S_IFLNK) &&
    S_ISSOCK(S_IFSOCK), "stat file-mode classifiers");

#ifdef _BITS_STAT_H
#error "x86 musl bits/stat.h is intentionally unguarded"
#endif
#ifdef AT_FDCWD
#error "x86 musl sys/stat.h does not acquire fcntl AT_* macros"
#endif
#ifdef AT_SYMLINK_NOFOLLOW
#error "x86 musl sys/stat.h does not acquire fcntl AT_* macros"
#endif

#if defined(CRABC_STAT_FTW_EXPECT_LEGACY_ALIASES)
#ifndef S_IREAD
#error "GNU/BSD sys/stat.h must publish S_IREAD"
#endif
#ifndef S_IWRITE
#error "GNU/BSD sys/stat.h must publish S_IWRITE"
#endif
#ifndef S_IEXEC
#error "GNU/BSD sys/stat.h must publish S_IEXEC"
#endif
#else
#ifdef S_IREAD
#error "non-GNU/BSD sys/stat.h must not publish S_IREAD"
#endif
#ifdef S_IWRITE
#error "non-GNU/BSD sys/stat.h must not publish S_IWRITE"
#endif
#ifdef S_IEXEC
#error "non-GNU/BSD sys/stat.h must not publish S_IEXEC"
#endif
#endif

#if defined(CRABC_STAT_FTW_EXPECT_LARGEFILE_ALIASES)
#ifndef stat64
#error "_LARGEFILE64_SOURCE must publish stat64"
#endif
#ifndef fstat64
#error "_LARGEFILE64_SOURCE must publish fstat64"
#endif
#ifndef lstat64
#error "_LARGEFILE64_SOURCE must publish lstat64"
#endif
#ifndef fstatat64
#error "_LARGEFILE64_SOURCE must publish fstatat64"
#endif
#ifndef ftw64
#error "_LARGEFILE64_SOURCE must publish ftw64"
#endif
#ifndef nftw64
#error "_LARGEFILE64_SOURCE must publish nftw64"
#endif
#endif

__attribute__((used)) static crabc_stat_signature crabc_stat_reference = stat;
__attribute__((used)) static crabc_lstat_signature crabc_lstat_reference = lstat;
__attribute__((used)) static crabc_fstatat_signature crabc_fstatat_reference =
    fstatat;
__attribute__((used)) static crabc_ftw_signature crabc_ftw_reference = ftw;
__attribute__((used)) static crabc_nftw_signature crabc_nftw_reference = nftw;

extern "C" int crabc_x86_64_stat_ftw_header_source_form_probe_cpp()
{
    return 0;
}
