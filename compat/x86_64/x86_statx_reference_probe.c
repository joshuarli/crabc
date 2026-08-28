/*
 * Pinned-musl/raw Linux/x86-64 statx ABI and metadata reference.
 *
 * The musl `statx` entry point is the normal-call and public-layout oracle.
 * Its pinned 1.2.6 implementation intentionally falls back to `fstatat` when
 * the direct kernel syscall reports ENOSYS. The raw call below is therefore
 * an independent direct-ABI oracle: an ENOSYS result records that the direct
 * boundary is unavailable without requiring musl to return ENOSYS too.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Musl 1.2.6 exposes the selected request-mask bits but not this Linux UAPI
 * expansion-reserved bit. Name it locally so the raw syscall check can pin
 * the direct kernel rejection without pretending it is a selected C API.
 */
#ifndef STATX__RESERVED
#define STATX__RESERVED 0x80000000U
#endif

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 && sizeof(off_t) == 8,
               "x86 LP64 widths");
_Static_assert(sizeof(struct statx_timestamp) == 16 &&
                   _Alignof(struct statx_timestamp) == 8,
               "x86 statx timestamp layout");
_Static_assert(sizeof(struct statx) == 256 && _Alignof(struct statx) == 8,
               "x86 statx layout");
/*
 * Linux intentionally reserves the remaining bytes for statx extensions.
 * Keep this stable ABI check to the fields the selected Rust facade names;
 * later UAPI fields must not become implicit facade commitments.
 */
_Static_assert(offsetof(struct statx, stx_mask) == 0 &&
                   offsetof(struct statx, stx_blksize) == 4 &&
                   offsetof(struct statx, stx_attributes) == 8 &&
                   offsetof(struct statx, stx_nlink) == 16 &&
                   offsetof(struct statx, stx_uid) == 20 &&
                   offsetof(struct statx, stx_gid) == 24 &&
                   offsetof(struct statx, stx_mode) == 28 &&
                   offsetof(struct statx, stx_ino) == 32 &&
                   offsetof(struct statx, stx_size) == 40 &&
                   offsetof(struct statx, stx_blocks) == 48 &&
                   offsetof(struct statx, stx_attributes_mask) == 56 &&
                   offsetof(struct statx, stx_atime) == 64 &&
                   offsetof(struct statx, stx_btime) == 80 &&
                   offsetof(struct statx, stx_ctime) == 96 &&
                   offsetof(struct statx, stx_mtime) == 112 &&
                   offsetof(struct statx, stx_rdev_major) == 128 &&
                   offsetof(struct statx, stx_rdev_minor) == 132 &&
                   offsetof(struct statx, stx_dev_major) == 136 &&
                   offsetof(struct statx, stx_dev_minor) == 140 &&
                   offsetof(struct statx, stx_mnt_id) == 144 &&
                   offsetof(struct statx, stx_dio_mem_align) == 152 &&
                   offsetof(struct statx, stx_dio_offset_align) == 156,
               "x86 statx selected field offsets");
_Static_assert(SYS_statx == 332, "x86 statx syscall number");
_Static_assert(AT_FDCWD == -100 && AT_SYMLINK_NOFOLLOW == 0x0100 &&
                   AT_NO_AUTOMOUNT == 0x0800 && AT_EMPTY_PATH == 0x1000 &&
                   AT_STATX_SYNC_AS_STAT == 0x0000 &&
                   AT_STATX_SYNC_TYPE == 0x6000 &&
                   AT_STATX_FORCE_SYNC == 0x2000 &&
                   AT_STATX_DONT_SYNC == 0x4000,
               "x86 statx AT constants");
_Static_assert(STATX_TYPE == 0x0001U && STATX_MODE == 0x0002U &&
                   STATX_NLINK == 0x0004U && STATX_UID == 0x0008U &&
                   STATX_GID == 0x0010U && STATX_ATIME == 0x0020U &&
                   STATX_MTIME == 0x0040U && STATX_CTIME == 0x0080U &&
                   STATX_INO == 0x0100U && STATX_SIZE == 0x0200U &&
                   STATX_BLOCKS == 0x0400U && STATX_BASIC_STATS == 0x07ffU &&
                   STATX_BTIME == 0x0800U && STATX_MNT_ID == 0x1000U &&
                   STATX_DIOALIGN == 0x2000U && STATX_ALL == 0x0fffU &&
                   STATX__RESERVED == 0x80000000U,
               "x86 statx request-mask constants");

enum {
    RECORD_MODE = 0640,
    REQUEST_MASK = STATX_BASIC_STATS | STATX_BTIME | STATX_MNT_ID |
                   STATX_DIOALIGN,
    REQUIRED_MASK = STATX_TYPE | STATX_MODE | STATX_INO | STATX_SIZE,
};

struct call_result {
    int value;
    int error;
};

static struct call_result musl_statx(int dirfd, const char *path, int flags,
                                     unsigned int mask, struct statx *value)
{
    struct call_result result;

    errno = 0;
    result.value = statx(dirfd, path, flags, mask, value);
    result.error = errno;
    return result;
}

static struct call_result raw_statx(int dirfd, const char *path, int flags,
                                    unsigned int mask, struct statx *value)
{
    struct call_result result;

    errno = 0;
    result.value = (int)syscall(SYS_statx, dirfd, path, flags, mask, value);
    result.error = errno;
    return result;
}

static int expected_error(struct call_result result, int error)
{
    return result.value == -1 && result.error == error;
}

static int has_regular_metadata(const struct statx *value)
{
    return (value->stx_mask & REQUIRED_MASK) == REQUIRED_MASK &&
           S_ISREG(value->stx_mode) && (value->stx_mode & 0777) == RECORD_MODE &&
           value->stx_size == 6;
}

static int has_symlink_metadata(const struct statx *value)
{
    return (value->stx_mask & REQUIRED_MASK) == REQUIRED_MASK &&
           S_ISLNK(value->stx_mode) && value->stx_size == 6;
}

/* Compare fields guaranteed by the required mask plus the device identity. */
static int same_selected_metadata(const struct statx *left,
                                  const struct statx *right)
{
    return left->stx_dev_major == right->stx_dev_major &&
           left->stx_dev_minor == right->stx_dev_minor &&
           left->stx_ino == right->stx_ino && left->stx_mode == right->stx_mode &&
           left->stx_size == right->stx_size;
}

int main(void)
{
    char template[] = "/tmp/crabc-x86-statx-XXXXXX";
    char absolute[sizeof(template) + sizeof("/record")];
    char *root = mkdtemp(template);
    struct statx musl_record;
    struct statx raw_record;
    struct statx musl_absolute;
    struct statx raw_absolute;
    struct statx musl_follow;
    struct statx raw_follow;
    struct statx musl_nofollow;
    struct statx raw_nofollow;
    struct statx musl_empty_path;
    struct statx raw_empty_path;
    struct call_result result;
    int absolute_length;
    int dirfd = -1;
    int fd = -1;
    int raw_available = 0;
    int status = 0;

    if (root == NULL)
        return 2;
    dirfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        status = 3;
        goto cleanup;
    }
    fd = openat(dirfd, "record", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
                RECORD_MODE);
    if (fd < 0 || write(fd, "record", 6) != 6 || fchmod(fd, RECORD_MODE) != 0) {
        status = 4;
        goto cleanup;
    }
    if (symlinkat("record", dirfd, "link") != 0) {
        status = 5;
        goto cleanup;
    }
    absolute_length = snprintf(absolute, sizeof(absolute), "%s/record", root);
    if (absolute_length < 0 || absolute_length >= (int)sizeof(absolute)) {
        status = 6;
        goto cleanup;
    }

    /* Pinned musl is the normal descriptor-relative path-call oracle. */
    result = musl_statx(dirfd, "record", AT_STATX_SYNC_AS_STAT, REQUEST_MASK,
                        &musl_record);
    if (result.value != 0 || !has_regular_metadata(&musl_record)) {
        status = 7;
        goto cleanup;
    }

    /* Raw is a separate direct syscall ABI observation, not a musl fallback. */
    result = raw_statx(dirfd, "record", AT_STATX_SYNC_AS_STAT, REQUEST_MASK,
                       &raw_record);
    if (result.value == 0) {
        raw_available = 1;
        if (!has_regular_metadata(&raw_record) ||
            !same_selected_metadata(&musl_record, &raw_record)) {
            status = 8;
            goto cleanup;
        }
    } else if (!expected_error(result, ENOSYS)) {
        status = 9;
        goto cleanup;
    }

    result = musl_statx(AT_FDCWD, absolute, AT_STATX_SYNC_AS_STAT, REQUEST_MASK,
                        &musl_absolute);
    if (result.value != 0 || !has_regular_metadata(&musl_absolute) ||
        !same_selected_metadata(&musl_record, &musl_absolute)) {
        status = 10;
        goto cleanup;
    }
    if (raw_available) {
        result = raw_statx(AT_FDCWD, absolute, AT_STATX_SYNC_AS_STAT,
                           REQUEST_MASK, &raw_absolute);
        if (result.value != 0 || !has_regular_metadata(&raw_absolute) ||
            !same_selected_metadata(&musl_absolute, &raw_absolute)) {
            status = 11;
            goto cleanup;
        }
    }

    result = musl_statx(dirfd, "link", AT_STATX_SYNC_AS_STAT, REQUEST_MASK,
                        &musl_follow);
    if (result.value != 0 || !has_regular_metadata(&musl_follow) ||
        !same_selected_metadata(&musl_record, &musl_follow)) {
        status = 12;
        goto cleanup;
    }
    if (raw_available) {
        result = raw_statx(dirfd, "link", AT_STATX_SYNC_AS_STAT, REQUEST_MASK,
                           &raw_follow);
        if (result.value != 0 || !has_regular_metadata(&raw_follow) ||
            !same_selected_metadata(&musl_follow, &raw_follow)) {
            status = 13;
            goto cleanup;
        }
    }

    result = musl_statx(dirfd, "link", AT_SYMLINK_NOFOLLOW, REQUEST_MASK,
                        &musl_nofollow);
    if (result.value != 0 || !has_symlink_metadata(&musl_nofollow) ||
        musl_nofollow.stx_ino == musl_record.stx_ino) {
        status = 14;
        goto cleanup;
    }
    if (raw_available) {
        result = raw_statx(dirfd, "link", AT_SYMLINK_NOFOLLOW, REQUEST_MASK,
                           &raw_nofollow);
        if (result.value != 0 || !has_symlink_metadata(&raw_nofollow) ||
            !same_selected_metadata(&musl_nofollow, &raw_nofollow)) {
            status = 15;
            goto cleanup;
        }
    }

    /* `statx` admits an open descriptor through its own empty-path flag. */
    result = musl_statx(fd, "", AT_EMPTY_PATH, REQUEST_MASK, &musl_empty_path);
    if (result.value != 0 || !has_regular_metadata(&musl_empty_path) ||
        !same_selected_metadata(&musl_record, &musl_empty_path)) {
        status = 16;
        goto cleanup;
    }
    if (raw_available) {
        result = raw_statx(fd, "", AT_EMPTY_PATH, REQUEST_MASK,
                           &raw_empty_path);
        if (result.value != 0 || !has_regular_metadata(&raw_empty_path) ||
            !same_selected_metadata(&musl_empty_path, &raw_empty_path)) {
            status = 17;
            goto cleanup;
        }
    }

    result = musl_statx(fd, "", AT_STATX_SYNC_AS_STAT, REQUEST_MASK,
                        &musl_empty_path);
    if (!expected_error(result, ENOENT)) {
        status = 18;
        goto cleanup;
    }
    if (raw_available) {
        result = raw_statx(fd, "", AT_STATX_SYNC_AS_STAT, REQUEST_MASK,
                           &raw_empty_path);
        if (!expected_error(result, ENOENT)) {
            status = 19;
            goto cleanup;
        }
    }

    result = musl_statx(dirfd, "missing", AT_STATX_SYNC_AS_STAT, REQUEST_MASK,
                        &musl_record);
    if (!expected_error(result, ENOENT)) {
        status = 20;
        goto cleanup;
    }
    if (raw_available) {
        result = raw_statx(dirfd, "missing", AT_STATX_SYNC_AS_STAT,
                           REQUEST_MASK, &raw_record);
        if (!expected_error(result, ENOENT)) {
            status = 21;
            goto cleanup;
        }
    }

    result = musl_statx(dirfd, "record",
                        AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC, REQUEST_MASK,
                        &musl_record);
    if (!expected_error(result, EINVAL)) {
        status = 22;
        goto cleanup;
    }
    if (raw_available) {
        result = raw_statx(dirfd, "record",
                           AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC,
                           REQUEST_MASK, &raw_record);
        if (!expected_error(result, EINVAL)) {
            status = 23;
            goto cleanup;
        }
        result = musl_statx(dirfd, "record", AT_STATX_SYNC_AS_STAT,
                            STATX__RESERVED, &musl_record);
        if (!expected_error(result, EINVAL)) {
            status = 24;
            goto cleanup;
        }
        result = raw_statx(dirfd, "record", AT_STATX_SYNC_AS_STAT,
                           STATX__RESERVED, &raw_record);
        if (!expected_error(result, EINVAL)) {
            status = 25;
            goto cleanup;
        }
    }

cleanup:
    if (dirfd >= 0) {
        if (unlinkat(dirfd, "link", 0) != 0 && errno != ENOENT && status == 0)
            status = 26;
        if (unlinkat(dirfd, "record", 0) != 0 && errno != ENOENT && status == 0)
            status = 27;
    }
    if (fd >= 0 && close(fd) != 0 && status == 0)
        status = 28;
    if (dirfd >= 0 && close(dirfd) != 0 && status == 0)
        status = 29;
    if (rmdir(template) != 0 && status == 0)
        status = 30;
    if (status != 0)
        return status;

    if (raw_available) {
        puts("statx=332 layout=size256:align8:offsets-through-dio156 at=fdcwd:-100:nofollow:0x100:no-automount:0x800:empty-path:0x1000:force-sync:0x2000:dont-sync:0x4000 mask=basic:0x7ff:btime:0x800:mnt-id:0x1000:dioalign:0x2000:reserved:0x80000000 musl=path:absolute:follow:nofollow:empty-path raw=matches-musl errors=empty-without-flag:ENOENT:missing:ENOENT:sync-conflict:EINVAL:reserved-mask:EINVAL c-api-selection=excluded");
    } else {
        puts("statx=332 layout=size256:align8:offsets-through-dio156 at=fdcwd:-100:nofollow:0x100:no-automount:0x800:empty-path:0x1000:force-sync:0x2000:dont-sync:0x4000 mask=basic:0x7ff:btime:0x800:mnt-id:0x1000:dioalign:0x2000:reserved:0x80000000 musl=path:absolute:follow:nofollow:empty-path raw=ENOSYS-musl-fallback errors=empty-without-flag:ENOENT:missing:ENOENT:sync-conflict:EINVAL direct-mask-errors=unavailable c-api-selection=excluded");
    }
    return 0;
}
