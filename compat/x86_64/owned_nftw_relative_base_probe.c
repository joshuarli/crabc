/*
 * Installed x86 nftw relative-path FTW.base regression.
 *
 * This is the bounded callback contract exercised by the retained os-test
 * basic/ftw/nftw.c fixture.  The runner supplies an otherwise empty /work
 * containing only ftw/nftw; this probe enters that directory itself and keeps
 * the fixture's nftw(".", ..., FTW_DEPTH) spelling intact.  In particular,
 * it does not turn the callback paths into absolute names before checking the
 * callback metadata.
 */

#include <ftw.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int dot_visits;
static int directory_visits;
static int file_visits;

static int write_all(int descriptor, const char *text)
{
    size_t length = 0;

    while (text[length] != '\0') {
        ++length;
    }
    while (length != 0) {
        ssize_t written = write(descriptor, text, length);
        if (written <= 0) {
            return -1;
        }
        text += written;
        length -= (size_t)written;
    }
    return 0;
}

static int visit(const char *path, const struct stat *metadata, int type,
    struct FTW *info)
{
    if (path == NULL || metadata == NULL || info == NULL) {
        return 91;
    }
    if (!strcmp(path, "./ftw/nftw")) {
        if (type != FTW_F || !S_ISREG(metadata->st_mode) || info->base != 6 ||
            info->level != 2 || strcmp(path + info->base, "nftw")) {
            return 92;
        }
        ++file_visits;
        return 0;
    }
    if (!strcmp(path, "./ftw")) {
        if (type != FTW_DP || !S_ISDIR(metadata->st_mode) || info->base != 2 ||
            info->level != 1 || strcmp(path + info->base, "ftw")) {
            return 93;
        }
        ++directory_visits;
        return 0;
    }
    if (!strcmp(path, ".")) {
        if (type != FTW_DP || !S_ISDIR(metadata->st_mode) || info->base != 0 ||
            info->level != 0 || strcmp(path + info->base, ".")) {
            return 94;
        }
        ++dot_visits;
        return 0;
    }
    return 95;
}

int main(void)
{
    int result;

    if (chdir("/work") != 0) {
        (void)write_all(STDERR_FILENO, "nftw-relative-base fixture CWD failed\n");
        return 1;
    }
    result = nftw(".", visit, 1024, FTW_DEPTH);
    if (result != 0 || dot_visits != 1 || directory_visits != 1 || file_visits != 1) {
        (void)write_all(STDERR_FILENO, "nftw-relative-base callback metadata failed\n");
        return 1;
    }
    if (write_all(STDOUT_FILENO, "nftw-relative-base-ok\n") != 0) {
        return 1;
    }
    return 0;
}
