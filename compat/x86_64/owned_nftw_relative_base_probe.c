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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int dot_visits;
static int directory_visits;
static int file_visits;

struct walk_record {
    char path[64];
    int kind;
    int base;
    int level;
    int position;
    int callback_errno;
};

static struct walk_record records[32];
static int record_count;
static int record_error;
static int legacy_walk;

static int record_visit(const char *path, const struct stat *metadata, int kind,
    int base, int level)
{
    struct walk_record *record;
    size_t length = strlen(path);

    if (metadata == NULL || length >= sizeof(records[0].path) ||
        record_count == (int)(sizeof(records) / sizeof(records[0]))) {
        record_error = 1;
        return 81;
    }
    record = &records[record_count];
    memcpy(record->path, path, length + 1);
    record->kind = kind;
    record->base = base;
    record->level = level;
    record->position = record_count++;
    record->callback_errno = errno;
    if (!legacy_walk && (base < 0 || (size_t)base > length ||
        (length && path[length - 1] != '/' &&
        strcmp(path + base, strrchr(path, '/') ? strrchr(path, '/') + 1 : path)))) {
        record_error = 1;
    }
    return 0;
}

static int extended_visit(const char *path, const struct stat *metadata, int kind,
    struct FTW *info)
{
    if (info == NULL) return 82;
    return record_visit(path, metadata, kind, info->base, info->level);
}

static int legacy_visit(const char *path, const struct stat *metadata, int kind)
{
    return record_visit(path, metadata, kind, -1, -1);
}

static const struct walk_record *find_record(const char *path)
{
    int index;

    for (index = 0; index < record_count; ++index) {
        if (!strcmp(records[index].path, path)) return &records[index];
    }
    return NULL;
}

static int check_walk(int flags, int limit, int legacy)
{
    const struct walk_record *root, *tree, *file, *link, *denied, *loop, *dangling;
    int result;

    record_count = record_error = 0;
    legacy_walk = legacy;
    errno = E2BIG;
    result = legacy ? ftw("tree", legacy_visit, limit) :
        nftw("tree", extended_visit, limit, flags);
    if (result != 0 || record_error) return 1;
    root = find_record("tree");
    tree = find_record("tree/branch");
    file = find_record("tree/branch/file");
    link = find_record("tree/branch/file-link");
    denied = find_record("tree/branch/denied");
    loop = find_record("tree/branch/loop");
    dangling = find_record("tree/branch/dangling");
    if (!root || !tree || !file || !link || !denied || !loop || !dangling ||
        record_count != 7 || root->level != (legacy ? -1 : 0) ||
        (!legacy && (tree->level != 1 || file->level != 2 ||
            root->base != 0 || tree->base != 5 || file->base != 12))) return 2;
    if (file->kind != FTW_F || link->kind != ((flags & FTW_PHYS || legacy) ? FTW_SL : FTW_F) ||
        denied->kind != FTW_DNR || denied->callback_errno != EACCES ||
        dangling->kind != ((flags & FTW_PHYS || legacy) ? FTW_SL : FTW_SLN) ||
        (!(flags & FTW_PHYS || legacy) && dangling->callback_errno != ENOENT) ||
        loop->kind != ((flags & FTW_PHYS || legacy) ? FTW_SL :
            ((flags & FTW_DEPTH) ? FTW_DP : FTW_D))) return 3;
    if ((flags & FTW_DEPTH) && !legacy) {
        if (file->position >= tree->position || tree->position >= root->position ||
            denied->position >= tree->position || loop->position >= tree->position)
            return 4;
    } else if (root->position >= tree->position || tree->position >= file->position ||
        tree->position >= denied->position || tree->position >= loop->position) {
        return 5;
    }
    return 0;
}

static int abort_visits;

static int stop_visit(const char *path, const struct stat *metadata, int kind,
    struct FTW *info)
{
    if (strcmp(path, "tree") || metadata == NULL || kind != FTW_D ||
        info == NULL || info->base != 0 || info->level != 0) return 83;
    ++abort_visits;
    errno = EINTR;
    return 37;
}

static int check_errors(void)
{
    int result;

    abort_visits = 0;
    errno = E2BIG;
    result = nftw("missing", stop_visit, 0, FTW_PHYS);
    if (result != 0 || errno != E2BIG || abort_visits != 0) return 1;
    result = nftw("missing", stop_visit, 2, FTW_PHYS);
    if (result != -1 || errno != ENOENT || abort_visits != 0) return 2;
    errno = E2BIG;
    result = nftw("tree", stop_visit, 2, FTW_PHYS);
    if (result != 37 || abort_visits != 1 || errno != EINTR) return 3;
    errno = E2BIG;
    result = nftw(NULL, NULL, 0, FTW_PHYS);
    if (result != 0 || errno != E2BIG) return 4;
    result = ftw(NULL, NULL, 0);
    if (result != 0 || errno != E2BIG) return 5;
    result = nftw(NULL, NULL, -1, FTW_PHYS);
    if (result != 0 || errno != E2BIG) return 6;
    result = ftw(NULL, NULL, -1);
    if (result != 0 || errno != E2BIG) return 7;
    return 0;
}

static int chdir_visits;

static int chdir_visit(const char *path, const struct stat *metadata, int kind,
    struct FTW *info)
{
    char cwd[128];
    const char *expected = !strcmp(path, "tree") ? "/cases/tree" :
        "/cases/tree/branch";

    if (metadata == NULL || info == NULL || getcwd(cwd, sizeof(cwd)) == NULL ||
        strcmp(cwd, expected)) return 84;
    ++chdir_visits;
    if (chdir("/") != 0) return 85;
    return 0;
}

static int chdir_stop(const char *path, const struct stat *metadata, int kind,
    struct FTW *info)
{
    (void)path;
    (void)metadata;
    (void)kind;
    (void)info;
    if (chdir("/") != 0) return 85;
    return 37;
}

static int check_chdir(void)
{
    char cwd[128];

    chdir_visits = 0;
    if (nftw("tree", chdir_visit, 3, FTW_PHYS | FTW_CHDIR) != 0 ||
        chdir_visits != 7 || getcwd(cwd, sizeof(cwd)) == NULL ||
        strcmp(cwd, "/cases")) return 1;
    if (nftw("tree", chdir_stop, 3, FTW_PHYS | FTW_CHDIR) != 37 ||
        getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/cases")) return 2;
    return 0;
}

static int compare_matrix(void)
{
    static const struct {
        const char *path;
        int limit;
        int flags;
        int legacy;
    } cases[] = {
        { "tree", 1, FTW_PHYS, 0 },
        { "tree", 2, FTW_PHYS, 0 },
        { "tree", 3, FTW_PHYS, 0 },
        { "tree", 3, 0, 0 },
        { "tree", 3, FTW_PHYS | FTW_DEPTH, 0 },
        { "tree", 3, FTW_DEPTH, 0 },
        { "tree/", 2, FTW_PHYS, 0 },
        { "tree/branch/loop", 2, 0, 0 },
        { "tree/branch/dangling", 2, 0, 0 },
        { "tree/branch/denied/child", 2, FTW_PHYS, 0 },
        { "missing", 2, FTW_PHYS, 0 },
        { "tree", 0, FTW_PHYS, 0 },
        { "tree", 1, 0, 1 },
        { "tree", 3, 0, 1 },
    };
    size_t case_index;

    for (case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]); ++case_index) {
        int result, final_errno, record_index;

        record_count = record_error = 0;
        legacy_walk = cases[case_index].legacy;
        errno = E2BIG;
        result = legacy_walk ? ftw(cases[case_index].path, legacy_visit,
            cases[case_index].limit) : nftw(cases[case_index].path,
            extended_visit, cases[case_index].limit, cases[case_index].flags);
        final_errno = errno;
        if (record_error) return 1;
        printf("case %zu %s %d %d %d %d %d %d\n", case_index,
            cases[case_index].path, cases[case_index].limit,
            cases[case_index].flags, cases[case_index].legacy,
            result, final_errno, record_count);
        for (record_index = 0; record_index < record_count; ++record_index) {
            const struct walk_record *record = &records[record_index];
            printf("visit %s %d %d %d %d\n", record->path, record->kind,
                record->base, record->level, record->callback_errno);
        }
    }
    return 0;
}

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

int main(int argc, char **argv)
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
    if (chdir("/cases") != 0 || setuid(65534) != 0) return 2;
    if (check_walk(FTW_PHYS, 3, 0) || check_walk(0, 3, 0) ||
        check_walk(FTW_PHYS | FTW_DEPTH, 3, 0) ||
        check_walk(FTW_PHYS, 3, 1) || check_errors() || compare_matrix()) {
        (void)write_all(STDERR_FILENO, "nftw-relative-base differential failed\n");
        return 3;
    }
    if (argc == 2 && !strcmp(argv[1], "--chdir") && check_chdir()) {
        (void)write_all(STDERR_FILENO, "nftw-relative-base chdir failed\n");
        return 4;
    }
    if (printf("nftw-relative-base-ok\n") < 0 || fflush(stdout) != 0) {
        return 1;
    }
    return 0;
}
