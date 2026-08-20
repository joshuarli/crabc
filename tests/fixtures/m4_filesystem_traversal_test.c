#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int selected_txt;
static int traversal_calls;
static int traversal_dirs;
static int traversal_files;
static int traversal_depth;
static int glob_errors;
static int chdir_callbacks;
static int chdir_cwd_matches;
static int chdir_callback_changed;

static int select_txt(const struct dirent *entry)
{
    size_t length = strlen(entry->d_name);
    selected_txt += length >= 4 && strcmp(entry->d_name + length - 4, ".txt") == 0;
    return length >= 4 && strcmp(entry->d_name + length - 4, ".txt") == 0;
}

static int report_glob_error(const char *path, int error)
{
    (void)path;
    (void)error;
    glob_errors++;
    return 0;
}

static int visit_ftw(const char *path, const struct stat *st, int type)
{
    (void)path;
    (void)st;
    traversal_calls++;
    if (type == FTW_D)
        traversal_dirs++;
    if (type == FTW_F)
        traversal_files++;
    return 0;
}

static int visit_nftw(const char *path, const struct stat *st, int type, struct FTW *info)
{
    (void)path;
    (void)st;
    if (type == FTW_DP)
        traversal_depth++;
    if (info->level < 0 || info->base < 0)
        return 99;
    return 0;
}

static int visit_nftw_chdir(const char *path, const struct stat *st, int type, struct FTW *info)
{
    char cwd[256];
    char expected[256];
    char *slash;
    (void)st;
    (void)info;
    chdir_callbacks++;
    if (!getcwd(cwd, sizeof cwd))
        return 91;
    snprintf(expected, sizeof expected, "%s", path);
    slash = strrchr(expected, '/');
    if (type == FTW_D || type == FTW_DP) {
        /* Directory callbacks run after entering that directory. */
    } else if (slash && slash != expected) {
        *slash = 0;
    } else if (slash == expected) {
        slash[1] = 0;
    } else {
        snprintf(expected, sizeof expected, ".");
    }
    if (strcmp(cwd, expected) == 0)
        chdir_cwd_matches++;
    if (!chdir_callback_changed && type == FTW_D) {
        chdir_callback_changed = 1;
        if (chdir("/") != 0)
            return 92;
    }
    return 0;
}

static int visit_nftw_chdir_abort(const char *path, const struct stat *st, int type, struct FTW *info)
{
    (void)path;
    (void)st;
    (void)type;
    (void)info;
    return 77;
}

int main(void)
{
    char template[] = "/tmp/crabc-m4-traversal-XXXXXX";
    char pattern[256];
    char nested[256];
    char file_a[256];
    char file_b[256];
    char file_c[256];
    char file_nested[256];
    char nested_mark[256];
    char tilde_match[256];
    struct dirent **entries = NULL;
    struct dirent **selected = NULL;
    struct stat st;
    char before_cwd[256];
    char after_cwd[256];
    glob_t matches = {0};
    glob_t appended = {0};
    int fd;
    int count;
    int selected_count;
    size_t i;

    if (!mkdtemp(template))
        return 1;
    snprintf(nested, sizeof nested, "%s/nested", template);
    snprintf(file_a, sizeof file_a, "%s/a.txt", template);
    snprintf(file_b, sizeof file_b, "%s/b.txt", template);
    snprintf(file_c, sizeof file_c, "%s/c.bin", template);
    snprintf(file_nested, sizeof file_nested, "%s/nested/inside.txt", template);
    snprintf(nested_mark, sizeof nested_mark, "%s/", nested);
    if (mkdir(nested, 0700) != 0)
        return 2;
    fd = open(file_b, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return 3;
    close(fd);
    fd = open(file_a, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return 4;
    close(fd);
    fd = open(file_c, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return 5;
    close(fd);
    fd = open(file_nested, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return 6;
    close(fd);

    count = scandir(template, &entries, NULL, alphasort);
    if (count < 5 || !entries || strcmp(entries[0]->d_name, ".") != 0 ||
        strcmp(entries[1]->d_name, "..") != 0)
        return 7;
    for (i = 0; i < (size_t)count; i++)
        free(entries[i]);
    free(entries);
    entries = NULL;

    selected_count = scandir(template, &selected, select_txt, alphasort);
    if (selected_count != 2 || selected_count != selected_txt || !selected)
        return 8;
    for (i = 0; i < (size_t)selected_count; i++)
        free(selected[i]);
    free(selected);
    selected = NULL;
    if (scandir("/tmp/crabc-m4-traversal-no-such-directory", &entries, NULL, NULL) != -1)
        return 9;

    snprintf(pattern, sizeof pattern, "%s/*.txt", template);
    if (glob(pattern, 0, NULL, &matches) != 0 || matches.gl_pathc != 2 ||
        strcmp(matches.gl_pathv[0], file_a) != 0 || strcmp(matches.gl_pathv[1], file_b) != 0)
        return 10;
    globfree(&matches);
    if (matches.gl_pathc != 0 || matches.gl_pathv != NULL)
        return 11;

    snprintf(pattern, sizeof pattern, "%s/no-match-*", template);
    if (glob(pattern, 0, NULL, &matches) != GLOB_NOMATCH)
        return 12;
    if (glob(pattern, GLOB_NOCHECK, NULL, &matches) != 0 || matches.gl_pathc != 1 ||
        strcmp(matches.gl_pathv[0], pattern) != 0)
        return 13;
    globfree(&matches);

    snprintf(pattern, sizeof pattern, "%s/*", template);
    if (glob(pattern, GLOB_MARK, NULL, &matches) != 0 || matches.gl_pathc != 4)
        return 14;
    if (strcmp(matches.gl_pathv[3], nested_mark) != 0)
        return 15;
    globfree(&matches);

    snprintf(pattern, sizeof pattern, "%s/a.txt", template);
    if (glob(pattern, 0, NULL, &appended) != 0 || appended.gl_pathc != 1)
        return 16;
    snprintf(pattern, sizeof pattern, "%s/b.txt", template);
    if (glob(pattern, GLOB_APPEND, NULL, &appended) != 0 || appended.gl_pathc != 2)
        return 17;
    globfree(&appended);

    {
        char saved_home[256];
        char current_home[256];
        const char *old_home = getenv("HOME");
        struct passwd *current_user;
        if (old_home) {
            if (strlen(old_home) >= sizeof saved_home)
                return 24;
            snprintf(saved_home, sizeof saved_home, "%s", old_home);
        }
        if (setenv("HOME", template, 1) != 0)
            return 25;
        snprintf(pattern, sizeof pattern, "~/a.txt");
        snprintf(tilde_match, sizeof tilde_match, "%s/a.txt", template);
        if (glob(pattern, GLOB_TILDE, NULL, &matches) != 0 || matches.gl_pathc != 1 ||
            strcmp(matches.gl_pathv[0], tilde_match) != 0)
            return 26;
        globfree(&matches);
        if (unsetenv("HOME") != 0)
            return 27;
        current_user = getpwuid(getuid());
        if (!current_user || !current_user->pw_dir)
            return 28;
        if (strlen(current_user->pw_dir) >= sizeof current_home)
            return 37;
        snprintf(current_home, sizeof current_home, "%s", current_user->pw_dir);
        if (stat(current_home, &st) != 0)
            return 47;
        {
            int tilde_result = glob("~", GLOB_TILDE_CHECK, NULL, &matches);
            if (tilde_result != 0 || matches.gl_pathc != 1 ||
                strcmp(matches.gl_pathv[0], current_home) != 0) {
                return 29;
            }
        }
        globfree(&matches);
        if (!current_user->pw_name || strlen(current_user->pw_name) >= sizeof pattern)
            return 35;
        snprintf(pattern, sizeof pattern, "~%s", current_user->pw_name);
        if (glob(pattern, GLOB_TILDE_CHECK, NULL, &matches) != 0 || matches.gl_pathc != 1 ||
            strcmp(matches.gl_pathv[0], current_home) != 0)
            return 36;
        globfree(&matches);
        if (glob("~crabc-user-that-does-not-exist", GLOB_TILDE_CHECK, NULL, &matches) !=
                GLOB_NOMATCH)
            return 30;
        if (glob("~crabc-user-that-does-not-exist", GLOB_TILDE, NULL, &matches) !=
                GLOB_NOMATCH)
            return 33;
        if (old_home) {
            if (setenv("HOME", saved_home, 1) != 0)
                return 31;
        } else if (unsetenv("HOME") != 0) {
            return 32;
        }
    }

    glob_errors = 0;
    if (glob("/tmp/crabc-m4-traversal-no-such-directory/*", GLOB_ERR,
             report_glob_error, &matches) != GLOB_ABORTED || glob_errors == 0)
        return 18;

    traversal_calls = traversal_dirs = traversal_files = 0;
    if (ftw(template, visit_ftw, 8) != 0 || traversal_calls < 5 ||
        traversal_dirs < 2 || traversal_files < 4)
        return 19;
    traversal_depth = 0;
    if (nftw(template, visit_nftw, 8, FTW_PHYS | FTW_DEPTH) != 0 || traversal_depth < 2)
        return 20;

    if (!getcwd(before_cwd, sizeof before_cwd))
        return 22;
    chdir_callbacks = chdir_cwd_matches = chdir_callback_changed = 0;
    {
        int chdir_result = nftw(template, visit_nftw_chdir, 8, FTW_PHYS | FTW_CHDIR);
        if (chdir_result != 0)
            return 23;
        if (chdir_callbacks < 5)
            return 23;
        if (chdir_cwd_matches != chdir_callbacks)
            return 23;
        if (!chdir_callback_changed)
            return 23;
        if (!getcwd(after_cwd, sizeof after_cwd))
            return 23;
        if (strcmp(before_cwd, after_cwd) != 0)
            return 23;
    }
    if (nftw(template, visit_nftw_chdir_abort, 8, FTW_PHYS | FTW_CHDIR) != 77 ||
        !getcwd(after_cwd, sizeof after_cwd) || strcmp(before_cwd, after_cwd) != 0)
        return 34;

    if (stat(file_nested, &st) != 0 || unlink(file_nested) != 0 ||
        rmdir(nested) != 0 || unlink(file_a) != 0 || unlink(file_b) != 0 ||
        unlink(file_c) != 0 || rmdir(template) != 0)
        return 21;

    puts("m4 filesystem traversal ok");
    return 0;
}
