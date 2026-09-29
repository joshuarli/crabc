/* Native Linux/x86-64 POSIX spawn file-actions lifecycle evidence.
 *
 * This fixture observes the opaque action list's musl representation and
 * insertion order.  It never executes a spawn, fork, vfork, clone, or exec.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>

struct crabc_fdop {
    struct crabc_fdop *next;
    struct crabc_fdop *prev;
    int cmd;
    int fd;
    int srcfd;
    int oflag;
    mode_t mode;
    char path[];
};

_Static_assert(sizeof(posix_spawn_file_actions_t) == 80,
               "posix_spawn_file_actions_t size");
_Static_assert(__alignof__(posix_spawn_file_actions_t) == 8,
               "posix_spawn_file_actions_t alignment");
_Static_assert(__builtin_offsetof(posix_spawn_file_actions_t, __actions) == 8,
               "posix_spawn_file_actions_t actions offset");
_Static_assert(__builtin_offsetof(struct crabc_fdop, path) == 36,
               "musl fdop path offset");

typedef int (*file_actions_init_fn)(posix_spawn_file_actions_t *);
typedef int (*file_actions_destroy_fn)(posix_spawn_file_actions_t *);
typedef int (*file_actions_addclose_fn)(posix_spawn_file_actions_t *, int);
typedef int (*file_actions_adddup2_fn)(posix_spawn_file_actions_t *, int, int);
typedef int (*file_actions_addopen_fn)(posix_spawn_file_actions_t *, int,
                                       const char *, int, mode_t);
typedef int (*file_actions_addchdir_fn)(posix_spawn_file_actions_t *,
                                        const char *);
typedef int (*file_actions_addfchdir_fn)(posix_spawn_file_actions_t *, int);

static int check_action(const struct crabc_fdop *op, int cmd, int fd,
                        int srcfd, int oflag, mode_t mode, const char *path)
{
    /* Musl leaves fields unused by an action uninitialized. */
    if (!op || op->cmd != cmd || op->fd != fd ||
        (cmd == 2 && op->srcfd != srcfd) ||
        (cmd == 3 && (op->oflag != oflag || op->mode != mode)))
        return 0;
    if (path) {
        const char *left = op->path;
        while (*left || *path) {
            if (*left++ != *path++)
                return 0;
        }
    }
    return 1;
}

static int check_reused_descriptor_actions(void)
{
    static const struct {
        int cmd;
        int fd;
        int srcfd;
        int oflag;
        mode_t mode;
        const char *path;
    } expected[] = {
        { 2, 3, 11, 0, 0, 0 },
        { 1, 3, 0, 0, 0, 0 },
        { 3, 3, 0, O_WRONLY | O_CREAT | O_TRUNC, 0600,
          "/tmp/crabc-spawn-first" },
        { 2, 1, 3, 0, 0, 0 },
        { 1, 3, 0, 0, 0, 0 },
        { 3, 3, 0, O_RDONLY, 0, "/tmp/crabc-spawn-second" },
        { 2, 2, 3, 0, 0, 0 },
    };
    posix_spawn_file_actions_t actions;
    const struct crabc_fdop *ordered[sizeof(expected) / sizeof(expected[0])];
    const struct crabc_fdop *operation;
    const struct crabc_fdop *head;
    char first_path[] = "/tmp/crabc-spawn-first";
    char second_path[] = "/tmp/crabc-spawn-second";
    int saved_errno;
    int index;

    if (posix_spawn_file_actions_init(&actions) != 0 || actions.__actions)
        return 20;
    errno = E2BIG;
    saved_errno = errno;

    if (posix_spawn_file_actions_adddup2(&actions, 11, 3) != 0 ||
        errno != saved_errno)
        return 21;
    if (posix_spawn_file_actions_addclose(&actions, 3) != 0 ||
        errno != saved_errno)
        return 22;
    if (posix_spawn_file_actions_addopen(&actions, 3, first_path,
            O_WRONLY | O_CREAT | O_TRUNC, 0600) != 0 || errno != saved_errno)
        return 23;
    first_path[5] = 'X';
    if (posix_spawn_file_actions_adddup2(&actions, 3, 1) != 0 ||
        errno != saved_errno)
        return 24;
    if (posix_spawn_file_actions_addclose(&actions, 3) != 0 ||
        errno != saved_errno)
        return 25;
    if (posix_spawn_file_actions_addopen(&actions, 3, second_path,
            O_RDONLY, 0) != 0 || errno != saved_errno)
        return 26;
    second_path[5] = 'Y';
    if (posix_spawn_file_actions_adddup2(&actions, 3, 2) != 0 ||
        errno != saved_errno)
        return 27;

    head = (const struct crabc_fdop *)actions.__actions;
    if (posix_spawn_file_actions_addclose(&actions, -1) != EBADF ||
        errno != saved_errno || actions.__actions != head)
        return 28;
    if (posix_spawn_file_actions_adddup2(&actions, -1, 3) != EBADF ||
        errno != saved_errno || actions.__actions != head)
        return 29;
    if (posix_spawn_file_actions_adddup2(&actions, 3, -1) != EBADF ||
        errno != saved_errno || actions.__actions != head)
        return 30;
    if (posix_spawn_file_actions_addopen(&actions, -1, 0, O_RDONLY, 0)
            != EBADF || errno != saved_errno || actions.__actions != head)
        return 31;
    if (posix_spawn_file_actions_addfchdir_np(&actions, -1) != EBADF ||
        errno != saved_errno || actions.__actions != head)
        return 32;

    operation = head;
    for (index = (int)(sizeof(expected) / sizeof(expected[0])) - 1;
         index >= 0; --index) {
        if (!operation)
            return 33;
        ordered[index] = operation;
        operation = operation->next;
    }
    if (operation)
        return 34;
    for (index = 0; index < (int)(sizeof(expected) / sizeof(expected[0]));
         ++index) {
        const struct crabc_fdop *older = index ? ordered[index - 1] : 0;
        const struct crabc_fdop *newer =
            index + 1 < (int)(sizeof(expected) / sizeof(expected[0]))
                ? ordered[index + 1] : 0;
        operation = ordered[index];
        if (operation->next != older || operation->prev != newer ||
            !check_action(operation, expected[index].cmd,
                          expected[index].fd, expected[index].srcfd,
                          expected[index].oflag, expected[index].mode,
                          expected[index].path)) {
            fprintf(stderr, "action mismatch %d\n", index);
            return 35;
        }
    }

    /* The executor reaches the oldest node through next, then follows prev. */
    operation = ordered[0];
    for (index = 0; index < (int)(sizeof(expected) / sizeof(expected[0]));
         ++index) {
        if (operation != ordered[index])
            return 36;
        if (printf("action %d %d %d %d %u %s\n", operation->cmd,
                   operation->fd,
                   operation->cmd == 2 ? operation->srcfd : 0,
                   operation->cmd == 3 ? operation->oflag : 0,
                   operation->cmd == 3 ? (unsigned)operation->mode : 0,
                   expected[index].path ? operation->path : "-") < 0)
            return 36;
        operation = operation->prev;
    }
    if (operation)
        return 36;
    if (fflush(stdout) != 0)
        return 37;

    errno = E2BIG;
    if (posix_spawn_file_actions_destroy(&actions) != 0 || errno != E2BIG ||
        actions.__actions != head)
        return 38;
    if (posix_spawn_file_actions_init(&actions) != 0 || actions.__actions)
        return 39;
    if (posix_spawn_file_actions_destroy(&actions) != 0 || actions.__actions)
        return 40;
    return 0;
}

int crabc_x86_64_posix_spawn_file_actions_probe(void)
{
    posix_spawn_file_actions_t actions;
    file_actions_init_fn init = posix_spawn_file_actions_init;
    file_actions_destroy_fn destroy = posix_spawn_file_actions_destroy;
    file_actions_addclose_fn addclose = posix_spawn_file_actions_addclose;
    file_actions_adddup2_fn adddup2 = posix_spawn_file_actions_adddup2;
    file_actions_addopen_fn addopen = posix_spawn_file_actions_addopen;
    file_actions_addchdir_fn addchdir = posix_spawn_file_actions_addchdir_np;
    file_actions_addfchdir_fn addfchdir = posix_spawn_file_actions_addfchdir_np;
    struct crabc_fdop *fchdir;
    struct crabc_fdop *chdir;
    struct crabc_fdop *open;
    struct crabc_fdop *dup2;
    struct crabc_fdop *close;
    struct crabc_fdop *head;
    int saved_errno;

    if (init(&actions) != 0)
        return 1;
    if (actions.__actions != 0)
        return 2;

    errno = E2BIG;
    saved_errno = errno;
    if (addclose(&actions, 4) != 0 || errno != saved_errno)
        return 3;
    close = (struct crabc_fdop *)actions.__actions;
    if (!check_action(close, 1, 4, 0, 0, 0, 0) || close->next || close->prev)
        return 4;

    if (adddup2(&actions, 5, 6) != 0 || errno != saved_errno)
        return 5;
    dup2 = (struct crabc_fdop *)actions.__actions;
    if (!check_action(dup2, 2, 6, 5, 0, 0, 0) || dup2->prev ||
        dup2->next != close || close->prev != dup2)
        return 6;

    if (addopen(&actions, 7, "/tmp/crabc-spawn-open", O_CREAT | O_RDWR,
                (mode_t)0640) != 0 || errno != saved_errno)
        return 7;
    open = (struct crabc_fdop *)actions.__actions;
    if (!check_action(open, 3, 7, 0, O_CREAT | O_RDWR, (mode_t)0640,
                      "/tmp/crabc-spawn-open") || open->prev ||
        open->next != dup2 || dup2->prev != open)
        return 8;

    if (addchdir(&actions, "/tmp/crabc-spawn-chdir") != 0 ||
        errno != saved_errno)
        return 9;
    chdir = (struct crabc_fdop *)actions.__actions;
    if (!check_action(chdir, 4, -1, 0, 0, 0, "/tmp/crabc-spawn-chdir") ||
        chdir->prev || chdir->next != open || open->prev != chdir)
        return 10;

    if (addfchdir(&actions, 8) != 0 || errno != saved_errno)
        return 11;
    fchdir = (struct crabc_fdop *)actions.__actions;
    if (!check_action(fchdir, 5, 8, 0, 0, 0, 0) || fchdir->prev ||
        fchdir->next != chdir || chdir->prev != fchdir)
        return 12;

    head = fchdir;
    if (addclose(&actions, -1) != EBADF || errno != saved_errno ||
        actions.__actions != head)
        return 13;
    if (adddup2(&actions, -1, 0) != EBADF || errno != saved_errno ||
        actions.__actions != head)
        return 14;
    if (adddup2(&actions, 0, -1) != EBADF || errno != saved_errno ||
        actions.__actions != head)
        return 15;
    if (addopen(&actions, -1, "/tmp/crabc-invalid", O_RDONLY, 0) != EBADF ||
        errno != saved_errno || actions.__actions != head)
        return 16;
    if (addfchdir(&actions, -1) != EBADF || errno != saved_errno ||
        actions.__actions != head)
        return 17;

    if (destroy(&actions) != 0 || errno != saved_errno)
        return 18;
    /* Musl frees the list but does not clear fa->__actions.  The caller must
     * not reuse the object until a fresh init; this checks only that source
     * contract and deliberately does not dereference the dangling pointer. */
    if (actions.__actions != head)
        return 19;
    return check_reused_descriptor_actions();
}

#ifndef CRABC_POSIX_SPAWN_FILE_ACTIONS_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_spawn_file_actions_probe();
}
#endif
