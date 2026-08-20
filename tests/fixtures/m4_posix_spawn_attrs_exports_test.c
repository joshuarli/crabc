#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t actions;
    sigset_t mask;
    sigset_t default_set;
    sigset_t got_mask;
    sigset_t got_default;
    struct sched_param param;
    struct sched_param got_param;
    short flags;
    pid_t pgroup;
    int policy;
    int directory_fd;
    int old_errno;

    CHECK(posix_spawnattr_init(&attr) == 0, "attr init");
    CHECK(posix_spawnattr_setflags(
              &attr,
              POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP |
                  POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK |
                  POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER |
                  POSIX_SPAWN_USEVFORK) == 0,
          "set flags");
    CHECK(posix_spawnattr_getflags(&attr, &flags) == 0 &&
              flags == (POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP |
                        POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK |
                        POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER |
                        POSIX_SPAWN_USEVFORK),
          "get flags");
    CHECK(posix_spawnattr_setflags(&attr, (short)0x80) == EINVAL,
          "invalid flags direct error");

    CHECK(posix_spawnattr_setpgroup(&attr, 1234) == 0 &&
              posix_spawnattr_getpgroup(&attr, &pgroup) == 0 &&
              pgroup == 1234,
          "pgroup");

    memset(&mask, 0x5a, sizeof(mask));
    memset(&default_set, 0xa5, sizeof(default_set));
    memset(&got_mask, 0, sizeof(got_mask));
    memset(&got_default, 0, sizeof(got_default));
    CHECK(posix_spawnattr_setsigmask(&attr, &mask) == 0 &&
              posix_spawnattr_getsigmask(&attr, &got_mask) == 0 &&
              memcmp(&mask, &got_mask, sizeof(mask)) == 0,
          "signal mask");
    CHECK(posix_spawnattr_setsigdefault(&attr, &default_set) == 0 &&
              posix_spawnattr_getsigdefault(&attr, &got_default) == 0 &&
              memcmp(&default_set, &got_default, sizeof(default_set)) == 0,
          "default signal set");

    param.sched_priority = 17;
    memset(&got_param, 0, sizeof(got_param));
    CHECK(posix_spawnattr_setschedparam(&attr, &param) == 0 &&
              posix_spawnattr_getschedparam(&attr, &got_param) == 0 &&
              got_param.sched_priority == 17,
          "sched param");
    CHECK(posix_spawnattr_setschedpolicy(&attr, SCHED_RR) == 0 &&
              posix_spawnattr_getschedpolicy(&attr, &policy) == 0 &&
              policy == SCHED_RR,
          "sched policy");

    old_errno = EAGAIN;
    errno = old_errno;
    CHECK(posix_spawnattr_getflags(NULL, &flags) == EINVAL && errno == old_errno,
          "attr null direct error");

    CHECK(posix_spawn_file_actions_init(&actions) == 0, "actions init");
    CHECK(posix_spawn_file_actions_addopen(
              &actions, 17, "/tmp/crabc-m4-spawn-open", O_CREAT | O_RDWR,
              0600) == 0,
          "addopen");
    CHECK(posix_spawn_file_actions_addchdir_np(&actions, "/tmp") == 0,
          "addchdir_np");

    directory_fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    CHECK(directory_fd >= 0, "open directory");
    CHECK(posix_spawn_file_actions_addfchdir_np(&actions, directory_fd) == 0,
          "addfchdir_np");

    errno = old_errno;
    CHECK(posix_spawn_file_actions_addopen(NULL, 17, "/tmp/x", O_RDONLY, 0) ==
              EINVAL && errno == old_errno,
          "actions null direct error");
    CHECK(posix_spawn_file_actions_addopen(&actions, 17, NULL, O_RDONLY, 0) ==
              EINVAL,
          "actions path direct error");

    close(directory_fd);
    CHECK(posix_spawn_file_actions_destroy(&actions) == 0, "actions destroy");
    CHECK(posix_spawnattr_destroy(&attr) == 0, "attr destroy");
    puts("m4 posix spawn attrs exports ok");
    return 0;
}
