#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <sys/acct.h>
#include <sys/klog.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/quota.h>
#include <sys/reboot.h>
#include <sys/swap.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            goto cleanup; \
        } \
    } while (0)

static int permitted_error(int error, int first, int second, int third,
                           int fourth, int fifth)
{
    return error == first || error == second || error == third ||
           error == fourth || error == fifth;
}

#define EXPECT_ERROR(expression, first, second, third, fourth, fifth, message) \
    do { \
        errno = 0; \
        if ((expression) != -1 || \
            !permitted_error(errno, (first), (second), (third), (fourth), (fifth))) { \
            puts(message); \
            goto cleanup; \
        } \
    } while (0)

static int check_vhangup_isolated(void)
{
    pid_t child = fork();
    int status = 0;

    if (child < 0)
        return 0;
    if (child == 0) {
        int result;
        if (setsid() < 0)
            _exit(240);
        errno = 0;
        result = vhangup();
        if (result == -1 && (errno == EPERM || errno == ENXIO))
            _exit(0);
        _exit(241);
    }
    if (waitpid(child, &status, 0) != child)
        return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(void)
{
    const char missing[] = "/tmp/crabc-c-abi-kernel-admin-no-such-entry";
    int result = 1;

    /* Capability-gated calls use nonexistent or null inputs, so no privileged
     * state can be changed even if the test runner has extra capabilities. */
    EXPECT_ERROR(acct(missing), EPERM, ENOENT, EACCES, EINVAL, EFAULT,
                  "acct");
    EXPECT_ERROR(delete_module("", 0), EPERM, ENOENT, EINVAL, EFAULT, EBUSY,
                  "delete_module");
    EXPECT_ERROR(init_module(NULL, 0, NULL), EPERM, EINVAL, EFAULT, ENOEXEC,
                  E2BIG, "init_module");

    /* An invalid syslog action cannot read or clear the kernel log. */
    EXPECT_ERROR(klogctl(-1, NULL, 0), EINVAL, EPERM, EFAULT, EACCES, ENOENT,
                  "klogctl");
    EXPECT_ERROR(mount(NULL, NULL, NULL, 0, NULL), EPERM, EFAULT, EINVAL,
                  EACCES, ENOENT, "mount");
    EXPECT_ERROR(umount(missing), EPERM, ENOENT, EINVAL, EACCES, EFAULT,
                  "umount");
    EXPECT_ERROR(umount2(missing, -1), EINVAL, EPERM, ENOENT, EACCES, EFAULT,
                  "umount2");
    EXPECT_ERROR(pivot_root(NULL, NULL), EPERM, EFAULT, EINVAL, EACCES, ENOENT,
                  "pivot_root");
    EXPECT_ERROR(quotactl(-1, NULL, 0, NULL), EINVAL, EPERM, EFAULT, EACCES,
                  ENOENT, "quotactl");
    EXPECT_ERROR(reboot(-1), EPERM, EINVAL, EFAULT, EACCES, ENOENT, "reboot");
    EXPECT_ERROR(swapoff(missing), EPERM, ENOENT, EINVAL, EACCES, EFAULT,
                  "swapoff");
    EXPECT_ERROR(swapon(missing, 0), EPERM, ENOENT, EINVAL, EACCES, EFAULT,
                  "swapon");
    CHECK(check_vhangup_isolated(), "vhangup");

    result = 0;

cleanup:
    if (result == 0)
        puts("c-abi kernel admin syscalls ok");
    return result;
}
