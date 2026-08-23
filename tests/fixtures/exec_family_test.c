#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

static int run_case(int which, int script_fd)
{
    int status = -1;
    pid_t child = fork();
    if (child < 0) return 100;
    if (child == 0) {
        char *const true_argv[] = { (char *)"true", NULL };
        char *const script_argv[] = { (char *)"exec-script", (char *)"argument", NULL };
        char *const custom_env[] = { (char *)"EXECVPE_MARKER=yes", NULL };

        switch (which) {
        case 0:
            execv("/bin/true", true_argv);
            _exit(110 + errno);
        case 1:
            execvp("exec-script", script_argv);
            _exit(110 + errno);
        case 2:
            execlp("exec-script", "exec-script", "argument", (char *)NULL);
            _exit(110 + errno);
        case 3:
            execvpe("exec-script", script_argv, custom_env);
            _exit(110 + errno);
        case 4:
            fexecve(script_fd, true_argv, environ);
            _exit(110 + errno);
        case 5:
            errno = 0;
            if (execvp("missing-exec-file", script_argv) < 0 && errno == ENOENT)
                _exit(0);
            _exit(110 + errno);
        case 6:
            errno = 0;
            if (execvp("blocked-exec-file", script_argv) < 0 && errno == EACCES)
                _exit(0);
            _exit(110 + errno);
        default:
            _exit(120);
        }
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 101;
    return WEXITSTATUS(status);
}

int main(void)
{
    char directory[] = "/tmp/crabc-exec-family-XXXXXX";
    char path[256];
    char script[256];
    char blocked[256];
    char *dir;
    int fd;
    int script_fd;
    FILE *stream;

    dir = mkdtemp(directory);
    CHECK(dir != NULL, "mkdtemp");
    CHECK(snprintf(script, sizeof script, "%s/exec-script", dir) > 0, "script path");
    CHECK(snprintf(blocked, sizeof blocked, "%s/blocked-exec-file", dir) > 0, "blocked path");

    stream = fopen(script, "w");
    CHECK(stream != NULL, "script open");
    CHECK(fputs("if [ \"$EXECVPE_MARKER\" = yes ]; then exit 43; fi\nexit 41\n", stream) >= 0,
          "script write");
    CHECK(fclose(stream) == 0, "script close");
    CHECK(chmod(script, 0755) == 0, "script chmod");

    fd = open(blocked, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0, "blocked open");
    CHECK(write(fd, "blocked\n", 8) == 8, "blocked write");
    CHECK(close(fd) == 0, "blocked close");
    CHECK(chmod(blocked, 0644) == 0, "blocked chmod");

    /* The trailing empty PATH component is the current-directory entry. */
    CHECK(snprintf(path, sizeof path, "%s:", directory) > 0, "path");
    CHECK(setenv("PATH", path, 1) == 0, "setenv path");
    script_fd = open("/bin/true", O_RDONLY);
    CHECK(script_fd >= 0, "open true");

    CHECK(run_case(0, script_fd) == 0, "execv");
    CHECK(run_case(1, script_fd) == 41, "execvp shell fallback");
    CHECK(run_case(2, script_fd) == 41, "execlp shell fallback");
    CHECK(run_case(3, script_fd) == 43, "execvpe environment");
    CHECK(run_case(4, script_fd) == 0, "fexecve");
    CHECK(run_case(5, script_fd) == 0, "execvp ENOENT");
    CHECK(run_case(6, script_fd) == 0, "execvp EACCES");

    CHECK(close(script_fd) == 0, "close true");
    CHECK(unlink(script) == 0, "unlink script");
    CHECK(unlink(blocked) == 0, "unlink blocked");
    CHECK(rmdir(directory) == 0, "rmdir");

    puts("c-abi exec family ok");
    return 0;
}
