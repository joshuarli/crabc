/*
 * Native C consumer for the test-only private wordexp process bridge.
 *
 * This declaration has no installed header and is compiled only against the
 * disposable archive built with crabc_owned_wordexp_process_private_test.
 * It intentionally exercises command-boundary expressions only: pathname
 * expansion remains the adjacent private adapter's responsibility.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    CRABC_WORDEXP_PROCESS_TEST_OK = 0,
    CRABC_WORDEXP_PROCESS_TEST_NO_SPACE = 1,
    CRABC_WORDEXP_PROCESS_TEST_OUTPUT_NUL = 2,
    CRABC_WORDEXP_PROCESS_TEST_COMMAND_FORBIDDEN = 3,
    CRABC_WORDEXP_PROCESS_TEST_BAD_ARGUMENT = 4,
    CRABC_WORDEXP_PROCESS_TEST_OUTPUT_CAPACITY = 5,
    CRABC_WORDEXP_PROCESS_TEST_EVALUATION_FAILURE = 6,
};

enum {
    CRABC_WORDEXP_PROCESS_TEST_SHOWERR = 1,
    CRABC_WORDEXP_PROCESS_TEST_NOCMD = 2,
};

extern int crabc_owned_wordexp_process_private_test(
    const char *input,
    int flags,
    char *output,
    size_t output_capacity,
    size_t *output_length,
    size_t *output_words
);

static int expect_words(
    const char *input,
    int flags,
    const char *const expected[],
    size_t expected_count
)
{
    char output[4096];
    size_t output_length = 0;
    size_t output_words = 0;
    size_t index;
    size_t offset = 0;

    if (crabc_owned_wordexp_process_private_test(
            input, flags, output, sizeof output, &output_length, &output_words
        ) != CRABC_WORDEXP_PROCESS_TEST_OK)
        return 0;
    if (output_words != expected_count)
        return 0;
    for (index = 0; index < expected_count; index++) {
        size_t length = strlen(expected[index]);
        if (offset > output_length || length >= output_length - offset ||
            memcmp(output + offset, expected[index], length) != 0 ||
            output[offset + length] != '\0')
            return 0;
        offset += length + 1;
    }
    return offset == output_length;
}

static int expect_status(const char *input, int flags, int expected)
{
    char output[64];
    size_t output_length = 123;
    size_t output_words = 123;
    int status = crabc_owned_wordexp_process_private_test(
        input, flags, output, sizeof output, &output_length, &output_words
    );
    return status == expected && output_length == 0 && output_words == 0;
}

static int file_length(const char *path)
{
    char bytes[64];
    int descriptor = open(path, O_RDONLY);
    ssize_t read_count;
    int total = 0;

    if (descriptor < 0)
        return -1;
    while ((read_count = read(descriptor, bytes, sizeof bytes)) > 0) {
        if (read_count > 64 - total) {
            close(descriptor);
            return -1;
        }
        total += (int)read_count;
    }
    if (close(descriptor) != 0 || read_count < 0)
        return -1;
    return total;
}

static pid_t pid_from_file(const char *path)
{
    char bytes[32];
    int descriptor = open(path, O_RDONLY);
    ssize_t length;
    size_t index;
    pid_t value = 0;

    if (descriptor < 0)
        return -1;
    length = read(descriptor, bytes, sizeof bytes);
    if (close(descriptor) != 0 || length <= 0 || length >= (ssize_t)sizeof bytes)
        return -1;
    for (index = 0; index < (size_t)length; index++) {
        if (bytes[index] < '0' || bytes[index] > '9')
            return -1;
        if (value > (pid_t)214748364 ||
            (value == (pid_t)214748364 && bytes[index] > '7'))
            /* avoid relying on strtol in this probe */
            return -1;
        value = value * 10 + (pid_t)(bytes[index] - '0');
    }
    return value > 0 ? value : -1;
}

static int already_reaped(pid_t child)
{
    int status;
    errno = 0;
    return waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD;
}

/* This mode is invoked from a root with no /bin/sh. It demonstrates that
 * evaluation which selects no command leaves the process adapter untouched. */
static int no_command_mode(void)
{
    static const char *const ordinary[] = { "ordinary", "fallback" };

    if (unsetenv("CRABC_WORDEXP_PROCESS_NO_COMMAND_UNSET") != 0 ||
        !expect_words(
            "ordinary ${CRABC_WORDEXP_PROCESS_NO_COMMAND_UNSET:-fallback}",
            0, ordinary, 2
        ))
        return 0;
    return 1;
}

int main(int argc, char **argv)
{
    static const char *const trim[] = { "trim" };
    static const char *const status_output[] = { "status" };
    static const char *const empty[] = { "" };
    static const char *const first[] = { "first" };
    static const char *const second[] = { "second" };
    static const char *const local[] = { "a'b", "a'b:" };
    static const char *const exported[] = { "new", "new" };
    static const char *const ifs[] = { "one,two" };
    static const char *const unquoted_backtick[] = { "\"hi\"" };
    static const char *const quoted_backtick[] = { "hi" };
    static const char *const foo[] = { "foo" };
    static const char *const selected[] = { "selected" };
    static const char *const quiet[] = { "quiet" };
    static const char *const shown[] = { "shown" };
    static const char *const autoreaped[] = { "autoreaped" };
    const char *marker;
    const char *pid_file;
    void (*prior_sigchld)(int);
    pid_t shell_leader;
    int autoreap_ok;

    if (argc == 2 && strcmp(argv[1], "--no-command") == 0) {
        if (!no_command_mode())
            return 19;
        puts("private x86 wordexp process no-command bridge: PASS");
        return 0;
    }
    if (argc != 3)
        return 1;
    marker = argv[1];
    pid_file = argv[2];
    if (setenv("CRABC_WORDEXP_PROCESS_MARKER", marker, 1) != 0 ||
        setenv("CRABC_WORDEXP_PROCESS_PIDFILE", pid_file, 1) != 0)
        return 2;
    unlink(marker);
    unlink(pid_file);

    if (!expect_words("\"$(printf 'trim\\n\\n')\"", 0, trim, 1))
        return 3;
    /* A nonzero command status remains a successful output transaction. */
    if (!expect_words("\"$(printf status; false)\"", 0, status_output, 1))
        return 4;
    if (!expect_words("\"$(printf '')\"", 0, empty, 1))
        return 5;

    if (setenv("CRABC_WORDEXP_PROCESS_CURRENT", "first", 1) != 0 ||
        !expect_words("\"$(printf '%s' \"$CRABC_WORDEXP_PROCESS_CURRENT\")\"", 0, first, 1) ||
        setenv("CRABC_WORDEXP_PROCESS_CURRENT", "second", 1) != 0 ||
        !expect_words("\"$(printf '%s' \"$CRABC_WORDEXP_PROCESS_CURRENT\")\"", 0, second, 1))
        return 6;

    if (unsetenv("CRABC_WORDEXP_PROCESS_LOCAL") != 0 ||
        !expect_words(
            "${CRABC_WORDEXP_PROCESS_LOCAL:=a\\'b} "
            "\"$(printf '%s:' \"$CRABC_WORDEXP_PROCESS_LOCAL\"; "
            "/bin/sh -c 'printf %s \"$CRABC_WORDEXP_PROCESS_LOCAL\"')\"",
            0, local, 2
        ) || getenv("CRABC_WORDEXP_PROCESS_LOCAL") != NULL)
        return 7;

    if (setenv("CRABC_WORDEXP_PROCESS_EXPORT", "", 1) != 0 ||
        !expect_words(
            "\"${CRABC_WORDEXP_PROCESS_EXPORT:=new}\" "
            "\"$(/bin/sh -c 'printf %s \"$CRABC_WORDEXP_PROCESS_EXPORT\"')\"",
            0, exported, 2
        ) || getenv("CRABC_WORDEXP_PROCESS_EXPORT") == NULL ||
        strcmp(getenv("CRABC_WORDEXP_PROCESS_EXPORT"), "") != 0)
        return 8;

    if (setenv("IFS", ":", 1) != 0)
        return 9;
    if (!expect_words(
            "\"$(value='one:two'; set -- $value; printf '%s,%s' \"$1\" \"$2\")\"",
            0, ifs, 1
        ) || getenv("IFS") == NULL || strcmp(getenv("IFS"), ":") != 0) {
        unsetenv("IFS");
        return 9;
    }
    if (unsetenv("IFS") != 0)
        return 9;

    if (!expect_words("`printf '%s' \\\"hi\\\"`", 0, unquoted_backtick, 1) ||
        !expect_words("\"`printf '%s' \\\"hi\\\"`\"", 0, quoted_backtick, 1) ||
        !expect_words("`printf fo" "\\" "\n" "o`", 0, foo, 1) ||
        !expect_words("\"`printf fo" "\\" "\n" "o`\"", 0, foo, 1))
        return 10;

    if (!expect_words(
            "$(printf selected; printf x >> \"$CRABC_WORDEXP_PROCESS_MARKER\")",
            0, selected, 1
        ) || file_length(marker) != 1)
        return 11;
    if (unsetenv("CRABC_WORDEXP_PROCESS_UNSELECTED") != 0 ||
        !expect_words(
            "${CRABC_WORDEXP_PROCESS_UNSELECTED:+$(printf not-selected; "
            "printf x >> \"$CRABC_WORDEXP_PROCESS_MARKER\")}",
            0, NULL, 0
        ) || file_length(marker) != 1)
        return 12;
    if (!expect_status(
            "$(printf forbidden; printf x >> \"$CRABC_WORDEXP_PROCESS_MARKER\")",
            CRABC_WORDEXP_PROCESS_TEST_NOCMD,
            CRABC_WORDEXP_PROCESS_TEST_COMMAND_FORBIDDEN
        ) || file_length(marker) != 1)
        return 13;

    if (!expect_words("\"$(printf hidden >&2; printf quiet)\"", 0, quiet, 1) ||
        !expect_words(
            "\"$(printf visible >&2; printf shown)\"",
            CRABC_WORDEXP_PROCESS_TEST_SHOWERR, shown, 1
        ))
        return 14;

    prior_sigchld = signal(SIGCHLD, SIG_IGN);
    if (prior_sigchld == SIG_ERR)
        return 15;
    autoreap_ok = expect_words("\"$(printf autoreaped)\"", 0, autoreaped, 1);
    if (signal(SIGCHLD, prior_sigchld) == SIG_ERR)
        return 16;
    if (!autoreap_ok)
        return 16;

    if (!expect_status(
            "$(trap '' PIPE; printf '%s' \"$$\" > \"$CRABC_WORDEXP_PROCESS_PIDFILE\"; "
            "printf 'x\\000'; while :; do :; done)",
            0, CRABC_WORDEXP_PROCESS_TEST_OUTPUT_NUL
        ))
        return 17;
    shell_leader = pid_from_file(pid_file);
    if (shell_leader <= 0 || !already_reaped(shell_leader))
        return 18;

    puts("private x86 wordexp process bridge: PASS");
    return 0;
}
